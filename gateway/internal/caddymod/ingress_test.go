package caddymod

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/gate"
	"github.com/deutschland-schild/schild/gateway/internal/stats"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

func testGate(t testing.TB) *gate.Gate {
	t.Helper()
	inst, err := waf.Build(waf.Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err != nil {
		t.Fatal(err)
	}
	res, _ := clientip.New([]string{"127.0.0.1/32", "::1/128"}, nil)
	g := gate.New(gate.Settings{Mode: decide.ModeAutoblock, EvalTimeout: 2 * time.Second, Resolver: res})
	g.Engine = &waf.Engine{}
	g.Engine.Swap(inst)
	g.Allow = allowlist.New()
	g.Counters = gate.NewCounters()
	g.SetReady(true)
	return g
}

func bind(t testing.TB, g *gate.Gate) {
	t.Helper()
	release, err := Bind(g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
}

// caddyDir is t.TempDir for tests that load Caddy with a storage folder
// in it: Caddy's TLS app cleans its storage in a goroutine that Stop does
// not wait for, and it may still hold a lock file in the folder while the
// test ends (TempDir cleanup: "directory not empty", evening measurement
// 2026-10-29 6). The cleanup retries the removal for a few seconds.
func caddyDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "schild-caddymod-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var err error
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if err = os.RemoveAll(dir); err == nil {
				return
			}
		}
		t.Errorf("remove %s: %v", dir, err)
	})
	return dir
}

func writeFile(t testing.TB, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func adapt(t *testing.T, caddyfile string) []byte {
	t.Helper()
	p := writeFile(t, t.TempDir(), "Caddyfile", caddyfile)
	b, _, err := ReadCaddyfile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDirectiveOrder(t *testing.T) {
	// Written after reverse_proxy and file_server, sorted before them all.
	b := adapt(t, `
http://a.example.test {
	reverse_proxy 127.0.0.1:9
	handle /files/* {
		file_server
	}
	redir /old /new
	rewrite /x /y
	basic_auth /admin/* {
		admin $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG
	}
	schild
}`)
	s := string(b)
	i := strings.Index(s, `"handler":"schild"`)
	if i < 0 {
		t.Fatalf("no schild handler: %s", s)
	}
	for _, h := range []string{"reverse_proxy", "file_server", "static_response", "rewrite", "authentication", "subroute\",\"routes\":[{\"handle\":[{\"handler\":\"file_server"} {
		if j := strings.Index(s, `"handler":"`+h); j >= 0 && j < i {
			t.Errorf("%s before schild: %s", h, s)
		}
	}
	c, err := CheckConfig(b, nil)
	if err != nil || c.Err() != nil || !c.Sites[0].Schild {
		t.Fatalf("check: %+v %v", c, err)
	}
}

func TestDirectiveSyntax(t *testing.T) {
	for _, bad := range []string{"schild on", "schild {\n\t\tmode observe\n\t}"} {
		p := writeFile(t, t.TempDir(), "Caddyfile", "http://a.example.test {\n\t"+bad+"\n\treverse_proxy 127.0.0.1:9\n}\n")
		if _, _, err := ReadCaddyfile(p); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// A matcher is allowed (every handler directive takes one) but does not
	// protect the whole site.
	b := adapt(t, "http://a.example.test {\n\tschild /api/*\n\treverse_proxy 127.0.0.1:9\n}\n")
	c, _ := CheckConfig(b, nil)
	if c.Err() == nil {
		t.Fatal("schild with a matcher in front of an unconditional reverse_proxy accepted")
	}
}

func TestCheckConfig(t *testing.T) {
	cases := []struct {
		name        string
		caddyfile   string
		unprotected []string
		errs        int
		warns       int
	}{
		{"protected", "http://a.example.test {\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n", nil, 0, 0},
		{"snippet", "(schild) {\n\tschild\n}\nhttp://a.example.test, http://www.a.example.test {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n}\n", nil, 0, 0},
		{"no schild", "http://a.example.test {\n\treverse_proxy 127.0.0.1:9\n}\n", nil, 1, 0},
		{"empty snippet (rollback Caddyfile)", "(schild) {\n}\nhttp://a.example.test {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n}\n", nil, 1, 0},
		{"php_fastcgi", "http://a.example.test {\n\troot * /srv\n\tphp_fastcgi 127.0.0.1:9000\n}\n", nil, 1, 0},
		{"listed", "http://a.example.test {\n\treverse_proxy 127.0.0.1:9\n}\n", []string{"a.example.test"}, 0, 0},
		{"listed wildcard", "http://x.a.example.test {\n\treverse_proxy 127.0.0.1:9\n}\n", []string{"*.a.example.test"}, 0, 0},
		{"wildcard is one label", "http://y.x.a.example.test {\n\treverse_proxy 127.0.0.1:9\n}\n", []string{"*.a.example.test"}, 1, 1},
		{"one of two hosts listed", "http://a.example.test, http://b.example.test {\n\treverse_proxy 127.0.0.1:9\n}\n", []string{"a.example.test"}, 1, 1},
		{"unused listing", "http://a.example.test {\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n", []string{"old.example.test"}, 0, 1},
		{"file_server only", "http://static.example.test {\n\troot * /srv\n\tfile_server\n}\n", nil, 0, 1},
		{"redirect only", "http://example.test {\n\tredir https://www.example.test{uri}\n}\n", nil, 0, 0},
		{"two sites, one without", "http://a.example.test {\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\nhttp://b.example.test {\n\treverse_proxy 127.0.0.1:10\n}\n", nil, 1, 0},
		{"catch-all site", ":8080 {\n\treverse_proxy 127.0.0.1:9\n}\n", nil, 1, 0},
		{"proxy in route before schild", "http://a.example.test {\n\troute {\n\t\treverse_proxy /early/* 127.0.0.1:9\n\t\tschild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", nil, 1, 0},
		{"schild inside route first", "http://a.example.test {\n\troute {\n\t\tschild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", nil, 0, 0},
		{"schild only in one handle", "http://a.example.test {\n\thandle /api/* {\n\t\tschild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n\thandle {\n\t\treverse_proxy 127.0.0.1:10\n\t}\n}\n", nil, 1, 0},
		{"handle_errors proxy without schild", "http://a.example.test {\n\trespond 404\n\thandle_errors {\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", nil, 1, 0},
		{"handle_errors proxy, schild only in the site", "http://a.example.test {\n\tschild\n\treverse_proxy 127.0.0.1:9\n\thandle_errors {\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", nil, 1, 0},
		{"handle_errors proxy with schild inside", "http://a.example.test {\n\tschild\n\treverse_proxy 127.0.0.1:9\n\thandle_errors {\n\t\tschild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n", nil, 0, 0},
		{"named route", "&(app) {\n\treverse_proxy 127.0.0.1:9\n}\nhttp://a.example.test {\n\tinvoke app\n}\nhttp://b.example.test {\n\tschild\n\tinvoke app\n}\n", nil, 1, 0},
		{"forward_auth before schild is fine", "http://a.example.test {\n\tschild\n\tforward_auth 127.0.0.1:9 {\n\t\turi /auth\n\t}\n\treverse_proxy 127.0.0.1:9\n}\n", nil, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := CheckConfig(adapt(t, tc.caddyfile), tc.unprotected)
			if err != nil {
				t.Fatal(err)
			}
			if len(c.Errors) != tc.errs || len(c.Warnings) != tc.warns {
				t.Fatalf("errors %d (want %d), warnings %d (want %d): %+v", len(c.Errors), tc.errs, len(c.Warnings), tc.warns, c)
			}
		})
	}
	if c, _ := CheckConfig([]byte(`{"apps":{}}`), nil); c.Err() == nil {
		t.Fatal("config without sites accepted")
	}
}

func TestTrustedProxiesWarning(t *testing.T) {
	const site = "http://a.example.test {\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n"
	plain := adapt(t, site)
	withProxies := adapt(t, "{\n\tservers {\n\t\ttrusted_proxies static 192.0.2.0/24\n\t}\n}\n"+site)
	if trustedProxiesWarning(plain, []string{"127.0.0.1/32", "::1/128"}) != "" {
		t.Error("warning for the loopback default")
	}
	if trustedProxiesWarning(plain, []string{"192.0.2.0/24"}) == "" {
		t.Error("no warning for a proxy Caddy does not know")
	}
	if trustedProxiesWarning(withProxies, []string{"192.0.2.0/24"}) != "" {
		t.Error("warning although the Caddyfile sets trusted_proxies")
	}
}

func TestPrepareIngress(t *testing.T) {
	dir := caddyDir(t)
	p := writeFile(t, dir, "Caddyfile", "{\n\tadmin localhost:2019\n\tstorage file_system /var/lib/caddy-old\n}\nhttp://a.example.test {\n\timport sites/*.caddy\n\treverse_proxy 127.0.0.1:9\n}\n")
	writeFile(t, dir, "sites/schild.caddy", "schild\n")
	ing, err := PrepareIngress(IngressOptions{Caddyfile: p, Storage: "/data/caddy", DefaultStorage: "/var/lib/schild/caddy"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(ing.JSON, &m)
	if a := m["admin"].(map[string]any); a["disabled"] != true {
		t.Fatalf("admin: %v", a)
	}
	if st := m["storage"].(map[string]any); st["root"] != "/data/caddy" || ing.StorageRoot != "/data/caddy" {
		t.Fatalf("storage: %v", st)
	}
	if len(ing.Check.Warnings) < 2 {
		t.Fatalf("expected warnings for admin and storage: %v", ing.Check.Warnings)
	}
	// Without ingress.storage the Caddyfile's storage stays; without both the default.
	ing, err = PrepareIngress(IngressOptions{Caddyfile: p, DefaultStorage: "/var/lib/schild/caddy"})
	if err != nil || ing.StorageRoot != "/var/lib/caddy-old" {
		t.Fatalf("caddyfile storage: %v %v", ing, err)
	}
	p2 := writeFile(t, dir, "Caddyfile2", "http://a.example.test {\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n")
	ing, err = PrepareIngress(IngressOptions{Caddyfile: p2, DefaultStorage: "/var/lib/schild/caddy"})
	if err != nil || ing.StorageRoot != "/var/lib/schild/caddy" {
		t.Fatalf("default storage: %v %v", ing, err)
	}
	// automatic HTTPS and the storage checks stay as the Caddyfile says.
	if strings.Contains(string(ing.JSON), "disable_storage_check") || strings.Contains(string(ing.JSON), `"automatic_https"`) {
		t.Fatalf("ingress config changed automatic HTTPS or storage checks: %s", ing.JSON)
	}
	p3 := writeFile(t, dir, "Caddyfile3", "http://a.example.test {\n\treverse_proxy 127.0.0.1:9\n}\n")
	if _, err := PrepareIngress(IngressOptions{Caddyfile: p3, DefaultStorage: "/x"}); err == nil || !strings.Contains(err.Error(), "without schild") {
		t.Fatalf("unprotected site: %v", err)
	}
	if _, err := PrepareIngress(IngressOptions{Caddyfile: filepath.Join(dir, "missing"), DefaultStorage: "/x"}); err == nil {
		t.Fatal("missing Caddyfile accepted")
	}
	if _, err := PrepareIngress(IngressOptions{Caddyfile: writeFile(t, dir, "Caddyfile4", "http://a.example.test {\n\tnot_a_directive\n}\n"), DefaultStorage: "/x"}); err == nil {
		t.Fatal("unknown directive accepted")
	}
}

// Every server refuses QUIC 0-RTT, also when the Caddyfile allows it: early
// data can be replayed.
func TestIngressRefusesEarlyData(t *testing.T) {
	dir := caddyDir(t)
	p := writeFile(t, dir, "Caddyfile", "{\n\tservers {\n\t\tprotocols h1 h2 h3\n\t}\n}\nhttps://a.example.test {\n\ttls internal\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\nhttp://b.example.test:8081 {\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n")
	ing, err := PrepareIngress(IngressOptions{Caddyfile: p, DefaultStorage: "/var/lib/schild/caddy"})
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Apps struct {
			HTTP struct {
				Servers map[string]map[string]any `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(ing.JSON, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Apps.HTTP.Servers) < 2 {
		t.Fatalf("servers: %v", m.Apps.HTTP.Servers)
	}
	for name, s := range m.Apps.HTTP.Servers {
		if s["allow_0rtt"] != false {
			t.Errorf("server %s: allow_0rtt %v", name, s["allow_0rtt"])
		}
	}
}

// TestValidateIngress: validation provisions the config but has no side
// effects: no storage, no log file and no log directory (the writers are
// provisioned, not opened); a broken log writer is still refused.
func TestValidateIngress(t *testing.T) {
	dir := caddyDir(t)
	p := writeFile(t, dir, "Caddyfile", fmt.Sprintf("{\n\tlog {\n\t\toutput file %s\n\t}\n}\nhttp://a.example.test:%s {\n\tschild\n\tlog {\n\t\toutput file %s\n\t\tformat json\n\t}\n\treverse_proxy 127.0.0.1:9\n}\n",
		filepath.Join(dir, "global", "caddy.log"), port(freePort(t)), filepath.Join(dir, "sub", "access.log")))
	ing, err := PrepareIngress(IngressOptions{Caddyfile: p, DefaultStorage: filepath.Join(dir, "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateIngress(ing); err != nil {
		t.Fatal(err)
	}
	if Bound() != nil {
		t.Fatal("validation left a gate bound")
	}
	for _, n := range []string{"caddy", "sub", "global"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			t.Fatalf("validation created %s", n)
		}
	}
	var m map[string]any
	if err := json.Unmarshal(ing.JSON, &m); err != nil {
		t.Fatal(err)
	}
	// The default log would print Caddy's JSON lines to stderr in the middle
	// of the report: it stays on stderr and shows errors only.
	quiet := map[string]any{"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"writer": map[string]any{"output": "discard"}, "level": "DEBUG"}}}}
	quietDefaultLog(quiet)
	if def := quiet["logging"].(map[string]any)["logs"].(map[string]any)["default"].(map[string]any); def["level"] != "ERROR" || def["writer"] != nil {
		t.Fatalf("default log not quiet: %v", quiet)
	}
	empty := map[string]any{}
	quietDefaultLog(empty)
	if def := empty["logging"].(map[string]any)["logs"].(map[string]any)["default"].(map[string]any); def["level"] != "ERROR" {
		t.Fatalf("default log not quiet: %v", empty)
	}
	m["logging"].(map[string]any)["logs"].(map[string]any)["default"].(map[string]any)["writer"] = map[string]any{"output": "file", "filename": "x.log", "no_such_option": true}
	broken, _ := json.Marshal(m)
	// A read-only root file system has no writable temp directory: the
	// fallback directory (the data volume) takes it and is left clean.
	fallback := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(fallback, "missing"))
	if err := ValidateIngress(ing); err == nil || !strings.Contains(err.Error(), "no writable place") {
		t.Fatalf("no temp directory, no fallback: %v", err)
	}
	if err := ValidateIngress(ing, "", filepath.Join(fallback, "missing-too"), fallback); err != nil {
		t.Fatalf("fallback directory: %v", err)
	}
	if left, _ := os.ReadDir(fallback); len(left) != 0 {
		t.Fatalf("validation left %v in the fallback directory", left)
	}
	if err := ValidateIngress(&Ingress{JSON: broken}, fallback); err == nil || !strings.Contains(err.Error(), "no_such_option") {
		t.Fatalf("broken log writer: %v", err)
	}
	if _, err := os.Stat("x.log"); err == nil {
		t.Fatal("validation created x.log")
	}
}

func port(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

type served struct {
	status int
	body   string
	header http.Header
}

func fetch(t testing.TB, c *http.Client, url, host string, hdr map[string]string) served {
	t.Helper()
	var resp *http.Response
	var err error
	for i := 0; i < 100; i++ {
		req, _ := http.NewRequest("GET", url, nil)
		req.Host = host
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
		req.Header.Set("Accept", "text/html")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err = c.Do(req)
		if err == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return served{resp.StatusCode, string(b), resp.Header}
}

// TestIngressServes loads a Caddyfile with several sites, a probe-block
// snippet, a storage folder via file_server, handle_errors and a JSON access
// log, and serves it through the embedded Caddy with the schild directive.
func TestIngressServes(t *testing.T) {
	var appHits, apiHits atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appHits.Add(1)
		fmt.Fprintf(w, "app %s", r.URL.Path)
	}))
	defer app.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer api.Close()
	dir := caddyDir(t)
	writeFile(t, dir, "storage/report.txt", "file from storage\n")
	writeFile(t, dir, "static/index.html", "<p>static</p>\n")
	addr := freePort(t)
	p := port(addr)
	accessLog := filepath.Join(dir, "log", "access.log")
	caddyfile := fmt.Sprintf(`{
	auto_https off
	http_port %[1]s
}

(schild) {
	schild
}

(probes) {
	@probes path /.env /wp-login.php /.git/*
	respond @probes 404
}

(logging) {
	log {
		output file %[2]s
		format json
	}
}

http://app.example.test:%[1]s, http://www.app.example.test:%[1]s {
	import schild
	import probes
	import logging
	encode gzip
	header X-Site app
	handle_path /storage/* {
		root * %[3]s
		file_server
	}
	reverse_proxy %[4]s
	handle_errors {
		respond "Fehler {err.status_code}" {err.status_code}
	}
}

http://api.example.test:%[1]s {
	import schild
	import logging
	reverse_proxy %[5]s
}

http://static.example.test:%[1]s {
	import logging
	root * %[6]s
	file_server
}
`, p, accessLog, filepath.Join(dir, "storage"), strings.TrimPrefix(app.URL, "http://"), strings.TrimPrefix(api.URL, "http://"), filepath.Join(dir, "static"))
	cf := writeFile(t, dir, "Caddyfile", caddyfile)
	ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: filepath.Join(dir, "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	if len(ing.Check.Sites) != 3 || len(ing.Check.Warnings) == 0 {
		t.Fatalf("check: %+v", ing.Check)
	}
	g := testGate(t)
	bind(t, g)
	if err := Load(ing.JSON); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	c := &http.Client{}
	base := "http://" + addr
	host := "app.example.test:" + p
	if r := fetch(t, c, base+"/hello", host, nil); r.status != 200 || r.body != "app /hello" || r.header.Get("X-Site") != "app" {
		t.Fatalf("app: %+v", r)
	}
	if r := fetch(t, c, base+"/hello", "www.app.example.test:"+p, nil); r.status != 200 {
		t.Fatalf("www: %+v", r)
	}
	if r := fetch(t, c, base+"/storage/report.txt", host, nil); r.status != 200 || r.body != "file from storage\n" {
		t.Fatalf("storage: %+v", r)
	}
	// The probe snippet answers what schild lets through; schild runs first
	// and stops what the CRS catches (autoblock).
	if r := fetch(t, c, base+"/wp-login.php", host, nil); r.status != 404 {
		t.Fatalf("probe: %d", r.status)
	}
	if r := fetch(t, c, base+"/.env", host, nil); r.status != 403 {
		t.Fatalf("probe caught by schild: %d", r.status)
	}
	// file_server 404 goes through handle_errors as in stock Caddy.
	if r := fetch(t, c, base+"/storage/missing.txt", host, nil); r.status != 404 || r.body != "Fehler 404" {
		t.Fatalf("handle_errors: %+v", r)
	}
	if r := fetch(t, c, base+"/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", host, nil); r.status != 403 || !strings.Contains(r.body, "Vorfallnummer") {
		t.Fatalf("xss on app: %d", r.status)
	}
	if r := fetch(t, c, base+"/v1/items", "api.example.test:"+p, map[string]string{"Accept": "application/json"}); r.status != 200 || r.body != `{"ok":true}` {
		t.Fatalf("api: %+v", r)
	}
	if r := fetch(t, c, base+"/v1/items?id=1%27%20OR%20%271%27=%271", "api.example.test:"+p, map[string]string{"Accept": "application/json"}); r.status != 403 ||
		!strings.Contains(r.header.Get("Content-Type"), "problem+json") {
		t.Fatalf("sqli on api: %+v", r)
	}
	if r := fetch(t, c, base+"/", "static.example.test:"+p, nil); r.status != 200 || r.body != "<p>static</p>\n" {
		t.Fatalf("static: %+v", r)
	}
	if appHits.Load() != 2 || apiHits.Load() != 1 {
		t.Fatalf("backend hits app %d api %d", appHits.Load(), apiHits.Load())
	}
	// Everything of app and api passed the one gate (static has no schild).
	if n := g.Counters.Rolling.Sum(stats.Requests, time.Hour, time.Now()); n != 9 {
		t.Fatalf("gate requests %d, want 9", n)
	}
	// The JSON access log is Caddy's, with the status schild answered.
	var lines []map[string]any
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		lines = readJSONLines(t, accessLog)
		if len(lines) >= 10 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(lines) < 10 {
		t.Fatalf("access log has %d lines", len(lines))
	}
	statuses := map[float64]int{}
	for _, l := range lines {
		if lg, _ := l["logger"].(string); !strings.HasPrefix(lg, "http.log.access") {
			t.Fatalf("access log line from logger %v", l["logger"])
		}
		req, _ := l["request"].(map[string]any)
		if req == nil || req["remote_ip"] == nil || req["uri"] == nil {
			t.Fatalf("access log line without request: %v", l)
		}
		st, _ := l["status"].(float64)
		statuses[st]++
	}
	if statuses[403] != 3 || statuses[404] != 2 || statuses[200] != 5 {
		t.Fatalf("access log statuses %v", statuses)
	}
}

func readJSONLines(t testing.TB, p string) []map[string]any {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			t.Fatalf("access log line is not JSON: %s", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

// TestSharedGateAcrossLoads: two config loads in one process keep one gate
// and its counters; a different gate cannot be bound meanwhile.
func TestSharedGateAcrossLoads(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()
	g := testGate(t)
	bind(t, g)
	if _, err := Bind(testGate(t)); !errors.Is(err, ErrOtherGate) {
		t.Fatalf("second gate bound: %v", err)
	}
	if release, err := Bind(g); err != nil {
		t.Fatal(err)
	} else {
		_ = release // same gate again: no-op
	}
	dir := caddyDir(t)
	addr := freePort(t)
	p := port(addr)
	conf := func(sites ...string) []byte {
		var b strings.Builder
		fmt.Fprintf(&b, "{\n\tauto_https off\n}\n")
		for _, s := range sites {
			fmt.Fprintf(&b, "http://%s:%s {\n\tschild\n\treverse_proxy %s\n}\n", s, p, strings.TrimPrefix(backend.URL, "http://"))
		}
		ing, err := PrepareIngress(IngressOptions{Caddyfile: writeFile(t, dir, "Caddyfile", b.String()), DefaultStorage: filepath.Join(dir, "caddy")})
		if err != nil {
			t.Fatal(err)
		}
		return ing.JSON
	}
	if err := Load(conf("a.example.test")); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	c := &http.Client{}
	if r := fetch(t, c, "http://"+addr+"/x", "a.example.test:"+p, nil); r.status != 200 {
		t.Fatalf("first load: %+v", r)
	}
	if err := Load(conf("a.example.test", "b.example.test")); err != nil {
		t.Fatal(err)
	}
	if r := fetch(t, c, "http://"+addr+"/x", "b.example.test:"+p, nil); r.status != 200 {
		t.Fatalf("second load: %+v", r)
	}
	if r := fetch(t, c, "http://"+addr+"/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "a.example.test:"+p, nil); r.status != 403 {
		t.Fatalf("second load blocks: %+v", r)
	}
	now := time.Now()
	if n := g.Counters.Rolling.Sum(stats.Requests, time.Hour, now); n != 3 {
		t.Fatalf("one gate across loads: requests %d, want 3", n)
	}
	if n := g.Counters.Rolling.Sum(stats.Blocked, time.Hour, now); n != 1 {
		t.Fatalf("blocked %d", n)
	}
	if Bound() != g {
		t.Fatal("gate replaced")
	}
}

// TestPanicRecovered: a panic in the schild handler answers that request
// with 503 and Retry-After; the server keeps serving.
func TestPanicRecovered(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()
	g := testGate(t)
	bind(t, g)
	var boom atomic.Bool
	g.Behaviour = nil
	g.Now = func() time.Time {
		if boom.Load() {
			panic("test panic in the gate")
		}
		return time.Now()
	}
	dir := caddyDir(t)
	addr := freePort(t)
	p := port(addr)
	cf := writeFile(t, dir, "Caddyfile", fmt.Sprintf("{\n\tauto_https off\n}\nhttp://a.example.test:%s {\n\tschild\n\treverse_proxy %s\n}\n", p, strings.TrimPrefix(backend.URL, "http://")))
	ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: filepath.Join(dir, "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	if err := Load(ing.JSON); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	c := &http.Client{}
	url, host := "http://"+addr+"/x", "a.example.test:"+p
	if r := fetch(t, c, url, host, nil); r.status != 200 {
		t.Fatalf("before: %+v", r)
	}
	boom.Store(true)
	for i := 0; i < 3; i++ {
		if r := fetch(t, c, url, host, nil); r.status != 503 || r.header.Get("Retry-After") == "" {
			t.Fatalf("panic: %+v", r)
		}
	}
	// D37: the reason panic keeps the block page (vector 028), also for a
	// browser navigation that would get the waiting page under overload.
	nav := map[string]string{"Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"}
	if r := fetch(t, c, url, host, nav); r.status != 503 || r.header.Get("Retry-After") != "5" || r.header.Get("Content-Language") != "" ||
		!strings.Contains(r.body, "Prüfung dauert gerade zu lange") {
		t.Fatalf("panic, browser navigation: %+v", r)
	}
	boom.Store(false)
	if r := fetch(t, c, url, host, nil); r.status != 200 {
		t.Fatalf("after: %+v", r)
	}
}

// TestIngressTimeoutFailClosed: a hanging WAF evaluation answers 503 with
// Retry-After and never reaches the backend.
func TestIngressTimeoutFailClosed(t *testing.T) {
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer backend.Close()
	g := testGate(t)
	s := g.Settings()
	s.EvalTimeout = 50 * time.Millisecond
	g.SetSettings(s)
	g.TestHook = func(string) { time.Sleep(300 * time.Millisecond) }
	bind(t, g)
	dir := caddyDir(t)
	addr := freePort(t)
	p := port(addr)
	cf := writeFile(t, dir, "Caddyfile", fmt.Sprintf("{\n\tauto_https off\n}\nhttp://a.example.test:%s {\n\timport %s\n\treverse_proxy %s\n}\n", p,
		writeFile(t, dir, "schild.caddy", "schild\n"), strings.TrimPrefix(backend.URL, "http://")))
	ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: filepath.Join(dir, "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	if err := Load(ing.JSON); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	r := fetch(t, &http.Client{Timeout: 5 * time.Second}, "http://"+addr+"/x", "a.example.test:"+p, nil)
	if r.status != 503 || r.header.Get("Retry-After") == "" || hits.Load() != 0 {
		t.Fatalf("timeout: %+v hits %d", r, hits.Load())
	}
}

// TestIngressTLSInternal: Caddy's internal issuer (a local ACME-less CA)
// issues the site certificate into ingress.storage; a restart with the same
// storage reuses the certificate instead of issuing a new one.
func TestIngressTLSInternal(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "tls ok") }))
	defer backend.Close()
	g := testGate(t)
	bind(t, g)
	dir := caddyDir(t)
	storage := filepath.Join(dir, "caddy-data")
	httpsAddr, httpAddr := freePort(t), freePort(t)
	cf := writeFile(t, dir, "Caddyfile", fmt.Sprintf(`{
	servers {
		protocols h1 h2
	}
	skip_install_trust
	https_port %s
	http_port %s
}

(schild) {
	schild
}

secure.example.test {
	tls internal
	import schild
	reverse_proxy %s
}
`, port(httpsAddr), port(httpAddr), strings.TrimPrefix(backend.URL, "http://")))
	serial := func() string {
		ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, Storage: storage, DefaultStorage: filepath.Join(dir, "unused")})
		if err != nil {
			t.Fatal(err)
		}
		if err := Load(ing.JSON); err != nil {
			t.Fatal(err)
		}
		defer Stop()
		var pool *x509.CertPool
		var leaf string
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if pool == nil {
				if pem, err := os.ReadFile(filepath.Join(storage, "pki", "authorities", "local", "root.crt")); err == nil {
					pool = x509.NewCertPool()
					pool.AppendCertsFromPEM(pem)
				}
			}
			if pool != nil {
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "secure.example.test", MinVersion: tls.VersionTLS12},
					DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, httpsAddr)
					},
				}
				c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
				resp, err := c.Get("https://secure.example.test/")
				if err == nil {
					b, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					tr.CloseIdleConnections()
					if resp.StatusCode != 200 || string(b) != "tls ok" {
						t.Fatalf("tls: %d %s", resp.StatusCode, b)
					}
					leaf = resp.TLS.PeerCertificates[0].SerialNumber.String()
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		if leaf == "" {
			t.Fatal("no TLS answer from the internal issuer setup")
		}
		return leaf
	}
	first := serial()
	certs, _ := filepath.Glob(filepath.Join(storage, "certificates", "local", "secure.example.test", "*.crt"))
	if len(certs) != 1 {
		t.Fatalf("certificate not in ingress.storage: %v", certs)
	}
	if second := serial(); second != first {
		t.Fatalf("certificate reissued on restart: %s then %s", first, second)
	}
	if n := g.Counters.Rolling.Sum(stats.Requests, time.Hour, time.Now()); n != 2 {
		t.Fatalf("TLS requests through the gate: %d", n)
	}
}

func TestCaddyVersion(t *testing.T) {
	if v := CaddyVersion(); v == "" {
		t.Fatal("empty Caddy version")
	}
}

// MVP-19 re-measurement, finding 1, at runtime: handle_errors is server-wide.
// With schild inside handle_errors, an error of a site without schild (a
// file_server 404 of a static site) is inspected before the error route
// proxies it, and a request the site's schild already passed is not
// evaluated a second time when a later handler fails.
func TestIngressHandleErrorsServerWide(t *testing.T) {
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/fail" {
			w.WriteHeader(200)
		}
		fmt.Fprintf(w, "backend %s", r.URL.Path)
	}))
	defer backend.Close()
	dir := caddyDir(t)
	writeFile(t, dir, "static/index.html", "<p>static</p>\n")
	addr := freePort(t)
	p := port(addr)
	be := strings.TrimPrefix(backend.URL, "http://")
	caddyfile := fmt.Sprintf(`{
	auto_https off
	http_port %[1]s
}

(schild) {
	schild
}

http://:%[1]s {
	import schild
	error /boom 500
	reverse_proxy %[2]s
	handle_errors {
		import schild
		reverse_proxy %[2]s
	}
}

http://b.example.test:%[1]s {
	root * %[3]s
	file_server
}
`, p, be, filepath.Join(dir, "static"))
	cf := writeFile(t, dir, "Caddyfile", caddyfile)
	ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: filepath.Join(dir, "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	g := testGate(t)
	bind(t, g)
	if err := Load(ing.JSON); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	c := &http.Client{}
	base := "http://" + addr
	bhost := "b.example.test:" + p
	// Attack on a missing file of the static site: the error route's schild stops it.
	if r := fetch(t, c, base+"/missing?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", bhost, nil); r.status != 403 {
		t.Fatalf("attack through another site's error: %d %q", r.status, r.body)
	}
	if hits.Load() != 0 {
		t.Fatalf("backend reached by an uninspected error: %d", hits.Load())
	}
	// A clean missing file is inspected once and proxied by handle_errors.
	if r := fetch(t, c, base+"/missing", bhost, nil); r.status != 200 || r.body != "backend /missing" {
		t.Fatalf("clean error route: %+v", r)
	}
	before := g.Counters.Rolling.Sum(stats.Requests, time.Hour, time.Now())
	// The guarded site's own error: one evaluation (the site's), not two.
	if r := fetch(t, c, base+"/boom", "a.example.test:"+p, nil); r.status != 200 || r.body != "backend /boom" {
		t.Fatalf("own error: %+v", r)
	}
	if n := g.Counters.Rolling.Sum(stats.Requests, time.Hour, time.Now()) - before; n != 1 {
		t.Fatalf("evaluations for one request: %d, want 1", n)
	}
	if hits.Load() != 2 {
		t.Fatalf("backend hits %d, want 2", hits.Load())
	}
}

// TestIngressRequestBodyLimit413 (MVP-19 measurement 3, M16, finding 4): a
// body over Caddy's request_body max_size is answered 413 as by stock
// Caddy, not 400 body_read_error; a body within the limit is forwarded.
func TestIngressRequestBodyLimit413(t *testing.T) {
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()
	dir := caddyDir(t)
	addr := freePort(t)
	p := port(addr)
	caddyfile := fmt.Sprintf(`{
	auto_https off
	http_port %[1]s
}

(schild) {
	schild
}

http://a.example.test:%[1]s {
	import schild
	request_body {
		max_size 1KB
	}
	reverse_proxy %[2]s
	handle_errors {
		import schild
		respond "{err.status_code}" {err.status_code}
	}
}
`, p, strings.TrimPrefix(backend.URL, "http://"))
	ing, err := PrepareIngress(IngressOptions{Caddyfile: writeFile(t, dir, "Caddyfile", caddyfile), DefaultStorage: filepath.Join(dir, "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	g := testGate(t)
	bind(t, g)
	if err := Load(ing.JSON); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	post := func(n int, chunked bool) int {
		t.Helper()
		var body io.Reader = strings.NewReader("text=" + strings.Repeat("a", n))
		if chunked {
			body = io.MultiReader(body) // unknown length: Transfer-Encoding chunked
		}
		req, _ := http.NewRequest("POST", "http://"+addr+"/form", body)
		req.Host = "a.example.test:" + p
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
		req.Header.Set("Accept", "text/html")
		var resp *http.Response
		for i := 0; i < 100; i++ {
			if resp, err = http.DefaultClient.Do(req); err == nil {
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if s := post(500, false); s != 200 {
		t.Fatalf("body within the limit: %d", s)
	}
	for _, chunked := range []bool{false, true} {
		if s := post(4000, chunked); s != http.StatusRequestEntityTooLarge {
			t.Fatalf("body over request_body max_size (chunked %v): %d, want 413", chunked, s)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("backend hits %d, want 1", hits.Load())
	}
}
