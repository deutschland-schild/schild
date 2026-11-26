package caddymod

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
)

// TEST ONLY: no Hetzner token looks like this.
const testToken = "TEST-ONLY-hetzner-token"

var zoneRuns atomic.Int64

// freshZone is a zone name no earlier run used: certmagic remembers for the
// whole process which zone a name is in, so a name used twice is not looked
// up again (go test -count).
func freshZone(tld string) string { return fmt.Sprintf("z%d.%s", zoneRuns.Add(1), tld) }

// testRoot writes the root of the test CA and returns its files and a pool.
func testRoot(t *testing.T, dir string) (cert, key string, pool *x509.CertPool) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "schild TEST ONLY root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert = writeFile(t, dir, "root.crt", string(crt))
	key = writeFile(t, dir, "root.key", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})))
	pool = x509.NewCertPool()
	pool.AppendCertsFromPEM(crt)
	return cert, key, pool
}

// withACMEServer adds Caddy's own ACME server to a config: a certificate
// authority that asks resolver for the TXT record of the DNS challenge. Only
// here: schild refuses acme_server in an operator's Caddyfile.
func withACMEServer(t *testing.T, cfg []byte, ca []byte) []byte {
	t.Helper()
	var m, c map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ca, &c); err != nil {
		t.Fatal(err)
	}
	apps, caApps := m["apps"].(map[string]any), c["apps"].(map[string]any)
	servers := apps["http"].(map[string]any)["servers"].(map[string]any)
	for _, s := range caApps["http"].(map[string]any)["servers"].(map[string]any) {
		servers["test_ca"] = s
	}
	apps["pki"] = caApps["pki"]
	auto := apps["tls"].(map[string]any)["automation"].(map[string]any)
	caAuto := caApps["tls"].(map[string]any)["automation"].(map[string]any)
	auto["policies"] = append(caAuto["policies"].([]any), auto["policies"].([]any)...)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// getTLS asks the gateway for host and returns status, body and the names of
// the certificate.
func getTLS(addr string, pool *x509.CertPool, host, path string) (int, string, []string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Get("https://" + host + path)
	if err != nil {
		return 0, "", nil, err
	}
	body := drain(resp.Body)
	return resp.StatusCode, body, resp.TLS.PeerCertificates[0].DNSNames, nil
}

// TestHetznerWildcard orders a wildcard certificate from a test CA with the
// DNS challenge through the mocked Hetzner API, once with the zone of the
// website at Hetzner and once with a zone for challenges only, to which the
// website's zone points with a CNAME.
func TestHetznerWildcard(t *testing.T) {
	one, two, acme := freshZone("test"), freshZone("test"), freshZone("example")
	cases := []struct {
		name, site, zone string // zone: the one at Hetzner
		others           []string
		cnames           map[string]string
		extra            string
	}{
		{name: "own zone", site: one, zone: one},
		{name: "zone for challenges only", site: two, zone: acme,
			others: []string{two},
			cnames: map[string]string{"_acme-challenge." + two: "_acme-challenge." + acme},
			extra:  "dns_challenge_override_domain _acme-challenge." + acme},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := newHetznerAPI(testToken, c.zone)
			api.intercept(t)
			before := api.snapshot()
			resolver := api.serveDNS(t, c.others, c.cnames)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("app ok")) }))
			defer backend.Close()
			bind(t, testGate(t))

			dir := caddyDir(t)
			rootCrt, rootKey, pool := testRoot(t, dir)
			token := writeFile(t, dir, "hetzner.token", testToken+"\n")
			caAddr, httpsAddr, httpAddr := freePort(t), freePort(t), freePort(t)
			cf := writeFile(t, dir, "Caddyfile", fmt.Sprintf(`{
	skip_install_trust
	https_port %s
	http_port %s
	servers {
		protocols h1 h2
	}
}

*.%s {
	tls {
		ca https://localhost:%s/acme/local/directory
		ca_root %s
		dns hetzner {file.%s}
		resolvers %s
		propagation_timeout 20s
		%s
	}
	schild
	reverse_proxy %s
}
`, port(httpsAddr), port(httpAddr), c.site, port(caAddr), rootCrt, token, resolver, c.extra, strings.TrimPrefix(backend.URL, "http://")))
			ca := adapt(t, caCaddyfile(rootCrt, rootKey, caAddr, resolver))
			load := func() []byte {
				ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: filepath.Join(dir, "caddy-data")})
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(ing.JSON), testToken) {
					t.Fatal("the token is in the adapted config")
				}
				if p := DNSTokenProblems(ing.JSON); len(p) != 0 {
					t.Fatalf("token problems: %v", p)
				}
				if err := ValidateIngress(ing); err != nil {
					t.Fatal(err)
				}
				return withACMEServer(t, ing.JSON, ca)
			}
			cfg := load()
			// The CA alone first, so that its own certificate is there when
			// the gateway asks for one: a failed order waits a minute.
			if err := Load(withStorage(t, ca, filepath.Join(dir, "caddy-data"))); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the test CA", 15*time.Second, func() error {
				_, _, _, err := getTLS(caAddr, pool, "localhost", "/acme/local/directory")
				return err
			})
			if err := Load(cfg); err != nil {
				t.Fatal(err)
			}
			defer Stop()
			host := "shop." + c.site
			var names []string
			waitFor(t, "the wildcard certificate", 45*time.Second, func() error {
				status, body, n, err := getTLS(httpsAddr, pool, host, "/")
				if err != nil {
					return err
				}
				names = n
				if status != 200 || body != "app ok" {
					return fmt.Errorf("status %d body %q", status, body)
				}
				return nil
			})
			if len(names) != 1 || names[0] != "*."+c.site {
				t.Fatalf("certificate for %v", names)
			}
			if status, _, _, err := getTLS(httpsAddr, pool, host, "/?id=1%27%20OR%201=1--%20"); err != nil || status != 403 {
				t.Fatalf("attack: status %d err %v", status, err)
			}

			// One TXT record at the name of the challenge and nothing else;
			// gone after the order.
			waitFor(t, "the zone as before", 15*time.Second, func() error {
				if now := api.snapshot(); now != before {
					return fmt.Errorf("zone is\n%s\nwas\n%s", now, before)
				}
				return nil
			})
			calls, refused, seen := api.state()
			if len(refused) != 0 {
				t.Fatalf("the API would refuse: %v", refused)
			}
			if len(seen) != 1 || !strings.HasPrefix(seen[0], c.zone+" _acme-challenge/TXT ") {
				t.Fatalf("records added: %v", seen)
			}
			for _, call := range calls {
				if call != "GET /actions" && !strings.HasPrefix(call, "POST /zones/"+c.zone+"/rrsets/_acme-challenge/TXT/actions/") {
					t.Fatalf("unexpected call %s", call)
				}
			}

			// A restart with the API down serves the stored certificate and
			// asks nobody.
			if err := Stop(); err != nil {
				t.Fatal(err)
			}
			api.set(func() { api.failAll, api.calls = 503, nil })
			if err := Load(load()); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the stored certificate", 10*time.Second, func() error {
				status, _, _, err := getTLS(httpsAddr, pool, host, "/")
				if err == nil && status != 200 {
					err = fmt.Errorf("status %d", status)
				}
				return err
			})
			if calls, _, _ := api.state(); len(calls) != 0 {
				t.Fatalf("calls after the restart: %v", calls)
			}
		})
	}
}

// TestHetznerTokenMissing: without a token the module panics when the order
// needs it. The gateway goes on serving and stays up.
func TestHetznerTokenMissing(t *testing.T) {
	t.Setenv(hetznerTokenEnv, "")
	zone := freshZone("test")
	api := newHetznerAPI(testToken, zone)
	api.intercept(t)
	resolver := api.serveDNS(t, nil, nil)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("app ok")) }))
	defer backend.Close()
	bind(t, testGate(t))
	dir := caddyDir(t)
	rootCrt, rootKey, pool := testRoot(t, dir)
	caAddr, httpsAddr, httpAddr := freePort(t), freePort(t), freePort(t)
	cf := writeFile(t, dir, "Caddyfile", fmt.Sprintf(`{
	skip_install_trust
	https_port %s
	http_port %s
	servers {
		protocols h1 h2
	}
}

*.%s {
	tls {
		ca https://localhost:%s/acme/local/directory
		ca_root %s
		dns hetzner {file.%s/none}
		resolvers %s
	}
	schild
	reverse_proxy %s
}

http://other.test {
	schild
	reverse_proxy %s
}
`, port(httpsAddr), port(httpAddr), zone, port(caAddr), rootCrt, dir, resolver, strings.TrimPrefix(backend.URL, "http://"), strings.TrimPrefix(backend.URL, "http://")))
	ca := adapt(t, caCaddyfile(rootCrt, rootKey, caAddr, resolver))
	storage := filepath.Join(dir, "caddy-data")
	ing, err := PrepareIngress(IngressOptions{Caddyfile: cf, DefaultStorage: storage})
	if err != nil {
		t.Fatal(err)
	}
	if p := DNSTokenProblems(ing.JSON); len(p) != 1 {
		t.Fatalf("token problems: %v", p)
	}
	if err := Load(withStorage(t, ca, storage)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the test CA", 15*time.Second, func() error {
		_, _, _, err := getTLS(caAddr, pool, "localhost", "/acme/local/directory")
		return err
	})
	if err := Load(withACMEServer(t, ing.JSON, ca)); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	// The module panics right after Caddy looked up the zone of the record.
	waitFor(t, "the order at the DNS provider", 20*time.Second, func() error {
		if !api.asked("_acme-challenge." + zone) {
			return errors.New("zone not looked up yet")
		}
		return nil
	})
	time.Sleep(time.Second)
	if r := fetch(t, &http.Client{Timeout: 3 * time.Second}, "http://"+httpAddr+"/", "other.test", nil); r.status != 200 {
		t.Fatalf("other site: %+v", r)
	}
	if calls, _, _ := api.state(); len(calls) != 0 {
		t.Fatalf("calls without a token: %v", calls)
	}
}

// caCaddyfile is a site that is an ACME server with the DNS challenge.
func caCaddyfile(rootCrt, rootKey, addr, resolver string) string {
	return fmt.Sprintf(`{
	skip_install_trust
	auto_https disable_redirects
	servers {
		protocols h1 h2
	}
	pki {
		ca local {
			root {
				cert %s
				key %s
			}
		}
	}
}

https://localhost:%s {
	tls internal
	acme_server {
		resolvers %s
		challenges dns-01
		allow_wildcard_names
	}
}
`, rootCrt, rootKey, port(addr), resolver)
}

func withStorage(t *testing.T, cfg []byte, root string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		t.Fatal(err)
	}
	m["admin"] = map[string]any{"disabled": true, "config": map[string]any{"persist": false}}
	m["storage"] = map[string]any{"module": "file_system", "root": root}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func waitFor(t *testing.T, what string, d time.Duration, f func() error) {
	t.Helper()
	var err error
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if err = f(); err == nil {
			return
		}
	}
	t.Fatalf("%s: %v", what, err)
}

// dnsProvider is what Caddy's DNS challenge uses of a provider.
type dnsProvider interface {
	libdns.RecordAppender
	libdns.RecordDeleter
}

func hetznerProvider(t *testing.T, token string) dnsProvider {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	raw, _ := json.Marshal(map[string]string{"api_token": token})
	m, err := ctx.LoadModuleByID("dns.providers.hetzner", raw)
	if err != nil {
		t.Fatal(err)
	}
	return m.(dnsProvider)
}

// TestHetznerProvider: how the module behaves where the API says no.
func TestHetznerProvider(t *testing.T) {
	txt := func(v string) []libdns.Record {
		return []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: v}}
	}
	zone := "example.test"
	cases := []struct {
		name  string
		token string
		prep  func(*hetznerAPI)
		want  string // in the error, "" = none
		value string // a record that is left at the challenge's name
	}{
		{name: "ok", value: "x"},
		{name: "a record of another node at the same name", value: "x", prep: func(h *hetznerAPI) {
			h.zones[zone]["_acme-challenge/TXT"] = &mockRRSet{values: []string{`"other"`}}
		}},
		{name: "a record with a TTL of its own at the same name", value: "x", prep: func(h *hetznerAPI) {
			ttl := 3600
			h.zones[zone]["_acme-challenge/TXT"] = &mockRRSet{ttl: &ttl, values: []string{`"other"`}}
		}},
		{name: "the challenge's RRSet is protected", want: "protected", prep: func(h *hetznerAPI) {
			h.zones[zone]["_acme-challenge/TXT"] = &mockRRSet{protected: true, values: []string{`"other"`}}
		}},
		{name: "zone in another project", want: "not found", prep: func(h *hetznerAPI) { delete(h.zones, zone) }},
		{name: "wrong token", token: "TEST-ONLY-other", want: "unauthorized"},
		{name: "rate limit, then ok", value: "x", prep: func(h *hetznerAPI) { h.fail = []int{429} }},
		{name: "out of order", want: "planned failure", prep: func(h *hetznerAPI) { h.failAll = 500 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := newHetznerAPI(testToken, zone)
			api.intercept(t)
			if c.prep != nil {
				c.prep(api)
			}
			before := api.snapshot()
			token := c.token
			if token == "" {
				token = testToken
			}
			p := hetznerProvider(t, token)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, err := p.AppendRecords(ctx, zone+".", txt("x"))
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("error %v, want %q", err, c.want)
				}
				if strings.Contains(err.Error(), token) {
					t.Fatalf("the token is in the error: %v", err)
				}
				if now := api.snapshot(); now != before {
					t.Fatalf("zone changed:\n%s", now)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s := api.snapshot(); !strings.Contains(s, `"`+c.value+`"`) {
				t.Fatalf("record missing:\n%s", s)
			}
			if _, err := p.DeleteRecords(ctx, zone+".", txt("x")); err != nil {
				t.Fatal(err)
			}
			if now := api.snapshot(); now != before {
				t.Fatalf("zone is\n%s\nwas\n%s", now, before)
			}
		})
	}
}

func TestDNSTokenProblems(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "good", testToken+"\n")
	empty := writeFile(t, dir, "empty", "\n")
	spaced := writeFile(t, dir, "spaced", testToken+" \n")
	locked := writeFile(t, dir, "locked", testToken)
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCHILD_TEST_HETZNER", testToken)
	t.Setenv(hetznerTokenEnv, "")
	cases := []struct {
		name, token, want string
		root              bool // means nothing for root
	}{
		{name: "file", token: "{file." + good + "}"},
		{name: "environment", token: "{env.SCHILD_TEST_HETZNER}"},
		{name: "in the Caddyfile", token: testToken},
		{name: "file missing", token: "{file." + dir + "/none}", want: "is empty"},
		{name: "file empty", token: "{file." + empty + "}", want: "is empty"},
		{name: "file not readable", token: "{file." + locked + "}", want: "is empty", root: true},
		{name: "variable not set", token: "{env.SCHILD_TEST_HETZNER_NONE}", want: "is empty"},
		{name: "space behind it", token: "{file." + spaced + "}", want: "a space or a line break"},
	}
	places := map[string]string{
		"site":   "*.example.test {\n\ttls {\n\t\tdns hetzner %s\n\t}\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n",
		"global": "{\n\tacme_dns hetzner %s\n}\n*.example.test {\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n",
		"dns":    "{\n\tdns hetzner %s\n}\n*.example.test {\n\ttls {\n\t\tdns\n\t}\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n",
	}
	for _, c := range cases {
		for place, body := range places {
			t.Run(c.name+" "+place, func(t *testing.T) {
				if c.root && os.Geteuid() == 0 {
					t.Skip("root reads everything")
				}
				got := strings.Join(DNSTokenProblems(adapt(t, fmt.Sprintf(body, c.token))), "; ")
				if c.want == "" && got != "" || !strings.Contains(got, c.want) {
					t.Fatalf("got %q, want %q", got, c.want)
				}
				if strings.Contains(got, testToken) {
					t.Fatalf("the token is in %q", got)
				}
			})
		}
	}
	t.Run("the module's own variable", func(t *testing.T) {
		t.Setenv(hetznerTokenEnv, testToken)
		if got := DNSTokenProblems(adapt(t, fmt.Sprintf(places["site"], "{env.SCHILD_TEST_HETZNER_NONE}"))); len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("no provider", func(t *testing.T) {
		if got := DNSTokenProblems(adapt(t, "example.test {\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n")); len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})
}

// TestDNSModules: the list of DNS modules is a decision (MVP-37); a module
// more or less changes this test.
func TestDNSModules(t *testing.T) {
	var got []string
	for _, m := range caddy.GetModules("dns.providers") {
		got = append(got, string(m.ID))
	}
	if strings.Join(got, " ") != "dns.providers.hetzner" {
		t.Fatalf("DNS modules compiled in: %v", got)
	}
}
