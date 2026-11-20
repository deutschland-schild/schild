//go:build !release

package app_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// TestLocalDecisions: the gateway decides alone (D72: no labs, relays or
// network rules): a clean request passes, an attack attempt is blocked by
// the CRS in autoblock and never reaches the backend.
func TestLocalDecisions(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	if r := h.Visit("GET", "/hello", "198.51.100.23", "", ""); r.StatusCode != 200 {
		t.Fatalf("clean: %d", r.StatusCode)
	}
	// Local CRS decision in autoblock (the CRS is not part of the learning
	// period; behaviour and distributed detectors are).
	for i := 0; i < 5; i++ {
		if r := h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "203.0.113.5", "", ""); r.StatusCode != 403 {
			t.Fatalf("xss: %d", r.StatusCode)
		}
	}
	if h.Hits.Load() != 1 {
		t.Fatalf("backend hits %d", h.Hits.Load())
	}
}

const ingressCaddyfile = `{
	auto_https off
}

(schild) {
	schild
}

http://shop.example:{port}, http://www.shop.example:{port} {
	import schild
	@probes path /wp-login.php /xmlrpc.php
	respond @probes 404
	reverse_proxy {backend}
}

http://api.example:{port} {
	import schild
	reverse_proxy {backend}
}
`

// TestStandaloneIngressRun runs `schild run` as the ingress: the operator's
// Caddyfile with the schild directive, no network.
func TestStandaloneIngressRun(t *testing.T) {
	h := apptest.New(t, apptest.Options{Listeners: true, Caddyfile: ingressCaddyfile})
	base := "http://" + h.IngressAddr
	_, port, _ := strings.Cut(h.IngressAddr, ":")
	hostGet := func(host, path string) (int, string) {
		t.Helper()
		return getHost(t, base+path, host+":"+port)
	}
	if code, body := hostGet("shop.example", "/hello"); code != 200 || body != "app ok" {
		t.Fatalf("shop: %d %q", code, body)
	}
	if code, _ := hostGet("api.example", "/v1/x"); code != 200 {
		t.Fatalf("api: %d", code)
	}
	if code, _ := hostGet("shop.example", "/wp-login.php"); code != 404 {
		t.Fatalf("probe: %d", code)
	}
	if code, body := hostGet("www.shop.example", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"); code != 403 || !strings.Contains(body, "Vorfallnummer") {
		t.Fatalf("xss: %d", code)
	}
	if code, _ := hostGet("shop.example", "/.schild/readyz"); code != 200 {
		t.Fatalf("readyz: %d", code)
	}
	if code, _ := get(t, "http://"+h.DashAddr+"/healthz", nil); code != 200 {
		t.Fatalf("dashboard: %d", code)
	}
	if h.Hits.Load() != 2 {
		t.Fatalf("backend hits %d", h.Hits.Load())
	}
	h.Flush()
	// The client address is the TCP peer: schild terminates the connection.
	rows, _, err := h.App.Store.ListEvents(context.Background(), store.EventFilter{Outcome: "blocked"}, 0, 10)
	if err != nil || len(rows) != 1 || rows[0].IP != "127.0.0.1" || !strings.HasPrefix(rows[0].Host, "www.shop.example") {
		t.Fatalf("blocked event: %v %+v", err, rows)
	}
	// v0.5 (D36): the websites come from the Caddyfile site blocks; the
	// event of www.shop.example belongs to the website shop.example.
	v := h.App.Sites.View()
	if v.Err != nil || v.Source != "caddyfile" || len(v.Websites()) != 2 || v.Websites()[0].ID != "shop.example" || v.Websites()[1].ID != "api.example" ||
		len(v.Websites()[0].Hosts) != 2 {
		t.Fatalf("websites: %v %+v", v.Err, v.Websites())
	}
	if rows[0].Site != "shop.example" {
		t.Fatalf("site of the blocked event: %q", rows[0].Site)
	}
	if in, err := h.App.Store.GetIncident(context.Background(), rows[0].Incident); err != nil || in.Site != "shop.example" {
		t.Fatalf("incident site: %v %+v", err, in)
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	// Caddy cleans its storage (and so creates the directory) once per
	// process: this test has to be the first ingress start of the package.
	if _, err := os.Stat(filepath.Join(h.Dir, "caddy")); err != nil {
		t.Fatalf("ingress.storage not used: %v", err)
	}
}

// TestIngressRefusesUnprotectedSite: a site that proxies without schild and
// is not listed in ingress.unprotected_sites stops `schild run`.
func TestIngressRefusesUnprotectedSite(t *testing.T) {
	h := apptest.New(t, apptest.Options{Listeners: true, Caddyfile: "{\n\tauto_https off\n}\nhttp://shop.example:{port} {\n\treverse_proxy {backend}\n}\n"})
	err := h.Stop()
	if err == nil || !strings.Contains(err.Error(), "without schild") {
		t.Fatalf("run with an unprotected site: %v", err)
	}
}

// TestIngressAccessLockHostSpellings: in ingress mode an access lock holds
// for every Host spelling Caddy routes to the locked site block (D69): a
// port that is no port, brackets around a name, case, odd wildcard labels.
// Security audit 2026-11-05: these spellings resolved to no website, so the
// lock let them through to the app.
func TestIngressAccessLockHostSpellings(t *testing.T) {
	h := apptest.New(t, apptest.Options{Listeners: true, Caddyfile: `{
	auto_https off
}

http://secret.example:{port} {
	schild
	reverse_proxy {backend}
}

http://*.kunden.example:{port} {
	schild
	reverse_proxy {backend}
}

http://open.example:{port} {
	schild
	reverse_proxy {backend}
}
`})
	pw := "korrekt-pferd-batterie"
	for _, w := range []string{"secret.example", "_.kunden.example"} {
		if _, err := h.App.SetAccess(context.Background(), w, app.AccessChange{
			Protection: access.Protection{Website: w, Scope: access.ScopeSite, Password: true}, Password: &pw, Actor: "cli"}); err != nil {
			t.Fatalf("lock %s: %v", w, err)
		}
	}
	_, port, _ := strings.Cut(h.IngressAddr, ":")
	for _, host := range []string{
		"secret.example:" + port, "secret.example", "SECRET.Example",
		"secret.example:abc", "secret.example:", "secret.example:0" + port, "secret.example:70000",
		"[secret.example]", "[secret.example]:" + port,
		"a.kunden.example", "a_b.kunden.example", "*.kunden.example:" + port, ".kunden.example", "-a.kunden.example",
	} {
		if code := rawStatus(t, h.IngressAddr, host, "/private/report.pdf"); code != http.StatusServiceUnavailable {
			t.Errorf("Host %q: %d, want 503 (the lock)", host, code)
		}
	}
	if n := h.Hits.Load(); n != 0 {
		t.Fatalf("%d locked requests reached the app", n)
	}
	// A website without a lock stays open, also with an odd port.
	if code := rawStatus(t, h.IngressAddr, "open.example:abc", "/"); code != http.StatusOK || h.Hits.Load() != 1 {
		t.Fatalf("open website: %d, %d app hits", code, h.Hits.Load())
	}
}

// rawStatus sends GET path with the Host header exactly as given (no
// client normalises it) and returns the status code.
func rawStatus(t *testing.T, addr, host, path string) int {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("Host %q: %v", host, err)
	}
	res.Body.Close()
	return res.StatusCode
}

// TestIngressFor checks the helper used by `schild ingress validate`.
func TestIngressFor(t *testing.T) {
	h := apptest.New(t, apptest.Options{Caddyfile: ingressCaddyfile, Extra: "", Mode: "observe"})
	ing, err := app.IngressFor(h.App.Config(), filepath.Join(h.Dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if ing.StorageRoot != filepath.Join(h.Dir, "caddy") || len(ing.Check.Sites) != 2 {
		t.Fatalf("%+v", ing.Check)
	}
}

func getHost(t *testing.T, url, host string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Host = host
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	req.Header.Set("Accept", "text/html")
	var resp *http.Response
	var err error
	for i := 0; i < 100; i++ {
		if resp, err = http.DefaultClient.Do(req); err == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
