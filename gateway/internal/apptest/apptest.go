//go:build !release

// Package apptest assembles a complete schild (app.New) with a test backend
// for integration and API contract tests. TEST ONLY.
package apptest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
	"github.com/deutschland-schild/schild/gateway/internal/geo"
	"github.com/deutschland-schild/schild/gateway/internal/testport"
)

// Harness is a running schild with a test backend.
type Harness struct {
	T       testing.TB
	App     *app.App
	Backend *httptest.Server
	Proxy   *httptest.Server
	Dash    *httptest.Server
	Client  *http.Client
	CSRF    string
	Dir     string
	Hits    atomic.Int64
	// Addresses in listener mode.
	ProxyAddr, DashAddr, MetricsAddr string
	// IngressAddr is 127.0.0.1:{port} of Options.Caddyfile.
	IngressAddr string
	done        chan error
	closed      bool
	cancel      context.CancelFunc
	Password    string
}

// Options tune the harness.
type Options struct {
	// Mode observe runs the test profile, the one way left to block nothing
	// (D89); "" and autoblock are every other gateway.
	Mode    string
	Profile string // "" or test
	Extra   string // appended YAML
	// Rules are YAML lines under rules: (two spaces deep), e.g.
	// "  crs: {state: detect}\n". The harness adds local.dir <dir>/rules.d
	// and crowdsec.auto_update false unless they name local or crowdsec;
	// {rules.d} stands for <dir>/rules.d.
	Rules string
	// Listeners runs app.Run with real listeners (embedded Caddy, dashboard,
	// metrics) on free ports instead of in-process handlers.
	Listeners bool
	// Dir reuses a directory (restart tests).
	Dir string
	// Caddyfile switches to ingress mode (MVP-19): the text is written to
	// <dir>/Caddyfile with {backend} replaced by the backend's host:port and
	// {port} by a free port (Harness.IngressAddr); listen.proxy and upstream
	// are left out.
	Caddyfile string
	// BotsNow is the clock of the bot engine (age of the range snapshots);
	// nil: a time inside the 30 days of the shipped snapshot, so tests of
	// verification do not depend on the day they run.
	BotsNow func() time.Time
	// StartFails: the test expects Run to refuse the start (Stop returns
	// its error), so New does not wait for the listeners.
	StartFails bool
}

// FreeAddr returns a 127.0.0.1 address for a listener of the app, which
// binds it later (testport: nobody takes the port in between).
func FreeAddr(t testing.TB) string {
	t.Helper()
	return testport.Free(t)
}

const password = "korrekt-pferd-batterie"

// New starts a harness.
func New(t testing.TB, o Options) *Harness {
	t.Helper()
	if o.Mode == "observe" {
		o.Profile = "test"
	}
	h := &Harness{T: t, Dir: o.Dir, Password: password}
	if h.Dir == "" {
		h.Dir = t.TempDir()
	}
	proxyAddr, dashAddr, metricsAddr := "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	if o.Listeners {
		proxyAddr, dashAddr, metricsAddr = FreeAddr(t), FreeAddr(t), FreeAddr(t)
	}
	h.ProxyAddr, h.DashAddr, h.MetricsAddr = proxyAddr, dashAddr, metricsAddr
	h.Backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "app ok")
	}))
	if err := geo.WriteFixture(filepath.Join(h.Dir, "geo", "geo.mmdb")); err != nil {
		t.Fatal(err)
	}
	// Tests never reach the real hub; a test that wants updates sets its own
	// crowdsec section in Rules. rules.d lies in the test's directory.
	rulesYAML := "\nrules:\n" + strings.ReplaceAll(o.Rules, "{rules.d}", strconv.Quote(filepath.Join(h.Dir, "rules.d")))
	if !strings.Contains(o.Rules, "crowdsec:") {
		rulesYAML += "  crowdsec: {auto_update: false}\n"
	}
	if !strings.Contains(o.Rules, "local:") {
		rulesYAML += fmt.Sprintf("  local: {dir: %q}\n", filepath.Join(h.Dir, "rules.d"))
	}
	o.Extra += rulesYAML
	yaml := h.yaml(o, dashAddr, metricsAddr)
	cfgPath := filepath.Join(h.Dir, "schild.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("SCHILD_TEST_LOG") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	a, err := app.New(ctx, app.Options{ConfigPath: cfgPath, Log: log, NoListeners: !o.Listeners,
		BotsNow: botsNow(o)})
	if err != nil {
		t.Fatal(err)
	}
	a.Events.Validate = true
	h.App = a
	if o.Listeners {
		h.done = make(chan error, 1)
		go func() { h.done <- a.Run(ctx) }()
	} else {
		a.Loops(ctx)
	}
	backendURL := h.Backend.URL
	forward := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest(r.Method, backendURL+r.URL.RequestURI(), r.Body)
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
	h.Proxy = httptest.NewServer(a.Gate.Handler(forward))
	h.Dash = httptest.NewServer(a.Dashboard.Handler())
	jar, _ := cookiejar.New(nil)
	h.Client = &http.Client{Jar: jar}
	t.Cleanup(h.Close)
	if o.Listeners && !o.StartFails {
		listening := []string{h.DashAddr, h.MetricsAddr}
		if o.Caddyfile != "" {
			listening = append(listening, h.IngressAddr)
		} else {
			listening = append(listening, h.ProxyAddr)
		}
		h.waitListening(listening)
	}
	return h
}

// yaml is schild.yaml: the plain proxy to the backend, or a Caddyfile.
func (h *Harness) yaml(o Options, dashAddr, metricsAddr string) string {
	t := h.T
	var b strings.Builder
	b.WriteString("config_version: 0\nnode_name: test-node\n")
	if o.Profile == "test" {
		b.WriteString("profile: test\n")
	}
	if o.Caddyfile != "" {
		h.IngressAddr = FreeAddr(t)
		_, port, _ := net.SplitHostPort(h.IngressAddr)
		text := strings.NewReplacer("{backend}", strings.TrimPrefix(h.Backend.URL, "http://"), "{port}", port).Replace(o.Caddyfile)
		cf := filepath.Join(h.Dir, "Caddyfile")
		if err := os.WriteFile(cf, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "listen:\n  dashboard: %q\n  metrics: %q\ningress:\n  caddyfile: %q\n  storage: %q\n", dashAddr, metricsAddr, cf, filepath.Join(h.Dir, "caddy"))
	} else {
		fmt.Fprintf(&b, "listen:\n  proxy: %q\n  dashboard: %q\n  metrics: %q\nupstream:\n  url: %q\n", h.ProxyAddr, dashAddr, metricsAddr, h.Backend.URL)
	}
	fmt.Fprintf(&b, "waf:\n  eval_timeout_ms: 5000\ngeo:\n  db_path: %s\nstorage:\n  path: %s\nallowlist:\n  - { ip: 192.0.2.10, label: \"Testlab admin\", level: no_block, expires: never }\n%s",
		filepath.Join(h.Dir, "geo", "geo.mmdb"), filepath.Join(h.Dir, "data"), o.Extra)
	return b.String()
}

// waitListening returns once Run accepts connections on every address. A
// test that sends its first request before that would have to guess how
// long a start takes on a busy machine; when Run ends instead (a port it
// cannot bind, a config it refuses), the test fails with Run's error and
// not with "connection refused" somewhere later.
func (h *Harness) waitListening(addrs []string) {
	h.T.Helper()
	deadline := time.Now().Add(time.Minute)
	for _, addr := range addrs {
		for {
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err == nil {
				_ = c.Close()
				break
			}
			select {
			case rerr := <-h.done:
				h.done <- rerr // Stop reads it again
				h.T.Fatalf("app.Run ended before it listened on %s: %v", addr, rerr)
			case <-time.After(10 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				h.T.Fatalf("app.Run does not listen on %s after a minute: %v", addr, err)
			}
		}
	}
}

// Stop ends the app (Run returns in listener mode) and returns Run's error.
func (h *Harness) Stop() error {
	if h.closed {
		return nil
	}
	h.closed = true
	h.Proxy.Close()
	h.Dash.Close()
	h.cancel()
	if h.done != nil {
		select {
		case err := <-h.done:
			return err
		case <-time.After(20 * time.Second):
			return errors.New("app.Run did not return within 20 s")
		}
	}
	time.Sleep(50 * time.Millisecond)
	// Without listeners Run does not shut down; close what it would close, so no writer of the request ring or the
	// metrics store is still busy when the test removes its temp directory.
	if h.App.Requests != nil {
		_ = h.App.Requests.Close()
	}
	if h.App.Monitor != nil {
		_ = h.App.Monitor.Close()
	}
	return h.App.Store.Close()
}

// Close stops everything.
func (h *Harness) Close() {
	_ = h.Stop()
	h.Backend.Close()
}

// Visit sends a request through the proxy as visitor ip (via X-Forwarded-For
// from the trusted loopback proxy).
func (h *Harness) Visit(method, path, ip, ctype, body string) *http.Response {
	h.T.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, h.Proxy.URL+path, rd)
	req.Host = "shop.example"
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	req.Header.Set("Accept", "text/html")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.T.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return resp
}

// Flush waits until queued events are written and the incident writer has
// stored every queued incident and folded every pending aggregation hit
// (synchronously, not by waiting for its 500 ms tick).
func (h *Harness) Flush() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.App.Events.Flush(ctx)
	h.App.Gate.FlushIncidents(ctx)
}

// API calls the dashboard API and returns status and raw body.
func (h *Harness) API(method, path string, body any) (int, []byte) {
	h.T.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.Dash.URL+"/api/v0"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != "GET" && h.CSRF != "" {
		req.Header.Set("X-CSRF-Token", h.CSRF)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		h.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// Login sets the first password (from localhost) and keeps the session.
func (h *Harness) Login() {
	h.T.Helper()
	code, b := h.API("POST", "/auth/setup", map[string]string{"password": h.Password, "setup_code": h.App.SetupCode()})
	if code != 200 {
		code, b = h.API("POST", "/auth/login", map[string]string{"password": h.Password})
	}
	if code != 200 {
		h.T.Fatalf("login: %d %s", code, b)
	}
	var s struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(b, &s)
	h.CSRF = s.CSRF
}

// WaitFor polls f.
func (h *Harness) WaitFor(what string, f func() bool) {
	h.T.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.T.Fatalf("timeout waiting for %s", what)
}

// botsNow is the bot engine clock of a harness: Options.BotsNow, else one
// day after the shipped range snapshot.
func botsNow(o Options) func() time.Time {
	if o.BotsNow != nil {
		return o.BotsNow
	}
	t := shippedRangesAt().Add(24 * time.Hour)
	return func() time.Time { return t }
}

// shippedRangesAt is when the oldest range snapshot of the shipped
// catalogue was fetched.
func shippedRangesAt() time.Time {
	var t time.Time
	for _, r := range bots.Default().Ranges() {
		at, err := time.Parse(time.RFC3339, r.FetchedAt)
		if err == nil && (t.IsZero() || at.Before(t)) {
			t = at
		}
	}
	if t.IsZero() {
		return time.Now()
	}
	return t
}
