//go:build !release

package app_test

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

func get(t *testing.T, url string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Host = "shop.example"
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	req.Header.Set("Accept", "text/html")
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
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

// TestRunWithListeners runs the real process layout: embedded Caddy on the
// proxy port, dashboard and metrics on their own ports, graceful stop.
func TestRunWithListeners(t *testing.T) {
	h := apptest.New(t, apptest.Options{Listeners: true})
	proxy := "http://" + h.ProxyAddr
	if code, _ := get(t, proxy+"/.schild/readyz", nil); code != 200 {
		t.Fatalf("readyz %d", code)
	}
	if code, body := get(t, proxy+"/hello", map[string]string{"X-Forwarded-For": "198.51.100.23"}); code != 200 || body != "app ok" {
		t.Fatalf("clean through Caddy: %d %q", code, body)
	}
	code, body := get(t, proxy+"/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", map[string]string{"X-Forwarded-For": "203.0.113.5"})
	if code != 403 || !strings.Contains(body, "Vorfallnummer") {
		t.Fatalf("xss through Caddy: %d", code)
	}
	if code, _ := get(t, "http://"+h.DashAddr+"/healthz", nil); code != 200 {
		t.Fatal("dashboard healthz")
	}
	// The dashboard answers under its own address, not under the website's
	// name (D76: Host check against DNS rebinding).
	if code, body := get(t, "http://"+h.DashAddr+"/api/v0/auth/session", map[string]string{"Host": h.DashAddr}); code != 200 || !strings.Contains(body, `"first_run":true`) {
		t.Fatalf("dashboard session: %d %s", code, body)
	}
	if code, body := get(t, "http://"+h.DashAddr+"/api/v0/auth/session", nil); code != 403 || !strings.Contains(body, "dashboard.allowed_hosts") {
		t.Fatalf("dashboard under the website's name: %d %s", code, body)
	}
	_, m := get(t, "http://"+h.MetricsAddr+"/metrics", nil)
	for _, want := range []string{`schild_requests_total{outcome="blocked"} 1`, "schild_waf_seconds_bucket", "schild_baseline_protection_active 1"} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	for _, bad := range []string{"203.0.113.5", "198.51.100.23", "shop.example"} {
		if strings.Contains(m, bad) {
			t.Errorf("metrics leak %s", bad)
		}
	}
	if h.Hits.Load() != 1 {
		t.Fatalf("backend hits %d", h.Hits.Load())
	}
	if err := h.Stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := http.Get(proxy + "/hello"); err == nil {
		t.Fatal("proxy still listening after stop")
	}
}

// TestSettingsSurviveRestartAndCLIAllow: dashboard settings live in the
// overlay in the data dir; an allowlist entry written by the CLI (another
// process) is picked up by the running proxy.
func TestSettingsSurviveRestartAndCLIAllow(t *testing.T) {
	app.Parallel(t)
	dir := t.TempDir()
	h := apptest.New(t, apptest.Options{Dir: dir})
	h.Login()
	code, b := h.API("PATCH", "/settings", map[string]any{"retention": map[string]any{"raw_ip_days": 3}})
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	// "schild allow" from another process: a second store handle.
	cli, err := store.Open(filepath.Join(dir, "data", "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	e, errs := allowlist.Validate(allowlist.Input{IP: "203.0.113.77", Label: "CLI", Level: allowlist.BypassWAF, TTL: "24h"}, time.Now())
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	e.Source = "cli"
	if err := cli.AddAllow(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	cli.Close()
	h.WaitFor("CLI allowlist entry", func() bool {
		lvl, _ := h.App.Allow.Match(mustAddr("203.0.113.77"), time.Now())
		return lvl == allowlist.BypassWAF
	})
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	h2 := apptest.New(t, apptest.Options{Dir: dir})
	if d := h2.App.Config().Retention.RawIPDays; d != 3 {
		t.Fatalf("retention after restart: %d", d)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
