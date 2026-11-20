//go:build !release

package dashboard_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

// The scenarios observe: this test is about the waves; a single address
// that fails ten logins would otherwise be blocked by login_bruteforce (D92).
const distYAML = `behaviour:
  presets: [wordpress]
  scenarios:
    login_bruteforce: {mode: observe}
    credential_stuffing: {mode: observe}
  distributed:
    detectors:
      route_wave: {mode: respond}
      account_wave: {mode: respond}
      fingerprint_cluster: {mode: respond}
      inconsistency: {mode: respond}
      shape_wave: {mode: observe}
`

var stuffUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
}

// post sends a login POST through the gate: rotating address and user
// agent, one client stack (same header set), optional cookie.
func post(t *testing.T, h *apptest.Harness, ip, ua, cookie, accept string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", h.Proxy.URL+"/wp-login.php", strings.NewReader("log=user-"+ip+"&pwd=secret-pw"))
	req.Host = "shop.example"
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", accept)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestDistributedEndToEnd(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "review", Extra: distYAML})
	h.Login()
	if err := h.App.SetInstalledAt(context.Background(), time.Now().Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// The app set its login form cookie for a real visitor earlier.
	h.App.Behaviour.LearnCookies("shop.example", []string{"wordpress_test_cookie"})

	limited := 0
	for i := 0; i < 400; i++ {
		r := post(t, h, fmt.Sprintf("198.18.%d.%d", i/250, i%250+1), stuffUAs[i%len(stuffUAs)], "", "text/html")
		if r.StatusCode == 429 {
			limited++
			if r.Header.Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
		}
	}
	if limited < 100 {
		t.Fatalf("route not tightened: %d of 400 limited", limited)
	}
	// Problem details for API clients.
	r := post(t, h, "198.18.3.3", stuffUAs[0], "", "application/json")
	if r.StatusCode != 429 || r.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("api client: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	// A legitimate user with the session cookie logs in normally.
	for i := 0; i < 10; i++ {
		if r := post(t, h, "192.0.2.77", stuffUAs[0], "wordpress_test_cookie=WP+Cookie+check", "text/html"); r.StatusCode != 200 {
			t.Fatalf("legitimate user stopped: %d", r.StatusCode)
		}
	}
	// Reading the form is never limited.
	if r := h.Visit("GET", "/wp-login.php", "198.18.4.4", "", ""); r.StatusCode != 200 {
		t.Fatalf("form GET: %d", r.StatusCode)
	}

	h.Flush()
	b := expect(t, h, "GET", "/distributed/waves", nil, 200, "WavePage")
	page := decode[dashboard.WavePage](t, b)
	dets := map[string]dashboard.Wave{}
	stopped := 0
	for _, w := range page.Items {
		dets[w.Detector] = w
		stopped += w.Stopped
	}
	fc, ok := dets["fingerprint_cluster"]
	_, rw := dets["route_wave"]
	if !ok || !rw || !fc.Active || fc.Action != "respond" || fc.Until == nil || fc.Fingerprint == "" || fc.UserAgents < 3 || !fc.SuggestSecondFactor || stopped < limited {
		t.Fatalf("waves: %s", b)
	}
	if strings.Contains(string(b), "198.18.") {
		t.Fatal("wave list names an address")
	}
	b = expect(t, h, "GET", "/distributed/waves/"+fc.ID, nil, 200, "WaveDetail")
	if d := decode[dashboard.WaveDetail](t, b); len(d.Requests) == 0 {
		t.Fatalf("detail: %s", b)
	}
	b = expect(t, h, "GET", "/distributed/settings", nil, 200, "DistributedSettings")
	if st := decode[dashboard.DistributedSettings](t, b); st.GatewayObserve || st.LearningUntil == nil || st.FingerprintKind != "headers" {
		t.Fatalf("settings: %s", b)
	}
	expect(t, h, "PATCH", "/distributed/settings", map[string]any{"detectors": map[string]any{"shape_wave": "respond"}}, 200, "DistributedSettings")
	if h.App.Config().Behaviour.Distributed.Detectors.ShapeWave.Mode != "respond" {
		t.Fatal("patch not applied")
	}

	// Thresholds (D97): set in the dashboard, effective at once; a field left
	// out and an empty object fall back to the default; bounds are refused.
	route := func(b []byte) dashboard.DetectorSetting {
		t.Helper()
		for _, d := range decode[dashboard.DistributedSettings](t, b).Detectors {
			if d.ID == "route_wave" {
				return d
			}
		}
		t.Fatalf("no route_wave: %s", b)
		return dashboard.DetectorSetting{}
	}
	b = expect(t, h, "PATCH", "/distributed/settings", map[string]any{"thresholds": map[string]any{"route_wave": map[string]any{"count": 50, "window_s": 120, "factor": 8}}}, 200, "DistributedSettings")
	if d := route(b); d.Thresholds.Count != 50 || d.Thresholds.WindowS != 120 || d.Thresholds.Factor != 8 || d.Defaults.Count != 30 || d.Defaults.WindowS != 60 {
		t.Fatalf("thresholds not applied: %+v", d)
	}
	b = expect(t, h, "PATCH", "/distributed/settings", map[string]any{"thresholds": map[string]any{"route_wave": map[string]any{"count": 40}}}, 200, "DistributedSettings")
	if d := route(b); d.Thresholds.Count != 40 || d.Thresholds.WindowS != 60 || d.Thresholds.Factor != 5 {
		t.Fatalf("entry does not replace the one before: %+v", d)
	}
	b = expect(t, h, "PATCH", "/distributed/settings", map[string]any{"thresholds": map[string]any{"route_wave": map[string]any{}}}, 200, "DistributedSettings")
	if d := route(b); d.Thresholds != d.Defaults {
		t.Fatalf("thresholds not reset: %+v", d)
	}
	for _, bad := range []map[string]any{
		{"route_wave": map[string]any{"count": 2}},
		{"account_wave": map[string]any{"factor": 5}},
		{"shape_wave": map[string]any{"window_s": 7200}},
	} {
		expect(t, h, "PATCH", "/distributed/settings", map[string]any{"thresholds": bad}, 400, "")
	}

	// End every running response early: the route is open again.
	for _, w := range page.Items {
		if w.Active {
			b = expect(t, h, "POST", "/distributed/waves/"+w.ID+"/end", nil, 200, "Wave")
			if e := decode[dashboard.Wave](t, b); e.Active || e.EndReason != "operator" {
				t.Fatalf("end: %s", b)
			}
		}
	}
	expect(t, h, "POST", "/distributed/waves/"+fc.ID+"/end", nil, 409, "Problem")
	if r := post(t, h, "198.18.5.5", stuffUAs[1], "", "text/html"); r.StatusCode != 200 {
		t.Fatalf("still tightened after ending: %d", r.StatusCode)
	}
}

// A gateway in mode observe detects waves but enforces nothing.
func TestDistributedGatewayObserve(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe", Extra: distYAML})
	h.Login()
	if err := h.App.SetInstalledAt(context.Background(), time.Now().Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		if r := post(t, h, fmt.Sprintf("198.18.%d.%d", i/250, i%250+1), stuffUAs[i%len(stuffUAs)], "", "text/html"); r.StatusCode != 200 {
			t.Fatalf("observe gateway answered %d", r.StatusCode)
		}
	}
	h.Flush()
	b := expect(t, h, "GET", "/distributed/waves", nil, 200, "WavePage")
	page := decode[dashboard.WavePage](t, b)
	if len(page.Items) == 0 {
		t.Fatal("no wave detected")
	}
	for _, w := range page.Items {
		if w.Action != "observe" || w.Reason != "gateway_observe" || w.Active {
			t.Fatalf("observe gateway enforced: %+v", w)
		}
	}
}
