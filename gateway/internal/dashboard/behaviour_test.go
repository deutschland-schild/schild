//go:build !release

package dashboard_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/geo"
)

// MVP-17 end to end through the gate, the app and the dashboard API:
// login brute force is blocked with the calm page and expires, CGNAT is
// never blocked, rate limits answer 429 with problem details, releases work,
// and nothing of it reaches a lab.
func TestBehaviourEndToEnd(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "review", Extra: `behaviour:
  presets: [wordpress]
  preset_limits: observe
  scenarios:
    login_bruteforce: {mode: block}
    path_probing: {mode: observe}
  rate_limits:
    - {id: search, label: Suche, route: /search, methods: [GET], limit: 2, per: 1m, mode: block}
`})
	h.Login()
	// Scenarios act only after the learning period (MVP-19 measurement).
	if err := h.App.SetInstalledAt(context.Background(), time.Now().Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	const attacker = "198.51.100.7"
	before := h.Hits.Load()
	for i := 0; i < 5; i++ {
		// The fake app answers 200: WordPress shows the form again = failed login.
		if r := h.Visit("POST", "/wp-login.php", attacker, "application/x-www-form-urlencoded", "log=admin&pwd=hunter2-secret"); r.StatusCode != 200 {
			t.Fatalf("attempt %d: %d", i+1, r.StatusCode)
		}
	}
	r := h.Visit("GET", "/", attacker, "", "")
	body, _ := io.ReadAll(r.Body)
	if r.StatusCode != 403 || !strings.Contains(string(body), "Kurze Pause") || r.Header.Get("Retry-After") == "" || r.Header.Get("X-Schild-Incident") == "" {
		t.Fatalf("not paused: %d %v %s", r.StatusCode, r.Header, body)
	}
	if h.Hits.Load()-before != 5 {
		t.Fatalf("blocked request reached the app (%d hits)", h.Hits.Load()-before)
	}
	incident := r.Header.Get("X-Schild-Incident")

	// CGNAT: many people behind one address are never blocked.
	for i := 0; i < 30; i++ {
		if r := h.Visit("POST", "/wp-login.php", "100.64.3.4", "application/x-www-form-urlencoded", "log=user"); r.StatusCode != 200 {
			t.Fatalf("CGNAT address stopped at attempt %d: %d", i+1, r.StatusCode)
		}
	}
	// Own allowlisted address (harness: 192.0.2.10) neither.
	for i := 0; i < 30; i++ {
		if r := h.Visit("POST", "/wp-login.php", "192.0.2.10", "application/x-www-form-urlencoded", "log=me"); r.StatusCode != 200 {
			t.Fatalf("allowlisted address stopped: %d", r.StatusCode)
		}
	}

	// Rate limit: 429, Retry-After, RFC 9457 problem details for API clients.
	get := func(path, ip, accept string) *http.Response {
		req, _ := http.NewRequest("GET", h.Proxy.URL+path, nil)
		req.Host = "shop.example"
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("Accept", accept)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	for i := 0; i < 2; i++ {
		if r := get("/search", "203.0.113.5", "application/json"); r.StatusCode != 200 {
			t.Fatalf("search %d: %d", i+1, r.StatusCode)
		}
	}
	resp := get("/search", "203.0.113.5", "application/json")
	var p struct {
		Type       string `json:"type"`
		Status     int    `json:"status"`
		Code       string `json:"code"`
		RetryAfter int    `json:"retry_after"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&p)
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Content-Type") != "application/problem+json" || resp.Header.Get("Retry-After") != "30" ||
		p.Status != 429 || p.Code != "rate_limited" || p.RetryAfter != 30 {
		t.Fatalf("429: %d %v %+v", resp.StatusCode, resp.Header, p)
	}
	if r := get("/search", "203.0.113.5", "text/html"); r.StatusCode != 429 || !strings.Contains(readAll(r), "Gerade zu viele Anfragen") {
		t.Fatal("429 page for browsers")
	}
	if r := get("/search", "100.64.9.9", "text/html"); r.StatusCode != 200 {
		t.Fatal("rate limit on a CGNAT address")
	}

	h.Flush()
	// Hits in the dashboard API.
	b := expect(t, h, "GET", "/behaviour/hits", nil, 200, "BehaviourHitPage")
	page := decode[dashboard.BehaviourHitPage](t, b)
	var block *dashboard.BehaviourHit
	kinds := map[string]int{}
	for i, x := range page.Items {
		kinds[x.Kind]++
		if x.Scenario == "login_bruteforce" && x.Action == "block" {
			block = &page.Items[i]
		}
		if x.IP == "100.64.3.4" && (x.Action == "block" || x.Reason != "net_class") {
			t.Fatalf("CGNAT hit: %+v", x)
		}
		if x.IP == "192.0.2.10" && x.Reason != "allowlisted" {
			t.Fatalf("allowlisted hit: %+v", x)
		}
	}
	if block == nil || !block.Active || block.IP != attacker || block.Incident != incident || block.Level != 1 || kinds["rate_limit"] == 0 {
		t.Fatalf("hits: %s", b)
	}
	b = expect(t, h, "GET", "/behaviour/hits?active=true", nil, 200, "BehaviourHitPage")
	if p := decode[dashboard.BehaviourHitPage](t, b); len(p.Items) != 1 {
		t.Fatalf("active filter: %s", b)
	}
	// The incident of a behaviour block names the address and the block
	// (D36 measurement D.4: empty address, no host).
	b = expect(t, h, "GET", "/incidents/"+incident, nil, 200, "Incident")
	if inc := decode[dashboard.Incident](t, b); inc.Request.IP != attacker || inc.Block == nil || inc.Block.DurationS != 900 || inc.Request.Incident != incident {
		t.Fatalf("behaviour incident: %s", b)
	}
	// D51: the incident as a download, and the download on record.
	b = expect(t, h, "POST", "/incidents/"+incident+"/export", nil, 200, "IncidentExport")
	if x := decode[dashboard.IncidentExport](t, b); x.Incident.Incident != incident || len(x.Events) == 0 || x.Truncated || x.ExportedAt == "" {
		t.Fatalf("export: %s", b)
	}
	expect(t, h, "POST", "/incidents/AAAA-AAAA/export", nil, 404, "Problem")
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		b = expect(t, h, "GET", "/events?type=schild.incident.exported.v1", nil, 200, "EventPage")
		if p := decode[dashboard.EventPage](t, b); len(p.Items) == 1 {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("no audit event: %s", b)
		}
	}
	b = expect(t, h, "GET", "/behaviour/hits/"+block.ID, nil, 200, "BehaviourHitDetail")
	d := decode[dashboard.BehaviourHitDetail](t, b)
	if len(d.Blocks) != 1 || d.Blocks[0].Source != "behaviour:login_bruteforce" || len(d.Requests) == 0 {
		t.Fatalf("detail: %s", b)
	}
	// The incident is the block page's number: the existing unblock path works.
	// It carries the block (D36 amendment): how long and why.
	inc := decode[dashboard.Incident](t, expect(t, h, "GET", "/incidents/"+incident, nil, 200, "Incident"))
	if b := inc.Block; b == nil || b.Source != "behaviour:login_bruteforce" || b.Level != 1 || b.DurationS != 900 || b.Persisted ||
		b.Incident != incident || b.Until == "" || b.EndedAt != "" {
		t.Fatalf("incident block: %+v", inc.Block)
	}

	// Settings: changing a scenario needs the password.
	b = expect(t, h, "GET", "/behaviour/settings", nil, 200, "BehaviourSettings")
	set := decode[dashboard.BehaviourSettings](t, b)
	for _, s := range set.Scenarios {
		if s.ID == "path_probing" && (s.Mode != "observe" || s.EffectiveMode != "observe" || s.Recommended != "block") {
			t.Fatalf("path_probing: %+v", s)
		}
		if s.ID == "login_bruteforce" && (s.BlocksActive != 1 || s.Hits24h < 1) {
			t.Fatalf("login settings: %+v", s)
		}
	}
	if set.BlockCapS != 86400 || set.HostingBlockCapS != 604800 || len(set.HostingBlockStepsS) != 4 || set.HostingBlockStepsS[3] != 604800 || set.BlockStepsS[3] != 86400 {
		t.Fatalf("settings: %s", b)
	}
	b = expect(t, h, "PATCH", "/behaviour/settings", map[string]any{"scenarios": map[string]any{"waf_repeat": "block"}}, 200, "BehaviourSettings")
	if h.App.Config().Behaviour.Scenarios.WAFRepeat.Mode != "block" {
		t.Fatalf("patch not applied: %s", b)
	}

	// Preset limits are switched one by one (D95): schild.yaml sets observe for
	// all, the dashboard moves single ones and names what is recommended.
	limitModes := func() map[string]dashboard.RateLimit {
		t.Helper()
		out := map[string]dashboard.RateLimit{}
		for _, l := range decode[dashboard.RateLimitPage](t, expect(t, h, "GET", "/behaviour/rate-limits?limit=500", nil, 200, "RateLimitPage")).Items {
			out[l.ID] = l
		}
		return out
	}
	if l := limitModes(); l["preset-wordpress-login"].Mode != "observe" || l["preset-wordpress-login"].Recommended != "block" || l["preset-wordpress-search"].Recommended != "observe" {
		t.Fatalf("preset limits: %+v", l["preset-wordpress-login"])
	}
	expect(t, h, "PATCH", "/behaviour/settings", map[string]any{"preset_limit_modes": map[string]any{"preset-wordpress-login": "block", "preset-wordpress-xmlrpc": "off"}}, 200, "BehaviourSettings")
	if l := limitModes(); l["preset-wordpress-login"].Mode != "block" || l["preset-wordpress-xmlrpc"].Mode != "off" || l["preset-wordpress-search"].Mode != "observe" {
		t.Fatalf("preset limit modes not applied: %+v", l)
	}
	for _, bad := range []map[string]any{{"preset-nope-login": "block"}, {"preset-wordpress-login": "challenge"}} {
		expect(t, h, "PATCH", "/behaviour/settings", map[string]any{"preset_limit_modes": bad}, 400, "")
	}

	// Thresholds (D93): set in the dashboard, effective at once, a field left
	// out and an empty object fall back to the default.
	probing := func(b []byte) dashboard.ScenarioSetting {
		t.Helper()
		for _, s := range decode[dashboard.BehaviourSettings](t, b).Scenarios {
			if s.ID == "path_probing" {
				return s
			}
		}
		t.Fatalf("no path_probing: %s", b)
		return dashboard.ScenarioSetting{}
	}
	b = expect(t, h, "PATCH", "/behaviour/settings", map[string]any{"thresholds": map[string]any{"path_probing": map[string]any{"count": 8, "window_s": 120}}}, 200, "BehaviourSettings")
	if s := probing(b); s.Thresholds.Count != 8 || s.Thresholds.WindowS != 120 || s.Defaults.Count != 20 || s.Defaults.WindowS != 60 || s.Mode != "observe" {
		t.Fatalf("thresholds not applied: %+v", s)
	}
	if got := h.App.Behaviour.Thresholds("path_probing"); got.Count != 8 || got.WindowS != 120 {
		t.Fatalf("engine thresholds: %+v", got)
	}
	b = expect(t, h, "PATCH", "/behaviour/settings", map[string]any{"thresholds": map[string]any{"path_probing": map[string]any{"count": 12}}}, 200, "BehaviourSettings")
	if s := probing(b); s.Thresholds.Count != 12 || s.Thresholds.WindowS != 60 {
		t.Fatalf("entry does not replace the one before: %+v", s)
	}
	b = expect(t, h, "PATCH", "/behaviour/settings", map[string]any{"thresholds": map[string]any{"path_probing": map[string]any{}}}, 200, "BehaviourSettings")
	if s := probing(b); s.Thresholds != s.Defaults {
		t.Fatalf("thresholds not reset: %+v", s)
	}
	for _, bad := range []map[string]any{
		{"path_probing": map[string]any{"count": 1}},
		{"path_probing": map[string]any{"baseline_factor": 5}},
		{"aggressive_crawl": map[string]any{"window_s": 7200}},
		{"waf_repeat": map[string]any{"slow_count": 30}},
	} {
		expect(t, h, "PATCH", "/behaviour/settings", map[string]any{"thresholds": bad}, 400, "")
	}
	if got := h.App.Behaviour.Thresholds("path_probing"); got.Count != 20 {
		t.Fatalf("a refused patch changed the thresholds: %+v", got)
	}

	// Release with a narrow exception: the visitor passes again.
	b = expect(t, h, "POST", "/behaviour/release", map[string]any{"ip": attacker, "allow": "exception", "scenario": "login_bruteforce", "ttl": "24h"}, 200, "ReleaseResult")
	rel := decode[dashboard.ReleaseResult](t, b)
	if rel.BlocksEnded != 1 || len(rel.ExceptionSources) != 1 || rel.ExceptionSources[0] != "behaviour:login_bruteforce" {
		t.Fatalf("release: %s", b)
	}
	if r := h.Visit("GET", "/", attacker, "", ""); r.StatusCode != 200 {
		t.Fatalf("released client still stopped: %d", r.StatusCode)
	}
	// The released block is no longer in force: ended_at (contracts v0.5).
	if inc := decode[dashboard.Incident](t, expect(t, h, "GET", "/incidents/"+incident, nil, 200, "Incident")); inc.Block == nil || inc.Block.EndedAt == "" {
		t.Fatalf("released block without ended_at: %+v", inc.Block)
	}
	b = expect(t, h, "POST", "/behaviour/release", map[string]any{"ip": "198.51.100.99", "allow": "permanent", "label": "Büro"}, 200, "ReleaseResult")
	if rel := decode[dashboard.ReleaseResult](t, b); rel.AllowlistEntry == nil {
		t.Fatalf("permanent: %s", b)
	}

	// Rate limit CRUD with Probelauf.
	b = expect(t, h, "GET", "/behaviour/rate-limits", nil, 200, "RateLimitPage")
	lp := decode[dashboard.RateLimitPage](t, b)
	src := map[string]string{}
	for _, l := range lp.Items {
		src[l.ID] = l.Source
	}
	if src["search"] != "config" || src["preset-wordpress-login"] != "preset" || src["preset-drupal-login"] != "" {
		t.Fatalf("limits: %v", src)
	}
	b = expect(t, h, "POST", "/behaviour/rate-limits/dry-run", map[string]any{"route": "/wp-login.php", "methods": []string{"POST"}, "limit": 1, "per": "1h"}, 200, "RateLimitDryRun")
	if dr := decode[dashboard.RateLimitDryRun](t, b); dr.Requests == 0 || dr.WouldLimit == 0 || dr.Clients == 0 || !dr.Sampled {
		t.Fatalf("dry run: %s", b)
	}
	expect(t, h, "POST", "/behaviour/rate-limits", map[string]any{"route": "/**", "limit": 600, "per": "1m"}, 400, "Problem")
	b = expect(t, h, "POST", "/behaviour/rate-limits", map[string]any{"route": "/**", "limit": 600, "per": "1m", "confirm_site_wide": true, "label": "Ganze Website"}, 201, "RateLimit")
	created := decode[dashboard.RateLimit](t, b)
	if created.Source != "dashboard" || created.Mode != "observe" || created.Burst != 600 {
		t.Fatalf("created: %s", b)
	}
	b = expect(t, h, "PATCH", "/behaviour/rate-limits/"+created.ID, map[string]any{"route": "/kontakt", "methods": []string{"POST"}, "limit": 3, "per": "10m", "mode": "block"}, 200, "RateLimit")
	if u := decode[dashboard.RateLimit](t, b); u.Route != "/kontakt" || u.Mode != "block" {
		t.Fatalf("updated: %s", b)
	}
	expect(t, h, "PATCH", "/behaviour/rate-limits/search", map[string]any{"route": "/x", "limit": 3, "per": "10m"}, 409, "Problem")
	expect(t, h, "DELETE", "/behaviour/rate-limits/preset-wordpress-login", nil, 409, "Problem")
	expect(t, h, "DELETE", "/behaviour/rate-limits/"+created.ID, nil, 204, "")
	expect(t, h, "DELETE", "/behaviour/rate-limits/nope", nil, 404, "Problem")
}

// Tor exits are never stopped by behaviour or rate limits, but the WAF
// still blocks attacks from them (initiator 2026-10-28).
func TestBehaviourTorExit(t *testing.T) {
	saved := geo.FixtureEntries
	geo.FixtureEntries = append(append([]geo.FixtureEntry(nil), saved...),
		geo.FixtureEntry{CIDR: "192.0.2.192/26", Country: "DE", City: "Berlin", ASOrg: "Example Tor Exit (TEST ONLY)", NetClass: "tor", ASN: 64510})
	defer func() { geo.FixtureEntries = saved }()
	h := apptest.New(t, apptest.Options{Mode: "review", Extra: `behaviour:
  scenarios:
    login_bruteforce: {mode: block}
  rate_limits:
    - {id: login, route: /wp-login.php, methods: [POST], limit: 1, per: 1m, mode: block}
`})
	const tor = "192.0.2.200"
	for i := 0; i < 20; i++ {
		if r := h.Visit("POST", "/wp-login.php", tor, "application/x-www-form-urlencoded", "log=admin&pwd=x"); r.StatusCode != 200 {
			t.Fatalf("tor exit stopped at attempt %d: %d", i+1, r.StatusCode)
		}
	}
	if r := h.Visit("GET", "/", tor, "", ""); r.StatusCode != 200 {
		t.Fatalf("tor exit blocked: %d", r.StatusCode)
	}
	// The WAF still applies.
	if r := h.Visit("GET", "/?id=1%27%20OR%20%271%27%3D%271%27--", tor, "", ""); r.StatusCode != 403 {
		t.Fatalf("WAF did not block the tor exit: %d", r.StatusCode)
	}
	h.Flush()
	h.Login()
	b := expect(t, h, "GET", "/behaviour/hits?ip="+tor, nil, 200, "BehaviourHitPage")
	page := decode[dashboard.BehaviourHitPage](t, b)
	if len(page.Items) == 0 {
		t.Fatalf("tor exit not counted: %s", b)
	}
	for _, x := range page.Items {
		if x.Action != "observe" || x.Reason != "net_class" || x.Geo == nil || x.Geo.NetClass != "tor" {
			t.Fatalf("tor hit: %+v", x)
		}
	}
}

func readAll(r *http.Response) string {
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return string(b)
}
