package behaviour

import (
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
)

// PHP behind nginx or Caddy, Laravel and Symfony serve "//wp-login.php",
// "/login/" or "/wp-login.php/x" as the route itself. Such a variant must
// count as the login and fall under the route's limits, or a brute force
// sends it and leaves both.
func TestRouteVariantsMatch(t *testing.T) {
	on := map[string]bool{"wordpress": true, "laravel": true}
	for p, want := range map[string]string{
		"/wp-login.php":          "wordpress",
		"//wp-login.php":         "wordpress",
		"/./wp-login.php":        "wordpress",
		"/x/../wp-login.php":     "wordpress",
		"/wp-login.php/":         "wordpress",
		"/wp-login.php/x":        "wordpress",
		"/login":                 "laravel",
		"/login/":                "laravel",
		"//login//":              "laravel",
		"/login/x":               "",
		"/wp-login.phpx":         "",
		"/other/wp-login.php":    "",
		"/wp-login.php.bak":      "",
		"/":                      "",
		"/wp-login.php/../about": "",
	} {
		got := ""
		if lr := matchLogin(on, "POST", p, "", noBody); lr != nil {
			got = lr.Preset
		}
		if got != want {
			t.Errorf("POST %s: preset %q, want %q", p, got, want)
		}
	}

	b := modes(nil)
	b.RateLimits = []config.RateLimit{
		{ID: "xmlrpc", Route: "/xmlrpc.php", Methods: []string{"POST"}, Limit: 2, Per: "1m", Burst: 2, Mode: config.BehaviourBlock},
		{ID: "admin", Route: "/wp-admin/*", Limit: 100, Per: "1m", Burst: 100, Mode: config.BehaviourObserve},
	}
	e, _, c := newEngine(b)
	limited := 0
	for _, p := range []string{"/xmlrpc.php", "//xmlrpc.php", "/xmlrpc.php/", "/./xmlrpc.php"} {
		if v := e.Check(req(c, "203.0.113.5", "residential", "POST", p)); v.RateLimited {
			limited++
		}
	}
	if limited != 2 {
		t.Fatalf("%d of 4 variants over a limit of 2 limited", limited)
	}
	var l *Limit
	for _, x := range e.Limits() {
		if x.ID == "admin" {
			l = x
		}
	}
	for p, want := range map[string]bool{"/wp-admin/": true, "/wp-admin/x": true, "//wp-admin//x": true, "/wp-admin": false} {
		if l.Matches("GET", "verein.example", p, "") != want {
			t.Errorf("route %s path %s: %v", l.Route, p, !want)
		}
	}
}

// The buckets run on wall-clock time. A clock that steps back (NTP) must not
// take tokens away: before the clamp an hour back left every active bucket
// 180 tokens short, so the client got 429 for an hour.
func TestRateLimitClockStepsBack(t *testing.T) {
	b := modes(nil)
	b.RateLimits = []config.RateLimit{{ID: "xmlrpc", Route: "/xmlrpc.php", Limit: 3, Per: "1m", Burst: 3, Mode: config.BehaviourBlock}}
	e, _, c := newEngine(b)
	if v := e.Check(req(c, "203.0.113.5", "residential", "POST", "/xmlrpc.php")); v.RateLimited {
		t.Fatal("first request limited")
	}
	c.add(-time.Hour)
	for i := 0; i < 2; i++ {
		if v := e.Check(req(c, "203.0.113.5", "residential", "POST", "/xmlrpc.php")); v.RateLimited {
			t.Fatalf("request %d after the clock stepped back limited (retry %v)", i+2, v.RetryAfter)
		}
	}
	if v := e.Check(req(c, "203.0.113.5", "residential", "POST", "/xmlrpc.php")); !v.RateLimited {
		t.Fatal("the burst no longer holds")
	}
}
