package behaviour

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
)

func TestFormValues(t *testing.T) {
	for _, tc := range []struct {
		raw, k string
		want   []string
	}{
		{"", "a", nil},
		{"a=1&b=2&a=3", "a", []string{"1", "3"}},
		{"a=1;b=2&c=3", "c", []string{"3"}},
		{"a=1;b=2&c=3", "a", []string{"1;b=2"}}, // ';' cuts nothing, as in PHP
		{"%61=x&a&&a=%zz&b=%zz", "a", []string{"x", "", "%zz"}},
		{"user+name=a%20b", "user name", []string{"a b"}},
		{"%61=a%20b%zz%4", "a", []string{"a b%zz%4"}}, // a bad escape stays, the good ones count
	} {
		if got := FormValues(tc.raw, tc.k); !slices.Equal(got, tc.want) {
			t.Errorf("FormValues(%q, %q) = %q, want %q", tc.raw, tc.k, got, tc.want)
		}
	}
}

// noBody is the form of a request without body.
func noBody() Form { return Form{} }

// A POST to wp-login.php is no login attempt only in the form WordPress
// itself sends. wp-login.php reads the action from the query overlaid by
// the body and falls back to "login" for whatever it does not know.
func TestWPLoginAction(t *testing.T) {
	on := map[string]bool{"wordpress": true}
	body := func(s string) func() Form { return func() Form { return Form{Fields: s} } }
	opaque := func() Form { return Form{Opaque: true} }
	many := strings.Repeat("x&", wpQueryVars)
	for _, tc := range []struct {
		name, query string
		form        func() Form
		login       bool
	}{
		{"plain login", "", body("log=a&pwd=b"), true},
		{"lost password", "action=lostpassword", body("user_login=a&redirect_to=&wp-submit=x"), false},
		{"register", "action=register", body("user_login=a&user_email=a%40b.example"), false},
		{"lost password without body", "action=lostpassword", noBody, false},
		{"same action in the body", "action=lostpassword", body("action=lostpassword&user_login=a"), false},
		{"two other actions", "action=register&action=lostpassword", noBody, false},

		{"unknown action is a login", "action=nothing", body("log=a&pwd=b"), true},
		{"empty action is a login", "action=", noBody, true},
		{"body overrides the query", "action=lostpassword", body("log=a&pwd=b&action=login"), true},
		{"unknown action in the body", "action=lostpassword", body("action=x&log=a&pwd=b"), true},
		{"action only in the body", "", body("action=lostpassword&user_login=a"), true},
		{"array in the query", "action=lostpassword&action[]=x", noBody, true},
		{"array in the body", "action=lostpassword", body("action%5B%5D=x&log=a"), true},
		{"escaped name", "action=lostpassword", body("%61ction=login&log=a"), true},
		{"escaped name next to a bad escape", "action=lostpassword", body("x=%zz&%61ction=login%zz"), true},
		{"leading space of the name", "action=lostpassword", body("+action=login&log=a"), true},
		{"name cut at a NUL byte", "action=lostpassword", body("action%00x=login&log=a"), true},
		{"behind a semicolon", "action=lostpassword", body("x=1;action=login&log=a"), true},
		{"semicolon in the value", "action=lostpassword;action=login", noBody, true},
		{"behind more parameters than PHP reads", many + "action=lostpassword", noBody, true},
		{"multipart or unread body", "action=lostpassword", opaque, true},
		{"nobody read the body", "action=lostpassword", nil, true},
	} {
		got := matchLogin(on, "POST", "/wp-login.php", tc.query, tc.form) != nil
		if got != tc.login {
			t.Errorf("%s: login attempt %v, want %v", tc.name, got, tc.login)
		}
	}
	// The body is not asked for when the query already says login.
	asked := false
	matchLogin(on, "POST", "/wp-login.php", "", func() Form { asked = true; return Form{} })
	if asked {
		t.Error("form read without need")
	}
}

// ResolveLogin keeps what the gate found with the body for Observe: the
// hidden attempts count for login_bruteforce.
func TestResolvedLoginCounts(t *testing.T) {
	b := modes(nil)
	b.Presets = []string{"wordpress"}
	b.Scenarios.Get(config.ScenarioLoginBruteforce).Mode = config.BehaviourBlock
	e, _, c := newEngine(b)
	thr := e.Thresholds(config.ScenarioLoginBruteforce)
	for i := 0; i < thr.Count+1; i++ {
		rq := req(c, "203.0.113.20", "hosting", "POST", "/wp-login.php")
		rq.RawQuery = "action=lostpassword"
		e.ResolveLogin(rq, func() Form { return Form{Fields: "log=admin&pwd=x&action=login"} })
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
	}
	if len(e.RunningBlocks()) != 1 {
		t.Fatalf("attempts behind ?action=lostpassword not counted: %d blocks", len(e.RunningBlocks()))
	}
	// A real lost-password form stays no login attempt.
	e, _, c = newEngine(b)
	for i := 0; i < thr.Count+1; i++ {
		rq := req(c, "203.0.113.21", "hosting", "POST", "/wp-login.php")
		rq.RawQuery = "action=lostpassword"
		e.ResolveLogin(rq, func() Form { return Form{Fields: "user_login=a&redirect_to=&wp-submit=x"} })
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
	}
	if n := len(e.RunningBlocks()); n != 0 {
		t.Fatalf("lost-password forms counted as login attempts: %d blocks", n)
	}
}

func TestQueryMatchingSemicolonAndHPP(t *testing.T) {
	// Semicolon in an unrelated parameter must not disable query matching.
	if !hasQuery("a=1;b=2&task=user.login", "task=user.login") {
		t.Fatal("queryMatches failed open on semicolon")
	}
	// Duplicate query parameter (HTTP parameter pollution): second occurrence still matches.
	if !hasQuery("task=other&task=user.login", "task=user.login") {
		t.Fatal("queryMatches missed duplicate query parameter")
	}

	// WordPress login preset: ?action=foo&action=login or semicolon in query is still a login attempt.
	b := modes(nil)
	b.Presets = []string{"wordpress", "joomla"}
	b.PresetLimits = config.BehaviourBlock
	e, _, c := newEngine(b)
	cfg := e.cfg.Load()

	for _, q := range []string{
		"",
		"action=login",
		"foo=1;bar=2",
		"action=lostpassword&action=login",
		"foo=1;bar=2&action=login",
	} {
		if matchLogin(cfg.presets, "POST", "/wp-login.php", q, noBody) == nil {
			t.Errorf("wp login missed query %q", q)
		}
	}
	if matchLogin(cfg.presets, "POST", "/wp-login.php", "action=lostpassword", noBody) != nil {
		t.Error("wp lostpassword alone should not match login")
	}

	// Joomla password-reset preset rate limit (Route=/index.php, Query=task=reset.request, Burst=3)
	// must enforce despite semicolons and duplicate query parameters (HPP).
	limited := false
	queries := []string{"foo=1;bar=2&task=reset.request", "task=other&task=reset.request"}
	for i := 0; i < 6; i++ {
		rq := req(c, "203.0.113.10", "hosting", "POST", "/index.php")
		rq.RawQuery = queries[i%len(queries)]
		if v := e.Check(rq); v.RateLimited {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("joomla password-reset preset rate limit bypassed via semicolon/HPP query")
	}
}

func TestTrustedProxyNeverBlockedOrLimited(t *testing.T) {
	b := modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock})
	b.Presets = []string{"wordpress"}
	b.RateLimits = []config.RateLimit{{
		ID: "strict", Route: "/wp-login.php", Methods: []string{"POST"},
		Limit: 1, Per: "1m", Burst: 1, Mode: config.BehaviourBlock,
	}}
	e, r, c := newEngine(b)

	for i := 0; i < 20; i++ {
		rq := req(c, "198.51.100.2", "hosting", "POST", "/wp-login.php")
		rq.TrustedProxy = true
		v := e.Check(rq)
		if v.Block || v.RateLimited {
			t.Fatalf("trusted proxy blocked or limited on req %d: %+v", i, v)
		}
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
		c.add(time.Second)
	}
	for _, ev := range r.triggered() {
		if ev.Action != ActionObserve || ev.Reason != ReasonAllowlisted {
			t.Fatalf("trusted proxy event not exempted: %+v", ev)
		}
	}
	if len(e.RunningBlocks()) != 0 {
		t.Fatalf("trusted proxy acquired active block: %+v", e.RunningBlocks())
	}
}

func TestAggressiveCrawlBlocksSpoofedSearchBot(t *testing.T) {
	b := modes(map[string]string{config.ScenarioAggressiveCrawl: config.BehaviourBlock})
	e, _, c := newEngine(b)
	const googleUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

	// Verified/non-impersonating search bot is observed with ReasonUnverifiedBot, never blocked.
	for i := 0; i < 250; i++ {
		rq := req(c, "66.249.66.1", "hosting", "GET", fmt.Sprintf("/p/%d", i))
		rq.UserAgent = googleUA
		if v := e.Check(rq); v.Block {
			t.Fatalf("non-impersonating search bot was blocked on req %d", i)
		}
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
		c.add(10 * time.Millisecond)
	}
	if len(e.RunningBlocks()) != 0 {
		t.Fatalf("non-impersonating search bot acquired active block: %+v", e.RunningBlocks())
	}

	// Impersonator claiming Googlebot UA is NOT skipped and gets blocked.
	blocked := false
	for i := 0; i < 250; i++ {
		rq := req(c, "203.0.113.99", "hosting", "GET", fmt.Sprintf("/p/%d", i))
		rq.UserAgent = googleUA
		rq.BotImpersonator = true
		if v := e.Check(rq); v.Block {
			blocked = true
			break
		}
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
		c.add(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("spoofed Googlebot (BotImpersonator=true) was not blocked by aggressive_crawl")
	}
}

func TestRouteWaveAndInconsistencyRequireMultipleSenders(t *testing.T) {
	b := distBehaviour(config.DistributedRespond)
	e, r, c := newDistEngine(b, t0.Add(-30*24*time.Hour), false)

	// One single IP sending 40 failed inconsistent logins must not trigger route_wave or inconsistency.
	for i := 0; i < 40; i++ {
		rq := req(c, "203.0.113.5", "hosting", "POST", "/wp-login.php")
		rq.Inconsistent = true
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
		c.add(50 * time.Millisecond)
	}
	for _, w := range r.waves() {
		if w.Detector == config.DetectorRouteWave || w.Detector == config.DetectorInconsistency {
			t.Fatalf("single sender triggered %s: %+v", w.Detector, w)
		}
	}

	// Multiple distinct senders (>= minRouteWaveSenders) still trigger route_wave & inconsistency.
	e2, r2, c2 := newDistEngine(b, t0.Add(-30*24*time.Hour), false)
	for i := 0; i < 40; i++ {
		ip := fmt.Sprintf("203.0.113.%d", (i%5)+10)
		rq := req(c2, ip, "hosting", "POST", "/wp-login.php")
		rq.Inconsistent = true
		e2.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
		c2.add(50 * time.Millisecond)
	}
	seen := map[string]bool{}
	for _, w := range r2.waves() {
		seen[w.Detector] = true
	}
	if !seen[config.DetectorRouteWave] || !seen[config.DetectorInconsistency] {
		t.Fatalf("multi-sender attack did not trigger both detectors: %+v", r2.waves())
	}
}

func TestKnownHostGuardsSiteTables(t *testing.T) {
	b := distBehaviour(config.DistributedRespond)
	e, _, c := newDistEngine(b, t0.Add(-30*24*time.Hour), false)
	e.KnownHost = func(host string) bool { return host == "shop.example" }

	// Real site records a cookie and a site entry.
	real := req(c, "192.0.2.10", "residential", "GET", "/wp-login.php")
	real.Host = "shop.example"
	e.Observe(real, Outcome{Forwarded: true, Response: Response{Status: 200, CookieNames: []string{"session_id"}}})

	// Flood arbitrary Host headers beyond site/cookie table capacities.
	for i := 0; i < 600; i++ {
		rq := req(c, "203.0.113.7", "hosting", "GET", "/wp-login.php")
		rq.Host = fmt.Sprintf("evil-%d.invalid", i)
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200, CookieNames: []string{"fake_cookie"}}})
	}

	// Real site must still be present in cookies table and sites table.
	check := req(c, "192.0.2.11", "residential", "POST", "/wp-login.php")
	check.Host = "shop.example"
	check.CookieNames = []string{"session_id"}
	if !e.HasSession(check) {
		t.Fatal("real site session cookie was evicted by unknown Host flood")
	}
	e.sitesMu.Lock()
	_, ok := e.sites["shop.example"]
	nSites := len(e.sites)
	e.sitesMu.Unlock()
	if !ok || nSites != 1 {
		t.Fatalf("sites table polluted or evicted: ok=%v len=%d", ok, nSites)
	}
}
