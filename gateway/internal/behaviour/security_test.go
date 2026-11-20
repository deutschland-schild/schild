package behaviour

import (
	"fmt"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
)

func TestQueryMatchingSemicolonAndHPP(t *testing.T) {
	// Semicolon in an unrelated parameter must not disable query matching.
	if !queryMatches("a=1;b=2&task=user.login", "task=user.login") {
		t.Fatal("queryMatches failed open on semicolon")
	}
	// Duplicate query parameter (HTTP parameter pollution): second occurrence still matches.
	if !queryMatches("task=other&task=user.login", "task=user.login") {
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
		if matchLogin(cfg.presets, "POST", "/wp-login.php", q) == nil {
			t.Errorf("wp login missed query %q", q)
		}
	}
	if matchLogin(cfg.presets, "POST", "/wp-login.php", "action=lostpassword") != nil {
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
	e, r, c := newEngine(b)
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
	_ = r
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

var _ = events.DistributedDetectedData{}
