package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The failed-login map stays bounded without resetting running counts
// (security review 3.4): a key close to its limit outlives a flood of one-off
// addresses, and the login budget of an IPv6 host is its /64.
func TestLoginFailsEvictNotFlush(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := &Server{Now: func() time.Time { return now }, loginFails: map[string][]time.Time{}}
	fail := func(r *http.Request) {
		if _, ok := s.attempt(httptest.NewRecorder(), loginKey(r)); !ok {
			t.Fatalf("no attempt left for %s", loginKey(r))
		}
	}
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "198.51.100.7:1"
	for range 4 {
		fail(req)
	}
	for i := range maxLoginKeys - 1 {
		s.loginFails[fmt.Sprintf("key-%d", i)] = []time.Time{now}
	}
	for i := range 200 {
		now = now.Add(time.Millisecond)
		other := httptest.NewRequest("POST", "/", nil)
		other.RemoteAddr = fmt.Sprintf("[2001:db8:%x::1]:1", i)
		fail(other)
	}
	if len(s.loginFails) != maxLoginKeys {
		t.Fatalf("map size %d", len(s.loginFails))
	}
	if n := len(s.loginFails["198.51.100.7"]); n != 4 {
		t.Fatalf("running count %d", n)
	}
	// Keys past their window go first. A key that takes a new attempt
	// drops its own expired ones.
	now = now.Add(16 * time.Minute)
	fail(req)
	s.loginFails["fresh"] = []time.Time{now}
	fail(httptest.NewRequest("POST", "/", nil))
	if len(s.loginFails) > 3 || len(s.loginFails["198.51.100.7"]) != 1 {
		t.Fatalf("expired keys stayed: %d", len(s.loginFails))
	}
	a, b := httptest.NewRequest("POST", "/", nil), httptest.NewRequest("POST", "/", nil)
	a.RemoteAddr, b.RemoteAddr = "[2001:db8::1]:1", "[2001:db8::ffff]:1"
	if loginKey(a) != loginKey(b) {
		t.Fatalf("%s != %s", loginKey(a), loginKey(b))
	}
}

// TestAlertWouldBlockReason: the reason of behaviour and rate-limit alerts
// is derived from their event's mode and reason, the gateway mode and the
// learning period; first wins in the contract's order (D36 open items).
func TestAlertWouldBlockReason(t *testing.T) {
	t0 := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	learnUntil := t0.Add(time.Hour)
	learning := func(t time.Time) bool { return t.Before(learnUntil) }
	blocking := reasonCtx{learning: learning}
	observing := reasonCtx{gatewayObserve: true, learning: learning}
	after := t0.Add(2 * time.Hour)
	beh := []struct {
		name         string
		t            time.Time
		mode, reason string
		rc           reasonCtx
		want         string
	}{
		{"gateway observe", after, "observe", "", observing, "gateway_observe"},
		{"gateway observe wins over learning", t0, "block", "learning", observing, "gateway_observe"},
		{"learning reason", after, "block", "learning", blocking, "learning"},
		{"learning wins over scenario observe", t0, "observe", "", blocking, "learning"},
		{"scenario observe", after, "observe", "", blocking, "scenario_observe"},
		{"old challenge event (before D92)", after, "challenge", "challenge_unavailable", blocking, "scenario_observe"},
		{"released", after, "block", "released", blocking, "allowlist"},
		{"shared address", after, "block", "net_class", blocking, "shared_address"},
	}
	for _, c := range beh {
		if got := behaviourWouldReason(c.t, c.mode, c.reason, c.rc); got != c.want {
			t.Errorf("behaviour %s: %q want %q", c.name, got, c.want)
		}
	}
	rl := []struct {
		name, mode, reason string
		rc                 reasonCtx
		want               string
	}{
		{"gateway observe", "observe", "", observing, "gateway_observe"},
		{"limit observes", "observe", "", blocking, "scenario_observe"},
		{"limit observes wins over allowlist", "observe", "allowlisted", blocking, "scenario_observe"},
		{"allowlisted", "block", "allowlisted", blocking, "allowlist"},
		{"released", "block", "released", blocking, "allowlist"},
		{"shared address", "block", "net_class", blocking, "shared_address"},
		{"no learning for limits", "block", "net_class", reasonCtx{learning: func(time.Time) bool { return true }}, "shared_address"},
	}
	for _, c := range rl {
		if got := rateLimitWouldReason(c.mode, c.reason, c.rc); got != c.want {
			t.Errorf("rate limit %s: %q want %q", c.name, got, c.want)
		}
	}
}

// TestCounters24hCoverage: Overview.counters_24h.partial and .since.
func TestCounters24hCoverage(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name              string
		started, lastDrop time.Time
		partial           bool
		since             string
	}{
		{"running for days", now.Add(-72 * time.Hour), time.Time{}, false, ""},
		{"started inside the window", now.Add(-3 * time.Hour), time.Time{}, true, "2026-10-29T09:00:00Z"},
		{"events dropped inside the window", now.Add(-72 * time.Hour), now.Add(-time.Hour), true, ""},
		{"events dropped before the window", now.Add(-72 * time.Hour), now.Add(-25 * time.Hour), false, ""},
		{"unknown start", time.Time{}, time.Time{}, false, ""},
	}
	for _, c := range cases {
		p, s := counters24hCoverage(now, c.started, c.lastDrop)
		if p != c.partial || s != c.since {
			t.Errorf("%s: %v %q want %v %q", c.name, p, s, c.partial, c.since)
		}
	}
}

// TestAlertOfReason: alertOf sets the reason exactly on would_block and
// would_rate_limit alerts.
func TestAlertOfReason(t *testing.T) {
	rc := reasonCtx{learning: func(time.Time) bool { return false }}
	t0 := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		typ, outcome, body string
		wantOutcome        string
		want               string
	}{
		{events.RequestEvaluated, "would_block", `{"data":{"would_block_reason":"allowlist"}}`, "would_block", "allowlist"},
		{events.RequestEvaluated, "would_block", `{"data":{"would_block_reason":"bogus"}}`, "would_block", ""},
		{events.RequestBlocked, "blocked", `{"data":{"would_block_reason":"allowlist"}}`, "blocked", ""},
		{events.BehaviourTriggered, "", `{"data":{"scenario":"scan_404","mode":"observe","action":"observe","would_action":"block"}}`, "would_block", "scenario_observe"},
		{events.BehaviourTriggered, "", `{"data":{"scenario":"scan_404","mode":"block","action":"block","would_action":"block"}}`, "blocked", ""},
		{events.RateLimitExceeded, "", `{"data":{"mode":"block","action":"observe","reason":"net_class"}}`, "would_rate_limit", "shared_address"},
		{events.RateLimitExceeded, "", `{"data":{"mode":"block","action":"block"}}`, "rate_limited", ""},
	}
	for _, c := range cases {
		e := &store.EventRow{ID: "e", Time: t0, Type: c.typ, Outcome: c.outcome, Rules: []string{"941100"}, Body: json.RawMessage(c.body)}
		var b alertBody
		if err := json.Unmarshal(e.Body, &b); err != nil {
			t.Fatal(err)
		}
		it, ok := alertOf(e, &b, rc)
		if !ok || it.Outcome != c.wantOutcome || it.WouldBlockReason != c.want {
			t.Errorf("%s %s: %v %q/%q want %q/%q", c.typ, c.body, ok, it.Outcome, it.WouldBlockReason, c.wantOutcome, c.want)
		}
	}
}
