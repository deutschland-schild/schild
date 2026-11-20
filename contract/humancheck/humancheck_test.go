package humancheck

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestDecideTriggersAndBypasses(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	until := now.Add(2 * time.Hour).Format(time.RFC3339)

	cases := []struct {
		name   string
		in     Input
		answer string
		reason string
	}{
		{
			name:   "off passes",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeOff}, Method: "GET", Path: "/", Accept: "text/html", Clearance: ClearanceNone, Now: now},
			answer: AnswerPass, reason: ReasonOff,
		},
		{
			name:   "post never challenged",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeAlways}, Method: "POST", Path: "/login", Accept: "text/html", Clearance: ClearanceNone, Now: now},
			answer: AnswerPass, reason: ReasonNotNavigation,
		},
		{
			name:   "json api never challenged",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeAlways}, Method: "GET", Path: "/api/items", Accept: "application/json", Clearance: ClearanceNone, Now: now},
			answer: AnswerPass, reason: ReasonNotNavigation,
		},
		{
			name:   "well-known bypassed",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeAlways}, Method: "GET", Path: "/.well-known/acme-challenge/abc", Accept: "text/html", Clearance: ClearanceNone, Now: now},
			answer: AnswerPass, reason: ReasonBypassPath,
		},
		{
			name:   "good bot bypassed",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeAlways}, Method: "GET", Path: "/", Accept: "text/html", GoodBot: true, Clearance: ClearanceNone, Now: now},
			answer: AnswerPass, reason: ReasonGoodBot,
		},
		{
			name:   "allowlisted bypassed",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeAlways}, Method: "GET", Path: "/", Accept: "text/html", Allowlisted: true, Clearance: ClearanceNone, Now: now},
			answer: AnswerPass, reason: ReasonAllowlisted,
		},
		{
			name:   "excluded path bypassed",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeAlways, Except: []string{"/healthz", "/webhook/*"}}, Method: "GET", Path: "/webhook/stripe", Accept: "text/html", Clearance: ClearanceNone, Now: now},
			answer: AnswerPass, reason: ReasonExcludedPath,
		},
		{
			name:   "pow clearance passes",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeAlways}, Method: "GET", Path: "/", Accept: "text/html", Clearance: ClearancePoW, Now: now},
			answer: AnswerPass, reason: ReasonClearanceValid,
		},
		{
			name:   "nojs clearance passes",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeAlways}, Method: "GET", Path: "/", Accept: "text/html", Clearance: ClearanceNoJS, Now: now},
			answer: AnswerPass, reason: ReasonClearanceValid,
		},
		{
			name:   "always challenges navigation",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeAlways}, Method: "GET", Path: "/blog", SecFetchMode: "navigate", Clearance: ClearanceNone, Now: now},
			answer: AnswerChallenge, reason: ReasonAlways,
		},
		{
			name:   "under attack admin challenges login",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeOff, UnderAttack: UnderAttack{Scope: UnderAttackAdmin, Until: until}}, Method: "GET", Path: "/wp-login.php", Accept: "text/html", Clearance: ClearanceNone, Now: now},
			answer: AnswerChallenge, reason: ReasonUnderAttack,
		},
		{
			name:   "under attack admin passes home",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeOff, UnderAttack: UnderAttack{Scope: UnderAttackAdmin, Until: until}}, Method: "GET", Path: "/", Accept: "text/html", Clearance: ClearanceNone, Now: now},
			answer: AnswerPass, reason: ReasonNoTrigger,
		},
		{
			name:   "under attack all challenges home",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeOff, UnderAttack: UnderAttack{Scope: UnderAttackAll, Until: until}}, Method: "GET", Path: "/", Accept: "text/html", Clearance: ClearanceNone, Now: now},
			answer: AnswerChallenge, reason: ReasonUnderAttack,
		},
		{
			name:   "expired under attack passes",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeOff, UnderAttack: UnderAttack{Scope: UnderAttackAll, Until: now.Add(-time.Minute).Format(time.RFC3339)}}, Method: "GET", Path: "/", Accept: "text/html", Clearance: ClearanceNone, Now: now},
			answer: AnswerPass, reason: ReasonOff,
		},
		{
			name:   "findings shared scenario hit challenges",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeFindings}, Method: "GET", Path: "/", Accept: "text/html", SharedScenarioHit: true, Clearance: ClearanceNone, Now: now},
			answer: AnswerChallenge, reason: ReasonSharedScenario,
		},
		{
			name:   "findings aggressive crawl hit challenges",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeFindings}, Method: "GET", Path: "/", Accept: "text/html", AggressiveCrawlHit: true, Clearance: ClearanceNone, Now: now},
			answer: AnswerChallenge, reason: ReasonAggressiveCrawl,
		},
		{
			name:   "distributed wave challenges even when mode off",
			in:     Input{Policy: Policy{Website: "example.org", Mode: ModeOff}, Method: "GET", Path: "/", Accept: "text/html", DistributedWave: true, Clearance: ClearanceNone, Now: now},
			answer: AnswerChallenge, reason: ReasonDistributedWave,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(tc.in)
			if got.Answer != tc.answer || got.Reason != tc.reason {
				t.Fatalf("Decide() = %+v, want answer=%s reason=%s", got, tc.answer, tc.reason)
			}
			wantStatus := 0
			if tc.answer == AnswerChallenge {
				wantStatus = StatusChallenge
			}
			if got.Status != wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, wantStatus)
			}
		})
	}
}

func TestChallengeAndClearanceTokens(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 15, 0, time.UTC)
	k1 := []byte("0123456789abcdef0123456789abcdef")
	k2 := []byte("fedcba9876543210fedcba9876543210")
	host := "example.org"
	prefix := IPPrefix(netip.MustParseAddr("203.0.113.42"))
	if prefix != "203.0.113.0/24" {
		t.Fatalf("IPPrefix v4 = %q", prefix)
	}
	if p6 := IPPrefix(netip.MustParseAddr("2001:db8:1234:5678::1")); p6 != "2001:db8:1234:5600::/56" {
		t.Fatalf("IPPrefix v6 = %q", p6)
	}
	ua := "Mozilla/5.0 Test"

	tok, payload, err := IssueChallenge(k1, host, prefix, ua, "/shop?item=1", 2000, now)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	// Find PoW solution.
	sol := -1
	for i := 0; i <= payload.Max; i++ {
		if PoWHash(payload.Salt, i) == payload.Challenge {
			sol = i
			break
		}
	}
	if sol < 0 {
		t.Fatal("failed to find PoW solution")
	}

	// Valid with current key or rotated [k2, k1].
	if _, err := VerifyChallenge([][]byte{k2, k1}, tok, host, prefix, ua, sol, true, now.Add(time.Minute)); err != nil {
		t.Fatalf("VerifyChallenge valid: %v", err)
	}
	// Wrong solution rejected when checkPoW=true, accepted when checkPoW=false (nojs continue).
	if _, err := VerifyChallenge([][]byte{k1}, tok, host, prefix, ua, (sol+1)%(payload.Max+1), true, now); err == nil {
		t.Fatal("expected error for wrong PoW solution")
	}
	if _, err := VerifyChallenge([][]byte{k1}, tok, host, prefix, ua, 0, false, now); err != nil {
		t.Fatalf("VerifyChallenge nojs continue: %v", err)
	}
	// Wrong host, IP prefix, UA, or expired must fail.
	if _, err := VerifyChallenge([][]byte{k1}, tok, "other.org", prefix, ua, sol, true, now); err == nil {
		t.Fatal("expected host mismatch")
	}
	if _, err := VerifyChallenge([][]byte{k1}, tok, host, "198.51.100.0/24", ua, sol, true, now); err == nil {
		t.Fatal("expected ip prefix mismatch")
	}
	if _, err := VerifyChallenge([][]byte{k1}, tok, host, prefix, "OtherUA", sol, true, now); err == nil {
		t.Fatal("expected ua mismatch")
	}
	if _, err := VerifyChallenge([][]byte{k1}, tok, host, prefix, ua, sol, true, now.Add(MaxChallengeTTL+time.Second)); err == nil {
		t.Fatal("expected expiry error")
	}

	// Clearance cookie: identifier-free and deterministic within the same minute.
	c1 := ClearanceValue(k1, host, ClearancePoW, prefix, ua, now.Add(30*time.Minute))
	c2 := ClearanceValue(k1, host, ClearancePoW, prefix, ua, now.Add(30*time.Minute+5*time.Second))
	if c1 != c2 {
		t.Fatalf("clearance cookie must be deterministic within the same rounded minute: %q vs %q", c1, c2)
	}
	if got := VerifyClearance([][]byte{k2, k1}, c1, host, prefix, ua, now.Add(10*time.Minute)); got != ClearancePoW {
		t.Fatalf("VerifyClearance = %q, want pow", got)
	}
	if got := VerifyClearance([][]byte{k1}, c1, "other.org", prefix, ua, now); got != ClearanceInvalid {
		t.Fatalf("VerifyClearance wrong host = %q, want invalid", got)
	}
	if got := VerifyClearance([][]byte{k1}, c1, host, prefix, ua, now.Add(31*time.Minute)); got != ClearanceInvalid {
		t.Fatalf("VerifyClearance expired = %q, want invalid", got)
	}
}

func TestPrefixAndSafeReturn(t *testing.T) {
	p := NewPrefix()
	if !ValidPrefix(p) || !strings.HasPrefix(p, "/_s-") {
		t.Fatalf("invalid generated prefix: %q", p)
	}
	if SafeReturnPath("//evil.example") != "/" || SafeReturnPath("/ok/path?a=1") != "/ok/path?a=1" {
		t.Fatal("SafeReturnPath failed")
	}
}
