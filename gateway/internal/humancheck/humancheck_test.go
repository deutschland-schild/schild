package humancheck

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	hc "github.com/deutschland-schild/schild/contract/humancheck"
)

func TestInterstitialAndVerifyFlow(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	g := New()
	st := g.State().Clone()
	st.Entries["example.org"] = &Entry{
		Policy: hc.Policy{Website: "example.org", Mode: hc.ModeAlways, Difficulty: 2000, ClearanceTTLS: 1800},
	}
	g.Store(st)

	ip := netip.MustParseAddr("203.0.113.10")
	req := httptest.NewRequest(http.MethodGet, "https://example.org/artikel?page=2", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "Mozilla/5.0 TestBrowser")

	v, ok := g.Check(req, "example.org", ip, RequestSignals{}, now)
	if !ok || v.Result.Answer != hc.AnswerChallenge {
		t.Fatalf("Check = (%+v, %v), want challenge", v, ok)
	}

	rec := httptest.NewRecorder()
	if !g.ServeInterstitial(rec, req, v, "example.org", now) {
		t.Fatal("ServeInterstitial returned false")
	}
	if rec.Code != hc.StatusChallenge {
		t.Fatalf("status = %d, want %d", rec.Code, hc.StatusChallenge)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("X-Robots-Tag"); got != "noindex" {
		t.Fatalf("X-Robots-Tag = %q", got)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, ScriptCSPHash()) {
		t.Fatalf("CSP missing pinned script hash: %q", csp)
	}

	body := rec.Body.String()
	salt := extractAttr(t, body, `data-salt="([^"]+)"`)
	chal := extractAttr(t, body, `data-challenge="([^"]+)"`)
	tok := extractAttr(t, body, `name="token" value="([^"]+)"`)

	sol := -1
	for i := 0; i <= 2000; i++ {
		if hc.PoWHash(salt, i) == chal {
			sol = i
			break
		}
	}
	if sol < 0 {
		t.Fatal("could not solve PoW")
	}

	// Submit valid PoW to {prefix}verify.
	verifyPath := st.Prefix + "verify"
	if act, isEp := g.IsEndpoint(verifyPath); !isEp || act != "verify" {
		t.Fatalf("IsEndpoint(%q) = (%q, %v)", verifyPath, act, isEp)
	}
	form := url.Values{"token": {tok}, "number": {strconv.Itoa(sol)}}.Encode()
	vReq := httptest.NewRequest(http.MethodPost, "https://example.org"+verifyPath, strings.NewReader(form))
	vReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vReq.Header.Set("User-Agent", "Mozilla/5.0 TestBrowser")
	vRec := httptest.NewRecorder()
	code := g.HandleEndpoint(vRec, vReq, "example.org", ip, "verify", now.Add(time.Second))
	if code != http.StatusSeeOther {
		t.Fatalf("verify status = %d, want 303", code)
	}
	if loc := vRec.Header().Get("Location"); loc != "/artikel?page=2" {
		t.Fatalf("redirect = %q, want /artikel?page=2", loc)
	}
	cookies := vRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != hc.CookieName || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("unexpected cookies: %+v", cookies)
	}

	// Replay of the same token must be rejected.
	rReq := httptest.NewRequest(http.MethodPost, "https://example.org"+verifyPath, strings.NewReader(form))
	rReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rReq.Header.Set("User-Agent", "Mozilla/5.0 TestBrowser")
	if code := g.HandleEndpoint(httptest.NewRecorder(), rReq, "example.org", ip, "verify", now.Add(2*time.Second)); code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400", code)
	}

	// Subsequent request with the clearance cookie passes and strips the cookie.
	nextReq := httptest.NewRequest(http.MethodGet, "https://example.org/artikel?page=2", nil)
	nextReq.Header.Set("Accept", "text/html")
	nextReq.Header.Set("User-Agent", "Mozilla/5.0 TestBrowser")
	nextReq.AddCookie(cookies[0])
	nextReq.AddCookie(&http.Cookie{Name: "app_session", Value: "keep"})

	v2, ok := g.Check(nextReq, "example.org", ip, RequestSignals{}, now.Add(5*time.Second))
	if !ok || v2.Result.Answer != hc.AnswerPass || v2.Result.Reason != hc.ReasonClearanceValid {
		t.Fatalf("second Check = (%+v, %v), want pass/clearance_valid", v2, ok)
	}
	StripCookie(nextReq)
	if _, err := nextReq.Cookie(hc.CookieName); err == nil {
		t.Fatal("clearance cookie was not stripped")
	}
	if c, err := nextReq.Cookie("app_session"); err != nil || c.Value != "keep" {
		t.Fatal("app cookie was unexpectedly modified")
	}

	counts := g.Counts()
	if counts.Served != 1 || counts.Passed != 1 || counts.Invalid != 1 {
		t.Fatalf("unexpected counts: %+v", counts)
	}
}

func TestNoJSContinueFlow(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	g := New()
	st := g.State().Clone()
	st.Entries["example.org"] = &Entry{Policy: hc.Policy{Website: "example.org", Mode: hc.ModeAlways}}
	g.Store(st)

	ip := netip.MustParseAddr("203.0.113.10")
	req := httptest.NewRequest(http.MethodGet, "https://example.org/kontakt", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "Lynx/2.9")
	v, _ := g.Check(req, "example.org", ip, RequestSignals{}, now)
	rec := httptest.NewRecorder()
	g.ServeInterstitial(rec, req, v, "example.org", now)
	tok := extractAttr(t, rec.Body.String(), `name="token" value="([^"]+)"`)

	form := url.Values{"token": {tok}}.Encode()
	cReq := httptest.NewRequest(http.MethodPost, "https://example.org"+st.Prefix+"continue", strings.NewReader(form))
	cReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cReq.Header.Set("User-Agent", "Lynx/2.9")
	cRec := httptest.NewRecorder()
	if code := g.HandleEndpoint(cRec, cReq, "example.org", ip, "continue", now.Add(time.Second)); code != http.StatusSeeOther {
		t.Fatalf("continue status = %d, want 303", code)
	}
	if g.Counts().NoJS != 1 {
		t.Fatalf("expected NoJS count 1, got %+v", g.Counts())
	}
}

func extractAttr(t *testing.T, s, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if len(m) < 2 {
		t.Fatalf("pattern %q not found in body", pattern)
	}
	return m[1]
}
