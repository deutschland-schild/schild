//go:build !release

package dashboard_test

import (
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

func TestTrustedProxiesTooBroad(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: "ingress:\n  trusted_proxies: [\"0.0.0.0/0\"]\n"})
	h.Login()
	ov := decode[dashboard.Overview](t, expect(t, h, "GET", "/overview", nil, 200, "Overview"))
	var found bool
	for _, r := range ov.Baseline.Reasons {
		found = found || r.Code == "trusted_proxies_too_broad"
	}
	if !found {
		t.Fatalf("reasons: %+v", ov.Baseline.Reasons)
	}
	if got := h.App.Gate.Settings().Resolver.TooBroad(); len(got) != 1 {
		t.Fatalf("too broad: %v", got)
	}
}

// TestNoNetworkAPI (D72): the gateway API has no network pages, fields or
// settings; local decisions and rules work.
func TestNoNetworkAPI(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	if r := h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "203.0.113.5", "", ""); r.StatusCode != 403 {
		t.Fatalf("xss: %d", r.StatusCode)
	}
	h.Flush()
	b := expect(t, h, "GET", "/overview", nil, 200, "Overview")
	for _, k := range []string{`"network"`, `"labs"`, `"relays"`, `"independent_operators"`, `"bundle_version"`, `"signals_sent"`, `"review_pending"`} {
		if strings.Contains(string(b), k) {
			t.Fatalf("overview has %s: %s", k, b)
		}
	}
	ov := decode[dashboard.Overview](t, b)
	if ov.Baseline.State == "off" || ov.Counters24h.Blocked != 1 {
		t.Fatalf("baseline %s, counters %+v", ov.Baseline.State, ov.Counters24h)
	}
	// Just started: the counters count since the start (D36 open items).
	if !ov.Counters24h.Partial || ov.Counters24h.Since == "" {
		t.Fatalf("counters of a fresh start: %+v", ov.Counters24h)
	}
	rp := decode[dashboard.RulePage](t, expect(t, h, "GET", "/rules", nil, 200, "RulePage"))
	if len(rp.Items) == 0 {
		t.Fatalf("rules: %+v", rp)
	}
	expect(t, h, "GET", "/rules?repository=network", nil, 400, "Problem")
	for _, path := range []string{"/rules/bundle", "/signals", "/review"} {
		if code, b := h.API("GET", path, nil); code == 200 {
			t.Fatalf("%s still answers: %s", path, b)
		}
	}
	if code, b := h.API("POST", "/review/rec-1/approve", map[string]any{"action": "block"}); code == 200 {
		t.Fatalf("approve still answers: %s", b)
	}
	expect(t, h, "POST", "/rules/net-1/suspend", map[string]any{"note": "x"}, 404, "Problem")
	expect(t, h, "GET", "/rule-repositories/network", nil, 404, "Problem")
	for _, patch := range []map[string]any{
		{"signals": map[string]any{"enabled": true}},
		{"remote_rules": map[string]any{"enabled": true}},
		{"min_independent_operators": 3},
		{"labs": []any{map[string]any{"id": "lab-a", "weight": 1}}},
	} {
		if code, b := h.API("PATCH", "/settings", patch); code != 400 {
			t.Fatalf("%v: %d %s", patch, code, b)
		}
	}
	// D89: there is no mode to set.
	expect(t, h, "PATCH", "/settings", map[string]any{"mode": "observe"}, 400, "Problem")
}

// D91: a proxy in front that is not trusted is named in the overview, not
// left to show every visitor as the proxy.
func TestTrustedProxiesMissing(t *testing.T) {
	// The harness sends from 127.0.0.1 with X-Forwarded-For; the list trusts
	// another range only.
	h := apptest.New(t, apptest.Options{Extra: "ingress:\n  trusted_proxies: [\"10.66.0.0/24\"]\n"})
	h.Login()
	has := func() bool {
		ov := decode[dashboard.Overview](t, expect(t, h, "GET", "/overview", nil, 200, "Overview"))
		for _, r := range ov.Baseline.Reasons {
			if r.Code == "trusted_proxies_missing" {
				return true
			}
		}
		return false
	}
	if has() {
		t.Fatal("named before any request")
	}
	for range 20 {
		h.Visit("GET", "/", "203.0.113.9", "", "")
	}
	if !has() {
		t.Fatal("20 requests from an untrusted proxy are not named")
	}
}
