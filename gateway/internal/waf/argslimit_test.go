package waf

import (
	"fmt"
	"strings"
	"testing"
)

// jsonArray returns a JSON array of n numbers whose last element is a SQL
// injection string.
func jsonArray(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprint(i)
	}
	parts[n-1] = `"1' UNION SELECT password FROM users--"`
	return "[" + strings.Join(parts, ",") + "]"
}

// Coraza >= 3.8 drops arguments beyond SecArgumentsLimit from urlencoded and
// JSON bodies and only sets ARGUMENTS_LIMIT_REACHED. Without rules 200004 and
// 200005 the tail of a long JSON array was never inspected (bypass found
// during the Coraza 3.3.3 -> 3.8.1 upgrade, D24).
func TestArgumentsLimitReached(t *testing.T) {
	inst := crs(t)
	a, err := eval(t, inst, browserReq("POST", "/api/items", "application/json", jsonArray(DefaultLimits.Args)))
	if err != nil {
		t.Fatal(err)
	}
	if a.ArgsLimit || !a.CRSBlock {
		t.Fatalf("array at the limit: ArgsLimit=%v CRSBlock=%v ids=%v, want the tail inspected", a.ArgsLimit, a.CRSBlock, a.MatchedIDs)
	}
	a, err = eval(t, inst, browserReq("POST", "/api/items", "application/json", jsonArray(DefaultLimits.Args+1)))
	if err != nil {
		t.Fatal(err)
	}
	if !a.ArgsLimit {
		t.Fatalf("array over the limit: ArgsLimit not set (ids %v, anomaly %d): tail would pass uninspected", a.MatchedIDs, a.CRSAnomaly)
	}
	for _, m := range a.Matches {
		if m.ID == InternalArgsLimitPost && m.Source != "internal" {
			t.Fatalf("200005 source %q", m.Source)
		}
	}
	for _, id := range a.MatchedIDs {
		if id >= 200000 && id <= 200009 {
			t.Fatalf("internal id %d listed in MatchedIDs", id)
		}
	}
}

// Phase 1: the gate's Precheck rejects long query strings first; this
// checks that Coraza's own flag is wired as well (defence in depth).
func TestArgumentsLimitQuery(t *testing.T) {
	inst := crs(t)
	q := strings.Repeat("a=1&", DefaultLimits.Args) + "b=2"
	r := browserReq("GET", "/search?"+q, "", "")
	tx := inst.WAF.NewTransaction()
	defer tx.Close()
	ProcessHeaders(tx, r, "203.0.113.7", 40000)
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	if a := inst.Analyze(tx.MatchedRules()); !a.ArgsLimit {
		t.Fatalf("query over the limit: ArgsLimit not set (ids %v)", a.MatchedIDs)
	}
}

// Engine.Swap closes the previous instance (Coraza pattern cache); requests
// that still hold it must keep working.
func TestSwapClosesPreviousButKeepsItUsable(t *testing.T) {
	var e Engine
	a, err := Build(Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err != nil {
		t.Fatal(err)
	}
	e.Swap(a)
	if old := e.Swap(b); old != a {
		t.Fatal("Swap must return the previous instance")
	}
	r := browserReq("GET", "/?id=1%27%20OR%20%271%27%3D%271%27--", "", "")
	an, err := eval(t, a, r)
	if err != nil {
		t.Fatal(err)
	}
	if !an.CRSBlock {
		t.Fatalf("closed instance no longer detects (ids %v)", an.MatchedIDs)
	}
	a.Close() // idempotent
}
