package waf

import (
	"testing"
)

// net/http keeps a raw '#' in the request target and the proxy forwards what
// follows it, so the rules must see that path and query too: "/a#?q=..." is a
// request with the argument q, not a request for "/a" without arguments.
func TestRawFragmentIsInspected(t *testing.T) {
	inst := crs(t)
	for _, target := range []string{
		"/a#?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
		"/a?x=1#&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
	} {
		r := browserReq("GET", target, "", "")
		a, err := eval(t, inst, r)
		if err != nil {
			t.Fatal(err)
		}
		seen := false
		for _, m := range a.Matches {
			if m.Source == "crs" && m.Location == "ARGS:q" {
				seen = true
			}
		}
		if !seen || !a.CRSBlock {
			t.Errorf("%s (query %q forwarded): no CRS finding in ARGS:q, matched %v", target, r.URL.RawQuery, a.MatchedIDs)
		}
	}
	// A '#' in an ordinary value is an argument character, not a finding.
	a, err := eval(t, inst, browserReq("GET", "/search?q=C#", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if a.CRSBlock {
		t.Errorf("/search?q=C# blocked: %v", a.MatchedIDs)
	}
}
