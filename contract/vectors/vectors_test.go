//go:build !release

package vectors

import (
	"strings"
	"testing"
)

// Every golden vector must give the expected verdict in Go. The Go/Python
// comparison runs in `make contracts-test`.
func TestGoldenVectors(t *testing.T) {
	r, err := NewRunner("../../contracts/testkeys/keys.json")
	if err != nil {
		t.Skipf("contracts/ not present: %v", err)
	}
	verdicts, vecs, err := r.RunAll("../../contracts/vectors")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string][2]int{}
	for i, v := range verdicts {
		if !v.Matches(vecs[i].Expect) {
			t.Errorf("%s: expected %+v, got valid=%v error=%q (%s)", v.File, vecs[i].Expect, v.Valid, v.Error, v.Detail)
		}
		c := counts[vecs[i].Contract]
		if vecs[i].Expect.Valid {
			c[0]++
		} else {
			c[1]++
		}
		counts[vecs[i].Contract] = c
		if vecs[i].Expect.Valid == (vecs[i].Expect.Error != "") {
			t.Errorf("%s: inconsistent expectation", v.File)
		}
		// v0.5: exactly the valid classifier vectors expect a result.
		// D36: also website-derive and website-status.
		classifier := vecs[i].Contract == "bot-match" || vecs[i].Contract == "geo-map" || strings.HasPrefix(vecs[i].Contract, "website-") || vecs[i].Contract == "waiting-page" || vecs[i].Contract == "storage-bounds" || vecs[i].Contract == "ingress-order" || vecs[i].Contract == "request-recheck" || vecs[i].Contract == "crowdsec-hub" || vecs[i].Contract == "rule-effect" || vecs[i].Contract == "body-limits" || vecs[i].Contract == "agent-block" || vecs[i].Contract == "access-gate" || vecs[i].Contract == "crawler-policy" || vecs[i].Contract == "human-check" || vecs[i].Contract == "cluster-record" || vecs[i].Contract == "audit"
		if (len(vecs[i].Expect.Result) > 0) != (classifier && vecs[i].Expect.Valid) {
			t.Errorf("%s: result expected exactly for valid classifier vectors", v.File)
		}
		if !strings.HasPrefix(v.File, strings.ReplaceAll(vecs[i].Contract, "/", "-")+"/") {
			t.Errorf("%s: stored under the wrong contract", v.File)
		}
	}
	want := []string{"envelope", "signal", "feedback", "ack", "submission", "checkpoint", "rule-bundle", "withdrawal", "stream", "events", "config/schild", "config/lab", "results", "seclang", "log-tree", "peer-request",
		"bot-catalogue", "bot-match", "geo-map", // v0.5 (MVP-22)
		"website-derive", "website-status", "website-exception", // v0.5 (D36)
		"website-visitor", // D36 amendment 2026-10-29
		"waiting-page",    // D37 (MVP-23 step 1)
		"storage-bounds",  // D38
		"ingress-order",   // D31 amendment 2026-10-29
		"request-recheck", // D33 amendment 2026-10-29
		"body-limits",     // D41
		"agent-block",     // D42
		"access-gate",     // D56
		"crawler-policy",  // D57
		"human-check",     // MVP-12 v1_cut
		"audit",           // draft, MVP-36
		"rule-effect"}     // D73
	for _, c := range want {
		if counts[c][0] < 5 || counts[c][1] < 10 {
			t.Errorf("%s: %d valid / %d invalid vectors, need >= 5 / >= 10", c, counts[c][0], counts[c][1])
		}
	}
}
