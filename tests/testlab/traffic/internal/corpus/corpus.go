// Package corpus generates the K3 resilience corpus: oversized bodies, deeply
// nested JSON, catastrophic-backtracking (ReDoS) strings and slow / low-and-
// slow markers. These probe whether the WAF stays responsive and fails safely;
// they are labelled malicious (the WAF should reject or safely bound them) and
// must never hang the pipeline. All generation is deterministic in the seed.
package corpus

import (
	"math/rand"
	"strings"

	"github.com/deutschland-schild/schild/testlab/internal/label"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/req"
)

// Generate returns n K3 requests against the given sites.
func Generate(seed int64, scenario string, sites []string, n int) []req.Request {
	if len(sites) == 0 {
		return nil
	}
	rng := rand.New(rand.NewSource(seed))
	kinds := []string{"oversized", "nested_json", "redos", "slow"}
	var out []req.Request
	for i := 0; i < n; i++ {
		site := sites[rng.Intn(len(sites))]
		kind := kinds[i%len(kinds)]
		r := req.Request{Site: site, Method: "POST", Path: "/api/items",
			Headers: map[string]string{"Content-Type": "application/json"},
			Label: label.Label{Class: label.Malicious, Scenario: scenario,
				Source: "k3-corpus", Technique: kind, ExpectBlock: true, Seq: i}}
		switch kind {
		case "oversized":
			// A large but bounded body (64 KiB) so the test itself stays cheap.
			r.Body = []byte(`{"name":"` + strings.Repeat("A", 64*1024) + `"}`)
		case "nested_json":
			depth := 200
			r.Body = []byte(strings.Repeat(`{"a":`, depth) + "1" + strings.Repeat("}", depth))
		case "redos":
			// Classic catastrophic-backtracking input; sent as a query value.
			r.Method = "GET"
			r.Path = "/search"
			r.Query = "q=" + strings.Repeat("a", 60) + "!"
			r.Body = nil
			r.Headers = nil
		case "slow":
			// Marker for the runner to send with delayed/byte-by-byte writes.
			r.Headers["X-Test-Slow"] = "byte-by-byte"
			r.Body = []byte(`{"name":"slowloris"}`)
		}
		out = append(out, r)
	}
	return out
}
