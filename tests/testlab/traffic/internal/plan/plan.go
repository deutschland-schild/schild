// Package plan assembles a deterministic, ordered traffic plan for a scenario.
// A plan is pure data: generating it touches no network, so make traffic can
// print and compare labelled request counts (the MVP-06 kill criterion: two
// runs with the same seed must produce the same labelled counts) before any
// request is sent.
package plan

import (
	"fmt"
	"math/rand"
	"sort"

	"github.com/deutschland-schild/schild/testlab/internal/label"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/attacks"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/corpus"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/legit"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/req"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/sources"
)

// Scenarios lists the supported scenario ids.
var Scenarios = []string{"T01", "T02", "T03", "T04", "T05"}

// Plan is the output: an ordered request list plus the canary markers planted
// in it (for the egress check).
type Plan struct {
	Scenario string        `json:"scenario"`
	Seed     int64         `json:"seed"`
	Requests []req.Request `json:"requests"`
	Canaries []string      `json:"canaries"`
}

// Options control plan size and the source ranges (per profile).
type Options struct {
	N        int     // total requests (0 -> scenario default)
	V4Base   [3]byte // inet /22 base, e.g. sources.T1Inet
	V6Prefix string  // inet /80 prefix, e.g. sources.T1Inet6
}

// defaultOptions fills unset fields with the t0 ranges.
func (o Options) withDefaults(scenario string) Options {
	if o.N == 0 {
		o.N = defaultN(scenario)
	}
	if o.V4Base == [3]byte{} {
		o.V4Base = sources.T0Inet
	}
	if o.V6Prefix == "" {
		o.V6Prefix = sources.T0Inet6
	}
	return o
}

func defaultN(scenario string) int {
	switch scenario {
	case "T01":
		return 200
	case "T02":
		return 100
	case "T03":
		return 60
	case "T04":
		return 240
	case "T05":
		return 40
	}
	return 100
}

// Build returns the plan for scenario. siteNames are the logical site names to
// spread traffic over (e.g. "wp", "dvwa", "juice", "api").
func Build(scenario string, seed int64, siteNames []string, opt Options) (Plan, error) {
	valid := false
	for _, s := range Scenarios {
		if s == scenario {
			valid = true
		}
	}
	if !valid {
		return Plan{}, fmt.Errorf("plan: unknown scenario %q (have %v)", scenario, Scenarios)
	}
	if len(siteNames) == 0 {
		return Plan{}, fmt.Errorf("plan: no sites")
	}
	opt = opt.withDefaults(scenario)
	p := Plan{Scenario: scenario, Seed: seed}

	switch scenario {
	case "T01":
		p.Requests, p.Canaries = legit.Generate(seed, scenario, siteNames, opt.N)
		assignLegitSources(seed, p.Requests, opt)
	case "T02":
		atk := attacks.Web(seed, scenario, siteNames, opt.N*7/10)
		lg, can := legit.Generate(seed+1, scenario, siteNames, opt.N-len(atk))
		p.Requests = append(atk, lg...)
		p.Canaries = can
		assignLegitSources(seed, p.Requests, opt)
	case "T03":
		p.Requests = attacks.CredentialStuffing(seed, scenario, siteNames, opt.N)
		assignBotnetSources(seed, p.Requests, opt, 12)
	case "T04":
		p.Requests = botnet(seed, scenario, siteNames, opt)
	case "T05":
		p.Requests = corpus.Generate(seed, scenario, siteNames, opt.N)
		assignLegitSources(seed, p.Requests, opt)
	}
	// Re-number seq across the merged plan so every request has a unique seq.
	for i := range p.Requests {
		p.Requests[i].Label.Seq = i
	}
	return p, nil
}

// botnet is a loud + low-and-slow mix from many sources across all sites.
func botnet(seed int64, scenario string, sites []string, opt Options) []req.Request {
	rng := rand.New(rand.NewSource(seed))
	pool := sources.Pool(seed, opt.N/2, opt.V4Base, opt.V6Prefix)
	out := make([]req.Request, 0, opt.N)
	for i := 0; i < opt.N; i++ {
		site := sites[rng.Intn(len(sites))]
		src := pool[rng.Intn(len(pool))]
		tech := "flood"
		hdrs := map[string]string{"User-Agent": "botnet/1.0"}
		if i%3 == 0 { // low-and-slow wave
			tech = "low_and_slow"
			hdrs["X-Test-Slow"] = "throttle"
		}
		out = append(out, req.Request{Method: "GET", Site: site, Path: "/", SrcIP: src,
			Headers: hdrs,
			Label: label.Label{Class: label.Malicious, Scenario: scenario, Source: "botnet",
				Technique: tech, ExpectBlock: true, Seq: i}})
	}
	return out
}

// assignLegitSources gives legit requests a small, stable set of client IPs.
func assignLegitSources(seed int64, reqs []req.Request, opt Options) {
	pool := sources.Pool(seed+100, 20, opt.V4Base, opt.V6Prefix)
	for i := range reqs {
		if reqs[i].SrcIP == "" {
			reqs[i].SrcIP = pool[i%len(pool)]
		}
	}
}

func assignBotnetSources(seed int64, reqs []req.Request, opt Options, poolSize int) {
	pool := sources.Pool(seed+200, poolSize, opt.V4Base, opt.V6Prefix)
	for i := range reqs {
		reqs[i].SrcIP = pool[i%len(pool)]
	}
}

// Counts returns the number of requests per class, for the reproducibility
// check and for logging.
func (p Plan) Counts() map[label.Class]int {
	m := map[label.Class]int{}
	for _, r := range p.Requests {
		m[r.Label.Class]++
	}
	return m
}

// CountsString renders Counts deterministically (sorted by class).
func (p Plan) CountsString() string {
	m := p.Counts()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	s := ""
	for _, k := range keys {
		s += fmt.Sprintf("%s=%d ", k, m[label.Class(k)])
	}
	return s
}
