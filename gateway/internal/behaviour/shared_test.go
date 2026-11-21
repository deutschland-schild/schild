package behaviour

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
)

// group is n engines that tell each other their counts, as the nodes of a
// group do once a second. One clock for all.
type group struct {
	t    *testing.T
	engs []*Engine
	recs []*rec
	c    *clock
}

func newGroup(t *testing.T, n int, b config.Behaviour) *group {
	g := &group{t: t}
	for i := 0; i < n; i++ {
		e, r, c := newEngine(b)
		if g.c == nil {
			g.c = c
		} else {
			e.Now = g.c.now
		}
		e.EnableSharing()
		g.engs, g.recs = append(g.engs, e), append(g.recs, r)
	}
	return g
}

// tell passes what every engine counted to all others, through JSON as on
// the wire.
func (g *group) tell() {
	g.t.Helper()
	for i, e := range g.engs {
		c := e.TakeCounts()
		if c == nil {
			continue
		}
		raw, err := json.Marshal(c)
		if err != nil {
			g.t.Fatal(err)
		}
		for j, other := range g.engs {
			if j == i {
				continue
			}
			var got Counts
			if err := json.Unmarshal(raw, &got); err != nil {
				g.t.Fatal(err)
			}
			other.ApplyCounts(&got)
		}
	}
}

func (g *group) triggered(scenario string) (hits []events.BehaviourTriggeredData) {
	for _, r := range g.recs {
		for _, h := range r.triggered() {
			if h.Scenario == scenario {
				hits = append(hits, h)
			}
		}
	}
	return hits
}

// A limit of 30 a minute, a client that spreads its requests over ten nodes
// one a second: a single node would let 30 pass, ten nodes that do not talk
// 300. Telling once a second, the group lets pass the limit and what ten
// nodes take in one second.
func TestGroupLimitCountsForTheGroup(t *testing.T) {
	b := modes(nil)
	b.RateLimits = []config.RateLimit{{ID: "api", Route: "/api/**", Limit: 30, Per: "1m", Burst: 30, Mode: config.BehaviourBlock}}
	const nodes = 10
	passed := func(talk bool) int {
		g := newGroup(t, nodes, b)
		n := 0
		// 10 requests a second for a minute, round robin.
		for i := 0; i < 600; i++ {
			if v := g.engs[i%nodes].Check(req(g.c, "203.0.113.5", "residential", "GET", "/api/items")); !v.RateLimited {
				n++
			}
			g.c.add(100 * time.Millisecond)
			if talk && i%10 == 9 {
				g.tell()
			}
		}
		return n
	}
	alone := passed(false)
	if alone < 300 {
		t.Fatalf("ten nodes that do not talk let %d pass; the test needs them to let ten times the limit", alone)
	}
	// One minute refills the bucket once more: 30 at the start, 30 over the minute.
	got := passed(true)
	if limit := 30 + 30 + nodes; got > limit {
		t.Errorf("the group let %d requests pass in a minute, want at most %d (the limit, its refill and one second of ten nodes)", got, limit)
	}
	if got < 30 {
		t.Errorf("the group let only %d pass: it must not be stricter than the limit", got)
	}
	// Another client is not touched by the counts of the first.
	g := newGroup(t, 2, b)
	for i := 0; i < 30; i++ {
		g.engs[0].Check(req(g.c, "203.0.113.5", "residential", "GET", "/api/items"))
	}
	g.tell()
	if v := g.engs[1].Check(req(g.c, "203.0.113.6", "residential", "GET", "/api/items")); v.RateLimited {
		t.Error("the counts of one client limited another")
	}
	if v := g.engs[1].Check(req(g.c, "203.0.113.5", "residential", "GET", "/api/items")); !v.RateLimited {
		t.Error("the second node lets the client pass that used its limit on the first")
	}
}

// Failed logins spread over the nodes: no node sees enough alone.
func TestGroupLoginBruteforceCountsForTheGroup(t *testing.T) {
	th := Effective(config.ScenarioLoginBruteforce, config.Thresholds{})
	const nodes = 5
	run := func(talk bool) int {
		g := newGroup(t, nodes, modes(nil))
		for i := 0; i < th.Count+nodes; i++ {
			e := g.engs[i%nodes]
			failLogin(e, g.c, "198.51.100.40", "hosting")
			g.c.add(200 * time.Millisecond)
			if talk {
				g.tell()
			}
		}
		return len(g.triggered(config.ScenarioLoginBruteforce))
	}
	if n := run(false); n != 0 {
		t.Fatalf("nodes that do not talk fired %d times; the test needs each to stay below the threshold of %d", n, th.Count)
	}
	if n := run(true); n == 0 {
		t.Errorf("%d failed logins over %d nodes did not fire login_bruteforce (threshold %d)", th.Count+nodes, nodes, th.Count)
	}
}

// Ten user names, each tried on another node: the sketch of the client is
// the union, under the one hash of the group.
func TestGroupCredentialStuffingCountsForTheGroup(t *testing.T) {
	const nodes = 5
	run := func(talk bool) int {
		g := newGroup(t, nodes, modes(nil))
		for i := 0; i < 12; i++ {
			rq := req(g.c, "198.51.100.41", "residential", "POST", "/wp-login.php")
			e := g.engs[i%nodes]
			e.Check(rq)
			e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}, HasUser: true, UserHash: HashUser(fmt.Sprintf("user%d@example.org", i))})
			g.c.add(30 * time.Second)
			if talk {
				g.tell()
			}
		}
		n := 0
		for _, h := range g.triggered(config.ScenarioCredentialStuffing) {
			if h.Scope == "client" {
				n++
			}
		}
		return n
	}
	if n := run(false); n != 0 {
		t.Fatalf("nodes that do not talk fired %d times", n)
	}
	if n := run(true); n == 0 {
		t.Error("12 user names over 5 nodes did not fire credential_stuffing")
	}
}

func TestGroupPathProbingCountsForTheGroup(t *testing.T) {
	th := Effective(config.ScenarioPathProbing, config.Thresholds{})
	const nodes = 4
	run := func(talk bool) int {
		g := newGroup(t, nodes, modes(nil))
		for i := 0; i < th.Count+nodes; i++ {
			rq := req(g.c, "198.51.100.42", "hosting", "GET", fmt.Sprintf("/missing-%d", i))
			e := g.engs[i%nodes]
			e.Check(rq)
			e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 404}})
			g.c.add(time.Second)
			if talk {
				g.tell()
			}
		}
		return len(g.triggered(config.ScenarioPathProbing))
	}
	if n := run(false); n != 0 {
		t.Fatalf("nodes that do not talk fired %d times (threshold %d)", n, th.Count)
	}
	if n := run(true); n == 0 {
		t.Errorf("%d missing paths over %d nodes did not fire path_probing", th.Count+nodes, nodes)
	}
}

// What a node is told is input from outside: bounded, and what does not
// parse changes nothing.
func TestApplyCountsBoundsItsInput(t *testing.T) {
	b := modes(nil)
	b.RateLimits = []config.RateLimit{{ID: "api", Route: "/api/**", Limit: 30, Per: "1m", Burst: 30, Mode: config.BehaviourBlock}}
	e, _, c := newEngine(b)
	e.ApplyCounts(nil)
	e.ApplyCounts(&Counts{
		Limits: []LimitCount{
			{Client: "not an address", Limit: "api", N: 5},
			{Client: "203.0.113.5/24", Limit: "api", N: 5},     // no client key
			{Client: "203.0.113.5/32", Limit: "unknown", N: 5}, // a limit this node does not have
			{Client: "203.0.113.5/32", Limit: "api", N: -3},
			{Client: "203.0.113.9/32", Limit: "api", N: 1 << 40},
		},
		Clients: []ClientCount{{Client: "::/0", LoginFailed: 1 << 40}, {Client: "203.0.113.5/32", Crawl: -1, WAFHits: -5}},
		Sites:   []SiteCount{{Host: "no-such-site.example", Crawl: 1 << 40}},
	})
	if v := e.Check(req(c, "203.0.113.5", "residential", "GET", "/api/items")); v.RateLimited {
		t.Error("counts that do not parse limited a client")
	}
	// A count far over the limit keeps a client out for one more burst at most.
	if v := e.Check(req(c, "203.0.113.9", "residential", "GET", "/api/items")); !v.RateLimited || v.RetryAfter > 2*time.Minute+5*time.Second {
		t.Errorf("an absurd count: limited %v, retry after %s, want at most two minutes", v.RateLimited, v.RetryAfter)
	}
	// A single gateway notes nothing.
	single, _, c2 := newEngine(b)
	single.Check(req(c2, "203.0.113.5", "residential", "GET", "/api/items"))
	if single.TakeCounts() != nil {
		t.Error("an engine without sharing noted counts")
	}
}
