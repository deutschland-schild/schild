package behaviour

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
)

// hand passes the whole running state of from to to, through JSON as on the
// wire, and returns the number of pages.
func hand(t *testing.T, from, to *Engine, raise bool, skip func(Key) bool) (pages int) {
	t.Helper()
	for cur := 0; cur >= 0; pages++ {
		var page *Warm
		page, cur = from.WarmPage(cur)
		raw, err := json.Marshal(page)
		if err != nil {
			t.Fatal(err)
		}
		var got Warm
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		to.ApplyWarm(&got, raise, skip)
		if pages > warmEnd {
			t.Fatal("the pages do not end")
		}
	}
	return pages
}

// restart puts a fresh engine in the place of node i of the group, as a
// node that starts: nothing counted, the clock of the group.
func (g *group) restart(i int, b config.Behaviour) *Engine {
	e, r, _ := newEngine(b)
	e.Now = g.c.now
	e.EnableSharing()
	g.engs[i], g.recs[i] = e, r
	return e
}

// One failed login short of the threshold, counted by the group; then one
// node restarts. Without the handover the next failed login on it is its
// first; with it, it is the one that blocks.
func TestRestartedNodeTakesTheFailedLoginsOfTheGroup(t *testing.T) {
	th := Effective(config.ScenarioLoginBruteforce, config.Thresholds{})
	const ip = "198.51.100.60"
	run := func(warm bool) int {
		g := newGroup(t, 2, modes(nil))
		for i := 0; i < th.Count-1; i++ {
			failLogin(g.engs[0], g.c, ip, "hosting")
			g.c.add(time.Second)
			g.tell()
		}
		e := g.restart(1, modes(nil))
		if warm {
			hand(t, g.engs[0], e, false, nil)
		}
		g.c.add(time.Second)
		failLogin(e, g.c, ip, "hosting")
		return len(g.triggered(config.ScenarioLoginBruteforce))
	}
	if n := run(false); n != 0 {
		t.Fatalf("without the handover the restarted node fired %d times; the test needs it to start at zero", n)
	}
	if n := run(true); n != 1 {
		t.Errorf("after the handover the failed login that reaches the threshold of %d fired %d times on the restarted node, want 1", th.Count, n)
	}
}

// A rate limit half used before the restart is half used after it, and the
// counts that follow do not use it a second time.
func TestRestartedNodeTakesTheTokensUsedOfARateLimit(t *testing.T) {
	b := modes(nil)
	b.RateLimits = []config.RateLimit{{ID: "api", Route: "/api/**", Limit: 20, Per: "1h", Burst: 20, Mode: config.BehaviourBlock}}
	const ip = "203.0.113.70"
	g := newGroup(t, 2, b)
	for i := 0; i < 10; i++ {
		if v := g.engs[0].Check(req(g.c, ip, "residential", "GET", "/api/items")); v.RateLimited {
			t.Fatalf("request %d of 10 was limited before the restart", i+1)
		}
	}
	g.tell()
	e := g.restart(1, b)
	hand(t, g.engs[0], e, false, nil)
	// The second pass and a count that is already in the state add nothing.
	hand(t, g.engs[0], e, true, nil)
	hand(t, g.engs[0], e, true, nil)
	passed := 0
	for i := 0; i < 20; i++ {
		if v := e.Check(req(g.c, ip, "residential", "GET", "/api/items")); !v.RateLimited {
			passed++
		}
	}
	if passed != 10 {
		t.Errorf("the restarted node let %d of 20 requests pass, want the 10 the limit had left", passed)
	}
	// Another client has the whole limit.
	if v := e.Check(req(g.c, "203.0.113.71", "residential", "GET", "/api/items")); v.RateLimited {
		t.Error("a client the member never saw is limited after the handover")
	}
}

// The first pass adds, the second only raises: what the member counted
// after the first pass arrives, what both hold is not counted twice.
func TestSecondPassOnlyRaises(t *testing.T) {
	th := Effective(config.ScenarioLoginBruteforce, config.Thresholds{})
	if th.Count < 4 {
		t.Skip("the threshold is too low for this test")
	}
	const ip = "198.51.100.61"
	g := newGroup(t, 2, modes(nil))
	failLogin(g.engs[0], g.c, ip, "hosting")
	failLogin(g.engs[0], g.c, ip, "hosting")
	e := g.restart(1, modes(nil))
	hand(t, g.engs[0], e, false, nil)
	// The member counts one more and does not tell (the tell is lost); the
	// second pass brings it, and brings it once however often it runs.
	failLogin(g.engs[0], g.c, ip, "hosting")
	g.engs[0].TakeCounts()
	for i := 0; i < 3; i++ {
		hand(t, g.engs[0], e, true, nil)
	}
	key, _ := KeyOf(netip.MustParseAddr(ip))
	var fast float64
	sec := int64(time.Second)
	e.clients.with(key, false, func(s *clientState) {
		if s != nil {
			fast = s.loginFast.value(g.c.now().UnixNano(), int64(th.WindowS)*sec)
		}
	})
	if fast < 2.99 || fast > 3.01 {
		t.Errorf("the restarted node counts %.2f failed logins of the client, want 3", fast)
	}
}

// An address erased while the state travels is left out by the node that
// takes it, and an address the member forgot is not in its state.
func TestHandoverLeavesOutAnErasedAddress(t *testing.T) {
	const erased, other = "198.51.100.62", "198.51.100.63"
	g := newGroup(t, 2, modes(nil))
	for _, ip := range []string{erased, other} {
		failLogin(g.engs[0], g.c, ip, "hosting")
	}
	held := func(e *Engine, ip string) bool {
		key, _ := KeyOf(netip.MustParseAddr(ip))
		ok := false
		e.clients.with(key, false, func(s *clientState) { ok = s != nil })
		return ok
	}
	// The member has not erased yet, the taking node knows the erasure.
	e := g.restart(1, modes(nil))
	gone, _ := KeyOf(netip.MustParseAddr(erased))
	hand(t, g.engs[0], e, false, func(k Key) bool { return k == gone })
	if held(e, erased) {
		t.Error("the taking node holds counts of an address it knows as erased")
	}
	if !held(e, other) {
		t.Error("the taking node lacks the counts of the other address")
	}
	// The member erased: its state names the address no more.
	g.engs[0].Forget(netip.MustParseAddr(erased))
	e = g.restart(1, modes(nil))
	hand(t, g.engs[0], e, false, nil)
	if held(e, erased) {
		t.Error("the state of a member that erased an address still carries it")
	}
}

// What comes from another node is input from outside: nothing in it may
// lock a client out for longer than a count could, or break the engine.
func TestApplyWarmBoundsWhatItTakes(t *testing.T) {
	b := modes(nil)
	b.RateLimits = []config.RateLimit{{ID: "api", Route: "/api/**", Limit: 10, Per: "1m", Burst: 10, Mode: config.BehaviourBlock}}
	e, _, c := newEngine(b)
	e.EnableSharing()
	huge := make([]byte, 1<<16)
	for i := range huge {
		huge[i] = 255
	}
	w := &Warm{
		Limits:   []WarmLimit{{Client: "203.0.113.80/32", Limit: "api", Used: 1e300}, {Client: "not an address", Limit: "api", Used: 5}, {Client: "203.0.113.81/32", Limit: "unknown", Used: 5}, {Client: "::/0", Limit: "api", Used: 5}},
		Clients:  []WarmClient{{Client: "203.0.113.80/32", LoginFast: -5, LoginSlow: 1e300, LoginN: -1, Users: huge, Probe: []uint32{1, 2, 3}, ProbeW: -9, Crawl: 1e300, WAF: []int{1}, WAFHits: -3}},
		Sites:    []WarmSite{{Host: "unknown.example", Crawl: 1e300, Clients: huge, Users: huge, Baseline: -1}},
		Routes:   []WarmRoute{{Host: "x", Route: "/nowhere", Failed: 1e300, Senders: huge}},
		Accounts: []WarmAccount{{User: 1, Failed: 1 << 40, FlaggedMS: 1 << 60, Attempts: 1 << 30, Senders: make([]uint64, 1000)}},
		Waves:    []WaveNote{{ID: "nonsense", Detector: "none"}},
	}
	e.ApplyWarm(w, false, nil)
	e.ApplyWarm(w, true, nil)
	e.ApplyWarm(nil, false, nil)
	// The bucket is at most one burst below zero: after two minutes of
	// refill the client passes again.
	c.add(2 * time.Minute)
	if v := e.Check(req(c, "203.0.113.80", "residential", "GET", "/api/items")); v.RateLimited {
		t.Error("a state that names a huge use keeps a client limited beyond what a count could")
	}
}

// The state of a full table comes in pages and all of it arrives.
func TestHandoverComesInPages(t *testing.T) {
	b := modes(nil)
	b.RateLimits = []config.RateLimit{{ID: "api", Route: "/api/**", Limit: 100, Per: "1h", Burst: 100, Mode: config.BehaviourBlock}}
	g := newGroup(t, 2, b)
	const clients = 3 * WarmPageEntries
	for i := 0; i < clients; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
		g.engs[0].Check(req(g.c, ip, "residential", "GET", "/api/items"))
	}
	e := g.restart(1, b)
	if pages := hand(t, g.engs[0], e, false, nil); pages < 3 {
		t.Errorf("%d clients travelled in %d pages, want at least 3", clients, pages)
	}
	if _, got, _ := e.Sizes(); got != clients {
		t.Errorf("the taking node holds %d buckets, want %d", got, clients)
	}
}
