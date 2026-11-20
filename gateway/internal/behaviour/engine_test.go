package behaviour

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

var t0 = time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)

type rec struct {
	mu        sync.Mutex
	events    []any
	types     []string
	incidents []*store.Incident
}

func (r *rec) sink() Sink {
	return Sink{
		Emit: func(id, typ string, t time.Time, data any, idx eventlog.Index) {
			r.mu.Lock()
			r.events, r.types = append(r.events, data), append(r.types, typ)
			r.mu.Unlock()
			// Every event must satisfy events.schema.json.
			ev := events.New(typ, "test-node", t, data)
			if id != "" {
				ev.ID = id
			}
			if err := ev.Validate(); err != nil {
				panic(fmt.Sprintf("%s: %v", typ, err))
			}
		},
		Incident: func(in *store.Incident) { r.mu.Lock(); r.incidents = append(r.incidents, in); r.mu.Unlock() },
	}
}

func (r *rec) triggered() []events.BehaviourTriggeredData {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []events.BehaviourTriggeredData
	for _, e := range r.events {
		if d, ok := e.(events.BehaviourTriggeredData); ok {
			out = append(out, d)
		}
	}
	return out
}

func (r *rec) exceeded() []events.RateLimitExceededData {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []events.RateLimitExceededData
	for _, e := range r.events {
		if d, ok := e.(events.RateLimitExceededData); ok {
			out = append(out, d)
		}
	}
	return out
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func modes(m map[string]string) config.Behaviour {
	b := config.Behaviour{PresetLimits: config.BehaviourOff}
	for _, id := range config.ScenarioIDs {
		b.Scenarios.Get(id).Mode = config.BehaviourObserve
	}
	for id, v := range m {
		b.Scenarios.Get(id).Mode = v
	}
	return b
}

// installedLongAgo: the learning period is over in most tests.
var installedLongAgo = t0.Add(-60 * 24 * time.Hour)

func newEngine(b config.Behaviour) (*Engine, *rec, *clock) {
	return newEngineInstalled(b, installedLongAgo)
}

func newEngineInstalled(b config.Behaviour, installed time.Time) (*Engine, *rec, *clock) {
	e := New(Config{Behaviour: b, InstalledAt: installed})
	r := &rec{}
	e.Sink = r.sink()
	c := &clock{t: t0}
	e.Now = c.now
	return e, r, c
}

func req(c *clock, ip, netClass, method, path string) *Request {
	a := netip.MustParseAddr(ip)
	return &Request{Time: c.t, IP: a, Method: method, Host: "verein.example", Path: path, UserAgent: "Mozilla/5.0",
		Client: events.Client{IP: a.String(), Attribution: "tcp_peer", Geo: events.Geo{Country: "DE", ASN: 64496, NetClass: netClass}}}
}

// failLogin posts a failed WordPress login (form shown again, 200).
func failLogin(e *Engine, c *clock, ip, netClass string) Verdict {
	r := req(c, ip, netClass, "POST", "/wp-login.php")
	v := e.Check(r)
	if v.Block || v.RateLimited {
		return v
	}
	e.Observe(r, Outcome{Forwarded: true, Response: Response{Status: 200}})
	return v
}

func TestDecideLadder(t *testing.T) {
	for _, c := range []struct {
		mode, nc, exempt string
		action, would    string
		reason           string
	}{
		{"observe", "residential", "", "observe", "block", ""},
		{"block", "residential", "", "block", "block", ""},
		{"block", "cgnat", "", "observe", "observe", ReasonNetClass},
		{"block", "mobile", "", "observe", "observe", ReasonNetClass},
		{"block", "residential", ReasonAllowlisted, "observe", "observe", ReasonAllowlisted},
		{"block", "hosting", ReasonReleased, "observe", "observe", ReasonReleased},
		{"block", "residential", ReasonUnverifiedBot, "observe", "observe", ReasonUnverifiedBot},
		{"observe", "mobile", "", "observe", "observe", ""},
		{"block", "tor", "", "observe", "observe", ReasonNetClass},
	} {
		a, w, r := Decide(c.mode, c.nc, c.exempt)
		if a != c.action || w != c.would || r != c.reason {
			t.Errorf("Decide(%s, %s, %q) = %s %s %q, want %s %s %q", c.mode, c.nc, c.exempt, a, w, r, c.action, c.would, c.reason)
		}
	}
}

// MVP-19 measurement, finding 3a: a scenario the operator set to block
// acts only after the learning period (learning_days from the
// first start, like the distributed detectors); before, it records what it
// would have done.
func TestScenariosObserveDuringLearning(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed time.Time
		at        time.Duration // after t0
		blocks    bool
	}{
		{"day 0", t0, 0, false},
		{"day 13", t0, 13 * 24 * time.Hour, false},
		{"day 14", t0, 14*24*time.Hour + time.Minute, true},
		{"unknown first start keeps learning", time.Time{}, 400 * 24 * time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{config.BehaviourBlock} {
				e, r, c := newEngineInstalled(modes(map[string]string{config.ScenarioLoginBruteforce: mode}), tc.installed)
				e.SetConfig(Config{Behaviour: modes(map[string]string{config.ScenarioLoginBruteforce: mode}), InstalledAt: tc.installed})
				c.t = t0.Add(tc.at)
				const ip = "198.51.100.7"
				for range 5 {
					failLogin(e, c, ip, "residential")
					c.add(time.Second)
				}
				hits := r.triggered()
				if len(hits) != 1 {
					t.Fatalf("%s: %d hits", mode, len(hits))
				}
				h := hits[0]
				v := e.Check(req(c, ip, "residential", "GET", "/"))
				acted := h.Action != config.BehaviourObserve
				if acted != tc.blocks || (mode == config.BehaviourBlock && v.Block != tc.blocks) {
					t.Fatalf("%s: action %s, block %v; want acting=%v", mode, h.Action, v.Block, tc.blocks)
				}
				if h.Mode != mode || h.WouldAction != config.BehaviourBlock {
					t.Fatalf("%s: event mode %s would %s", mode, h.Mode, h.WouldAction)
				}
				if !tc.blocks && (h.Incident != "" || len(r.incidents) != 0) {
					t.Fatalf("%s: incident during learning", mode)
				}
				if wantReason := map[bool]string{true: "", false: ReasonLearning}[tc.blocks]; h.Reason != wantReason {
					t.Fatalf("%s: reason %q, want %q", mode, h.Reason, wantReason)
				}
			}
		})
	}
}

func TestLoginBruteforceBlockExpiryAndEscalation(t *testing.T) {
	// D29 amendment: the ladder follows the client's net class.
	for _, tc := range []struct {
		netClass string
		steps    []time.Duration
	}{
		{"hosting", []time.Duration{15 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 7 * 24 * time.Hour}},
		{"residential", []time.Duration{15 * time.Minute, time.Hour, 4 * time.Hour, 24 * time.Hour, 24 * time.Hour}},
		{"vpn", []time.Duration{15 * time.Minute, time.Hour, 4 * time.Hour, 24 * time.Hour, 24 * time.Hour}},
	} {
		t.Run(tc.netClass, func(t *testing.T) {
			e, r, c := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock}))
			var kept []events.ActiveBlock
			e.Sink.Persist = func(ab events.ActiveBlock) { kept = append(kept, ab) }
			const ip = "198.51.100.7"
			nc := tc.netClass
			var want []time.Duration
			for step, dur := range tc.steps {
				for i := 0; i < 4; i++ {
					if v := failLogin(e, c, ip, nc); v.Block {
						t.Fatalf("step %d: blocked after %d failures", step, i+1)
					}
					c.add(time.Second)
				}
				failLogin(e, c, ip, nc) // 5th failure in a minute
				v := e.Check(req(c, ip, nc, "GET", "/"))
				if !v.Block || v.Scenario != config.ScenarioLoginBruteforce || v.Incident == "" {
					t.Fatalf("step %d: not blocked: %+v", step, v)
				}
				if got := v.Until.Sub(c.t.Truncate(time.Second)); got != dur {
					t.Fatalf("step %d: block for %v, want %v", step, got, dur)
				}
				bi, ok := e.ActiveBlock(netip.MustParseAddr(ip))
				if !ok || bi.NetClass != nc || bi.Duration != dur || bi.Persisted != (dur > 24*time.Hour) {
					t.Fatalf("step %d: block info %+v", step, bi)
				}
				want = append(want, dur)
				// Every block ends by itself.
				c.t = v.Until.Add(time.Second)
				if v := e.Check(req(c, ip, nc, "GET", "/")); v.Block {
					t.Fatalf("step %d: block did not expire", step)
				}
			}
			hits := r.triggered()
			if len(hits) != len(want) {
				t.Fatalf("%d hits, want %d", len(hits), len(want))
			}
			wantKept := 0
			for i, h := range hits {
				if h.Action != ActionBlock || h.Level != min(i+1, 4) || h.DurationS != int(want[i]/time.Second) || h.DurationS != events.BlockDurationS(nc, h.Level) {
					t.Errorf("hit %d: %+v", i, h)
				}
				if h.Count < 5 || h.Threshold != 5 || h.Route != "/wp-login.php" || h.Preset != "wordpress" || h.KeyBits != 32 {
					t.Errorf("hit %d: %+v", i, h)
				}
				if h.DurationS > events.PersistOverS {
					wantKept++
				}
			}
			if len(kept) != wantKept {
				t.Fatalf("persisted %d blocks, want %d: %+v", len(kept), wantKept, kept)
			}
			for _, ab := range kept {
				if ab.ClientKey != ip || ab.KeyBits != 32 || ab.NetClass != "hosting" || ab.DurationS != 604800 || ab.Level != 4 || ab.Source != "behaviour:login_bruteforce" {
					t.Fatalf("kept block %+v", ab)
				}
			}
			if len(r.incidents) != len(want) || r.incidents[0].Sources[0] != "behaviour:login_bruteforce" {
				t.Fatalf("incidents: %+v", r.incidents)
			}
			// The ladder starts again a day after the last block.
			c.add(25 * time.Hour)
			for i := 0; i < 5; i++ {
				failLogin(e, c, ip, nc)
			}
			if v := e.Check(req(c, ip, nc, "GET", "/")); v.Until.Sub(c.t.Truncate(time.Second)) != 15*time.Minute {
				t.Fatalf("ladder not reset: %+v", v)
			}
		})
	}
}

// blockHosting drives one hosting client up to the 7-day step and returns
// the kept block.
func blockHosting(t *testing.T, e *Engine, c *clock, ip string) events.ActiveBlock {
	t.Helper()
	var kept []events.ActiveBlock
	e.Sink.Persist = func(ab events.ActiveBlock) { kept = append(kept, ab) }
	for step := 0; step < 4; step++ {
		for i := 0; i < 5; i++ {
			failLogin(e, c, ip, "hosting")
		}
		v := e.Check(req(c, ip, "hosting", "GET", "/"))
		if !v.Block {
			t.Fatalf("step %d: not blocked", step)
		}
		if step < 3 {
			c.t = v.Until.Add(time.Second)
		}
	}
	if len(kept) != 1 {
		t.Fatalf("kept %d blocks", len(kept))
	}
	return kept[0]
}

func TestLongBlockSurvivesRestart(t *testing.T) {
	e, _, c := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock}))
	const ip = "198.51.100.9"
	ab := blockHosting(t, e, c, ip)
	// A new engine (restart) gets the row back from schild.db.
	c.add(time.Hour)
	e2, _, _ := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock}))
	e2.Now = c.now
	expired := ab
	expired.ClientKey, expired.Until = "198.51.100.10", c.t.Add(-time.Second).UTC().Format(time.RFC3339)
	short := ab
	short.ClientKey, short.DurationS = "198.51.100.11", 86400
	allowed := ab
	allowed.ClientKey = "198.51.100.12"
	n, drop := e2.RestoreBlocks([]events.ActiveBlock{ab, expired, short, allowed}, func(a netip.Addr) bool { return a.String() == "198.51.100.12" })
	if n != 1 || len(drop) != 3 {
		t.Fatalf("restored %d, dropped %v", n, drop)
	}
	v := e2.Check(req(c, ip, "hosting", "GET", "/"))
	if !v.Block || v.Incident != ab.Incident || v.Until.UTC().Format(time.RFC3339) != ab.Until {
		t.Fatalf("restored block: %+v", v)
	}
	bi, ok := e2.ActiveBlock(netip.MustParseAddr(ip))
	if !ok || !bi.Persisted || bi.Duration != 7*24*time.Hour || bi.NetClass != "hosting" || bi.Level != 4 {
		t.Fatalf("block info %+v", bi)
	}
	// Expiry is always enforced.
	c.t = v.Until.Add(time.Second)
	if v := e2.Check(req(c, ip, "hosting", "GET", "/")); v.Block {
		t.Fatal("restored block did not expire")
	}
	var gone []string
	e2.Sink.Unpersist = func(k string) { gone = append(gone, k) }
	e2.Sweep()
	if len(gone) != 1 || gone[0] != ip || len(e2.LongBlocks()) != 0 {
		t.Fatalf("sweep: %v", gone)
	}
}

func TestLongBlockSurvivesEviction(t *testing.T) {
	e, _, c := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock}))
	const ip = "198.51.100.13"
	blockHosting(t, e, c, ip)
	key, _ := KeyOf(netip.MustParseAddr(ip))
	e.blocks.delete(key) // as if a flood evicted it
	if v := e.Check(req(c, ip, "hosting", "GET", "/")); !v.Block {
		t.Fatal("kept block lost with its table entry")
	}
}

func TestLongBlockDeletionAndAllowlistWin(t *testing.T) {
	for _, how := range []string{"forget", "allowlist", "release"} {
		t.Run(how, func(t *testing.T) {
			e, _, c := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock}))
			const ip = "198.51.100.14"
			blockHosting(t, e, c, ip)
			var gone []string
			e.Sink.Unpersist = func(k string) { gone = append(gone, k) }
			a := netip.MustParseAddr(ip)
			var ended int
			switch how {
			case "forget":
				ended = e.Forget(a)
			case "allowlist":
				ended = e.DropBlocks(func(x netip.Addr) bool { return x == a })
			case "release":
				ended = e.Release(a)
			}
			if ended != 1 || len(gone) != 1 || gone[0] != ip {
				t.Fatalf("ended %d, unpersisted %v", ended, gone)
			}
			if v := e.Check(req(c, ip, "hosting", "GET", "/")); v.Block {
				t.Fatal("still blocked")
			}
			if _, ok := e.ActiveBlock(a); ok {
				t.Fatal("block info after the end")
			}
		})
	}
}

func TestSlowLoginBruteforce(t *testing.T) {
	e, r, c := newEngine(modes(nil))
	for i := 0; i < 30; i++ {
		failLogin(e, c, "198.51.100.8", "residential")
		c.add(100 * time.Second) // 1 per 100 s: never 5 per minute
	}
	hits := r.triggered()
	if len(hits) != 1 || hits[0].Threshold != 30 || hits[0].WindowS != 3600 || hits[0].Action != ActionObserve || hits[0].WouldAction != ActionBlock {
		t.Fatalf("slow variant: %+v", hits)
	}
}

func TestSuccessfulLoginsDoNotCount(t *testing.T) {
	e, r, c := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock}))
	for i := 0; i < 50; i++ {
		rq := req(c, "198.51.100.9", "residential", "POST", "/wp-login.php")
		e.Check(rq)
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 302, Location: "https://verein.example/wp-admin/"}})
		c.add(time.Second)
	}
	if len(r.triggered()) != 0 {
		t.Fatal("successful logins counted")
	}
}

func TestSharedAddressesNeverBlocked(t *testing.T) {
	b := modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock, config.ScenarioPathProbing: config.BehaviourBlock,
		config.ScenarioAggressiveCrawl: config.BehaviourBlock, config.ScenarioWAFRepeat: config.BehaviourBlock, config.ScenarioCredentialStuffing: config.BehaviourBlock})
	b.RateLimits = []config.RateLimit{{ID: "login", Route: "/wp-login.php", Limit: 2, Per: "1m", Burst: 2, Mode: config.BehaviourBlock}}
	e, r, c := newEngine(b)
	for _, nc := range []string{"cgnat", "mobile", "tor"} {
		ip := map[string]string{"cgnat": "100.64.1.1", "mobile": "2001:db8:7:1::5", "tor": "198.51.100.200"}[nc]
		for i := 0; i < 200; i++ {
			rq := req(c, ip, nc, "POST", "/wp-login.php")
			if v := e.Check(rq); v.Block || v.RateLimited {
				t.Fatalf("%s blocked: %+v", nc, v)
			}
			e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}, WAFRules: []int{942100 + i%3}})
			pr := req(c, ip, nc, "GET", fmt.Sprintf("/missing-%d", i))
			e.Check(pr)
			e.Observe(pr, Outcome{Forwarded: true, Response: Response{Status: 404}})
			c.add(200 * time.Millisecond)
		}
	}
	hits := r.triggered()
	if len(hits) == 0 {
		t.Fatal("shared addresses must still be counted")
	}
	for _, h := range hits {
		if h.Action == ActionBlock || h.Reason != ReasonNetClass {
			t.Fatalf("shared address acted on: %+v", h)
		}
	}
	for _, x := range r.exceeded() {
		if x.Action != ActionObserve || x.Reason != ReasonNetClass {
			t.Fatalf("rate limit on shared address: %+v", x)
		}
	}
	if len(r.incidents) != 0 {
		t.Fatal("incident for a shared address")
	}
}

func TestAllowlistedAndReleasedExempt(t *testing.T) {
	b := modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock})
	b.RateLimits = []config.RateLimit{{ID: "login", Route: "/wp-login.php", Limit: 1, Per: "1m", Burst: 1, Mode: config.BehaviourBlock}}
	e, r, c := newEngine(b)
	for i := 0; i < 20; i++ {
		rq := req(c, "192.0.2.10", "business", "POST", "/wp-login.php")
		rq.Allowlisted = true
		if v := e.Check(rq); v.Block || v.RateLimited {
			t.Fatalf("allowlisted blocked: %+v", v)
		}
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
		c.add(time.Second)
	}
	for _, h := range r.triggered() {
		if h.Action != ActionObserve || h.Reason != ReasonAllowlisted {
			t.Fatalf("allowlisted: %+v", h)
		}
	}
	// An exception for this scenario (released in the dashboard).
	exc := func(src string) bool { return src == "behaviour:login_bruteforce" || src == "ratelimit:login" }
	for i := 0; i < 20; i++ {
		rq := req(c, "198.51.100.20", "residential", "POST", "/wp-login.php")
		rq.Except = exc
		if v := e.Check(rq); v.Block || v.RateLimited {
			t.Fatalf("released blocked: %+v", v)
		}
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
		c.add(time.Second)
	}
}

func TestReleaseEndsBlock(t *testing.T) {
	e, _, c := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock}))
	for i := 0; i < 5; i++ {
		failLogin(e, c, "2001:db8:1:2::7", "residential")
	}
	// The key is the /64: another address of the same /64 is blocked too.
	if v := e.Check(req(c, "2001:db8:1:2::99", "residential", "GET", "/")); !v.Block {
		t.Fatal("/64 not blocked")
	}
	if _, ok := e.ActiveBlock(netip.MustParseAddr("2001:db8:1:2::7")); !ok {
		t.Fatal("no active block")
	}
	if n := e.Release(netip.MustParseAddr("2001:db8:1:2::7")); n != 1 {
		t.Fatalf("released %d blocks", n)
	}
	if v := e.Check(req(c, "2001:db8:1:2::7", "residential", "GET", "/")); v.Block {
		t.Fatal("still blocked after release")
	}
	if !e.ReleasedSince(netip.MustParseAddr("2001:db8:1:2::1"), t0.Add(-time.Minute)) {
		t.Fatal("release not remembered")
	}
	// Different /64: not affected.
	if v := e.Check(req(c, "2001:db8:1:3::7", "residential", "GET", "/")); v.Block {
		t.Fatal("other /64 blocked")
	}
}

// TestEndedReportsIncident (D36 fix round 2, re-measurement C): a block the
// operator ends (release, allowlist) reports its incident once, so the
// incident is stored as unblocked; nothing is reported without a block.
func TestEndedReportsIncident(t *testing.T) {
	for _, how := range []string{"release", "allowlist"} {
		e, _, c := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock}))
		var got []string
		e.Sink.Ended = func(incident string, at time.Time) { got = append(got, incident) }
		for i := 0; i < 5; i++ {
			failLogin(e, c, "198.51.100.7", "residential")
		}
		bi, ok := e.ActiveBlock(netip.MustParseAddr("198.51.100.7"))
		if !ok || bi.Incident == "" {
			t.Fatalf("%s: no block with an incident: %+v", how, bi)
		}
		ip := netip.MustParseAddr("198.51.100.7")
		switch how {
		case "release":
			e.Release(ip)
			e.Release(ip)
		case "allowlist":
			e.DropBlocks(func(a netip.Addr) bool { return a == ip })
			e.DropBlocks(func(a netip.Addr) bool { return a == ip })
		}
		if len(got) != 1 || got[0] != bi.Incident {
			t.Fatalf("%s: ended %v, want [%s]", how, got, bi.Incident)
		}
	}
}

func TestRateLimit(t *testing.T) {
	b := modes(nil)
	b.RateLimits = []config.RateLimit{
		{ID: "contact", Route: "/wp-json/contact-form-7/v1/contact-forms/*/feedback", Methods: []string{"POST"}, Limit: 3, Per: "1m", Burst: 3, Mode: config.BehaviourBlock},
		{ID: "search", Route: "/search/**", Limit: 2, Per: "1s", Burst: 2, Mode: config.BehaviourObserve},
	}
	e, r, c := newEngine(b)
	for i := 0; i < 3; i++ {
		if v := e.Check(req(c, "203.0.113.5", "residential", "POST", "/wp-json/contact-form-7/v1/contact-forms/12/feedback")); v.RateLimited {
			t.Fatalf("request %d limited", i+1)
		}
	}
	v := e.Check(req(c, "203.0.113.5", "residential", "POST", "/wp-json/contact-form-7/v1/contact-forms/12/feedback"))
	if !v.RateLimited || v.LimitID != "contact" || RetryAfterSeconds(v.RetryAfter) != 20 {
		t.Fatalf("4th request: %+v (retry %d)", v, RetryAfterSeconds(v.RetryAfter))
	}
	// GET is not limited, another client neither.
	if v := e.Check(req(c, "203.0.113.5", "residential", "GET", "/wp-json/contact-form-7/v1/contact-forms/12/feedback")); v.RateLimited {
		t.Fatal("GET limited")
	}
	if v := e.Check(req(c, "203.0.113.6", "residential", "POST", "/wp-json/contact-form-7/v1/contact-forms/12/feedback")); v.RateLimited {
		t.Fatal("other client limited")
	}
	c.add(20 * time.Second)
	if v := e.Check(req(c, "203.0.113.5", "residential", "POST", "/wp-json/contact-form-7/v1/contact-forms/12/feedback")); v.RateLimited {
		t.Fatal("token not refilled")
	}
	// observe: counted, never answered with 429.
	for i := 0; i < 10; i++ {
		if v := e.Check(req(c, "203.0.113.7", "residential", "GET", "/search/a/b")); v.RateLimited {
			t.Fatal("observe limit answered 429")
		}
	}
	ex := r.exceeded()
	if len(ex) != 2 || ex[0].LimitID != "contact" || ex[0].Action != ActionBlock || ex[0].RetryAfterS != 20 || ex[1].Action != ActionObserve || ex[1].Count != 1 {
		t.Fatalf("records: %+v", ex)
	}
	if n, cl := e.LimitCounts24h("search"); n != 8 || cl != 1 {
		t.Fatalf("search counts %d %d", n, cl)
	}
}

// An exceeded rate limit that is not enforced (mode observe, allowlisted)
// is reported in the verdict, so the gate counts it as would_rate_limit
// (MVP-21 measurement finding 2).
func TestObservedRateLimitInVerdict(t *testing.T) {
	b := modes(nil)
	b.RateLimits = []config.RateLimit{{ID: "search", Route: "/search", Limit: 2, Per: "1m", Burst: 2, Mode: config.BehaviourObserve},
		{ID: "login", Route: "/wp-login.php", Limit: 2, Per: "1m", Burst: 2, Mode: config.BehaviourBlock}}
	e, _, c := newEngine(b)
	would := 0
	for i := 0; i < 10; i++ {
		v := e.Check(req(c, "203.0.113.7", "residential", "GET", "/search"))
		if v.RateLimited {
			t.Fatal("observe limit answered 429")
		}
		if v.WouldRateLimit {
			would++
		}
	}
	if would != 8 {
		t.Fatalf("would_rate_limit %d, want 8", would)
	}
	// Enforced: RateLimited, never WouldRateLimit.
	for i := 0; i < 3; i++ {
		v := e.Check(req(c, "203.0.113.8", "residential", "POST", "/wp-login.php"))
		if v.WouldRateLimit {
			t.Fatalf("enforced limit also counted as would: %+v", v)
		}
		if i == 2 && !v.RateLimited {
			t.Fatal("3rd login not limited")
		}
	}
	// Allowlisted sender over a block limit: forwarded, counted as would.
	would = 0
	for i := 0; i < 4; i++ {
		rq := req(c, "192.0.2.10", "residential", "POST", "/wp-login.php")
		rq.Allowlisted = true
		v := e.Check(rq)
		if v.RateLimited {
			t.Fatal("allowlisted limited")
		}
		if v.WouldRateLimit {
			would++
		}
	}
	if would != 2 {
		t.Fatalf("allowlisted would_rate_limit %d, want 2", would)
	}
}

func TestPresetLimits(t *testing.T) {
	b := modes(nil)
	b.Presets = []string{"wordpress", "nextcloud", "laravel", "generic"}
	b.PresetLimits = config.BehaviourBlock
	e, _, c := newEngine(b)
	ids := map[string]bool{}
	routes := map[string]int{}
	for _, l := range e.Limits() {
		ids[l.ID] = true
		routes[l.Route+" "+l.Query]++
		if l.Source != "preset" || l.Mode != config.BehaviourBlock {
			t.Fatalf("preset limit %+v", l)
		}
	}
	if !ids["preset-wordpress-xmlrpc"] || !ids["preset-nextcloud-login"] || ids["preset-drupal-login"] {
		t.Fatalf("ids: %v", ids)
	}
	if routes["/login "] != 1 {
		t.Fatalf("/login listed %d times", routes["/login "])
	}
	// WordPress search (?s=) is limited, other start-page requests are not.
	var limited bool
	for i := 0; i < 40; i++ {
		rq := req(c, "198.51.100.30", "residential", "GET", "/")
		rq.RawQuery = "s=test"
		limited = limited || e.Check(rq).RateLimited
	}
	if !limited {
		t.Fatal("search preset not applied")
	}
	// Every request that falls under a limit counts, over it or not (D96):
	// the loop above stops checking at the first limited one, the 31st.
	if n := e.LimitMatched24h("preset-wordpress-search"); n != 31 {
		t.Fatalf("matched %d, want 31", n)
	}
	// "/wp-json/**" is matched as a prefix, also through a path the backend
	// would clean up.
	for _, p := range []string{"/wp-json/wp/v2/posts", "/wp-json//wp/v2/posts", "/x/../wp-json/a"} {
		e.Check(req(c, "198.51.100.32", "residential", "POST", p))
	}
	e.Check(req(c, "198.51.100.32", "residential", "POST", "/wp-jsonx/a"))
	if n := e.LimitMatched24h("preset-wordpress-api-write"); n != 3 {
		t.Fatalf("prefix route matched %d, want 3", n)
	}
	for i := 0; i < 40; i++ {
		if e.Check(req(c, "198.51.100.31", "residential", "GET", "/")).RateLimited {
			t.Fatal("start page limited")
		}
	}
}

// D95: left open, every preset limit takes its recommendation; its own entry
// wins over the one mode for all; a route two presets share is generic.
func TestPresetLimitModes(t *testing.T) {
	byID := func(b config.Behaviour) map[string]*Limit {
		e, _, _ := newEngine(b)
		out := map[string]*Limit{}
		for _, l := range e.Limits() {
			out[l.ID] = l
		}
		return out
	}
	b := modes(nil)
	b.PresetLimits = ""
	l := byID(b)
	for id, want := range map[string]string{"preset-wordpress-login": "block", "preset-wordpress-password-reset": "block", "preset-wordpress-xmlrpc": "block",
		"preset-wordpress-search": "observe", "preset-wordpress-contact": "observe", "preset-generic-api-write": "observe", "preset-generic-login": "block"} {
		if l[id] == nil || l[id].Mode != want || l[id].Recommended != want {
			t.Fatalf("%s: %+v, want %s", id, l[id], want)
		}
	}
	if l["preset-joomla-api-write"] != nil || l["preset-laravel-login"] != nil {
		t.Fatal("a shared route is still named after one preset")
	}
	if g := l["preset-generic-api-write"]; g.Preset != "generic" || g.Label != "API (schreibend)" || g.Route != "/api/**" {
		t.Fatalf("shared route: %+v", g)
	}
	// One enabled preset keeps its own name for the route.
	b.Presets = []string{"laravel"}
	if l := byID(b); l["preset-laravel-login"] == nil || l["preset-generic-login"] != nil {
		t.Fatal("laravel alone")
	}
	b = modes(nil)
	b.PresetLimits = config.BehaviourOff
	b.PresetLimitModes = map[string]string{"preset-wordpress-search": config.BehaviourBlock, "preset-gone": config.BehaviourBlock}
	l = byID(b)
	if l["preset-wordpress-search"].Mode != "block" || l["preset-wordpress-login"].Mode != "off" || l["preset-wordpress-login"].Recommended != "block" {
		t.Fatalf("modes: %+v %+v", l["preset-wordpress-search"], l["preset-wordpress-login"])
	}
}

func TestPathProbing(t *testing.T) {
	e, r, c := newEngine(modes(map[string]string{config.ScenarioPathProbing: config.BehaviourBlock}))
	probe := func(ip, p string, status int) {
		rq := req(c, ip, "hosting", "GET", p)
		e.Check(rq)
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: status}})
	}
	for i := 0; i < 19; i++ {
		probe("203.0.113.45", fmt.Sprintf("/page-%d", i), 404)
		probe("203.0.113.45", "/page-0", 404)                     // repeats count once
		probe("203.0.113.45", fmt.Sprintf("/img/%d.png", i), 404) // static never counts
	}
	if len(r.triggered()) != 0 {
		t.Fatal("triggered before 20 distinct paths")
	}
	probe("203.0.113.45", "/page-19", 404)
	if h := r.triggered(); len(h) != 1 || h[0].Count != 20 || h[0].Action != ActionBlock {
		t.Fatalf("probing: %+v", h)
	}
	// Known probe paths weigh 5: four are enough.
	for _, p := range []string{"/.env", "/.git/config", "/wp-config.php.bak", "/phpmyadmin/"} {
		probe("203.0.113.46", p, 404)
	}
	h := r.triggered()
	if len(h) != 2 || h[1].Count != 20 {
		t.Fatalf("probe paths: %+v", h)
	}
}

func TestCredentialStuffing(t *testing.T) {
	e, r, c := newEngine(modes(nil))
	login := func(ip string, user int) {
		rq := req(c, ip, "residential", "POST", "/wp-login.php")
		e.Check(rq)
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}, HasUser: true, UserHash: HashUser(fmt.Sprintf("user%d@example.org", user))})
	}
	// One client, 10 distinct names in under 10 minutes (one per 30 s, so
	// login_bruteforce does not fire first).
	for i := 0; i < 10; i++ {
		login("198.51.100.40", i)
		c.add(30 * time.Second)
	}
	var cs []events.BehaviourTriggeredData
	for _, h := range r.triggered() {
		if h.Scenario == config.ScenarioCredentialStuffing {
			cs = append(cs, h)
		}
	}
	if len(cs) != 1 || cs[0].Scope != "client" || cs[0].Count < 9 {
		t.Fatalf("client stuffing: %+v", r.triggered())
	}
	// A pool of 1000 addresses, one attempt each with its own name: no
	// single client stands out, the site does.
	for i := 0; i < 1000; i++ {
		login(fmt.Sprintf("198.18.%d.%d", i/250, i%250+1), 1000+i)
		c.add(100 * time.Millisecond)
	}
	var site []events.BehaviourTriggeredData
	for _, h := range r.triggered() {
		if h.Scope == "site" {
			site = append(site, h)
		}
	}
	if len(site) != 1 || site[0].Client != nil || site[0].Reason != ReasonSiteScope || site[0].Action != ActionObserve || site[0].Count < 50 {
		t.Fatalf("site stuffing: %+v", site)
	}
}

func TestHLLEstimate(t *testing.T) {
	for _, n := range []int{5, 10, 50, 1000} {
		h := newHLL(10)
		for i := 0; i < n; i++ {
			h.add(HashUser(fmt.Sprintf("name-%d", i)))
			h.add(HashUser(fmt.Sprintf("NAME-%d ", i))) // normalised: same name
		}
		if est := h.estimate(); est < float64(n)*0.85 || est > float64(n)*1.15 {
			t.Errorf("n=%d: estimate %.1f", n, est)
		}
	}
}

func TestWAFRepeat(t *testing.T) {
	e, r, c := newEngine(modes(map[string]string{config.ScenarioWAFRepeat: config.BehaviourBlock}))
	rq := req(c, "203.0.113.9", "hosting", "GET", "/index.php")
	e.Observe(rq, Outcome{WAFRules: []int{942100, 942190, 941100}})
	if len(r.triggered()) != 0 {
		t.Fatal("one request with several rules is no repeat")
	}
	c.add(10 * time.Second)
	rq = req(c, "203.0.113.9", "hosting", "GET", "/index.php")
	e.Observe(rq, Outcome{WAFRules: []int{942100}})
	if h := r.triggered(); len(h) != 1 || h[0].Scenario != config.ScenarioWAFRepeat || h[0].Action != ActionBlock {
		t.Fatalf("waf_repeat: %+v", h)
	}
}

func TestAggressiveCrawl(t *testing.T) {
	e, r, c := newEngine(modes(map[string]string{config.ScenarioAggressiveCrawl: config.BehaviourBlock}))
	crawl := func(ip, ua string, n int) {
		for i := 0; i < n; i++ {
			rq := req(c, ip, "hosting", "GET", fmt.Sprintf("/article/%d", i))
			rq.UserAgent = ua
			e.Check(rq)
			e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
			c.add(200 * time.Millisecond)
		}
	}
	crawl("203.0.113.70", "python-requests/2.32", 150)
	crawl("203.0.113.71", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", 150)
	h := r.triggered()
	if len(h) != 2 || h[0].Action != ActionBlock || h[1].Action != ActionObserve || h[1].Reason != ReasonUnverifiedBot {
		t.Fatalf("crawl: %+v", h)
	}
}

// A gateway in mode observe (stage 3, test profile) blocks and limits
// nobody, whatever the scenario modes say; it counts "hätte gesperrt".
func TestGatewayObserveCapsEverything(t *testing.T) {
	b := modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock})
	b.RateLimits = []config.RateLimit{{ID: "login", Route: "/wp-login.php", Limit: 1, Per: "1m", Burst: 1, Mode: config.BehaviourBlock}}
	e := New(Config{Behaviour: b, GatewayObserve: true})
	r := &rec{}
	e.Sink = r.sink()
	c := &clock{t: t0}
	e.Now = c.now
	for i := 0; i < 20; i++ {
		if v := failLogin(e, c, "198.51.100.80", "hosting"); v.Block || v.RateLimited {
			t.Fatalf("observe gateway stopped a request: %+v", v)
		}
	}
	if e.EffectiveMode(config.ScenarioLoginBruteforce) != config.BehaviourObserve || len(r.incidents) != 0 {
		t.Fatal("effective mode")
	}
	hits := r.triggered()
	if len(hits) != 1 || hits[0].Mode != ActionObserve || hits[0].Action != ActionObserve || hits[0].WouldAction != ActionBlock {
		t.Fatalf("hits: %+v", hits)
	}
	if ex := r.exceeded(); len(ex) == 0 || ex[0].Mode != ActionObserve || ex[0].Action != ActionObserve {
		t.Fatalf("limits: %+v", ex)
	}
}

// Tor exits (initiator 2026-10-28) are treated like CGNAT and mobile: no
// block by a scenario, no 429 from a limit; they are still counted.
func TestTorNeverBlockedOrLimited(t *testing.T) {
	b := modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock, config.ScenarioPathProbing: config.BehaviourBlock})
	b.RateLimits = []config.RateLimit{{ID: "login", Route: "/wp-login.php", Limit: 1, Per: "1m", Burst: 1, Mode: config.BehaviourBlock}}
	e, r, c := newEngine(b)
	for i := 0; i < 50; i++ {
		if v := failLogin(e, c, "198.51.100.201", "tor"); v.Block || v.RateLimited {
			t.Fatalf("tor exit stopped at %d: %+v", i+1, v)
		}
		c.add(time.Second)
	}
	hits, ex := r.triggered(), r.exceeded()
	if len(hits) == 0 || len(ex) == 0 {
		t.Fatal("tor exit must still be counted")
	}
	for _, h := range hits {
		if h.Action != ActionObserve || h.Reason != ReasonNetClass {
			t.Fatalf("tor hit: %+v", h)
		}
	}
	for _, x := range ex {
		if x.Action != ActionObserve || x.Reason != ReasonNetClass {
			t.Fatalf("tor limit: %+v", x)
		}
	}
	if len(r.incidents) != 0 {
		t.Fatal("incident for a tor exit")
	}
}

func TestOffScenarioIsSilent(t *testing.T) {
	e, r, c := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourOff}))
	for i := 0; i < 50; i++ {
		failLogin(e, c, "198.51.100.50", "residential")
	}
	if len(r.triggered()) != 0 {
		t.Fatal("off scenario fired")
	}
}

// A flood of one million distinct addresses keeps every table within its
// capacity and the heap within budget; clean traffic still passes.
func TestFloodBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("flood")
	}
	b := modes(map[string]string{config.ScenarioPathProbing: config.BehaviourBlock, config.ScenarioLoginBruteforce: config.BehaviourBlock})
	b.Presets = config.BehaviourPresets
	b.PresetLimits = config.BehaviourBlock
	e, _, c := newEngine(b)
	e.Sink = Sink{} // events are not the subject here
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 1_000_000; i++ {
		var a netip.Addr
		if i%2 == 0 {
			a = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		} else {
			a = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i), 15: 1})
		}
		rq := &Request{Time: c.t, IP: a, Method: "POST", Host: "verein.example", Path: "/wp-login.php",
			Client: events.Client{IP: a.String(), Attribution: "tcp_peer", Geo: events.Geo{Country: "ZZ", NetClass: "hosting"}}}
		e.Check(rq)
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
		pr := *rq
		pr.Method, pr.Path = "GET", fmt.Sprintf("/x%d", i%97)
		e.Observe(&pr, Outcome{Forwarded: true, Response: Response{Status: 404}})
		if i%1000 == 0 {
			c.add(time.Millisecond)
		}
	}
	clients, buckets, blocks := e.Sizes()
	if clients > CapacityClients || buckets > CapacityBuckets || blocks > CapacityBlocks {
		t.Fatalf("tables over capacity: %d %d %d", clients, buckets, blocks)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	grown := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("tables %d/%d/%d, heap grew %d MiB, evicted %d", clients, buckets, blocks, grown>>20, e.clients.evictions())
	if grown > 96<<20 {
		t.Fatalf("heap grew %d MiB under the flood", grown>>20)
	}
	// Clean traffic: a normal visitor is neither blocked nor slowed down.
	start := time.Now()
	for i := 0; i < 10000; i++ {
		rq := req(c, "192.0.2.77", "residential", "GET", "/")
		if v := e.Check(rq); v.Block || v.RateLimited {
			t.Fatal("clean visitor stopped")
		}
		e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}})
	}
	if per := time.Since(start) / 10000; per > 200*time.Microsecond {
		t.Fatalf("clean request costs %v under flood", per)
	}
}

func TestSweep(t *testing.T) {
	e, _, c := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock}))
	for i := 0; i < 5; i++ {
		failLogin(e, c, "198.51.100.60", "residential")
	}
	failLogin(e, c, "198.51.100.61", "residential")
	c.add(50 * time.Hour)
	e.Sweep()
	if cl, _, bl := e.Sizes(); cl != 0 || bl != 0 {
		t.Fatalf("sweep left %d clients, %d blocks", cl, bl)
	}
}

func TestPresetsAndPaths(t *testing.T) {
	on := map[string]bool{"wordpress": true, "joomla": true, "drupal": true, "nextcloud": true, "typo3": true, "laravel": true, "generic": true}
	for _, c := range []struct {
		method, path, query string
		resp                Response
		preset              string
		failed              bool
	}{
		{"POST", "/wp-login.php", "", Response{Status: 200}, "wordpress", true},
		{"POST", "/wp-login.php", "", Response{Status: 302, Location: "/wp-admin/"}, "wordpress", false},
		{"POST", "/wp-login.php", "action=lostpassword", Response{Status: 200}, "", false},
		{"POST", "/administrator/index.php", "", Response{Status: 303, Location: "/administrator/index.php"}, "joomla", true},
		{"POST", "/administrator/index.php", "", Response{Status: 303, Location: "/administrator/index.php", CookieNames: []string{"joomla_user_state"}}, "joomla", false},
		{"POST", "/user/login", "", Response{Status: 200}, "drupal", true},
		{"POST", "/user/login", "", Response{Status: 303, Location: "/user/1"}, "drupal", false},
		{"POST", "/index.php/login", "", Response{Status: 303, Location: "/index.php/login?user=x"}, "nextcloud", true},
		{"POST", "/index.php/login", "", Response{Status: 303, Location: "/index.php/apps/files/"}, "nextcloud", false},
		{"POST", "/typo3/login", "", Response{Status: 200}, "typo3", true},
		{"POST", "/login", "", Response{Status: 302, Location: "https://shop.example/login"}, "generic", true},
		{"POST", "/login", "", Response{Status: 422}, "generic", true},
		{"POST", "/login", "", Response{Status: 302, Location: "/home"}, "generic", false},
		{"POST", "/login", "", Response{Status: 200}, "generic", false},
		{"GET", "/wp-login.php", "", Response{Status: 200}, "", false},
	} {
		lr := matchLogin(on, c.method, c.path, c.query, noBody)
		preset, failed := "", false
		if lr != nil {
			preset, failed = lr.Preset, lr.Failed(c.resp)
		}
		if preset != c.preset || failed != c.failed {
			t.Errorf("%s %s?%s %+v: preset %q failed %v, want %q %v", c.method, c.path, c.query, c.resp, preset, failed, c.preset, c.failed)
		}
	}
	for p, want := range map[string]bool{"/.env": true, "/.git": true, "/a/.git/HEAD": true, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php": true, "/about": false} {
		if IsProbePath(p) != want {
			t.Errorf("IsProbePath(%q) != %v", p, want)
		}
	}
	for r, cases := range map[string]map[string]bool{
		"/api/**":   {"/api/x": true, "/api/x/y": true, "/apix": false},
		"/c/*/feed": {"/c/1/feed": true, "/c/1/2/feed": false},
		"/**":       {"/": true, "/anything/at/all": true},
	} {
		re := routeRe(r)
		for p, want := range cases {
			if re.MatchString(p) != want {
				t.Errorf("route %s path %s: %v", r, p, !want)
			}
		}
	}
	k, bits := KeyOf(netip.MustParseAddr("::ffff:198.51.100.7"))
	if bits != 32 || k.String() != "198.51.100.7/32" {
		t.Errorf("mapped IPv4 key %s/%d", k, bits)
	}
	if k, bits := KeyOf(netip.MustParseAddr("2001:db8:a:b:c:d:e:f")); bits != 64 || k.String() != "2001:db8:a:b::/64" {
		t.Errorf("IPv6 key %s", k)
	}
}
