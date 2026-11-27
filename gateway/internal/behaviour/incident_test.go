package behaviour

import (
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
)

// A node of a group draws no incident number it knows already: in the group
// the number is the identity of a block (D109).
func TestNewIncidentDrawsAnotherThanAKnownOne(t *testing.T) {
	e := New(Config{})
	if id := e.NewIncident(); len(id) != 9 {
		t.Fatalf("a number of the default generator: %q", id)
	}
	draws := []string{"AAAA-0001", "AAAA-0002", "AAAA-0003"}
	n := 0
	e.DrawIncidents(func() string { n++; return draws[min(n, len(draws))-1] })
	if id := e.NewIncident(); id != "AAAA-0001" || n != 1 {
		t.Fatalf("on a single gateway: %q after %d draws, want the first draw", id, n)
	}
	n = 0
	e.KnownIncidents(func(id string) bool { return id != "AAAA-0003" })
	if id := e.NewIncident(); id != "AAAA-0003" || n != 3 {
		t.Fatalf("with two known numbers: %q after %d draws, want the third draw", id, n)
	}
	// A generator that gives known numbers only does not hold a block up.
	n = 0
	e.KnownIncidents(func(string) bool { return true })
	if id := e.NewIncident(); id == "" || n != incidentDraws {
		t.Fatalf("with every number known: %q after %d draws, want %d draws", id, n, incidentDraws)
	}
}

// The detector path: a block a scenario decides draws its number through
// NewIncident, and only when the block is created. A request of a client
// that is blocked already draws none, so on a node of a group it reads no
// store.
func TestDetectorDrawsItsIncidentOnlyForANewBlock(t *testing.T) {
	e, _, c := newEngine(modes(map[string]string{config.ScenarioLoginBruteforce: config.BehaviourBlock}))
	draws, asked := 0, 0
	e.DrawIncidents(func() string { draws++; return []string{"AAAA-AAA2", "AAAA-AAA3"}[min(draws, 2)-1] })
	e.KnownIncidents(func(id string) bool { asked++; return id == "AAAA-AAA2" })
	const ip = "198.51.100.7"
	for i := 0; i < 4; i++ {
		failLogin(e, c, ip, "hosting")
		c.add(time.Second)
	}
	if draws != 0 {
		t.Fatalf("%d draws before any block", draws)
	}
	// The fifth failure, observed twice without a look at the block between
	// them: the second one meets the block the first one set.
	r := req(c, ip, "hosting", "POST", "/wp-login.php")
	e.Check(r)
	e.Observe(r, Outcome{Forwarded: true, Response: Response{Status: 200}})
	bi, ok := e.ActiveBlock(netip.MustParseAddr(ip))
	if !ok || bi.Incident != "AAAA-AAA3" || draws != 2 || asked != 2 {
		t.Fatalf("block %+v after %d draws and %d questions, want the second draw: the first number is known", bi, draws, asked)
	}
	if bi.Taken {
		t.Fatal("a block the engine decided counts as taken from the group")
	}
	// The scenario triggers once more for the client that is blocked now (a
	// request that was under way when the block started).
	key, bits := KeyOf(netip.MustParseAddr(ip))
	e.fire(r, e.cfg.Load(), key, bits, trigger{scenario: config.ScenarioLoginBruteforce, count: 6, threshold: 5, window: 60})
	if draws != 2 || asked != 2 {
		t.Fatalf("a request of a blocked client drew a number: %d draws, %d questions", draws, asked)
	}
	if again, _ := e.ActiveBlock(netip.MustParseAddr(ip)); again.Incident != bi.Incident {
		t.Fatalf("the block changed its number: %s, was %s", again.Incident, bi.Incident)
	}
}

// A block from a record of the group keeps whether another node decided it,
// also as a kept block over a restart; Release names the incidents it ended.
func TestBlockKeepsWhoDecidedIt(t *testing.T) {
	e, _, c := newEngine(modes(nil))
	var own, taken []events.ActiveBlock
	e.Sink.Persist = func(ab events.ActiveBlock) { own = append(own, ab) }
	e.Sink.PersistTaken = func(ab events.ActiveBlock) { taken = append(taken, ab) }
	apply := func(ip, incident string, d time.Duration, isTaken bool) Key {
		key, bits := KeyOf(netip.MustParseAddr(ip))
		if !e.ApplyBlock(key, bits, BlockInfo{Scenario: DashboardSource, Since: c.t, Until: c.t.Add(d), Level: 1, Incident: incident, NetClass: "hosting", Duration: d, Taken: isTaken}) {
			t.Fatalf("block of %s not applied", ip)
		}
		return key
	}
	apply("203.0.113.1", "AAAA-AAA2", 15*time.Minute, true)
	apply("203.0.113.2", "AAAA-AAA3", 48*time.Hour, true)
	apply("203.0.113.3", "AAAA-AAA4", 48*time.Hour, false)
	e.SetAgentBlock(AgentBlock{IP: netip.MustParseAddr("203.0.113.4"), Source: DashboardSource, NetClass: "hosting", Duration: 48 * time.Hour, Incident: "AAAA-AAA5", Time: c.t})
	want := map[string]bool{"AAAA-AAA2": true, "AAAA-AAA3": true, "AAAA-AAA4": false, "AAAA-AAA5": false}
	for _, rb := range e.RunningBlocks() {
		if rb.Taken != want[rb.Incident] {
			t.Errorf("block %s: taken %v, want %v", rb.Incident, rb.Taken, want[rb.Incident])
		}
	}
	if len(taken) != 1 || taken[0].Incident != "AAAA-AAA3" || len(own) != 2 {
		t.Fatalf("kept as taken %v, as own %v", taken, own)
	}
	if key, ok := e.IncidentKey("AAAA-AAA3"); !ok || key.Addr().String() != "203.0.113.2" {
		t.Fatalf("key of the incident: %v %v", key, ok)
	}
	// Over a restart: the rows come back, and the store names those without
	// the mark of an own decision.
	e2, _, _ := newEngine(modes(nil))
	if n, _ := e2.RestoreBlocks(append(own, taken...), nil); n != 3 {
		t.Fatalf("%d blocks restored, want 3", n)
	}
	e2.TakenBlocks([]string{"203.0.113.2"})
	for _, rb := range e2.RunningBlocks() {
		if rb.Taken != want[rb.Incident] {
			t.Errorf("after the restart, block %s: taken %v, want %v", rb.Incident, rb.Taken, want[rb.Incident])
		}
	}
	if bi, _ := e2.ActiveBlock(netip.MustParseAddr("203.0.113.2")); !bi.Taken {
		t.Error("after the restart the taken block reads as an own decision")
	}
	if n, incidents := e.ReleaseIncidents(netip.MustParseAddr("203.0.113.1")); n != 1 || len(incidents) != 1 || incidents[0] != "AAAA-AAA2" {
		t.Fatalf("release ended %d blocks, incidents %v", n, incidents)
	}
	if n, incidents := e.ReleaseIncidents(netip.MustParseAddr("203.0.113.9")); n != 0 || len(incidents) != 0 {
		t.Fatalf("release of a client without a block: %d, %v", n, incidents)
	}
}

// With a full block table a block of the group has room only where it drops
// none that runs; DropIncident ends a block without a word, its kept row
// included.
func TestBlockRoomAndDropIncident(t *testing.T) {
	e, _, c := newEngine(modes(nil))
	e.blocks.per = 1 // one block in each part of the table
	var gone []string
	ended := 0
	e.Sink.Persist = func(events.ActiveBlock) {}
	e.Sink.Unpersist = func(k string) { gone = append(gone, k) }
	e.Sink.Ended = func(string, time.Time) { ended++ }
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}) }
	first, bits := KeyOf(addr(1))
	e.ApplyBlock(first, bits, BlockInfo{Scenario: DashboardSource, Since: c.t, Until: c.t.Add(48 * time.Hour), Level: 1, Incident: "AAAA-AAA2", NetClass: "hosting",
		Duration: 48 * time.Hour, Taken: true})
	room := e.BlockRoom()
	if !room(first) {
		t.Fatal("no room for the client whose block runs")
	}
	// Another client of the same part of the table.
	var other Key
	for i := 2; i < 5000; i++ {
		if k, _ := KeyOf(addr(i)); e.blocks.hash(k)%shards == e.blocks.hash(first)%shards {
			other = k
			break
		}
	}
	if !other.IsValid() {
		t.Fatal("no second client in the part of the table")
	}
	if room(other) || e.BlockRoom()(other) {
		t.Fatal("room for a block that would drop one that runs")
	}
	if !e.DropIncident("AAAA-AAA2") || e.IncidentRunning("AAAA-AAA2") {
		t.Fatal("the block did not end")
	}
	if ended != 0 || len(gone) != 1 || gone[0] != "198.18.0.1" {
		t.Fatalf("after the drop: %d reported as ended (want none), kept rows removed %v", ended, gone)
	}
	// The ended block is one a full table drops first: there is room now.
	if !e.BlockRoom()(other) {
		t.Fatal("no room although the only block of the part ended")
	}
}
