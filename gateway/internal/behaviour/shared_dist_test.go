package behaviour

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
)

// distGroup is n engines with the detectors of distributed attacks on
// respond, past their learning period, that tell each other their counts.
func distGroup(t *testing.T, n int) *group {
	g := &group{t: t}
	for i := 0; i < n; i++ {
		e, r, c := newDistEngine(distBehaviour(config.DistributedRespond), t0.Add(-30*24*time.Hour), false)
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

// spread sends n failed logins, each from a new address with a rotating
// user agent and one client stack, round robin over the nodes, 20 a second.
// With talk the nodes tell each other once a second.
func (g *group) spread(n int, fp string, talk bool) {
	for i := 0; i < n; i++ {
		e := g.engs[i%len(g.engs)]
		rq := req(g.c, fmt.Sprintf("198.18.%d.%d", i/250, i%250+1), "residential", "POST", "/wp-login.php")
		rq.UserAgent = rotatingUAs[i%len(rotatingUAs)]
		rq.Fingerprint, rq.FPKind, rq.Inconsistent = fp, FPHeaders, true
		if v := e.Check(rq); !v.Block && !v.RateLimited {
			e.Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}, HasUser: true, UserHash: HashUser(fmt.Sprintf("victim%d@example.org", i))})
		}
		g.c.add(50 * time.Millisecond)
		if talk && i%20 == 19 {
			g.tell()
		}
	}
}

// waveIDs returns the ids of the waves the nodes wrote an event for, per
// detector, and how many events that were.
func (g *group) waveIDs() (ids map[string]map[string]bool, events int) {
	ids = map[string]map[string]bool{}
	for _, r := range g.recs {
		for _, w := range r.waves() {
			if ids[w.Detector] == nil {
				ids[w.Detector] = map[string]bool{}
			}
			ids[w.Detector][w.WaveID] = true
			events++
		}
	}
	return ids, events
}

// Credential stuffing through 60 rotating senders, spread evenly over four
// nodes: each node sees 15 failed logins, below every threshold (20
// senders of one client stack, 30 failures on the route). Nodes that do not
// talk detect nothing; a group detects it as a single gateway would, as one
// wave per detector, and its response acts on every node.
func TestGroupDetectsAWaveSpreadOverItsNodes(t *testing.T) {
	const nodes, senders = 4, 60
	// Control: one gateway alone detects it.
	single := distGroup(t, 1)
	single.spread(senders, "abcdef012345", false)
	want, _ := single.waveIDs()
	if len(want[config.DetectorFingerprintCluster]) != 1 || len(want[config.DetectorRouteWave]) != 1 {
		t.Fatalf("a single gateway detects %v; the test needs a wave of the client stack and of the route", want)
	}
	// Control: four nodes that do not talk detect nothing.
	alone := distGroup(t, nodes)
	alone.spread(senders, "abcdef012345", false)
	if ids, n := alone.waveIDs(); n != 0 {
		t.Fatalf("four nodes that do not talk detected %v; the test needs every node below its thresholds", ids)
	}

	g := distGroup(t, nodes)
	g.spread(senders, "abcdef012345", true)
	g.tell()
	ids, _ := g.waveIDs()
	for det := range want {
		if len(ids[det]) != 1 {
			t.Errorf("%s: the group recorded %d waves, a single gateway one: %v", det, len(ids[det]), ids[det])
		}
	}
	// Every node holds every wave under the one id, whether it wrote the
	// event or was told.
	for det, set := range ids {
		for id := range set {
			for i, e := range g.engs {
				w, ok := e.WaveByID(id)
				if !ok || w.Detector != det || !w.Active(g.c.t) {
					t.Errorf("node %d does not hold the running wave %s of %s: %+v (held: %v)", i, id, det, w, ok)
				}
			}
		}
	}
	// The response acts on every node: the route is tightened to 10 a
	// minute for requests without a session cookie, whichever node they
	// reach.
	for i, e := range g.engs {
		limited := 0
		for j := 0; j < 15; j++ {
			rq := req(g.c, fmt.Sprintf("203.0.113.%d", j+1), "residential", "POST", "/wp-login.php")
			if v := e.Check(rq); v.RateLimited && v.LimitID == "distributed" {
				limited++
			}
		}
		if limited < 4 {
			t.Errorf("node %d limited %d of 15 logins on the tightened route", i, limited)
		}
	}
	// It ends once: each node ends the wave at its time, and only nodes
	// that wrote its event write its end.
	g.c.add(3 * time.Hour)
	for i, e := range g.engs {
		e.Sweep()
		if len(g.recs[i].ended()) > len(g.recs[i].waves()) {
			t.Errorf("node %d wrote %d ends for %d waves it recorded", i, len(g.recs[i].ended()), len(g.recs[i].waves()))
		}
	}
}

// A request shape used by 24 senders, spread over three nodes (8 each, the
// threshold is 20): the group blocks the shape on every node under one
// incident, and an end by the operator on one node ends it on all.
func TestGroupShapeWaveAndItsEnd(t *testing.T) {
	sig := "sha256:" + fmt.Sprintf("%064x", 42)
	run := func(g *group, talk bool) {
		for i := 0; i < 24; i++ {
			rq := req(g.c, fmt.Sprintf("203.0.113.%d", i+1), "hosting", "POST", "/wp-json/gallery/v1/upload")
			g.engs[i%len(g.engs)].Observe(rq, Outcome{Shape: sig, ShapeRules: []int{933100}})
			g.c.add(100 * time.Millisecond)
			if talk && i%10 == 9 {
				g.tell()
			}
		}
		if talk {
			g.tell()
		}
	}
	alone := distGroup(t, 3)
	run(alone, false)
	for i, e := range alone.engs {
		if _, ok := e.ShapeBlocked(sig, alone.c.t); ok {
			t.Fatalf("node %d of three that do not talk blocks the shape; the test needs it below the threshold", i)
		}
	}
	g := distGroup(t, 3)
	run(g, true)
	incidents := map[string]bool{}
	for i, e := range g.engs {
		inc, ok := e.ShapeBlocked(sig, g.c.t)
		if !ok || inc == "" {
			t.Fatalf("node %d does not block the shape", i)
		}
		incidents[inc] = true
	}
	if ids, _ := g.waveIDs(); len(ids[config.DetectorShapeWave]) != 1 || len(incidents) != 1 {
		t.Errorf("the group recorded %d shape waves under %d incidents, want one of each", len(ids[config.DetectorShapeWave]), len(incidents))
	}
	// The operator ends it on the last node, which may have been told only.
	var id string
	ids, _ := g.waveIDs()
	for k := range ids[config.DetectorShapeWave] {
		id = k
	}
	if _, ok, active := g.engs[2].EndWave(id); !ok || !active {
		t.Fatalf("EndWave on node 2: known %v, active %v", ok, active)
	}
	g.tell()
	ended := 0
	for i, e := range g.engs {
		if _, ok := e.ShapeBlocked(sig, g.c.t); ok {
			t.Errorf("node %d still blocks the shape the operator released", i)
		}
		ended += len(g.recs[i].ended())
	}
	if ended != 1 {
		t.Errorf("the end by the operator was recorded %d times", ended)
	}
}

// One account under attack from many senders: the wait between attempts
// holds for the group, so spreading the attempts over the nodes buys none.
func TestGroupAccountSlowdown(t *testing.T) {
	g := distGroup(t, 3)
	user := HashUser("vorstand@verein.example")
	for i := 0; i < 15; i++ {
		rq := req(g.c, fmt.Sprintf("198.18.1.%d", i+1), "residential", "POST", "/wp-login.php")
		g.engs[i%3].Observe(rq, Outcome{Forwarded: true, Response: Response{Status: 200}, HasUser: true, UserHash: user})
		g.c.add(200 * time.Millisecond)
		if i%5 == 4 {
			g.tell()
		}
	}
	g.tell()
	for i, e := range g.engs {
		rq := req(g.c, "198.18.9.9", "residential", "POST", "/wp-login.php")
		if v := e.AccountWait(rq, user); !v.RateLimited {
			t.Errorf("node %d lets an attempt on the attacked account pass at once", i)
		}
		// Another account is not slowed down.
		if v := e.AccountWait(rq, HashUser("kasse@verein.example")); v.RateLimited {
			t.Errorf("node %d slows down an account nobody attacked", i)
		}
	}
	if ids, _ := g.waveIDs(); len(ids[config.DetectorAccountWave]) != 1 {
		t.Errorf("the group recorded %d account waves, want one", len(ids[config.DetectorAccountWave]))
	}
}

// What a node is told is input from outside: unknown websites and routes,
// lists beyond their bounds and waves that do not fit are left out, the
// tables stay within their capacities, and nothing is decided or recorded.
func TestApplyDistIsBounded(t *testing.T) {
	g := distGroup(t, 1)
	e, r := g.engs[0], g.recs[0]
	e.KnownHost = func(h string) bool { return h == "verein.example" }
	many := make([]uint64, 100000)
	for i := range many {
		many[i] = uint64(i) * 0x9e3779b97f4a7c15
	}
	dc := &DistCounts{}
	for i := 0; i < 5000; i++ {
		dc.Routes = append(dc.Routes, RouteCount{Host: fmt.Sprintf("h%d.example", i), Route: "/wp-login.php", Failed: 1 << 40, Senders: many})
		dc.Routes = append(dc.Routes, RouteCount{Host: "verein.example", Route: fmt.Sprintf("/not-a-route/%d", i), Failed: 1 << 40, Senders: many})
		dc.Shapes = append(dc.Shapes, ShapeCount{Sig: fmt.Sprintf("sha256:%064x", i), Senders: many})
		dc.FPs = append(dc.FPs, FPCount{FP: fmt.Sprintf("%012x", i), Host: "verein.example", Route: "/wp-login.php", Senders: many, UAs: make([]uint32, 1000)})
		dc.Accounts = append(dc.Accounts, AccountCount{User: uint64(i), Failed: -5, Senders: many, Flagged: true})
	}
	long := strings.Repeat("x", 100000)
	now := g.c.t.UnixMilli()
	dc.Waves = []WaveNote{
		{ID: "not-an-id", Detector: config.DetectorShapeWave, Key: "sig", Action: config.DistributedRespond, Started: now, Until: now + 60000},
		{ID: derivedID("1"), Detector: "no_such_detector", Key: "sig", Action: config.DistributedRespond, Started: now, Until: now + 60000},
		{ID: derivedID("2"), Detector: config.DetectorRouteWave, Host: "other.example", Key: "/wp-login.php", Action: config.DistributedRespond, Started: now, Until: now + 60000},
		{ID: derivedID("3"), Detector: config.DetectorRouteWave, Host: "verein.example", Key: "/not-a-route", Action: config.DistributedRespond, Started: now, Until: now + 60000},
		{ID: derivedID("4"), Detector: config.DetectorShapeWave, Key: long, Action: config.DistributedRespond, Started: now, Until: now + 60000},
		{ID: derivedID("5"), Detector: config.DetectorShapeWave, Key: "sig", Action: config.DistributedRespond, Started: now + 3600000, Until: now + 7200000},
		{ID: derivedID("6"), Detector: config.DetectorShapeWave, Key: "old", Action: config.DistributedRespond, Started: now - 30*24*3600000, Until: now + 60000},
	}
	e.ApplyCounts(&Counts{Dist: dc})
	routes, accounts, fps, shapes, waves := e.DistSizes()
	if routes != 0 {
		t.Errorf("%d routes of unknown websites or routes were taken", routes)
	}
	if accounts > shareDistEntries || fps > shareDistEntries || shapes > shareDistEntries {
		t.Errorf("tables beyond what one message may hold: accounts %d, fingerprints %d, shapes %d", accounts, fps, shapes)
	}
	if waves != 0 {
		t.Errorf("%d waves that do not fit were adopted", waves)
	}
	if len(r.waves()) != 0 || len(r.ended()) != 0 || len(r.incidents) != 0 {
		t.Errorf("being told something recorded: %d waves, %d ends, %d incidents", len(r.waves()), len(r.ended()), len(r.incidents))
	}
	// A wave that fits is held, and enforced only as far as this node
	// would itself: a node in the test profile enforces nothing.
	note := WaveNote{ID: derivedID("7"), Detector: config.DetectorShapeWave, Key: "sha256:abc", RequestSig: "sha256:abc", Action: config.DistributedRespond,
		Started: now, Until: now + 20*60000, Incident: "ABCD-EFGH", Senders: 25, Count: 25, Threshold: 20, WindowS: 60}
	e.ApplyCounts(&Counts{Dist: &DistCounts{Waves: []WaveNote{note}}})
	if inc, ok := e.ShapeBlocked("sha256:abc", g.c.t); !ok || inc != "ABCD-EFGH" {
		t.Errorf("a wave of the group is not enforced: %q %v", inc, ok)
	}
	if len(r.waves()) != 0 {
		t.Error("a wave another node detected was recorded here again")
	}
	obs, ro, _ := newDistEngine(distBehaviour(config.DistributedRespond), t0.Add(-30*24*time.Hour), true)
	obs.Now = g.c.now
	obs.EnableSharing()
	obs.ApplyCounts(&Counts{Dist: &DistCounts{Waves: []WaveNote{note}}})
	if _, ok := obs.ShapeBlocked("sha256:abc", g.c.t); ok {
		t.Error("a node in the test profile enforces a wave of the group")
	}
	if w, ok := obs.WaveByID(note.ID); !ok || w.Action != config.DistributedObserve || w.Incident != "" {
		t.Errorf("the observing node holds %+v (held %v)", w, ok)
	}
	if len(ro.waves()) != 0 {
		t.Error("the observing node recorded the wave again")
	}
}

// A single gateway notes nothing for others and names its waves at random.
func TestSingleGatewaySharesNoDetectorCounts(t *testing.T) {
	e, r, c := newDistEngine(distBehaviour(config.DistributedRespond), t0.Add(-30*24*time.Hour), false)
	stuffing(e, c, 40, "abcdef012345", "residential")
	if e.TakeCounts() != nil {
		t.Error("a single gateway has counts to tell")
	}
	ws := r.waves()
	if len(ws) == 0 {
		t.Fatal("no wave")
	}
	if ws[0].WaveID == groupWaveID(ws[0].Detector, "verein.example", "/wp-login.php", t0) {
		t.Error("a single gateway derives the id of its wave")
	}
}
