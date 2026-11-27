//go:build !release

package app_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The blocks of a group by incident (contracts/cluster.md section 5, D109): one record per block, a lift as a record of its own.

// recordIDs are the ids of the records of a class a node holds, sorted.
func recordIDs(t *testing.T, g *groupNode, class string) []string {
	t.Helper()
	recs, err := g.h.App.Cluster.State(class)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, r := range recs {
		if !r.Deleted {
			out = append(out, r.ID)
		}
	}
	sort.Strings(out)
	return out
}

func holds(t *testing.T, g *groupNode, class string, ids ...string) bool {
	t.Helper()
	sort.Strings(ids)
	return slices.Equal(recordIDs(t, g, class), ids)
}

// rawRecords reads the records of a node as they lie in its cluster.db.
func rawRecords(t *testing.T, g *groupNode, where string, args ...any) []json.RawMessage {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(g.clusterDir(), "cluster.db")+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT raw FROM records WHERE `+where, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

// carrying names the records in the cluster.db of a node whose id or data
// carries the text, as class and id.
func carrying(t *testing.T, g *groupNode, text string) []string {
	t.Helper()
	var out []string
	for _, raw := range rawRecords(t, g, "1") {
		var rec contract.Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		data, _ := rec.Payload()
		if strings.Contains(rec.ID, text) || strings.Contains(string(data), text) {
			out = append(out, rec.Class+" "+rec.ID)
		}
	}
	return out
}

// release releases an address in the dashboard of a node.
func (g *groupNode) release(t *testing.T, ip string) {
	t.Helper()
	if code, body := g.h.API("POST", "/behaviour/release", map[string]any{"ip": ip}); code != 200 {
		t.Fatalf("release of %s on %s: %d %s", ip, g.name, code, body)
	}
}

// unblock unblocks an incident in the dashboard of a node. The incident of
// a block travels with the events of its node; the blocks of these tests
// are set in the engine and have none, so the node gets one here.
func (g *groupNode) unblock(t *testing.T, incident, ip string) {
	t.Helper()
	g.unblockOf(t, incident, ip, "dashboard")
}

// unblockOf is unblock for an incident of a block of the source.
func (g *groupNode) unblockOf(t *testing.T, incident, ip, source string) {
	t.Helper()
	ctx := context.Background()
	if err := g.h.App.Store.InsertIncident(store.Foreign(ctx), &store.Incident{Incident: incident, Time: time.Now(), IP: ip, Status: "blocked", Sources: []string{source}}); err != nil {
		t.Fatal(err)
	}
	if code, body := g.h.API("POST", "/incidents/"+incident+"/unblock", map[string]any{}); code != 200 {
		t.Fatalf("unblock of %s on %s: %d %s", incident, g.name, code, body)
	}
}

// agentGroup is a group whose nodes serve the agent API.
func agentGroup(t *testing.T, names ...string) []*groupNode {
	t.Helper()
	nodes := newGroup(t, names...)
	for _, g := range nodes {
		g.extra = agentYAML
		g.start(t)
	}
	return nodes
}

// agentLift lifts one incident through the agent API of a node. As for
// unblock, the node gets the incident the events of its node would bring.
func (g *groupNode) agentLift(t *testing.T, incident, ip string) {
	t.Helper()
	ctx := context.Background()
	if err := g.h.App.Store.InsertIncident(store.Foreign(ctx), &store.Incident{Incident: incident, Time: time.Now(), IP: ip, Status: "blocked", Sources: []string{"dashboard"}}); err != nil {
		t.Fatal(err)
	}
	if w := g.agentCall(t, "POST", "/agent/v0/incidents/"+incident+"/lift", `{"reason":"false alarm"}`); w.Code != 200 {
		t.Fatalf("lift of %s by an agent on %s: %d %s", incident, g.name, w.Code, w.Body)
	}
}

// writeStopped writes into the store of a node that is stopped, with the
// node's key and the clock now (nil: the clock of the machine).
func (g *groupNode) writeStopped(t *testing.T, now func() time.Time, f func(n *cluster.Node)) {
	t.Helper()
	n, err := cluster.Open(cluster.Options{Dir: g.clusterDir(), Listen: g.addr, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	f(n)
}

// blockAnew blocks a client under a new incident on a node whose block
// table dropped its block. The node starts the dropped block again from its
// record with its next round, so the new decision has to come first.
func (g *groupNode) blockAnew(t *testing.T, ip, incident string, d time.Duration) {
	t.Helper()
	addr := netip.MustParseAddr(ip)
	for try := 0; try < 50; try++ {
		g.h.App.Behaviour.EvictBlock(addr)
		g.block(ip, incident, d)
		if g.blocked(ip) == incident {
			return
		}
	}
	t.Fatalf("%s: the block %s did not start before the dropped one came back", g.name, incident)
}

// watchBlocked samples whether the client is blocked on each node, from now
// until stop: at every moment no change of a node's blocks is under way.
// stop reports the nodes that served the client for a moment.
func watchBlocked(t *testing.T, ip string, nodes ...*groupNode) (stop func()) {
	t.Helper()
	addr := netip.MustParseAddr(ip)
	done := make(chan struct{})
	gaps := make([]atomic.Int64, len(nodes))
	var wg sync.WaitGroup
	for i, g := range nodes {
		wg.Add(1)
		go func(i int, x *app.App) {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if x.GroupBlocked(addr) == "" {
					gaps[i].Add(1)
				}
				time.Sleep(200 * time.Microsecond)
			}
		}(i, g.h.App)
	}
	return func() {
		t.Helper()
		close(done)
		wg.Wait()
		for i, g := range nodes {
			if n := gaps[i].Load(); n > 0 {
				t.Errorf("%s served the client in between (%d samples without a block), and one block of it ran the whole time", g.name, n)
			}
		}
	}
}

// notReleased checks that no node released the address: the end of one
// block of a client is not a release of the client.
func notReleased(t *testing.T, ip string, since time.Time, nodes ...*groupNode) {
	t.Helper()
	for _, g := range nodes {
		if g.h.App.Behaviour.ReleasedSince(netip.MustParseAddr(ip), since) {
			t.Errorf("%s released the client, and one of its blocks was lifted", g.name)
		}
	}
}

func blockUntil() time.Time { return time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second) }

// writtenBlock is the data of a block record a test writes by hand.
func writtenBlock(ip, node string, until time.Time) *contract.IncidentBlock {
	return &contract.IncidentBlock{Client: ip, Bits: 32, Scope: contract.ScopeGateway, Source: "dashboard", Level: 1, Since: contract.TimeText(until.Add(-15 * time.Minute)),
		Until: contract.TimeText(until), DurationS: 900, NetClass: "hosting", Node: node}
}

func inService(t *testing.T, nodes ...*groupNode) {
	t.Helper()
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" is in step", func() bool { return g.h.App.InService() })
	}
}

// a: two nodes block one client at the same moment under two incidents.
// Every node holds both records; the lift of one incident (an agent names
// one) ends that block alone, the client stays blocked on every node; the
// lift of the second unblocks it everywhere. ("Freigeben" in the dashboard
// means the client and lifts both: TestFreigebenLiftsEveryBlockOfTheClient.)
func TestTwoBlocksOfOneClientStandSideBySide(t *testing.T) {
	app.Parallel(t)
	nodes := agentGroup(t, "web-1", "web-2", "web-3")
	for _, g := range nodes {
		g.h.Login()
	}
	inService(t, nodes...)
	const ip, x, y = "203.0.113.31", "AAAA-AAA2", "BBBB-AAA3"
	nodes[0].block(ip, x, 15*time.Minute)
	nodes[1].block(ip, y, 15*time.Minute)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" holds both blocks", func() bool { return holds(t, g, contract.ClassIncidentBlocks, x, y) && g.blocked(ip) != "" })
	}
	if nodes[0].blocked(ip) != x || nodes[1].blocked(ip) != y {
		t.Fatalf("each node runs the block it decided: web-1 %q, web-2 %q", nodes[0].blocked(ip), nodes[1].blocked(ip))
	}
	start := time.Now()
	stop := watchBlocked(t, ip, nodes...)
	nodes[2].agentLift(t, x, ip)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" ended the released block and runs the other", func() bool {
			return holds(t, g, contract.ClassIncidentBlocks, y) && holds(t, g, contract.ClassLifts, x) && g.blocked(ip) == y
		})
	}
	time.Sleep(time.Second)
	stop()
	notReleased(t, ip, start, nodes...)
	for _, g := range nodes {
		if got := g.blocked(ip); got != y {
			t.Errorf("%s runs %q a second after one of two blocks was released, want %q", g.name, got, y)
		}
	}
	nodes[0].unblock(t, y, ip)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" serves the client again", func() bool { return g.blocked(ip) == "" && holds(t, g, contract.ClassIncidentBlocks) })
	}
}

// b: a block a full table drops on one node is no lift. Nothing is written,
// and the block stays on the others.
func TestBlockAFullTableDropsIsNoLift(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	const ip, x = "203.0.113.32", "CCCC-AAA2"
	a.block(ip, x, 15*time.Minute)
	b.h.WaitFor("web-2 holds the block", func() bool { return b.blocked(ip) == x })
	a.h.App.Behaviour.EvictBlock(netip.MustParseAddr(ip))
	// web-1 holds the record of the block, so the block starts there again.
	a.h.WaitFor("web-1 runs the dropped block again", func() bool { return a.blocked(ip) == x })
	time.Sleep(1500 * time.Millisecond)
	for _, g := range []*groupNode{a, b} {
		if lifts := recordIDs(t, g, contract.ClassLifts); len(lifts) != 0 {
			t.Errorf("%s holds the lifts %v for a block a full table dropped", g.name, lifts)
		}
		if !holds(t, g, contract.ClassIncidentBlocks, x) {
			t.Errorf("%s lost the record of the block: %v", g.name, recordIDs(t, g, contract.ClassIncidentBlocks))
		}
	}
	if got := b.blocked(ip); got != x {
		t.Errorf("web-2 runs %q after web-1's table dropped the block, want %q", got, x)
	}
}

// c: dropped by a full table and blocked anew under another incident on
// that node: releasing the new incident ends the new block alone.
func TestBlockAfterADroppedOneIsABlockOfItsOwn(t *testing.T) {
	app.Parallel(t)
	nodes := agentGroup(t, "web-1", "web-2")
	a, b := nodes[0], nodes[1]
	inService(t, a, b)
	const ip, x, y = "203.0.113.33", "DDDD-AAA2", "DDDD-AAA3"
	a.block(ip, x, 15*time.Minute)
	b.h.WaitFor("web-2 holds the block", func() bool { return b.blocked(ip) == x })
	a.blockAnew(t, ip, y, 15*time.Minute)
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" holds both blocks", func() bool { return holds(t, g, contract.ClassIncidentBlocks, x, y) })
	}
	if a.blocked(ip) != y || b.blocked(ip) != x {
		t.Fatalf("web-1 runs %q (want %q), web-2 runs %q (want %q)", a.blocked(ip), y, b.blocked(ip), x)
	}
	start := time.Now()
	stop := watchBlocked(t, ip, a, b)
	defer notReleased(t, ip, start, a, b)
	defer stop()
	a.agentLift(t, y, ip)
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" ended the new block and runs the first", func() bool {
			return holds(t, g, contract.ClassIncidentBlocks, x) && holds(t, g, contract.ClassLifts, y) && g.blocked(ip) == x
		})
	}
}

// d: a lift ends its block whichever of the two records arrives first. A
// block record handed to a node that holds the lift does not start the
// block and is not stored, also on a third node that never saw the block.
func TestLiftBeforeTheBlockRecordKeepsTheBlockFromStarting(t *testing.T) {
	app.Parallel(t)
	nodes := trio(t)
	a, b, c := nodes[0], nodes[1], nodes[2]
	for _, g := range nodes {
		g.h.Login()
	}
	inService(t, nodes...)
	blockRecord := func(incident string) json.RawMessage {
		raws := rawRecords(t, a, "class = ? AND id = ?", contract.ClassIncidentBlocks, incident)
		if len(raws) != 1 {
			t.Fatalf("web-1 holds %d records of the block %s", len(raws), incident)
		}
		return raws[0]
	}
	// The block first, then the lift; then the block record once more.
	const ip1, x1 = "203.0.113.34", "EEEE-AAA2"
	a.block(ip1, x1, 15*time.Minute)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" runs the block", func() bool { return g.blocked(ip1) == x1 })
	}
	raw1 := blockRecord(x1)
	b.unblock(t, x1, ip1)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" ended the block", func() bool { return g.blocked(ip1) == "" && holds(t, g, contract.ClassIncidentBlocks) })
	}
	for _, g := range nodes {
		if _, err := g.h.App.Cluster.Take(raw1); err != nil {
			t.Fatal(err)
		}
	}
	// The lift first: web-3 was away for the block and its lift, takes the
	// lift when it returns and is handed the block record after it.
	const ip2, x2 = "203.0.113.35", "EEEE-AAA3"
	if err := c.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.block(ip2, x2, 15*time.Minute)
	b.h.WaitFor("web-2 runs the second block", func() bool { return b.blocked(ip2) == x2 })
	raw2 := blockRecord(x2)
	b.unblock(t, x2, ip2)
	a.h.WaitFor("web-1 ended the second block", func() bool { return a.blocked(ip2) == "" })
	c.start(t)
	c.h.WaitFor("web-3 holds the lift", func() bool { return slices.Contains(recordIDs(t, c, contract.ClassLifts), x2) })
	if got := c.blocked(ip2); got != "" {
		t.Fatalf("web-3 runs %q before it was handed the block record", got)
	}
	if _, err := c.h.App.Cluster.Take(raw2); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	for _, g := range nodes {
		for _, ip := range []string{ip1, ip2} {
			if got := g.blocked(ip); got != "" {
				t.Errorf("%s runs %q for %s: a block record that came after its lift started the block", g.name, got, ip)
			}
		}
		if ids := recordIDs(t, g, contract.ClassIncidentBlocks); len(ids) != 0 {
			t.Errorf("%s stored the block records %v although it holds their lifts", g.name, ids)
		}
	}
}

// e: a release on a node that does not run the block ends it on the others:
// a node in mode observe, and a node whose own allowlist names the address.
func TestReleaseOnANodeThatDoesNotRunTheBlock(t *testing.T) {
	app.Parallel(t)
	nodes := newGroup(t, "web-1", "web-2", "web-3")
	a, b, c := nodes[0], nodes[1], nodes[2]
	c.mode = "observe"
	for _, g := range nodes {
		g.start(t)
	}
	for _, g := range nodes {
		g.h.Login()
	}
	inService(t, nodes...)
	const ip, x = "203.0.113.36", "FFFF-AAA2"
	a.block(ip, x, 15*time.Minute)
	b.h.WaitFor("web-2 runs the block", func() bool { return b.blocked(ip) == x })
	c.h.WaitFor("web-3 holds the record of the block", func() bool { return holds(t, c, contract.ClassIncidentBlocks, x) })
	if got := c.blocked(ip); got != "" {
		t.Fatalf("web-3 blocks %q in mode observe", got)
	}
	c.release(t, ip)
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" ended the block web-3 released", func() bool { return g.blocked(ip) == "" })
	}
	// 192.0.2.10 is on the allowlist of the harness; the engine of web-1
	// holds a block of it all the same (set below the allowlist).
	const own, y = "192.0.2.10", "FFFF-AAA3"
	a.block(own, y, 15*time.Minute)
	b.h.WaitFor("web-2 holds the record of the second block", func() bool { return holds(t, b, contract.ClassIncidentBlocks, y) })
	if got := b.blocked(own); got != "" {
		t.Fatalf("web-2 blocks an address of its own allowlist: %q", got)
	}
	b.release(t, own)
	a.h.WaitFor("web-1 ended the block web-2 released", func() bool { return a.blocked(own) == "" })
}

// f: a lift whose write to the group fails is written in a later round, and
// it survives a restart of the node between the release and the write.
func TestLiftIsWrittenUntilItsWriteSucceeds(t *testing.T) {
	a, b := pair(t)
	b.h.Login()
	var fail atomic.Bool
	failing := b.h.App
	defer app.SetTestLiftWrite(func(x *app.App, _ string) error {
		if x == failing && fail.Load() {
			return errors.New("test: the store of the group does not take the write")
		}
		return nil
	})()
	const ip1, x1 = "203.0.113.37", "GGGG-AAA2"
	fail.Store(true)
	a.block(ip1, x1, 15*time.Minute)
	b.h.WaitFor("web-2 runs the block", func() bool { return b.blocked(ip1) == x1 })
	b.release(t, ip1)
	time.Sleep(1200 * time.Millisecond)
	if a.blocked(ip1) != x1 || b.blocked(ip1) != "" {
		t.Fatalf("while the write fails: web-1 %q (want the block), web-2 %q (want none)", a.blocked(ip1), b.blocked(ip1))
	}
	fail.Store(false)
	a.h.WaitFor("web-1 ended the block when the write went through", func() bool { return a.blocked(ip1) == "" })

	// The same with a restart of web-2 before the write went through.
	const ip2, x2 = "203.0.113.38", "GGGG-AAA3"
	fail.Store(true)
	a.block(ip2, x2, 15*time.Minute)
	b.h.WaitFor("web-2 runs the second block", func() bool { return b.blocked(ip2) == x2 })
	b.release(t, ip2)
	time.Sleep(600 * time.Millisecond)
	if a.blocked(ip2) != x2 {
		t.Fatalf("web-1 runs %q before the lift was written", a.blocked(ip2))
	}
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	b.start(t) // a new app: the hook holds the old one and fails no write of it
	a.h.WaitFor("web-1 ended the block after the restart of web-2", func() bool { return a.blocked(ip2) == "" })
	if got := b.blocked(ip2); got != "" {
		t.Errorf("web-2 runs %q after its restart, and the address was released there", got)
	}
	b.h.WaitFor("web-2 holds the lift it wrote", func() bool { return slices.Contains(recordIDs(t, b, contract.ClassLifts), x2) })
}

// g: a lift that arrives late does not end a newer block of the same
// client: it names its incident, and the newer block has another.
func TestLateLiftLeavesANewerBlockOfTheClientAlone(t *testing.T) {
	a, b := pair(t)
	b.h.Login()
	var fail atomic.Bool
	failing := b.h.App
	defer app.SetTestLiftWrite(func(x *app.App, _ string) error {
		if x == failing && fail.Load() {
			return errors.New("test: web-2 is cut off")
		}
		return nil
	})()
	const ip, x, y = "203.0.113.39", "HHHH-AAA2", "HHHH-AAA3"
	a.block(ip, x, 15*time.Minute)
	b.h.WaitFor("web-2 runs the block", func() bool { return b.blocked(ip) == x })
	fail.Store(true)
	b.release(t, ip)
	// Meanwhile the block ends on web-1 without a lift, and the client is
	// blocked anew there.
	a.blockAnew(t, ip, y, 15*time.Minute)
	b.h.WaitFor("web-2 runs the newer block", func() bool { return b.blocked(ip) == y })
	fail.Store(false)
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" holds the late lift and the newer block", func() bool {
			return holds(t, g, contract.ClassLifts, x) && holds(t, g, contract.ClassIncidentBlocks, y)
		})
	}
	time.Sleep(time.Second)
	for _, g := range []*groupNode{a, b} {
		if got := g.blocked(ip); got != y {
			t.Errorf("%s runs %q after the late lift of %s, want the newer block %s", g.name, got, x, y)
		}
	}
}

// h: a node that was away while an address was erased returns with its
// block from before the erasure. The block does not start on the others and
// ends on the node that returns. A block set later than the bound of
// clocks after the erasure is a new decision and stands.
func TestErasureEndsTheBlockANodeBringsBack(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	ctx := context.Background()
	a.h.Login()
	b.h.WaitFor("web-2 knows the user", func() bool { return b.h.App.Store.HasUsers(ctx) })
	const ip, x, y = "203.0.113.40", "JJJJ-AAA2", "JJJJ-AAA3"
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.block(ip, x, 15*time.Minute)
	a.h.WaitFor("web-1 wrote the record of its block", func() bool { return holds(t, a, contract.ClassIncidentBlocks, x) })
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	b.h.Login()
	if code, body := b.h.API("POST", "/privacy/delete", map[string]any{"ip": ip, "confirm": true}); code != 200 {
		t.Fatalf("erasure on web-2: %d %s", code, body)
	}
	a.start(t)
	a.h.WaitFor("web-1 ended its block from before the erasure", func() bool { return a.blocked(ip) == "" && holds(t, a, contract.ClassIncidentBlocks) })
	time.Sleep(1500 * time.Millisecond)
	for _, g := range []*groupNode{a, b} {
		if got := g.blocked(ip); got != "" {
			t.Errorf("%s runs %q: the block from before the erasure came back", g.name, got)
		}
		if ids := recordIDs(t, g, contract.ClassIncidentBlocks); len(ids) != 0 {
			t.Errorf("%s holds the block records %v of an erased client", g.name, ids)
		}
	}
	// A block decided within the bound of clocks after the erasure runs on
	// no node, the node that decided it included: the erasure wins.
	const z = "JJJJ-AAA4"
	a.block(ip, z, 15*time.Minute)
	a.h.WaitFor("web-1 ended the block it decided right after the erasure", func() bool { return a.blocked(ip) == "" })
	time.Sleep(600 * time.Millisecond)
	for _, g := range []*groupNode{a, b} {
		if got, ids := g.blocked(ip), recordIDs(t, g, contract.ClassIncidentBlocks); got != "" || len(ids) != 0 {
			t.Errorf("%s runs %q and holds %v for a block from the minute after the erasure", g.name, got, ids)
		}
	}
	// Later than the bound of clocks after the erasure.
	a.h.App.Behaviour.SetAgentBlock(behaviour.AgentBlock{IP: netip.MustParseAddr(ip), Source: behaviour.DashboardSource, NetClass: "hosting", Duration: 15 * time.Minute,
		Incident: y, Time: time.Now().Add(contract.MaxClockAhead + 2*time.Second)})
	b.h.WaitFor("web-2 runs the block set after the erasure", func() bool { return b.blocked(ip) == y })
	time.Sleep(time.Second)
	for _, g := range []*groupNode{a, b} {
		if got := g.blocked(ip); got != y || !holds(t, g, contract.ClassIncidentBlocks, y) {
			t.Errorf("%s runs %q and holds %v: a block set after the erasure does not stand", g.name, got, recordIDs(t, g, contract.ClassIncidentBlocks))
		}
	}
}

// i: after a lift no record in the cluster.db of any node carries the
// address of the client, and the lift names none.
func TestLiftedBlockLeavesNoAddressInTheStore(t *testing.T) {
	app.Parallel(t)
	nodes := trio(t)
	nodes[1].h.Login()
	const ip, x = "203.0.113.41", "KKKK-AAA2"
	nodes[0].block(ip, x, 15*time.Minute)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" runs the block and holds its record, with the address", func() bool { return g.blocked(ip) == x && len(carrying(t, g, ip)) > 0 })
	}
	nodes[1].release(t, ip)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" holds the lift and no record with the address", func() bool {
			return holds(t, g, contract.ClassLifts, x) && len(carrying(t, g, ip)) == 0
		})
		for _, raw := range rawRecords(t, g, "class = ?", contract.ClassLifts) {
			var rec contract.Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				t.Fatal(err)
			}
			if data, _ := rec.Payload(); string(data) != `{"node":"web-2"}` {
				t.Errorf("%s: the lift carries %s, want the name of the node alone", g.name, data)
			}
		}
	}
}

// j: a block record whose clock is later than the lift of its incident (a
// node up to 60 s ahead) does not bring the block back.
func TestBlockRecordWithALaterClockDoesNotBeatItsLift(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	ctx := context.Background()
	const ip, x = "203.0.113.42", "LLLL-AAA2"
	if err := a.h.App.Store.NoteLifts(ctx, time.Now(), x); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 holds the lift", func() bool { return holds(t, b, contract.ClassLifts, x) })
	lifts, err := b.h.App.Cluster.State(contract.ClassLifts)
	if err != nil || len(lifts) != 1 {
		t.Fatal(err, len(lifts))
	}
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	// web-2 writes the block of that incident with a clock 50 s ahead.
	ahead := func() time.Time { return time.Now().Add(50 * time.Second) }
	b.writeStopped(t, ahead, func(n *cluster.Node) {
		until := blockUntil()
		rec, err := n.Publish(contract.ClassIncidentBlocks, x, writtenBlock(ip, "web-2", until), false, until)
		if err != nil {
			t.Fatal(err)
		}
		if rec.HLC <= lifts[0].HLC {
			t.Fatalf("the block record is not later than the lift: %d, %d", rec.HLC, lifts[0].HLC)
		}
	})
	b.start(t)
	inService(t, a, b)
	time.Sleep(2 * time.Second)
	for _, g := range []*groupNode{a, b} {
		if got := g.blocked(ip); got != "" {
			t.Errorf("%s runs %q: a block record with a later clock beat the lift of its incident", g.name, got)
		}
		if ids := recordIDs(t, g, contract.ClassIncidentBlocks); len(ids) != 0 {
			t.Errorf("%s stored the block records %v although it holds the lift", g.name, ids)
		}
	}
}

// l: no echo. In a group of three one release leaves one record of class
// lifts, written by the node the person released on; a block that ends at
// its time leaves none.
func TestOneReleaseIsOneLiftOfOneNode(t *testing.T) {
	app.Parallel(t)
	nodes := trio(t)
	nodes[1].h.Login()
	inService(t, nodes...)
	const ip, x = "203.0.113.46", "NNNN-AAA2"
	nodes[0].block(ip, x, 15*time.Minute)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" runs the block", func() bool { return g.blocked(ip) == x })
	}
	nodes[1].release(t, ip)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" ended the block", func() bool { return g.blocked(ip) == "" && holds(t, g, contract.ClassLifts, x) })
	}
	// A block that ends at its time.
	const short, y = "203.0.113.47", "NNNN-AAA3"
	nodes[0].block(short, y, 3*time.Second)
	nodes[2].h.WaitFor("web-3 runs the short block", func() bool { return nodes[2].blocked(short) == y })
	nodes[2].h.WaitFor("the short block is over", func() bool { return nodes[2].blocked(short) == "" && nodes[0].blocked(short) == "" })
	time.Sleep(2 * time.Second)
	for _, g := range nodes {
		lifts, err := g.h.App.Cluster.State(contract.ClassLifts)
		if err != nil {
			t.Fatal(err)
		}
		if len(lifts) != 1 || lifts[0].ID != x || lifts[0].Origin != nodes[1].h.App.Cluster.ID() {
			t.Errorf("%s holds %d lifts, want the one of %s written by web-2", g.name, len(lifts), x)
			for _, l := range lifts {
				t.Logf("%s: lift of %s by %s", g.name, l.ID, g.h.App.Cluster.PeerName(l.Origin))
			}
		}
	}
	// Nobody but web-2 signed a lift: the sequence numbers of the others
	// name no record of class lifts either.
	for _, g := range nodes {
		for _, raw := range rawRecords(t, g, "class = ?", contract.ClassLifts) {
			var rec contract.Record
			if json.Unmarshal(raw, &rec) != nil || rec.Origin != nodes[1].h.App.Cluster.ID() {
				t.Errorf("%s holds a lift signed by another node than web-2", g.name)
			}
		}
	}
}

// m: lifts leave while the bound of running blocks holds new blocks back.
func TestBoundOfBlocksDoesNotHoldALiftBack(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	ctx := context.Background()
	inService(t, a, b)
	a.h.App.SetGroupBlocksMax(2)
	a.block("203.0.113.48", "PPPP-AAA2", 15*time.Minute)
	a.block("203.0.113.49", "PPPP-AAA3", 15*time.Minute)
	b.h.WaitFor("web-2 runs the two blocks within the bound", func() bool { return b.blocked("203.0.113.48") != "" && b.blocked("203.0.113.49") != "" })
	a.block("203.0.113.50", "PPPP-AAA4", 15*time.Minute)
	time.Sleep(time.Second)
	if got := b.blocked("203.0.113.50"); got != "" {
		t.Fatalf("web-2 runs %q: the bound did not hold the third block back", got)
	}
	// A lift of an incident the node holds no block of: the bound stays
	// reached while it leaves.
	if err := a.h.App.Store.NoteLifts(ctx, time.Now(), "PPPP-9999"); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 took the lift", func() bool { return holds(t, b, contract.ClassLifts, "PPPP-9999") })
	if got := b.blocked("203.0.113.50"); got != "" {
		t.Errorf("web-2 runs %q: the bound was not reached while the lift left", got)
	}
}

// n: the hash of the blocks is the same on every node after blocks and
// lifts settled, and it covers what the contract says: the blocks the node
// holds a record of that are not lifted.
func TestHashOfBlocksIsTheSameOnEveryNode(t *testing.T) {
	defer app.SetStateDiffTimes(2*time.Second, 5*time.Second, 5*time.Second)()
	nodes := trio(t)
	a, b, c := nodes[0], nodes[1], nodes[2]
	b.h.Login()
	inService(t, nodes...)
	const ip, x, y, ip2, z = "203.0.113.52", "QQQQ-AAA3", "QQQQ-AAA4", "203.0.113.53", "QQQQ-AAA5"
	a.block(ip, x, 15*time.Minute)
	b.block(ip, y, 15*time.Minute)
	c.block(ip2, z, 15*time.Minute)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" holds every block", func() bool { return holds(t, g, contract.ClassIncidentBlocks, x, y, z) })
		if got, want := g.h.App.HashedBlocks(), []string{x, y, z}; !slices.Equal(got, want) {
			t.Errorf("%s hashes the blocks %v, want %v: every block held", g.name, got, want)
		}
	}
	b.release(t, ip2)
	// The lift of one incident of a client that has two blocks.
	if err := c.h.App.Store.NoteLifts(context.Background(), time.Now(), x); err != nil {
		t.Fatal(err)
	}
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" holds the block that is left", func() bool {
			return holds(t, g, contract.ClassIncidentBlocks, y) && holds(t, g, contract.ClassLifts, x, z)
		})
		if got, want := g.h.App.HashedBlocks(), []string{y}; !slices.Equal(got, want) {
			t.Errorf("%s hashes the blocks %v after the lifts, want %v: no lifted block", g.name, got, want)
		}
	}
	for _, g := range nodes {
		for _, other := range nodes {
			if g == other {
				continue
			}
			g, other := g, other
			g.h.WaitFor(g.name+" sees the same blocks on "+other.name, func() bool { return sharedStateOf(g, other.name)["blocks"] == "same" })
		}
		if n := g.h.App.GroupStatus().Shared.Blocks; n != 1 {
			t.Errorf("%s shows %d shared blocks, want the one that is not lifted", g.name, n)
		}
	}
	time.Sleep(8 * time.Second)
	for _, g := range nodes {
		if g.h.App.StateDiffers() || slices.Contains(g.h.App.ClusterReasons(), "cluster_state_differs") {
			t.Errorf("%s names a difference although the blocks settled", g.name)
		}
	}
}

// o: a node draws no incident number it holds a block record or a lift of.
// An incident of its own that has neither is no block of the group, and the
// number is drawn from memory alone: the request path asks.
func TestKnownIncidentNumberIsNotDrawnAgain(t *testing.T) {
	// Not parallel: the test asks what web-2 knows right after the records
	// arrived, and web-2 had not noted them yet when other tests took the CPU
	// (2 of 7 runs under the race detector).
	a, b := pair(t)
	ctx := context.Background()
	b.h.Login()
	const ip, block, lift, fresh = "203.0.113.54", "RRRR-AAA2", "RRRR-AAA3", "RRRR-AAA5"
	a.block("192.0.2.10", block, 15*time.Minute) // on the allowlist of web-2: a record, no block and no incident there
	if err := a.h.App.Store.NoteLifts(ctx, time.Now(), lift); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 holds the block record and the lift", func() bool {
		return holds(t, b, contract.ClassIncidentBlocks, block) && holds(t, b, contract.ClassLifts, lift)
	})
	for _, id := range []string{block, lift} {
		if !b.h.App.IncidentKnown(id) {
			t.Errorf("web-2 does not know the number %s", id)
		}
	}
	if b.h.App.IncidentKnown(fresh) {
		t.Fatalf("web-2 knows the number %s, which nobody used", fresh)
	}
	draws := []string{block, lift, fresh}
	var drawn atomic.Int32
	b.h.App.Behaviour.DrawIncidents(func() string { return draws[min(int(drawn.Add(1))-1, len(draws)-1)] })
	code, body := b.h.API("POST", "/blocks", map[string]any{"address": ip, "duration_s": 3600, "reason": "test"})
	if code != 200 {
		t.Fatalf("block on web-2: %d %s", code, body)
	}
	var rb struct {
		Incident string `json:"incident"`
	}
	_ = json.Unmarshal(body, &rb)
	if rb.Incident != fresh {
		t.Errorf("the new block has the number %s, want %s: the two numbers before it are known", rb.Incident, fresh)
	}
}
