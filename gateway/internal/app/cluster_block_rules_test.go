//go:build !release

package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The rules of the blocks of a group that a review of the first build of
// D109 found broken: a client the node holds a block of is blocked on it, a
// node writes only what it decided, and no release goes without its lift.

// A block the node holds and does not run starts when the block that ran
// ends at its time, also when it is the only one left of its client.
func TestHeldBlockStartsWhenTheOneThatRanEndsAtItsTime(t *testing.T) {
	a, b := pair(t)
	inService(t, a, b)
	const ip, x, y = "203.0.113.60", "SSSS-AAA2", "SSSS-AAA3"
	b.block(ip, y, 15*time.Minute)
	a.h.WaitFor("web-1 runs the block of web-2", func() bool { return a.blocked(ip) == y })
	// web-1 decides a short block of its own for the client, in place of
	// the one it ran: no step of the test has to fit into its three seconds.
	a.blockAnew(t, ip, x, 3*time.Second)
	if !slices.Contains(recordIDs(t, a, contract.ClassIncidentBlocks), y) {
		t.Fatalf("web-1 holds %v, want the block of web-2", recordIDs(t, a, contract.ClassIncidentBlocks))
	}
	a.h.WaitFor("web-1 runs the block of web-2 after its own ended", func() bool { return a.blocked(ip) == y })
	if got := b.blocked(ip); got != y {
		t.Errorf("web-2 runs %q, want %q", got, y)
	}
}

// A lift ends a block the node held no record of (its own, not written
// yet): the block the group holds of that client starts at once.
func TestHeldBlockStartsWhenALiftEndsABlockWithoutARecord(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	inService(t, a, b)
	const ip, x, y = "203.0.113.61", "SSSS-AAA4", "SSSS-AAA5"
	a.h.App.SetGroupBlocksMax(0) // web-1 writes no block
	a.block(ip, x, 15*time.Minute)
	b.block(ip, y, 15*time.Minute)
	a.h.WaitFor("web-1 holds the block of web-2 and runs its own", func() bool { return holds(t, a, contract.ClassIncidentBlocks, y) && a.blocked(ip) == x })
	stop := watchBlocked(t, ip, a)
	if err := b.h.App.Store.NoteLifts(ctx, time.Now(), x); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("web-1 took the lift and runs the block of web-2", func() bool { return holds(t, a, contract.ClassLifts, x) && a.blocked(ip) == y })
	stop()
}

// An erasure ends the blocks from before it; a block the group holds that
// was set later starts at once on a node that ran one from before.
func TestHeldBlockStartsWhenAnErasureEndsTheOneThatRan(t *testing.T) {
	a, b := pair(t)
	inService(t, a, b)
	const ip, x, y = "203.0.113.62", "SSSS-AAA6", "SSSS-AAA7"
	b.h.App.SetGroupBlocksMax(0) // the block of web-2 stays its own
	b.block(ip, x, 15*time.Minute)
	// Set three minutes after the erasure to come.
	a.h.App.Behaviour.SetAgentBlock(behaviour.AgentBlock{IP: netip.MustParseAddr(ip), Source: behaviour.DashboardSource, NetClass: "hosting", Duration: 15 * time.Minute,
		Incident: y, Time: time.Now().Add(3 * time.Minute)})
	b.h.WaitFor("web-2 holds the later block and runs its own", func() bool { return holds(t, b, contract.ClassIncidentBlocks, y) && b.blocked(ip) == x })
	stop := watchBlocked(t, ip, b)
	// The erasure, as a record of web-1: no dashboard, so no lift.
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.writeStopped(t, nil, func(n *cluster.Node) {
		if _, err := n.Publish(contract.ClassErasure, ip, &contract.Erasure{IP: ip, Node: "web-1"}, false, time.Now().Add(contract.ErasureKeepS*time.Second)); err != nil {
			t.Fatal(err)
		}
	})
	a.start(t)
	b.h.WaitFor("web-2 took the erasure and runs the later block", func() bool { return holds(t, b, contract.ClassErasure, ip) && b.blocked(ip) == y })
	stop()
	if lifts := recordIDs(t, b, contract.ClassLifts); len(lifts) != 0 {
		t.Errorf("web-2 holds the lifts %v after an erasure it only took", lifts)
	}
}

// A block the node holds and does not run because its allowlist names the
// address starts when the entry is gone, on the node that decided it and
// on the node that took it.
func TestHeldBlockStartsWhenTheAllowlistEntryEnds(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	inService(t, a, b)
	const ip, x = "203.0.113.63", "SSSS-AAA8"
	a.block(ip, x, 15*time.Minute)
	b.h.WaitFor("web-2 runs the block", func() bool { return b.blocked(ip) == x })
	entry := &store.AllowEntry{IP: ip, Label: "for a while", Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}
	if err := b.h.App.Store.AddAllow(ctx, entry); err != nil {
		t.Fatal(err)
	}
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" allows the address and ended the block", func() bool { return allowed(g, ip) && g.blocked(ip) == "" })
		if !holds(t, g, contract.ClassIncidentBlocks, x) {
			t.Fatalf("%s lost the record of the block: an allowlist entry is no lift", g.name)
		}
	}
	if err := b.h.App.Store.DeleteAllow(ctx, entry.ID); err != nil {
		t.Fatal(err)
	}
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" runs the block again without the entry", func() bool { return !allowed(g, ip) && g.blocked(ip) == x })
		if lifts := recordIDs(t, g, contract.ClassLifts); len(lifts) != 0 {
			t.Errorf("%s holds the lifts %v, and nobody released", g.name, lifts)
		}
	}
}

// I1: a node writes only the blocks it decided. A block it took from the
// group and keeps over a restart is none, also when the node lost its
// cluster directory and holds no record of it: the record of the node that
// decided stays. A block the node decided itself is written again.
func TestNodeWritesOnlyTheBlocksItDecided(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	inService(t, a, b)
	// Kept blocks: over 24 h, of an address the geo fixture knows as hosting.
	const ip, x, own, y = "203.0.113.57", "TTTT-AAA2", "203.0.113.58", "TTTT-AAA3"
	a.block(ip, x, 48*time.Hour)
	b.block(own, y, 48*time.Hour)
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" runs both blocks", func() bool { return g.blocked(ip) == x && g.blocked(own) == y })
	}
	signer := func(g *groupNode, incident string) string {
		recs, err := g.h.App.Cluster.State(contract.ClassIncidentBlocks)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if blk, err := contract.DecodeIncidentBlock(r); err == nil && r.ID == incident {
				return r.Origin + " " + blk.Node
			}
		}
		return ""
	}
	want := a.h.App.Cluster.ID() + " web-1"
	if got := signer(b, x); got != want {
		t.Fatalf("the record of the block is signed %q, want %q", got, want)
	}
	b.h.App.FlushBlocks()
	if taken, err := b.h.App.Store.TakenBlocks(ctx); err != nil || !slices.Equal(taken, []string{ip}) {
		t.Fatalf("web-2 keeps %v as taken from the group (%v), want the block of web-1 alone", taken, err)
	}
	// web-2 loses its cluster directory and starts as a new member.
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(b.clusterDir()); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	// Its first round ran before its mesh: the block it decided runs, and
	// the block of web-1 waits for its record, which web-2 does not hold.
	if b.blocked(own) != y {
		t.Fatalf("after its restart web-2 runs %q for the block it decided and kept", b.blocked(own))
	}
	inService(t, a, b)
	b.h.WaitFor("web-2 runs the block of web-1 again, from its record", func() bool { return b.blocked(ip) == x })
	// Its own block is written again, under its new key.
	wantOwn := b.h.App.Cluster.ID() + " web-2"
	a.h.WaitFor("web-1 holds the block web-2 decided, written again by web-2", func() bool { return signer(a, y) == wantOwn })
	time.Sleep(1500 * time.Millisecond)
	for _, g := range []*groupNode{a, b} {
		if got := signer(g, x); got != want {
			t.Errorf("%s holds the block of web-1 signed %q, want %q: web-2 wrote a block it did not decide", g.name, got, want)
		}
		if g.blocked(ip) != x {
			t.Errorf("%s runs %q for the block of web-1", g.name, g.blocked(ip))
		}
	}
}

// I2: the release of an address is one step with the blocks it lifts. A
// block record that arrives while the release is under way either came
// before it, and is lifted with it, or after it, and runs: never ended on
// this node alone, without a lift for the group.
func TestReleaseIsOneStepWithTheBlocksItLifts(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	a.h.Login()
	b.h.WaitFor("web-2 knows the user", func() bool { return b.h.App.Store.HasUsers(ctx) })
	const ip, x = "203.0.113.64", "TTTT-AAA4"
	// The record of a block of web-1 that web-2 never saw.
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.block(ip, x, 15*time.Minute)
	a.h.WaitFor("web-1 wrote the record of its block", func() bool { return holds(t, a, contract.ClassIncidentBlocks, x) })
	raws := rawRecords(t, a, "class = ? AND id = ?", contract.ClassIncidentBlocks, x)
	if len(raws) != 1 {
		t.Fatalf("%d records of the block", len(raws))
	}
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	b.h.Login()
	// The record arrives in the middle of the release: after web-2 looked
	// at what it holds of the client, before it ends the blocks.
	target := b.h.App
	var inWindow atomic.Bool
	defer app.SetTestClientBlocks(func(x *app.App, done bool) {
		if x != target || done {
			return
		}
		go func() { _, _ = target.Cluster.Take(raws[0]) }()
		for i := 0; i < 50 && b.blocked(ip) == ""; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		inWindow.Store(b.blocked(ip) != "")
	})()
	code, body := b.h.API("POST", "/behaviour/release", map[string]any{"ip": ip})
	if code != 200 {
		t.Fatalf("release on web-2: %d %s", code, body)
	}
	var res struct {
		BlocksEnded int `json:"blocks_ended"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if inWindow.Load() {
		t.Error("the block of the record started in the middle of the release: the release does not hold the lock of the blocks from its look to its end")
	}
	time.Sleep(1500 * time.Millisecond)
	lifted := slices.Contains(recordIDs(t, b, contract.ClassLifts), x)
	switch {
	case res.BlocksEnded > 0 && (!lifted || b.blocked(ip) != ""):
		t.Errorf("the release ended %d blocks on web-2; lift for the group: %v, block running now: %q. A block ended here without its lift", res.BlocksEnded, lifted, b.blocked(ip))
	case res.BlocksEnded == 0 && (lifted || b.blocked(ip) != x):
		t.Errorf("the release ended no block on web-2; lift: %v, block running now: %q, want the block that came after the release", lifted, b.blocked(ip))
	}
}

const agentListen = "127.0.0.1:8789"

// agentCall calls the agent API of a node with a new token of the scope.
func (g *groupNode) agentCall(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	tok := contractapi.NewToken()
	now := time.Now().UTC()
	if err := g.h.App.Store.AddAgentToken(context.Background(), store.AgentToken{ID: contractapi.TokenID(tok), Hash: contractapi.HashToken(tok), Scope: contractapi.ScopeBlocksWrite,
		Label: "test", Created: now, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = agentListen
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.h.App.AgentAPI.Handler(agentListen).ServeHTTP(w, r)
	return w
}

const agentYAML = "agent_api:\n  enabled: true\n  requests_per_minute: 600\n"

// I3: an agent lifts a block on a node that does not run it. The group
// holds the block, so the lift is noted and ends it where it runs.
func TestAgentLiftsABlockTheNodeDoesNotRun(t *testing.T) {
	nodes := newGroup(t, "web-1", "web-2")
	a, b := nodes[0], nodes[1]
	b.extra = agentYAML
	a.start(t)
	b.start(t)
	inService(t, a, b)
	// 192.0.2.10 is on the allowlist of the harness: web-2 holds the record
	// of the block and does not run it.
	const ip, x = "192.0.2.10", "TTTT-AAA5"
	a.block(ip, x, 15*time.Minute)
	b.h.WaitFor("web-2 holds the record of the block", func() bool { return holds(t, b, contract.ClassIncidentBlocks, x) })
	if got := b.blocked(ip); got != "" {
		t.Fatalf("web-2 blocks an address of its own allowlist: %q", got)
	}
	w := b.agentCall(t, "POST", "/agent/v0/incidents/"+x+"/lift", `{"reason":"false alarm"}`)
	if w.Code != 200 {
		t.Fatalf("lift on web-2: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"unblocked"`) {
		t.Errorf("the answer does not say that the incident is unblocked: %s", w.Body)
	}
	a.h.WaitFor("web-1 ended the block the agent lifted on web-2", func() bool { return a.blocked(ip) == "" })
	// The lift counts on web-2 although no block ended there: its event is
	// written, and it is one write of the token's budget.
	b.h.Flush()
	evs, err := b.h.App.Store.EventsByIncident(context.Background(), x, 20)
	if err != nil || !slices.ContainsFunc(evs, func(e *store.EventRow) bool { return e.Type == events.BlockLifted }) {
		t.Errorf("web-2 wrote no event of the lift (%d events of the incident, %v)", len(evs), err)
	}
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" holds the lift and no record of the block", func() bool { return holds(t, g, contract.ClassLifts, x) && holds(t, g, contract.ClassIncidentBlocks) })
	}
	// A second lift finds nothing to lift.
	if w := b.agentCall(t, "POST", "/agent/v0/incidents/"+x+"/lift", `{"reason":"once more"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"unblocked"`) {
		t.Errorf("second lift on web-2: %d %s", w.Code, w.Body)
	}
}

// o, the agent path: the block an agent sets draws its number through the
// node, which gives none it knows.
func TestAgentBlockDrawsNoKnownIncidentNumber(t *testing.T) {
	nodes := newGroup(t, "web-1", "web-2")
	a, b := nodes[0], nodes[1]
	b.extra = agentYAML
	a.start(t)
	b.start(t)
	inService(t, a, b)
	const known, fresh = "TTTT-AAA6", "TTTT-AAA7"
	a.block("192.0.2.10", known, 15*time.Minute)
	b.h.WaitFor("web-2 holds the record of the block", func() bool { return holds(t, b, contract.ClassIncidentBlocks, known) })
	// The event the agent names: a request the WAF stops.
	const attacker = "203.0.113.57"
	b.h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", attacker, "", "")
	b.h.Flush()
	rows, _, err := b.h.App.Store.ListEvents(t.Context(), store.EventFilter{IP: attacker}, 0, 10)
	if err != nil || len(rows) == 0 {
		t.Fatalf("no event of %s: %v", attacker, err)
	}
	var drawn atomic.Int32
	b.h.App.Behaviour.DrawIncidents(func() string {
		if drawn.Add(1) == 1 {
			return known
		}
		return fresh
	})
	w := b.agentCall(t, "POST", "/agent/v0/blocks", fmt.Sprintf(`{"target":{"event_id":"%s"},"duration_s":3600,"reason":"scanner, checked by hand"}`, rows[0].ID))
	var res contractapi.BlockResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || w.Code != 200 {
		t.Fatalf("block on web-2: %d %s (%v)", w.Code, w.Body, err)
	}
	if res.Incident != fresh || drawn.Load() != 2 {
		t.Errorf("the agent block has the number %s after %d draws, want %s: the first number is one of a block record", res.Incident, drawn.Load(), fresh)
	}
}

// A lift whose write fails does not hold back the lifts noted after it,
// and a lift under a number no node would take is dropped, not tried for
// ever.
func TestOneFailingLiftDoesNotHoldTheOthersBack(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	inService(t, a, b)
	const stuck, good, bad = "UUUU-AAA2", "UUUU-AAA3", "no incident number"
	target := a.h.App
	defer app.SetTestLiftWrite(func(x *app.App, incident string) error {
		if x == target && incident == stuck {
			return errors.New("test: this one lift is not written")
		}
		return nil
	})()
	now := time.Now()
	for i, id := range []string{stuck, bad, good} {
		if err := a.h.App.Store.NoteLifts(ctx, now.Add(time.Duration(i)*time.Millisecond), id); err != nil {
			t.Fatal(err)
		}
	}
	b.h.WaitFor("web-2 took the lift noted after the one that fails", func() bool { return holds(t, b, contract.ClassLifts, good) })
	a.h.WaitFor("web-1 dropped the lift no node would take", func() bool { return !a.h.App.Store.LiftNoted(bad) })
	if !a.h.App.Store.LiftNoted(stuck) {
		t.Error("the lift whose write fails is no longer noted")
	}
	if refused := b.h.App.Cluster.Rejected.Load(); refused != 0 {
		t.Errorf("web-2 refused %d records: the lift under a wrong number was written", refused)
	}
}

// The first start with this build asks every member the node reaches for
// its records, not one alone: the first one that answers may hold none (it
// may still run the build before).
func TestFirstStartAsksEveryMemberItReaches(t *testing.T) {
	nodes := trio(t)
	inService(t, nodes...)
	const mark = "blocks_by_incident"
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" made the cut", func() bool { return g.h.App.Cluster.Mark(mark) == "asked" })
	}
	first, holder, c := nodes[0], nodes[1], nodes[2]
	// A block record web-3 lacks although its vector says it has it: what a
	// node refused while it ran the build before. Of the two others only
	// web-2 holds it.
	const ip, x = "203.0.113.65", "UUUU-AAA4"
	holder.block(ip, x, 15*time.Minute)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" runs the block", func() bool { return g.blocked(ip) == x })
	}
	for _, g := range nodes {
		if err := g.h.Stop(); err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range []*groupNode{c, first} {
		execCluster(t, g.clusterDir(), `DELETE FROM records WHERE class = ? AND id = ?`, contract.ClassIncidentBlocks, x)
	}
	execCluster(t, c.clusterDir(), `DELETE FROM meta WHERE k = ?`, "mark:"+mark)
	// web-3 starts while only web-1 runs, asks it and gets nothing.
	first.start(t)
	c.start(t)
	c.h.WaitFor("web-3 reaches web-1", func() bool { return len(c.h.App.Cluster.Reachable()) == 1 })
	time.Sleep(3 * time.Second)
	if got := c.h.App.Cluster.Mark(mark); got == "asked" {
		t.Error("web-3 noted its first start as done after it asked one member of two")
	}
	if got := c.blocked(ip); got != "" {
		t.Fatalf("web-3 runs %q before the member that holds the record is back", got)
	}
	// web-2 returns, and web-3 asks it too.
	holder.start(t)
	c.h.WaitFor("web-3 holds the block again: it asked the member that holds it too", func() bool { return c.blocked(ip) == x })
	c.h.WaitFor("web-3 made the cut", func() bool { return c.h.App.Cluster.Mark(mark) == "asked" })
}

// A block that runs again after an allowlist entry ended it for a while can
// be released, in the dashboard and by an agent, although its incident
// reads unblocked: the entry ended the block without a lift, which is
// right, and marked the incident.
func TestBlockThatRunsAgainAfterAnAllowlistEntryCanBeReleased(t *testing.T) {
	nodes := newGroup(t, "web-1", "web-2")
	a, b := nodes[0], nodes[1]
	b.extra = agentYAML
	a.start(t)
	b.start(t)
	ctx := context.Background()
	b.h.Login()
	inService(t, a, b)
	blocks := map[string]string{"203.0.113.66": "VVVV-AAA2", "203.0.113.67": "VVVV-AAA3"}
	var entries []*store.AllowEntry
	for ip, incident := range blocks {
		a.block(ip, incident, 15*time.Minute)
		b.h.WaitFor("web-2 runs the block "+incident, func() bool { return b.blocked(ip) == incident })
		e := &store.AllowEntry{IP: ip, Label: "for a while", Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}
		if err := b.h.App.Store.AddAllow(ctx, e); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	for ip, incident := range blocks {
		for _, g := range []*groupNode{a, b} {
			g := g
			g.h.WaitFor(g.name+" ended the block "+incident+" by the allowlist", func() bool { return g.blocked(ip) == "" })
		}
		b.h.WaitFor("web-2 holds the incident "+incident+" as unblocked", func() bool {
			b.h.App.FlushBlocks()
			in, err := b.h.App.Store.GetIncident(ctx, incident)
			return err == nil && in.Status == "unblocked"
		})
	}
	for _, e := range entries {
		if err := b.h.App.Store.DeleteAllow(ctx, e.ID); err != nil {
			t.Fatal(err)
		}
	}
	for ip, incident := range blocks {
		for _, g := range []*groupNode{a, b} {
			g := g
			g.h.WaitFor(g.name+" runs the block "+incident+" again", func() bool { return g.blocked(ip) == incident })
		}
	}
	// In the dashboard.
	if code, body := b.h.API("POST", "/incidents/VVVV-AAA2/unblock", map[string]any{}); code != 200 {
		t.Fatalf("unblock in the dashboard of web-2 of a block that runs: %d %s", code, body)
	}
	// By an agent.
	if w := b.agentCall(t, "POST", "/agent/v0/incidents/VVVV-AAA3/lift", `{"reason":"false alarm"}`); w.Code != 200 {
		t.Fatalf("lift by an agent on web-2 of a block that runs: %d %s", w.Code, w.Body)
	}
	for ip, incident := range blocks {
		for _, g := range []*groupNode{a, b} {
			g := g
			g.h.WaitFor(g.name+" ended the released block "+incident, func() bool {
				return g.blocked(ip) == "" && slices.Contains(recordIDs(t, g, contract.ClassLifts), incident)
			})
		}
	}
	// A second release finds nothing to release.
	if code, body := b.h.API("POST", "/incidents/VVVV-AAA2/unblock", map[string]any{}); code != 409 {
		t.Errorf("second unblock: %d %s, want 409", code, body)
	}
}

// keptRow reads the kept block of a client from the store of a node.
func keptRow(t *testing.T, g *groupNode, ip string) events.ActiveBlock {
	t.Helper()
	g.h.App.FlushBlocks()
	rows, err := g.h.App.Store.ListBlocks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ClientKey == ip {
			return r
		}
	}
	t.Fatalf("%s keeps no block of %s", g.name, ip)
	return events.ActiveBlock{}
}

// Who decided a kept block, as its row says.
const (
	keptOwn      = 1
	keptTaken    = 0
	keptUnmarked = -1 // a row of the build before the mark
)

// putKept writes kept blocks into the store of a node that is stopped: a
// row that outlived the end of its block, or one of a build before.
func (g *groupNode) putKept(t *testing.T, mark int, rows ...events.ActiveBlock) {
	t.Helper()
	st, err := store.Open(filepath.Join(g.dir, "data", "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, r := range rows {
		put := st.PutTakenBlock
		if mark == keptOwn {
			put = st.PutBlock
		}
		if err := put(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		if mark == keptUnmarked {
			if _, err := st.DB().Exec(`UPDATE kept_blocks SET own = -1 WHERE client_key = ?`, r.ClientKey); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A kept block comes back with a restart when its row outlived its end (the
// write that removes it was dropped, the node was stopped before it, a
// backup was put back). It must not run: a block whose incident is lifted,
// by a record or by a release made here that waits for the group, and a
// block of another node the node holds no record of.
func TestKeptBlockThatMustNotRunEndsAtTheStart(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	b.h.Login()
	inService(t, a, b)
	// Four kept blocks on web-2, hosting addresses of the geo fixture.
	const (
		ipOwn, own       = "203.0.113.56", "WWWW-AAA5" // of web-2, lifted in the group
		ipLifted, lifted = "203.0.113.57", "WWWW-AAA2" // of web-1, lifted in the group
		ipLost, lost     = "203.0.113.58", "WWWW-AAA3" // of web-1, its record gone from web-2
		ipNoted, noted   = "203.0.113.59", "WWWW-AAA4" // of web-2, released there, the lift not written
	)
	// No lift of web-2 is written, also not after its restart.
	defer app.SetTestLiftWrite(func(x *app.App, _ string) error {
		if x.Cluster.Name() == "web-2" {
			return errors.New("test: web-2 writes no lift")
		}
		return nil
	})()
	a.block(ipLifted, lifted, 48*time.Hour)
	a.block(ipLost, lost, 48*time.Hour)
	b.block(ipNoted, noted, 48*time.Hour)
	b.block(ipOwn, own, 48*time.Hour)
	b.h.WaitFor("web-2 runs the four blocks", func() bool {
		return b.blocked(ipLifted) == lifted && b.blocked(ipLost) == lost && b.blocked(ipNoted) == noted && b.blocked(ipOwn) == own &&
			holds(t, b, contract.ClassIncidentBlocks, lifted, lost, noted, own)
	})
	rowLifted, rowLost, rowNoted, rowOwn := keptRow(t, b, ipLifted), keptRow(t, b, ipLost), keptRow(t, b, ipNoted), keptRow(t, b, ipOwn)
	if err := a.h.App.Store.NoteLifts(ctx, time.Now(), lifted, own); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 took the lifts", func() bool {
		return b.blocked(ipLifted) == "" && b.blocked(ipOwn) == "" && holds(t, b, contract.ClassLifts, lifted, own)
	})
	b.release(t, ipNoted)
	if b.blocked(ipNoted) != "" || !b.h.App.Store.LiftNoted(noted) {
		t.Fatal("the release on web-2 did not end the block or is not noted")
	}
	b.h.App.FlushBlocks()
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	execCluster(t, b.clusterDir(), `DELETE FROM records WHERE class = ? AND id = ?`, contract.ClassIncidentBlocks, lost)
	b.putKept(t, keptTaken, rowLifted, rowLost)
	b.putKept(t, keptOwn, rowNoted, rowOwn)
	b.start(t)
	// The first round of web-2 ran before its mesh.
	for ip, why := range map[string]string{ipOwn: "web-2 decided it, and the group holds its lift", ipLifted: "the group holds its lift", ipLost: "web-2 did not decide it and holds no record of it", ipNoted: "it was released on web-2, and the lift waits"} {
		if got := b.blocked(ip); got != "" {
			t.Errorf("after its restart web-2 runs %q for %s: %s", got, ip, why)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	if ids := recordIDs(t, a, contract.ClassIncidentBlocks); slices.Contains(ids, own) || slices.Contains(ids, lifted) {
		t.Errorf("web-1 holds the block records %v: web-2 wrote a lifted block to the group again", ids)
	}
	for _, ip := range []string{ipOwn, ipLifted, ipLost, ipNoted} {
		if got := b.blocked(ip); got != "" {
			t.Errorf("web-2 runs %q for %s a moment after its restart", got, ip)
		}
	}
	b.h.App.FlushBlocks()
	if rows, err := b.h.App.Store.ListBlocks(ctx); err != nil || len(rows) != 0 {
		t.Errorf("web-2 still keeps %d blocks (%v), want none: the rows go with the blocks", len(rows), err)
	}
	// Ended, not lifted: the block web-2 lost the record of runs on web-1,
	// and nobody wrote a lift for it.
	if got := a.blocked(ipLost); got != lost {
		t.Errorf("web-1 runs %q for the block web-2 lost the record of, want %q", got, lost)
	}
	if slices.Contains(recordIDs(t, a, contract.ClassLifts), lost) {
		t.Error("a lift was written for a block that nobody released")
	}
	if in, err := b.h.App.Store.GetIncident(ctx, lost); err != nil || in.Status != "blocked" {
		t.Errorf("web-2 holds the incident of that block as %+v (%v), want blocked: the block ended here without a lift", in, err)
	}
}

// With a block table that is full and more block records than it takes,
// the round starts none: each start would drop another block that runs.
func TestRoundStartsNoBlockTheTableHasNoRoomFor(t *testing.T) {
	a, b := pair(t)
	inService(t, a, b)
	b.h.App.Behaviour.SetBlockCapacity(32) // one block in each of its 32 parts
	const n = 96
	for i := 0; i < n; i++ {
		a.block(fmt.Sprintf("198.18.7.%d", i+1), fmt.Sprintf("XXXX-%04d", 2222+i), 15*time.Minute)
	}
	b.h.WaitFor("web-2 holds every record", func() bool { return len(recordIDs(t, b, contract.ClassIncidentBlocks)) == n })
	time.Sleep(time.Second)
	var starts atomic.Int32
	target := b.h.App
	undo := app.SetTestBlockRuns(func(x *app.App, _ string) {
		if x == target {
			starts.Add(1)
		}
	})
	time.Sleep(2 * time.Second)
	undo()
	if got := starts.Load(); got != 0 {
		t.Errorf("web-2 started %d blocks in two seconds with a full table: each dropped one that ran", got)
	}
	running := len(b.h.App.Behaviour.RunningBlocks())
	if running == 0 || running > 32 {
		t.Errorf("web-2 runs %d blocks, want as many as its table takes (at most 32)", running)
	}
}

// A gateway that is in no group decided every block it keeps that does not
// say who did (a row of a build before the mark), and none it took from a
// group it was in. When it joins a group later, it hands its own long
// blocks over.
func TestSingleGatewayOwnsItsKeptBlocksWhenItJoinsAGroup(t *testing.T) {
	g := newGroup(t, "web-1")[0]
	const ip, incident, ipTaken, taken = "203.0.113.57", "YYYY-AAA2", "203.0.113.58", "YYYY-AAA3"
	single := func() *apptest.Harness { return apptest.New(t, apptest.Options{Dir: g.dir}) }
	h := single()
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	row := func(ip, incident string) events.ActiveBlock {
		return events.ActiveBlock{ClientKey: ip, KeyBits: 32, NetClass: "hosting", Source: "dashboard", Level: 1, DurationS: 172800,
			Since: now.Format(time.RFC3339), Until: now.Add(48 * time.Hour).Format(time.RFC3339), Incident: incident}
	}
	g.putKept(t, keptUnmarked, row(ip, incident))
	g.putKept(t, keptTaken, row(ipTaken, taken))
	h = single()
	if bi, ok := h.App.Behaviour.ActiveBlock(netip.MustParseAddr(ip)); !ok || bi.Incident != incident || bi.Taken {
		t.Fatalf("the single gateway runs %+v (%v), want its kept block as its own decision", bi, ok)
	}
	if bi, ok := h.App.Behaviour.ActiveBlock(netip.MustParseAddr(ipTaken)); !ok || !bi.Taken {
		t.Fatalf("the single gateway runs %+v (%v) for the block it took from a group, want it as taken", bi, ok)
	}
	if rows, err := h.App.Store.TakenBlocks(context.Background()); err != nil || !slices.Equal(rows, []string{ipTaken}) {
		t.Fatalf("the single gateway keeps %v as taken (%v), want the one block it took", rows, err)
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	// It joins a group.
	g.start(t)
	g.h.WaitFor("the node handed its kept block to the group", func() bool { return holds(t, g, contract.ClassIncidentBlocks, incident) })
	if got := g.blocked(ip); got != incident {
		t.Errorf("the node runs %q, want its kept block", got)
	}
	if got := g.blocked(ipTaken); got != "" {
		t.Errorf("the node runs %q: a block of another node it holds no record of", got)
	}
}

// A node that comes from the build before keeps blocks that do not say who
// decided them. Once it read the records of its group it decides (section
// 16): a block whose record another node signed is that node's and runs by
// its record; a block the node holds no record of at all is its own and is
// written to the group, not dropped. So a single gateway that is updated
// and put into a group in one step keeps its long blocks.
func TestKeptBlocksOfTheBuildBeforeAreResolvedByTheRecords(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	inService(t, a, b)
	const ipTheirs, theirs, ipOwn, own = "203.0.113.57", "YYYY-AAA4", "203.0.113.58", "YYYY-AAA5"
	b.h.App.SetGroupBlocksMax(0) // the long block of web-2 has no record
	a.block(ipTheirs, theirs, 48*time.Hour)
	b.block(ipOwn, own, 48*time.Hour)
	b.h.WaitFor("web-2 runs both blocks", func() bool { return b.blocked(ipTheirs) == theirs && b.blocked(ipOwn) == own })
	if err := b.h.App.Store.InsertIncident(ctx, &store.Incident{Incident: own, Time: time.Now(), IP: ipOwn, Status: "blocked", Sources: []string{"dashboard"}}); err != nil {
		t.Fatal(err)
	}
	rowTheirs, rowOwn := keptRow(t, b, ipTheirs), keptRow(t, b, ipOwn)
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	// As the build before kept them.
	b.putKept(t, keptUnmarked, rowTheirs, rowOwn)
	b.start(t)
	// The first round of web-2 ran before its mesh.
	if b.blocked(ipOwn) != own || b.blocked(ipTheirs) != theirs {
		t.Fatalf("after its start web-2 runs %q and %q, want both kept blocks", b.blocked(ipOwn), b.blocked(ipTheirs))
	}
	a.h.WaitFor("web-1 holds the block of web-2, which had no record", func() bool { return slices.Contains(recordIDs(t, a, contract.ClassIncidentBlocks), own) })
	b.h.App.FlushBlocks()
	taken, err1 := b.h.App.Store.TakenBlocks(ctx)
	unmarked, err2 := b.h.App.Store.UnmarkedBlocks(ctx)
	if err1 != nil || err2 != nil || !slices.Equal(taken, []string{ipTheirs}) || len(unmarked) != 0 {
		t.Errorf("web-2 keeps as taken %v, as not marked %v (%v, %v): want the block of web-1 as taken and none open", taken, unmarked, err1, err2)
	}
	if in, err := b.h.App.Store.GetIncident(ctx, own); err != nil || in.Status != "blocked" {
		t.Errorf("the incident of the block of web-2 is %+v (%v), want blocked", in, err)
	}
	for _, rec := range func() []*contract.Record { r, _ := a.h.App.Cluster.State(contract.ClassIncidentBlocks); return r }() {
		want := map[string]string{own: b.h.App.Cluster.ID(), theirs: a.h.App.Cluster.ID()}[rec.ID]
		if rec.Origin != want {
			t.Errorf("the record of %s is written by %s", rec.ID, a.h.App.Cluster.PeerName(rec.Origin))
		}
	}
}

// Class blocks has one record per client. A record of that class that
// replaces the one before of its client, under another incident (written by
// a node of the build before), takes its place on every node: the block of
// the record before is no longer held.
func TestRecordOfClassBlocksThatWasReplacedIsNoLongerHeld(t *testing.T) {
	a, b := pair(t)
	inService(t, a, b)
	const mark = "blocks_by_incident"
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" made the cut", func() bool { return g.h.App.Cluster.Mark(mark) == "asked" })
	}
	const ip, x, y = "203.0.113.68", "ZZZZ-AAA2", "ZZZZ-AAA3"
	write := func(incident string) {
		if err := a.h.Stop(); err != nil {
			t.Fatal(err)
		}
		until := blockUntil()
		a.writeStopped(t, nil, func(n *cluster.Node) {
			if _, err := n.Publish(contract.ClassBlocks, ip, blockBefore(ip, incident, "web-1", until), false, until); err != nil {
				t.Fatal(err)
			}
		})
		a.start(t)
	}
	write(x)
	b.h.WaitFor("web-2 runs the first block", func() bool { return b.blocked(ip) == x })
	write(y)
	b.h.WaitFor("web-2 runs the block that replaced the first", func() bool { return b.blocked(ip) == y })
	for _, g := range []*groupNode{a, b} {
		if got := g.h.App.HashedBlocks(); !slices.Equal(got, []string{y}) {
			t.Errorf("%s hashes the blocks %v, want %v", g.name, got, []string{y})
		}
		if n := g.h.App.GroupStatus().Shared.Blocks; n != 1 {
			t.Errorf("%s holds %d blocks, want the one whose record its store holds", g.name, n)
		}
	}
	// A tombstone of that class takes the place of the record too, whatever
	// incident it names: here one that no node holds a block of.
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.writeStopped(t, nil, func(n *cluster.Node) {
		if _, err := n.Publish(contract.ClassBlocks, ip, &contract.Lift{Incident: "ZZZZ-AAA9", Node: "web-1"}, true, time.Now().Add(contract.MaxBlockS*time.Second+time.Hour)); err != nil {
			t.Fatal(err)
		}
	})
	a.start(t)
	b.h.WaitFor("web-2 holds no block of the client after the tombstone", func() bool {
		return b.blocked(ip) == "" && len(b.h.App.HashedBlocks()) == 0 && b.h.App.GroupStatus().Shared.Blocks == 0
	})
}

// The blocks from before an erasure end on a node that takes the erasure
// also when it cannot erase what its store holds of the address.
func TestErasureEndsTheBlocksAlsoWhenTheStoreFails(t *testing.T) {
	a, b := pair(t)
	inService(t, a, b)
	const ip, x = "203.0.113.69", "ZZZZ-AAA4"
	a.block(ip, x, 15*time.Minute)
	b.h.WaitFor("web-2 runs the block", func() bool { return b.blocked(ip) == x })
	// The erasure in the store of web-2 fails: one of its tables is away.
	db := b.h.App.Store.DB()
	if _, err := db.Exec(`ALTER TABLE exceptions RENAME TO exceptions_away`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ALTER TABLE exceptions_away RENAME TO exceptions`)
	// The erasure, as a record of web-1: no dashboard, so no lift ends the
	// block instead.
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.writeStopped(t, nil, func(n *cluster.Node) {
		if _, err := n.Publish(contract.ClassErasure, ip, &contract.Erasure{IP: ip, Node: "web-1"}, false, time.Now().Add(contract.ErasureKeepS*time.Second)); err != nil {
			t.Fatal(err)
		}
	})
	a.start(t)
	b.h.WaitFor("web-2 ended the block from before the erasure", func() bool {
		return holds(t, b, contract.ClassErasure, ip) && b.blocked(ip) == "" && holds(t, b, contract.ClassIncidentBlocks)
	})
	if lifts := recordIDs(t, b, contract.ClassLifts); len(lifts) != 0 {
		t.Errorf("web-2 holds the lifts %v: the block ended by a lift, not by the erasure", lifts)
	}
}

// An agent lifts an incident that has a block: one the engine runs or the
// group holds a record of. Before the record of the block arrived the node
// cannot say that, answers 409, and the agent tries again; the incident of
// a single refused request has no block and is never lifted.
func TestAgentLiftsOnlyAnIncidentThatHasABlock(t *testing.T) {
	nodes := newGroup(t, "web-1", "web-2")
	a, b := nodes[0], nodes[1]
	b.extra = agentYAML
	a.start(t)
	b.start(t)
	inService(t, a, b)
	const ip, x = "203.0.113.70", "ZZZZ-AAA5"
	a.h.App.SetGroupBlocksMax(0) // web-1 has not written the record
	a.block(ip, x, 15*time.Minute)
	// The incident travelled with the events of web-1.
	if err := b.h.App.Store.InsertIncident(store.Foreign(context.Background()), &store.Incident{Incident: x, Time: time.Now(), IP: ip, Status: "blocked", Sources: []string{"dashboard"}}); err != nil {
		t.Fatal(err)
	}
	lift := func(incident string) *httptest.ResponseRecorder {
		return b.agentCall(t, "POST", "/agent/v0/incidents/"+incident+"/lift", `{"reason":"false alarm"}`)
	}
	if w := lift(x); w.Code != 409 || !strings.Contains(w.Body.String(), contractapi.CodeNoRunningBlock) {
		t.Fatalf("lift on web-2 before the record of the block came: %d %s, want 409", w.Code, w.Body)
	}
	// The incident of a single request the WAF refused.
	const attacker = "203.0.113.57"
	b.h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", attacker, "", "")
	b.h.Flush()
	rows, _, err := b.h.App.Store.ListEvents(t.Context(), store.EventFilter{IP: attacker}, 0, 10)
	if err != nil || len(rows) == 0 || rows[0].Incident == "" {
		t.Fatalf("no incident of %s: %v", attacker, err)
	}
	refused := rows[0].Incident
	if w := lift(refused); w.Code != 409 || !strings.Contains(w.Body.String(), contractapi.CodeNoRunningBlock) {
		t.Fatalf("lift of the incident of a refused request: %d %s, want 409", w.Code, w.Body)
	}
	if b.h.App.Store.LiftNoted(x) || b.h.App.Store.LiftNoted(refused) {
		t.Fatal("a lift is noted for an incident the node knows no block of")
	}
	// The record arrives, and the agent tries again.
	a.h.App.SetGroupBlocksMax(20000)
	b.h.WaitFor("web-2 holds the record of the block", func() bool { return holds(t, b, contract.ClassIncidentBlocks, x) })
	if w := lift(x); w.Code != 200 {
		t.Fatalf("lift on web-2 when it holds the record: %d %s", w.Code, w.Body)
	}
	a.h.WaitFor("web-1 ended its block by the lift of the agent", func() bool { return a.blocked(ip) == "" && holds(t, a, contract.ClassLifts, x) })
	time.Sleep(600 * time.Millisecond)
	if lifts := recordIDs(t, a, contract.ClassLifts); !slices.Equal(lifts, []string{x}) {
		t.Errorf("the group holds the lifts %v, want the one of the block", lifts)
	}
}

// The whole way, through the detector: a client trips a scenario on one
// node, the block and its incident reach the other node, and a release in
// the dashboard there ends the block on both.
func TestBlockOfADetectorIsReleasedOnAnotherNode(t *testing.T) {
	nodes := newGroup(t, "web-1", "web-2")
	a, b := nodes[0], nodes[1]
	ctx := context.Background()
	for _, g := range nodes {
		g.mode = "review"
		g.extra = "behaviour:\n  presets: [wordpress]\n  scenarios:\n    login_bruteforce: {mode: block}\n"
		g.start(t)
		// Scenarios act only after the learning period.
		if err := g.h.App.SetInstalledAt(ctx, time.Now().Add(-30*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	b.h.Login()
	inService(t, a, b)
	const attacker = "198.51.100.7"
	for i := 0; i < 5; i++ {
		// The fake app answers 200: WordPress shows the form again, a failed login.
		if r := a.h.Visit("POST", "/wp-login.php", attacker, "application/x-www-form-urlencoded", "log=admin&pwd=x"); r.StatusCode != 200 {
			t.Fatalf("attempt %d on web-1: %d", i+1, r.StatusCode)
		}
	}
	r := a.h.Visit("GET", "/", attacker, "", "")
	incident := r.Header.Get("X-Schild-Incident")
	if r.StatusCode != 403 || incident == "" {
		t.Fatalf("web-1 does not block the client: %d", r.StatusCode)
	}
	a.h.Flush()
	b.h.WaitFor("web-2 blocks the client under the incident of web-1", func() bool { return b.blocked(attacker) == incident })
	if r := b.h.Visit("GET", "/", attacker, "", ""); r.StatusCode != 403 || r.Header.Get("X-Schild-Incident") != incident {
		t.Fatalf("a request of the client on web-2: %d, incident %q", r.StatusCode, r.Header.Get("X-Schild-Incident"))
	}
	b.h.WaitFor("web-2 holds the incident as web-1 wrote it", func() bool {
		in, err := b.h.App.Store.GetIncident(ctx, incident)
		return err == nil && strings.Contains(in.Reason, "login_bruteforce")
	})
	blk, err := contract.DecodeIncidentBlock(func() *contract.Record {
		recs, _ := b.h.App.Cluster.State(contract.ClassIncidentBlocks)
		for _, rec := range recs {
			if rec.ID == incident {
				return rec
			}
		}
		return &contract.Record{}
	}())
	if err != nil || blk.Source != "behaviour:login_bruteforce" || blk.Node != "web-1" || blk.Client != attacker {
		t.Fatalf("the record of the block on web-2: %+v (%v)", blk, err)
	}
	if code, body := b.h.API("POST", "/incidents/"+incident+"/unblock", map[string]any{}); code != 200 {
		t.Fatalf("unblock on web-2: %d %s", code, body)
	}
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" serves the client again", func() bool {
			return g.blocked(attacker) == "" && holds(t, g, contract.ClassLifts, incident) && holds(t, g, contract.ClassIncidentBlocks)
		})
	}
	if r := a.h.Visit("GET", "/", attacker, "", ""); r.StatusCode != 200 {
		t.Errorf("a request of the released client on web-1: %d", r.StatusCode)
	}
}

// "Freigeben" of an incident in the dashboard means the client: every block
// the node holds for that client is lifted with it, one lift per incident.
// Two nodes often block one client at the same moment under two incidents;
// releasing one of them, on a third node or on one of the two, leaves the
// client unblocked on every node. It is no release of the address.
func TestFreigebenLiftsEveryBlockOfTheClient(t *testing.T) {
	nodes := trio(t)
	a, b, c := nodes[0], nodes[1], nodes[2]
	ctx := context.Background()
	for _, g := range nodes {
		g.h.Login()
	}
	inService(t, nodes...)
	start := time.Now()
	// What runs for the client on the releasing node when the unblock has
	// acted and still holds the lock of the blocks.
	var after atomic.Value
	var watch atomic.Pointer[app.App]
	var watched atomic.Value
	defer app.SetTestClientBlocks(func(x *app.App, done bool) {
		if done && x == watch.Load() {
			bi, _ := x.Behaviour.ActiveBlock(netip.MustParseAddr(watched.Load().(string)))
			after.Store(bi.Incident)
		}
	})()
	for _, tc := range []struct {
		ip, x, y string
		on       *groupNode
		click    string
	}{
		{"203.0.113.71", "FRGB-AAA2", "FRGB-AAA3", c, "FRGB-AAA2"}, // on a third node
		{"203.0.113.72", "FRGB-AAA4", "FRGB-AAA5", a, "FRGB-AAA5"}, // on one of the two, the incident of the other
	} {
		a.block(tc.ip, tc.x, 15*time.Minute)
		b.block(tc.ip, tc.y, 15*time.Minute)
		for _, g := range nodes {
			g := g
			g.h.WaitFor(g.name+" holds both blocks of "+tc.ip, func() bool {
				return slices.Contains(recordIDs(t, g, contract.ClassIncidentBlocks), tc.x) && slices.Contains(recordIDs(t, g, contract.ClassIncidentBlocks), tc.y) && g.blocked(tc.ip) != ""
			})
		}
		// The node holds the incident of the other block too (it wrote it,
		// or took it with the record).
		for _, incident := range []string{tc.x, tc.y} {
			if err := tc.on.h.App.Store.InsertIncident(store.Foreign(ctx), &store.Incident{Incident: incident, Time: time.Now(), IP: tc.ip, Status: "blocked", Sources: []string{"dashboard"}}); err != nil {
				t.Fatal(err)
			}
		}
		after.Store("")
		watched.Store(tc.ip)
		watch.Store(tc.on.h.App)
		tc.on.unblock(t, tc.click, tc.ip)
		watch.Store(nil)
		// The other blocks of the client end in the step of the unblock,
		// not with the next round: only the clicked one may still run then.
		if got := after.Load().(string); got != "" && got != tc.click {
			t.Errorf("%s still runs %q for %s when the unblock of %s has acted, under the lock", tc.on.name, got, tc.ip, tc.click)
		}
		if got := tc.on.blocked(tc.ip); got != "" {
			t.Errorf("%s runs %q for %s right after Freigeben there, want no block of the client", tc.on.name, got, tc.ip)
		}
		for _, g := range nodes {
			g := g
			g.h.WaitFor(g.name+" serves "+tc.ip+" again and holds a lift for each of its incidents", func() bool {
				lifts, blocks := recordIDs(t, g, contract.ClassLifts), recordIDs(t, g, contract.ClassIncidentBlocks)
				return g.blocked(tc.ip) == "" && slices.Contains(lifts, tc.x) && slices.Contains(lifts, tc.y) && !slices.Contains(blocks, tc.x) && !slices.Contains(blocks, tc.y)
			})
		}
		// The other incident reads unblocked too where the person released.
		other := tc.x
		if other == tc.click {
			other = tc.y
		}
		if in, err := tc.on.h.App.Store.GetIncident(ctx, other); err != nil || in.Status != "unblocked" {
			t.Errorf("%s: the incident %s of the other block is %+v (%v), want unblocked", tc.on.name, other, in, err)
		}
		notReleased(t, tc.ip, start, nodes...)
	}
	time.Sleep(time.Second)
	for _, g := range nodes {
		lifts, err := g.h.App.Cluster.State(contract.ClassLifts)
		if err != nil || len(lifts) != 4 {
			t.Fatalf("%s holds %d lifts (%v), want one for each of the four incidents", g.name, len(lifts), err)
		}
		for _, l := range lifts {
			want := c.h.App.Cluster.ID()
			if l.ID == "FRGB-AAA4" || l.ID == "FRGB-AAA5" {
				want = a.h.App.Cluster.ID()
			}
			if l.Origin != want {
				t.Errorf("%s: the lift of %s is written by %s, want by the node the person released on", g.name, l.ID, g.h.App.Cluster.PeerName(l.Origin))
			}
		}
		for _, ip := range []string{"203.0.113.71", "203.0.113.72"} {
			if got := g.blocked(ip); got != "" {
				t.Errorf("%s runs %q for %s a second after Freigeben", g.name, got, ip)
			}
		}
	}
}

// A block that arrives after a person released its client: a twin another
// node decided before it knew of the release.
//
// After "Freigeben" the client has an exception for the sources that
// blocked it, for 24 h, on every node. A block of such a source is held
// and does not run while the exception runs, on no node, the node that
// decided it included: as the detector of a single gateway decides nothing
// for such a client. So the list of blocks and the firewall say what the
// gate does. No lift is written for it.
//
// Known limit: after "Adresse freigeben" without an exception nothing says
// that the client was released. The block that arrives blocks it again,
// although it was decided before the person released; a single gateway
// would need the client to trip a detector anew.
func TestBlockThatArrivesAfterARelease(t *testing.T) {
	a, b := pair(t)
	a.h.Login()
	inService(t, a, b)
	b.h.App.SetGroupBlocksMax(0) // the twins of web-2 are not written yet
	const (
		ipA, xA, yA = "203.0.113.73", "TWNS-AAA2", "TWNS-AAA3" // Freigeben
		ipB, xB, yB = "203.0.113.74", "TWNS-AAA4", "TWNS-AAA5" // Adresse freigeben
	)
	for ip, twins := range map[string][2]string{ipA: {xA, yA}, ipB: {xB, yB}} {
		a.blockAgent(ip, twins[0])
		b.blockAgent(ip, twins[1])
		b.h.WaitFor("web-2 holds the block of web-1 for "+ip, func() bool { return slices.Contains(recordIDs(t, b, contract.ClassIncidentBlocks), twins[0]) })
	}
	a.unblockOf(t, xA, ipA, agentSource)
	a.release(t, ipB)
	if a.blocked(ipA) != "" || a.blocked(ipB) != "" {
		t.Fatalf("web-1 runs %q and %q after the releases", a.blocked(ipA), a.blocked(ipB))
	}
	b.h.WaitFor("web-2 took the lifts and the exception", func() bool {
		return holds(t, b, contract.ClassLifts, xA, xB) && b.h.App.Gate.Exceptions.Has(netip.MustParseAddr(ipA), agentSource, time.Now())
	})
	// The exception reached web-2 while its twin ran: the twin ends there,
	// by the round, and web-2 writes it all the same when it may.
	b.h.App.SetGroupBlocksMax(20000)
	listed := func(g *groupNode, ip string) bool {
		for _, rb := range g.h.App.Behaviour.RunningBlocks() {
			if rb.Key.Addr().String() == ip {
				return true
			}
		}
		return false
	}
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" holds both twins and runs the one of the client released by address", func() bool {
			return holds(t, g, contract.ClassIncidentBlocks, yA, yB) && g.blocked(ipB) == yB
		})
		g.h.WaitFor(g.name+" does not run the twin of the client with the exception", func() bool { return g.blocked(ipA) == "" })
	}
	time.Sleep(1500 * time.Millisecond)
	for _, g := range []*groupNode{a, b} {
		if got := g.blocked(ipA); got != "" || listed(g, ipA) {
			t.Errorf("%s runs %q for the client released by Freigeben (in its list of blocks: %v), want no block while the exception runs", g.name, got, listed(g, ipA))
		}
		if !holds(t, g, contract.ClassIncidentBlocks, yA, yB) || slices.Contains(recordIDs(t, g, contract.ClassLifts), yA) {
			t.Errorf("%s holds the blocks %v and the lifts %v: an exception lifts nothing and drops no record", g.name, recordIDs(t, g, contract.ClassIncidentBlocks), recordIDs(t, g, contract.ClassLifts))
		}
		if r := g.h.Visit("GET", "/", ipA, "", ""); r.StatusCode != 200 {
			t.Errorf("%s answers %d to the client released by Freigeben", g.name, r.StatusCode)
		}
		// The known limit.
		if r := g.h.Visit("GET", "/", ipB, "", ""); r.StatusCode != 403 || g.blocked(ipB) != yB {
			t.Errorf("%s answers %d to the client released by address and runs %q: the block that arrived does not block it", g.name, r.StatusCode, g.blocked(ipB))
		}
	}
	// The block that ended on web-2 by the exception ended without a lift:
	// its incident reads as it did.
	// When the exception is over, the block the group still holds runs.
	// Over in the store, and loaded from there as the gateway loads its
	// exceptions every minute.
	for _, g := range []*groupNode{a, b} {
		g.endExceptions(t, ipA)
	}
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" runs the twin when the exception is over", func() bool { return g.blocked(ipA) == yA })
	}
}

// agentSource is the source of the blocks blockAgent sets.
const agentSource = "agent:tok"

// blockAgent sets a block as an agent does, in the engine of the node.
func (g *groupNode) blockAgent(ip, incident string) {
	g.h.App.Behaviour.SetAgentBlock(behaviour.AgentBlock{IP: netip.MustParseAddr(ip), TokenID: "tok", NetClass: "hosting", Duration: 15 * time.Minute,
		Incident: incident, Time: time.Now()})
}

// endExceptions lets the exceptions of an address run out: over in the
// store, and loaded from it as the gateway does every minute.
func (g *groupNode) endExceptions(t *testing.T, ip string) {
	t.Helper()
	ctx := context.Background()
	if _, err := g.h.App.Store.DB().Exec(`UPDATE exceptions SET expires_ms = ? WHERE ip = ?`, time.Now().Add(-time.Minute).UnixMilli(), ip); err != nil {
		t.Fatal(err)
	}
	xs, err := g.h.App.Store.ActiveExceptions(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	g.h.App.Gate.Exceptions.Load(xs)
}

// "Freigeben" finds the client by the block of the incident, not by the
// address stored with the incident: retention shortens that one to its /24,
// and the shortened address is the client key of somebody else.
func TestFreigebenFindsTheClientByItsBlockNotByTheStoredAddress(t *testing.T) {
	a, b := pair(t)
	a.h.Login()
	inService(t, a, b)
	const ip, x, y, short, z = "203.0.113.77", "SHRT-AAA2", "SHRT-AAA3", "203.0.113.0", "SHRT-AAA4"
	a.block(ip, x, 15*time.Minute)
	b.block(ip, y, 15*time.Minute)
	a.block(short, z, 15*time.Minute) // another client, at the address the first one is shortened to
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" holds the three blocks", func() bool { return holds(t, g, contract.ClassIncidentBlocks, x, y, z) && g.blocked(short) == z })
	}
	// The incident as retention left it.
	a.unblock(t, x, short)
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" serves the client of the incident again", func() bool { return g.blocked(ip) == "" && holds(t, g, contract.ClassLifts, x, y) })
	}
	// An incident with a shortened address and no block this node knows:
	// the clicked incident alone.
	const gone = "SHRT-AAA5"
	a.unblock(t, gone, short)
	time.Sleep(time.Second)
	for _, g := range []*groupNode{a, b} {
		if got := g.blocked(short); got != z {
			t.Errorf("%s runs %q for the other client at the shortened address, want its block %q", g.name, got, z)
		}
		if lifts := recordIDs(t, g, contract.ClassLifts); slices.Contains(lifts, z) || !slices.Contains(lifts, gone) {
			t.Errorf("%s holds the lifts %v: the block of the other client was lifted, or the clicked incident was not", g.name, lifts)
		}
	}
}

// "Freigeben" of the incident of a single refused request, which has no
// block: unblocked as on a single gateway, and no lift for the group.
func TestFreigebenOfAnIncidentWithoutABlockWritesNoLift(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	b.h.Login()
	inService(t, a, b)
	const attacker = "203.0.113.57"
	b.h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", attacker, "", "")
	b.h.Flush()
	rows, _, err := b.h.App.Store.ListEvents(ctx, store.EventFilter{IP: attacker}, 0, 10)
	if err != nil || len(rows) == 0 || rows[0].Incident == "" {
		t.Fatalf("no incident of %s: %v", attacker, err)
	}
	incident := rows[0].Incident
	if code, body := b.h.API("POST", "/incidents/"+incident+"/unblock", map[string]any{}); code != 200 {
		t.Fatalf("unblock on web-2: %d %s", code, body)
	}
	if in, err := b.h.App.Store.GetIncident(ctx, incident); err != nil || in.Status != "unblocked" {
		t.Fatalf("the incident is %+v (%v), want unblocked", in, err)
	}
	time.Sleep(time.Second)
	for _, g := range []*groupNode{a, b} {
		if lifts := recordIDs(t, g, contract.ClassLifts); len(lifts) != 0 || g.h.App.Store.LiftNoted(incident) {
			t.Errorf("%s holds the lifts %v (noted: %v) for an incident that never had a block", g.name, lifts, g.h.App.Store.LiftNoted(incident))
		}
	}
}

// A node that takes a lift stores the incident as unblocked, also when the
// block does not run there any more: the exception of a "Freigeben" made on
// another node arrived first and ended the block without a word. The node
// that decided the block wrote the incident, so its change travels; on a
// third node it is no news of that node.
func TestLiftMarksTheIncidentWhereTheBlockEndedBefore(t *testing.T) {
	nodes := trio(t)
	a, b, c := nodes[0], nodes[1], nodes[2]
	ctx := context.Background()
	b.h.Login()
	inService(t, nodes...)
	var fail atomic.Bool
	fail.Store(true)
	defer app.SetTestLiftWrite(func(x *app.App, _ string) error {
		if x == b.h.App && fail.Load() {
			return errors.New("test: the lift of web-2 is late")
		}
		return nil
	})()
	const ip, x = "203.0.113.78", "LFTM-AAA2"
	a.blockAgent(ip, x)
	// web-1 decided the block and wrote its incident.
	if err := a.h.App.Store.InsertIncident(ctx, &store.Incident{Incident: x, Time: time.Now(), IP: ip, Status: "blocked", Sources: []string{agentSource}}); err != nil {
		t.Fatal(err)
	}
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" runs the block", func() bool { return g.blocked(ip) == x })
	}
	status := func(g *groupNode) string {
		g.h.App.FlushBlocks()
		in, err := g.h.App.Store.GetIncident(ctx, x)
		if err != nil {
			t.Fatal(err)
		}
		return in.Status
	}
	// Freigeben on web-2: its exception reaches the others, its lift not yet.
	if code, body := b.h.API("POST", "/incidents/"+x+"/unblock", map[string]any{}); code != 200 {
		t.Fatalf("unblock on web-2: %d %s", code, body)
	}
	for _, g := range []*groupNode{a, c} {
		g := g
		g.h.WaitFor(g.name+" ended the block by the exception", func() bool { return g.blocked(ip) == "" })
		if got := status(g); got != "blocked" {
			t.Fatalf("%s holds the incident as %s after the exception ended the block: a block that ends without a lift leaves its incident alone", g.name, got)
		}
		if lifts := recordIDs(t, g, contract.ClassLifts); len(lifts) != 0 {
			t.Fatalf("%s holds the lifts %v before web-2 wrote one", g.name, lifts)
		}
	}
	ownA, ownC := a.h.App.Store.OwnGen(), c.h.App.Store.OwnGen()
	fail.Store(false)
	for _, g := range []*groupNode{a, c} {
		g := g
		g.h.WaitFor(g.name+" holds the lift and the incident as unblocked", func() bool { return holds(t, g, contract.ClassLifts, x) && status(g) == "unblocked" })
	}
	if a.h.App.Store.OwnGen() == ownA {
		t.Error("web-1 wrote the incident, and its change is no news of web-1: no node asks it again")
	}
	if got := c.h.App.Store.OwnGen(); got != ownC {
		t.Errorf("web-3 did not write the incident, and marked it as news of its own (%d, was %d)", got, ownC)
	}
}

// A block a person sets by hand while an exception covers its source: on
// its node it runs and is listed, and the gate lets the requests of the
// client pass it while the exception runs, as on a single gateway. The
// other nodes hold its record and do not run it.
func TestBlockSetByHandUnderAnExceptionRunsOnItsNode(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	a.h.Login()
	inService(t, a, b)
	const ip = "198.51.100.77"
	until := time.Now().Add(24 * time.Hour)
	if err := a.h.App.Store.AddException(ctx, store.Exception{IP: ip, Sources: []string{"dashboard"}, Expires: until}); err != nil {
		t.Fatal(err)
	}
	a.h.App.Gate.Exceptions.Add(netip.MustParseAddr(ip), []string{"dashboard"}, until)
	b.h.WaitFor("web-2 took the exception", func() bool { return b.h.App.Gate.Exceptions.Has(netip.MustParseAddr(ip), "dashboard", time.Now()) })
	code, body := a.h.API("POST", "/blocks", map[string]any{"address": ip, "duration_s": 3600, "reason": "test"})
	if code != 200 {
		t.Fatalf("block by hand on web-1: %d %s", code, body)
	}
	var rb struct {
		Incident string `json:"incident"`
	}
	_ = json.Unmarshal(body, &rb)
	b.h.WaitFor("web-2 holds the record of the block", func() bool { return holds(t, b, contract.ClassIncidentBlocks, rb.Incident) })
	time.Sleep(time.Second)
	if got := a.blocked(ip); got != rb.Incident {
		t.Errorf("web-1 runs %q a second after the block was set by hand, want %q: the answer said it is set", got, rb.Incident)
	}
	if got := b.blocked(ip); got != "" {
		t.Errorf("web-2 runs %q for a block whose source the exception covers", got)
	}
	for _, g := range []*groupNode{a, b} {
		if r := g.h.Visit("GET", "/", ip, "", ""); r.StatusCode != 200 {
			t.Errorf("%s answers %d to the client with the exception", g.name, r.StatusCode)
		}
	}
}

// "Freigeben" works for a block the node holds and does not run, although
// its incident reads unblocked: the group holds the block, that is enough.
func TestFreigebenOfABlockTheNodeHoldsAndDoesNotRun(t *testing.T) {
	nodes := newGroup(t, "web-1", "web-2", "web-3")
	a, c := nodes[0], nodes[2]
	c.mode = "observe"
	for _, g := range nodes {
		g.start(t)
	}
	ctx := context.Background()
	c.h.Login()
	inService(t, nodes...)
	const ip, x = "203.0.113.79", "HELD-AAA2"
	a.block(ip, x, 15*time.Minute)
	c.h.WaitFor("web-3 holds the record of the block and its incident", func() bool {
		_, err := c.h.App.Store.GetIncident(ctx, x)
		return err == nil && holds(t, c, contract.ClassIncidentBlocks, x)
	})
	// The word that the block ended somewhere for a while, which travels
	// with the incident.
	if err := c.h.App.Store.MarkUnblocked(store.Foreign(ctx), x, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	if code, body := c.h.API("POST", "/incidents/"+x+"/unblock", map[string]any{}); code != 200 {
		t.Fatalf("unblock on web-3, which holds the block and does not run it: %d %s", code, body)
	}
	a.h.WaitFor("web-1 ended the block", func() bool { return a.blocked(ip) == "" && holds(t, a, contract.ClassLifts, x) })
}
