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
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/app"
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
	a.block(ip, x, 4*time.Second)
	b.block(ip, y, 15*time.Minute)
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" holds both blocks", func() bool { return holds(t, g, contract.ClassIncidentBlocks, x, y) })
	}
	if a.blocked(ip) != x {
		t.Fatalf("web-1 runs %q, want its own block %q", a.blocked(ip), x)
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
	if b.blocked(ip) != x || b.blocked(own) != y {
		t.Fatalf("after its restart web-2 runs %q and %q, want the kept blocks", b.blocked(ip), b.blocked(own))
	}
	inService(t, a, b)
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
	defer app.SetTestClientBlocks(func(x *app.App) {
		if x != target {
			return
		}
		go func() { _, _ = target.Cluster.Take(raws[0]) }()
		for i := 0; i < 50 && b.blocked(ip) == ""; i++ {
			time.Sleep(10 * time.Millisecond)
		}
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
// its records, not one alone.
func TestFirstStartAsksEveryMemberItReaches(t *testing.T) {
	nodes := trio(t)
	inService(t, nodes...)
	const mark = "blocks_by_incident"
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" made the cut", func() bool { return g.h.App.Cluster.Mark(mark) == "asked" })
	}
	c := nodes[2]
	// first is the member web-3 names first when it lists whom it reaches,
	// holder the other one.
	first, holder := nodes[0], nodes[1]
	if holder.h.App.Cluster.ID() < first.h.App.Cluster.ID() {
		first, holder = holder, first
	}
	// A block record web-3 lacks although its vector says it has it: what a
	// node refused while it ran the build before. Of the two others only
	// one holds it.
	const ip, x = "203.0.113.65", "UUUU-AAA4"
	holder.block(ip, x, 15*time.Minute)
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" runs the block", func() bool { return g.blocked(ip) == x })
	}
	for _, g := range []*groupNode{c, first} {
		if err := g.h.Stop(); err != nil {
			t.Fatal(err)
		}
		execCluster(t, g.clusterDir(), `DELETE FROM records WHERE class = ? AND id = ?`, contract.ClassIncidentBlocks, x)
	}
	execCluster(t, c.clusterDir(), `DELETE FROM meta WHERE k = ?`, "mark:"+mark)
	first.start(t)
	c.start(t)
	c.h.WaitFor("web-3 holds the block again after its first start: it asked the member that holds it too", func() bool { return c.blocked(ip) == x })
	c.h.WaitFor("web-3 made the cut", func() bool { return c.h.App.Cluster.Mark(mark) == "asked" })
}
