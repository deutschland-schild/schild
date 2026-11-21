package cluster

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/testport"
)

type testNode struct {
	t      *testing.T
	dir    string
	addr   string
	name   string
	node   *Node
	cancel context.CancelFunc
	done   chan struct{}

	mu   sync.Mutex
	seen []*contract.Record
	// peers are cluster.peers of a node set up by configuration.
	peers []string
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestNode(t *testing.T, name string) *testNode {
	t.Helper()
	return &testNode{t: t, dir: filepath.Join(t.TempDir(), "cluster"), addr: testport.Free(t), name: name}
}

func (tn *testNode) start() {
	tn.t.Helper()
	n, err := Open(Options{Dir: tn.dir, Listen: tn.addr, Log: quiet(), Hold: 300 * time.Millisecond, Peers: tn.peers})
	if err != nil {
		tn.t.Fatalf("%s: open: %v", tn.name, err)
	}
	n.On(contract.ClassBlocks, func(r *contract.Record) {
		tn.mu.Lock()
		tn.seen = append(tn.seen, r)
		tn.mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	tn.node, tn.cancel, tn.done = n, cancel, make(chan struct{})
	go func() {
		defer close(tn.done)
		if err := n.Run(ctx); err != nil {
			tn.t.Errorf("%s: run: %v", tn.name, err)
		}
	}()
	waitFor(tn.t, tn.name+" listens", func() bool { return n.Addr() != "" })
	tn.t.Cleanup(tn.stop)
}

func (tn *testNode) stop() {
	if tn.node == nil {
		return
	}
	tn.cancel()
	<-tn.done
	tn.node.Close()
	tn.node = nil
}

func (tn *testNode) join(via *testNode) {
	tn.t.Helper()
	code, _, err := Invite(via.dir, nil)
	if err != nil {
		tn.t.Fatal(err)
	}
	if _, _, err := Join(context.Background(), tn.dir, tn.name, tn.addr, via.addr, code, nil); err != nil {
		tn.t.Fatalf("%s joins: %v", tn.name, err)
	}
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// threeNodes: a founds the group, b and c join through a, all run.
func threeNodes(t *testing.T) (a, b, c *testNode) {
	t.Helper()
	a, b, c = newTestNode(t, "web-1"), newTestNode(t, "web-2"), newTestNode(t, "web-3")
	if _, err := Init(a.dir, a.name, a.addr, nil); err != nil {
		t.Fatal(err)
	}
	a.start()
	b.join(a)
	c.join(a)
	b.start()
	c.start()
	return a, b, c
}

func block(client string, until time.Time) *contract.Block {
	return &contract.Block{Client: client, Bits: 32, Source: "dashboard", Level: 1, Since: contract.TimeText(until.Add(-time.Hour)), Until: contract.TimeText(until),
		DurationS: 3600, Incident: "S-" + client, NetClass: "hosting", Node: "web-1"}
}

func (tn *testNode) publishBlock(client string) {
	tn.t.Helper()
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if _, err := tn.node.Publish(contract.ClassBlocks, client, block(client, until), false, until); err != nil {
		tn.t.Fatal(err)
	}
}

// holds reports the state of a client on a node: "block", "lift" or "".
func (tn *testNode) holds(client string) string {
	recs, err := tn.node.State(contract.ClassBlocks)
	if err != nil {
		tn.t.Fatal(err)
	}
	for _, r := range recs {
		if r.ID == client {
			if r.Deleted {
				return "lift"
			}
			return "block"
		}
	}
	return ""
}

func TestGroupSharesBlocksAndLifts(t *testing.T) {
	a, b, c := threeNodes(t)
	a.publishBlock("203.0.113.7")
	for _, n := range []*testNode{b, c} {
		waitFor(t, n.name+" holds the block of web-1", func() bool { return n.holds("203.0.113.7") == "block" })
	}
	// c lifts it: a tombstone, which every node takes.
	if _, err := c.node.Publish(contract.ClassBlocks, "203.0.113.7", &contract.Lift{Incident: "S-203.0.113.7", Node: "web-3"}, true, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*testNode{a, b} {
		waitFor(t, n.name+" holds the lift of web-3", func() bool { return n.holds("203.0.113.7") == "lift" })
	}
	b.mu.Lock()
	got := len(b.seen)
	b.mu.Unlock()
	if got != 2 {
		t.Errorf("web-2 was told %d changes, want the block and the lift", got)
	}
}

func TestNodeCatchesUpAfterAnOutage(t *testing.T) {
	a, b, c := threeNodes(t)
	waitFor(t, "web-1 knows web-3", func() bool { return a.node.IsMember(c.node.ID()) })
	c.stop()
	a.publishBlock("203.0.113.7")
	b.publishBlock("203.0.113.8")
	waitFor(t, "web-2 holds the block of web-1", func() bool { return b.holds("203.0.113.7") == "block" })
	a.stop() // the origin of one block is gone when web-3 returns
	c.start()
	waitFor(t, "web-3 holds what it missed, also the block of the node that is away", func() bool {
		return c.holds("203.0.113.7") == "block" && c.holds("203.0.113.8") == "block"
	})
}

func TestTwoWritesOfOneClientSettleTheSame(t *testing.T) {
	a, b, c := threeNodes(t)
	a.publishBlock("203.0.113.7")
	b.publishBlock("203.0.113.7")
	winner := func(n *testNode) string {
		recs, _ := n.node.State(contract.ClassBlocks)
		if len(recs) != 1 {
			return ""
		}
		return recs[0].Origin
	}
	waitFor(t, "every node holds the same single record", func() bool {
		w := winner(a)
		return w != "" && winner(b) == w && winner(c) == w
	})
}

func TestRemovedMemberIsCutOff(t *testing.T) {
	a, b, c := threeNodes(t)
	waitFor(t, "web-2 knows web-3", func() bool { return b.node.IsMember(c.node.ID()) })
	if _, err := Remove(a.dir, "web-3", nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "web-2 learned of the removal", func() bool { return !b.node.IsMember(c.node.ID()) })
	waitFor(t, "web-3 is told that it was removed", func() bool { return c.node.Removed() })
	// What it writes now reaches nobody.
	c.publishBlock("203.0.113.9")
	a.publishBlock("203.0.113.10")
	waitFor(t, "web-2 holds the block of web-1", func() bool { return b.holds("203.0.113.10") == "block" })
	time.Sleep(600 * time.Millisecond)
	for _, n := range []*testNode{a, b} {
		if n.holds("203.0.113.9") != "" {
			t.Errorf("%s took a block a removed member signed", n.name)
		}
	}
	// And handed over directly it is refused.
	recs, raws, _ := c.node.winners(contract.ClassBlocks)
	for i, r := range recs {
		if r.ID == "203.0.113.9" {
			// Counted now, or refused and counted when web-1 asked web-3
			// the last time before it stopped asking.
			if n, _ := a.node.take([]json.RawMessage{raws[i]}, map[string]uint64{r.Origin: r.Seq}); n != 0 || a.holds("203.0.113.9") != "" {
				t.Errorf("a record of a removed member was applied (%d)", n)
			}
			if a.node.Rejected.Load() == 0 {
				t.Error("the refused record was not counted")
			}
		}
	}
}

func TestTamperedAndForeignRecordsAreRefused(t *testing.T) {
	a := newTestNode(t, "web-1")
	if _, err := Init(a.dir, a.name, a.addr, nil); err != nil {
		t.Fatal(err)
	}
	a.start()
	// A stranger with its own group signs a block for the same client.
	x := newTestNode(t, "evil")
	if _, err := Init(x.dir, x.name, x.addr, nil); err != nil {
		t.Fatal(err)
	}
	x.start()
	x.publishBlock("203.0.113.7")
	recs, raws, _ := x.node.winners(contract.ClassBlocks)
	foreign := raws[0]
	// The same record, relabelled to the group of web-1.
	relabelled := *recs[0]
	relabelled.Group = a.node.Group()
	rl, _ := json.Marshal(relabelled)
	// A record of web-1 itself with other data under the old signature.
	a.publishBlock("203.0.113.8")
	own, _, _ := a.node.winners(contract.ClassBlocks)
	bent := *own[0]
	bent.Seq, bent.HLC = bent.Seq+1, bent.HLC+1
	bt, _ := json.Marshal(bent)

	for name, raw := range map[string][]byte{"foreign group": foreign, "relabelled": rl, "bent": bt, "no json": []byte("{")} {
		before := a.node.Rejected.Load() + a.node.Deferred.Load()
		n, err := a.node.take([]json.RawMessage{raw}, nil)
		if err != nil || n != 0 {
			t.Errorf("%s: applied %d, err %v", name, n, err)
		}
		if a.node.Rejected.Load()+a.node.Deferred.Load() != before+1 {
			t.Errorf("%s: not counted", name)
		}
	}
	if a.holds("203.0.113.7") != "" {
		t.Error("a block of a stranger is held")
	}
}

func TestJoinCodes(t *testing.T) {
	a := newTestNode(t, "web-1")
	clock := time.Now()
	now := func() time.Time { return clock }
	if _, err := Init(a.dir, a.name, a.addr, now); err != nil {
		t.Fatal(err)
	}
	a.start()
	code, _, err := Invite(a.dir, now)
	if err != nil {
		t.Fatal(err)
	}
	b := newTestNode(t, "web-2")
	if _, n, err := Join(context.Background(), b.dir, b.name, b.addr, a.addr, code, nil); err != nil || n != 2 {
		t.Fatalf("join: %d members, %v", n, err)
	}
	// The same code a second time.
	c := newTestNode(t, "web-3")
	if _, _, err := Join(context.Background(), c.dir, c.name, c.addr, a.addr, code, nil); err == nil || !strings.Contains(err.Error(), "join code not valid") {
		t.Errorf("a used code: %v", err)
	}
	// A code of another node: its key does not fit the node asked.
	x := newTestNode(t, "other")
	if _, err := Init(x.dir, x.name, x.addr, nil); err != nil {
		t.Fatal(err)
	}
	other, _, _ := Invite(x.dir, nil)
	d := newTestNode(t, "web-4")
	if _, _, err := Join(context.Background(), d.dir, d.name, d.addr, a.addr, other, nil); err == nil || !strings.Contains(err.Error(), "another key") {
		t.Errorf("a code of another node: %v", err)
	}
	// A node that is in a group does not join another.
	fresh, _, _ := Invite(a.dir, nil)
	if _, _, err := Join(context.Background(), b.dir, b.name, b.addr, a.addr, fresh, nil); !errors.Is(err, ErrHasGroup) {
		t.Errorf("join twice: %v", err)
	}
	// An expired code. The running node reads the wall clock, so the invite
	// is written an hour and a second in the past.
	clock = time.Now().Add(-contract.JoinCodeTTL - time.Second)
	old, _, _ := Invite(a.dir, now)
	e := newTestNode(t, "web-5")
	if _, _, err := Join(context.Background(), e.dir, e.name, e.addr, a.addr, old, nil); err == nil || !strings.Contains(err.Error(), "join code not valid") {
		t.Errorf("an expired code: %v", err)
	}
}

func TestStatus(t *testing.T) {
	a, b, _ := threeNodes(t)
	a.publishBlock("203.0.113.7")
	waitFor(t, "web-2 holds the block", func() bool { return b.holds("203.0.113.7") == "block" })
	waitFor(t, "web-2 wrote its view", func() bool {
		st, err := ReadStatus(b.dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(st.Members) != 3 || st.Records[contract.ClassBlocks] != 1 || st.Seen.IsZero() {
			return false
		}
		for _, m := range st.Members {
			if !m.Self && m.OutOK.IsZero() {
				return false
			}
		}
		return true
	})
}

func TestNodeWithoutGroup(t *testing.T) {
	if _, err := Open(Options{Dir: filepath.Join(t.TempDir(), "cluster"), Listen: "127.0.0.1:0"}); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("open without a group: %v", err)
	}
}

// A handler that takes a lock of its owner, while the owner publishes under
// the same lock: the block sync of the gateway does exactly this.
func TestHandlerAndPublishDoNotLockEachOther(t *testing.T) {
	a, b, _ := threeNodes(t)
	var owner sync.Mutex
	b.node.On(contract.ClassBlocks, func(*contract.Record) {
		owner.Lock()
		time.Sleep(time.Millisecond)
		owner.Unlock()
	})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			owner.Lock()
			until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
			client := fmt.Sprintf("198.51.100.%d", i%250+1)
			_, _ = b.node.Publish(contract.ClassBlocks, client, block(client, until), false, until)
			owner.Unlock()
		}
	}()
	for i := 0; i < 60; i++ {
		a.publishBlock(fmt.Sprintf("203.0.113.%d", i+1))
	}
	waitFor(t, "web-2 took every block of web-1 while it published its own", func() bool { return b.holds("203.0.113.60") == "block" })
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publish and handler lock each other")
	}
}

// A group set up by configuration: the same secret and the same list of
// addresses on every node, no command between them.
func TestGroupByConfiguration(t *testing.T) {
	secret := []byte("the-same-file-on-every-node-0123456789")
	a, b, c := newTestNode(t, "web-1"), newTestNode(t, "web-2"), newTestNode(t, "web-3")
	all := []string{a.addr, b.addr, c.addr}
	var group string
	for _, n := range []*testNode{a, b, c} {
		g, err := Configure(n.dir, n.name, n.addr, secret, nil)
		if err != nil {
			t.Fatalf("%s: %v", n.name, err)
		}
		if group != "" && g != group {
			t.Fatalf("%s is in group %s, the others in %s", n.name, g, group)
		}
		group = g
		n.peers = all
	}
	// The order of the starts does not matter: web-3 comes up alone first.
	c.start()
	c.publishBlock("203.0.113.7")
	a.start()
	b.start()
	for _, n := range []*testNode{a, b} {
		waitFor(t, n.name+" found the group and holds the block of web-3", func() bool { return n.holds("203.0.113.7") == "block" })
	}
	for _, n := range []*testNode{a, b, c} {
		for _, m := range []*testNode{a, b, c} {
			waitFor(t, n.name+" knows "+m.name, func() bool { return n.node.IsMember(m.node.ID()) })
		}
	}
	// The same deployment again changes nothing; a new address is a new record.
	b.stop()
	before, _ := ReadStatus(b.dir, nil)
	if _, err := Configure(b.dir, b.name, b.addr, secret, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := ReadStatus(b.dir, nil)
	if len(after.Members) != len(before.Members) {
		t.Errorf("a second deployment changed the member list: %d, then %d", len(before.Members), len(after.Members))
	}

	// A node with another secret is in another group and gets nothing.
	x := newTestNode(t, "stranger")
	if g, err := Configure(x.dir, x.name, x.addr, []byte("another-file-another-file-another-file"), nil); err != nil || g == group {
		t.Fatalf("another secret: group %s, %v", g, err)
	}
	x.peers = all
	x.start()
	a.publishBlock("203.0.113.8")
	waitFor(t, "web-3 holds the new block", func() bool { return c.holds("203.0.113.8") == "block" })
	time.Sleep(1500 * time.Millisecond)
	if a.node.IsMember(x.node.ID()) || c.node.IsMember(x.node.ID()) {
		t.Error("a node with another secret became a member")
	}
	if x.holds("203.0.113.8") != "" || x.holds("203.0.113.7") != "" {
		t.Error("a node with another secret holds blocks of the group")
	}
	// And the secret of one group does not move a node out of another.
	if _, err := Configure(x.dir, x.name, x.addr, secret, nil); !errors.Is(err, ErrOtherGroup) {
		t.Errorf("a node of another group with this secret: %v", err)
	}
}

func TestRemovedNodeStaysOutAlthoughItHoldsTheSecret(t *testing.T) {
	secret := []byte("the-same-file-on-every-node-0123456789")
	a, b := newTestNode(t, "web-1"), newTestNode(t, "web-2")
	for _, n := range []*testNode{a, b} {
		if _, err := Configure(n.dir, n.name, n.addr, secret, nil); err != nil {
			t.Fatal(err)
		}
		n.peers = []string{a.addr, b.addr}
	}
	a.start()
	b.start()
	waitFor(t, "web-1 knows web-2", func() bool { return a.node.IsMember(b.node.ID()) })
	id := b.node.ID()
	if _, err := Remove(a.dir, "web-2", nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "web-2 is told that it was removed", func() bool { return b.node.Removed() })
	b.stop()
	// The next deployment starts it again with the same files: it is told
	// again, and stays out.
	if _, err := Configure(b.dir, b.name, b.addr, secret, nil); err != nil {
		t.Fatal(err)
	}
	b.start()
	waitFor(t, "web-2 is told again after its restart", func() bool { return b.node.Removed() })
	a.publishBlock("203.0.113.7")
	time.Sleep(time.Second)
	if a.node.IsMember(id) {
		t.Error("a removed node is a member again")
	}
	if b.holds("203.0.113.7") != "" {
		t.Error("a removed node got a block of the group")
	}
}

func TestReadSecret(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	s, _ := NewSecret()
	if got, err := ReadSecret(write("ok", s+"\n", 0o600)); err != nil || string(got) != s {
		t.Errorf("a good secret: %q, %v", got, err)
	}
	if _, err := ReadSecret(write("open", s, 0o644)); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Errorf("a secret others read: %v", err)
	}
	if _, err := ReadSecret(write("short", "abc", 0o600)); !errors.Is(err, contract.ErrSecret) {
		t.Errorf("a short secret: %v", err)
	}
	if _, err := ReadSecret(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file was read")
	}
}

// An edge has a place in the member list and may read two things: the
// member list, and what was registered for edges.
func TestEdgeReadsTheMemberListAndNothingElse(t *testing.T) {
	a, b, _ := threeNodes(t)
	a.node.OnEdgeAsk("firewall", func(from string, body []byte) ([]byte, error) {
		return []byte(`{"blocks":` + string(body) + `}`), nil
	})
	a.node.OnAsk("events", func(string, []byte) ([]byte, error) { return []byte(`{"rows":"secret"}`), nil })
	a.publishBlock("203.0.113.7")
	code, _, err := InviteRole(a.dir, contract.RoleEdge, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "cluster")
	if _, _, err := Join(context.Background(), dir, "lb-1", "", a.addr, code, nil); err != nil {
		t.Fatalf("edge joins: %v", err)
	}
	// A code made for an edge admits no gateway.
	code2, _, _ := InviteRole(a.dir, contract.RoleEdge, nil)
	g := newTestNode(t, "web-9")
	if _, _, err := Join(context.Background(), g.dir, g.name, g.addr, a.addr, code2, nil); err == nil || !strings.Contains(err.Error(), "does not admit this node as gateway") {
		t.Errorf("a gateway with an edge's code: %v", err)
	}
	e, err := OpenEdge(dir, quiet())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx := context.Background()
	out, err := e.Ask(ctx, "firewall", []byte(`"lb-1"`), 5*time.Second)
	if err != nil || string(out) != `{"blocks":"lb-1"}` {
		t.Fatalf("the edge asks for the blocks: %q, %v", out, err)
	}
	// What gateways ask each other is not for an edge.
	if _, err := e.Ask(ctx, "events", nil, 5*time.Second); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("an edge asked for events: %v", err)
	}
	// The sync gives it member records only: the block of web-1 stays out.
	waitFor(t, "the edge knows every gateway", func() bool {
		e.seen = time.Time{}
		_, _ = e.Ask(ctx, "firewall", nil, 5*time.Second)
		return len(e.gateways()) == 3
	})
	recs, _ := e.n.State(contract.ClassBlocks)
	if len(recs) != 0 {
		t.Errorf("an edge holds %d block records", len(recs))
	}
	// It cannot write: a record it signs is refused by every gateway.
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	rec, err := e.n.publish(contract.ClassBlocks, "203.0.113.99", block("203.0.113.99", until), false, until)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rec)
	before := b.node.Rejected.Load() + b.node.Deferred.Load()
	if n, _ := b.node.take([]json.RawMessage{raw}, nil); n != 0 || b.node.Rejected.Load()+b.node.Deferred.Load() != before+1 {
		t.Errorf("a gateway took a record an edge signed (%d)", n)
	}
	// It may not tell, lock or hello either.
	c := meshClient(e.n.cert, func(ed25519.PublicKey) bool { return true }, 3*time.Second)
	for _, path := range []string{pathTell, pathLock, pathUnlock} {
		var x map[string]any
		if err := postJSON(ctx, c, "https://"+a.addr+path, map[string]string{"kind": "counts", "name": "x"}, &x); err == nil || !strings.Contains(err.Error(), "403") {
			t.Errorf("an edge called %s: %v", path, err)
		}
	}
	// A removed edge is told so and gets nothing more.
	if _, err := Remove(a.dir, "lb-1", nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the removed edge is refused", func() bool {
		_, err := e.Ask(ctx, "firewall", nil, 5*time.Second)
		return errors.Is(err, ErrRemovedSelf)
	})
	// A gateway's directory is no edge.
	if _, err := OpenEdge(a.dir, quiet()); !errors.Is(err, ErrNoEdge) {
		t.Errorf("a gateway opened as an edge: %v", err)
	}
}

// A paused node serves on, takes nothing and hands nothing over; what was
// written meanwhile on either side arrives after resume.
func TestPauseAndResume(t *testing.T) {
	a, b, c := threeNodes(t)
	a.publishBlock("203.0.113.1")
	waitFor(t, "web-2 holds the first block", func() bool { return b.holds("203.0.113.1") == "block" })
	if err := Pause(b.dir, true, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "web-2 noticed that it is paused", func() bool { return b.node.Paused() })
	a.publishBlock("203.0.113.2")
	b.publishBlock("203.0.113.3")
	waitFor(t, "web-3 holds the block of web-1", func() bool { return c.holds("203.0.113.2") == "block" })
	time.Sleep(1500 * time.Millisecond)
	if b.holds("203.0.113.2") != "" {
		t.Error("a paused node took a record")
	}
	if a.holds("203.0.113.3") != "" || c.holds("203.0.113.3") != "" {
		t.Error("a paused node handed a record over")
	}
	if b.holds("203.0.113.3") != "block" {
		t.Error("a paused node lost what was written on it")
	}
	st, err := ReadStatus(b.dir, nil)
	if err != nil || st.Paused == "" {
		t.Errorf("status does not say paused: %+v, %v", st, err)
	}
	if err := Pause(b.dir, false, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "after resume every node holds every block", func() bool {
		return b.holds("203.0.113.2") == "block" && a.holds("203.0.113.3") == "block" && c.holds("203.0.113.3") == "block"
	})
}

func TestGroupIsFullAtSixteenGateways(t *testing.T) {
	a := newTestNode(t, "web-1")
	if _, err := Init(a.dir, a.name, a.addr, nil); err != nil {
		t.Fatal(err)
	}
	a.start()
	for i := 2; i <= MaxGateways; i++ {
		n := newTestNode(t, fmt.Sprintf("web-%d", i))
		n.join(a)
	}
	code, _, _ := Invite(a.dir, nil)
	extra := newTestNode(t, "web-17")
	if _, _, err := Join(context.Background(), extra.dir, extra.name, extra.addr, a.addr, code, nil); err == nil || !strings.Contains(err.Error(), "the group is full") {
		t.Fatalf("the seventeenth gateway: %v", err)
	}
	// An edge is another count.
	ecode, _, _ := InviteRole(a.dir, contract.RoleEdge, nil)
	if _, _, err := Join(context.Background(), filepath.Join(t.TempDir(), "cluster"), "lb-1", "", a.addr, ecode, nil); err != nil {
		t.Errorf("an edge next to sixteen gateways: %v", err)
	}
}
