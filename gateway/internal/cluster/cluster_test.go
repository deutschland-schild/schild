package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestNode(t *testing.T, name string) *testNode {
	t.Helper()
	return &testNode{t: t, dir: filepath.Join(t.TempDir(), "cluster"), addr: testport.Free(t), name: name}
}

func (tn *testNode) start() {
	tn.t.Helper()
	n, err := Open(Options{Dir: tn.dir, Listen: tn.addr, Log: quiet(), Hold: 300 * time.Millisecond})
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
	waitFor(t, "web-3 learned of its removal or is refused", func() bool {
		ok := c.node.IsMember(c.node.ID())
		c.node.pmu.Lock()
		defer c.node.pmu.Unlock()
		refused := false
		for _, p := range c.node.peers {
			p.mu.Lock()
			refused = refused || strings.Contains(p.err, "403")
			p.mu.Unlock()
		}
		return !ok || refused
	})
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
