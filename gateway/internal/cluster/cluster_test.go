package cluster

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/jobs"
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

// testSecret is the group secret of the test groups.
var testSecret = []byte("the-same-file-on-every-node-0123456789")

// inGroup sets the nodes up as a deployment does: the same secret on every
// node, and every node's address in cluster.peers.
func inGroup(t *testing.T, secret []byte, nodes ...*testNode) string {
	t.Helper()
	var all []string
	for _, n := range nodes {
		all = append(all, n.addr)
	}
	group := ""
	for _, n := range nodes {
		g, _, err := Configure(n.dir, n.name, n.addr, secret, nil)
		if err != nil {
			t.Fatalf("%s: %v", n.name, err)
		}
		group = g
		n.peers = all
	}
	return group
}

// knowEachOther waits until every node holds every other as a member.
func knowEachOther(t *testing.T, nodes ...*testNode) {
	t.Helper()
	for _, n := range nodes {
		for _, m := range nodes {
			waitFor(t, n.name+" knows "+m.name, func() bool { return n.node.IsMember(m.node.ID()) })
		}
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

// threeNodes: three nodes set up with the same secret, all run and know
// each other.
func threeNodes(t *testing.T) (a, b, c *testNode) {
	t.Helper()
	a, b, c = newTestNode(t, "web-1"), newTestNode(t, "web-2"), newTestNode(t, "web-3")
	inGroup(t, testSecret, a, b, c)
	a.start()
	b.start()
	c.start()
	knowEachOther(t, a, b, c)
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
	// The handler runs after the record is stored: wait for it.
	waitFor(t, "web-2 was told the block and the lift", func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return len(b.seen) == 2
	})
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
	inGroup(t, testSecret, a)
	a.start()
	// A stranger with its own group signs a block for the same client.
	x := newTestNode(t, "evil")
	inGroup(t, []byte("another-file-another-file-another-file"), x)
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
	// What the running node noted of a member's clock is in the status
	// (`schild cluster status` reads the store, not the process).
	if err := b.node.NoteClock(a.node.ID(), -90*time.Second); err != nil {
		t.Fatal(err)
	}
	st, err := ReadStatus(b.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	noted := 0
	for _, m := range st.Members {
		if m.ID == a.node.ID() {
			if m.Clock != -90*time.Second || m.ClockAt.IsZero() {
				t.Errorf("clock of web-1 in the status: %s at %s", m.Clock, m.ClockAt)
			}
			noted++
		} else if !m.ClockAt.IsZero() {
			t.Errorf("a clock noted for %s, of which nothing was said", m.Member.Name)
		}
	}
	if noted != 1 {
		t.Errorf("web-1 in the status %d times", noted)
	}
	// That the node left traffic because of its clock is in the status too,
	// and gone when it is back.
	if !st.ClockOut.IsZero() {
		t.Error("the status says the node left traffic for its clock, of which nothing was said")
	}
	if err := b.node.NoteClockOut(true); err != nil {
		t.Fatal(err)
	}
	if st, err = ReadStatus(b.dir, nil); err != nil || st.ClockOut.IsZero() {
		t.Errorf("after the note the status does not say the node left traffic for its clock (%v)", err)
	}
	if err := b.node.NoteClockOut(false); err != nil {
		t.Fatal(err)
	}
	if st, err = ReadStatus(b.dir, nil); err != nil || !st.ClockOut.IsZero() {
		t.Errorf("the note is taken back, the status still says the node left traffic (%v)", err)
	}
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
		g, _, err := Configure(n.dir, n.name, n.addr, secret, nil)
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
	if _, _, err := Configure(b.dir, b.name, b.addr, secret, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := ReadStatus(b.dir, nil)
	if len(after.Members) != len(before.Members) {
		t.Errorf("a second deployment changed the member list: %d, then %d", len(before.Members), len(after.Members))
	}

	// A node with another secret is in another group and gets nothing.
	x := newTestNode(t, "stranger")
	if g, _, err := Configure(x.dir, x.name, x.addr, []byte("another-file-another-file-another-file"), nil); err != nil || g == group {
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
}

func TestRemovedNodeStaysOutAlthoughItHoldsTheSecret(t *testing.T) {
	secret := []byte("the-same-file-on-every-node-0123456789")
	a, b := newTestNode(t, "web-1"), newTestNode(t, "web-2")
	for _, n := range []*testNode{a, b} {
		if _, _, err := Configure(n.dir, n.name, n.addr, secret, nil); err != nil {
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
	if _, _, err := Configure(b.dir, b.name, b.addr, secret, nil); err != nil {
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
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // past the umask
			t.Fatal(err)
		}
		return p
	}
	s, _ := NewSecret()
	if got, err := ReadSecret(write("ok", s+"\n", 0o600)); err != nil || string(got) != s {
		t.Errorf("a good secret: %q, %v", got, err)
	}
	// Owner and group may read it (root:schild 0640 or 0440); nobody else
	// reads it, and the group does not write it.
	for _, mode := range []os.FileMode{0o640, 0o440, 0o400} {
		if got, err := ReadSecret(write(fmt.Sprintf("group-%o", mode), s, mode)); err != nil || string(got) != s {
			t.Errorf("a secret of mode %04o: %q, %v", mode, got, err)
		}
	}
	for _, mode := range []os.FileMode{0o644, 0o604, 0o660, 0o620, 0o601} {
		_, err := ReadSecret(write(fmt.Sprintf("open-%o", mode), s, mode))
		if err == nil || !strings.Contains(err.Error(), "chown schild:schild") || !strings.Contains(err.Error(), "chmod 0640") {
			t.Errorf("a secret of mode %04o: %v", mode, err)
		}
	}
	if _, err := ReadSecret(write("short", "abc", 0o600)); !errors.Is(err, contract.ErrSecret) {
		t.Errorf("a short secret: %v", err)
	}
	if _, err := ReadSecret(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file was read")
	}
}

// A "paused" key left in cluster.db by an earlier build (schild cluster
// pause, removed) is ignored: the node takes and hands over as before.
func TestStalePausedKeyIgnored(t *testing.T) {
	a, b, c := threeNodes(t)
	s, err := openState(b.dir, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := setMeta(tx, "paused", []byte("2026-01-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s.close()
	a.publishBlock("203.0.113.2")
	b.publishBlock("203.0.113.3")
	waitFor(t, "every node holds every block", func() bool {
		return b.holds("203.0.113.2") == "block" && a.holds("203.0.113.3") == "block" && c.holds("203.0.113.3") == "block"
	})
	if _, err := ReadStatus(b.dir, nil); err != nil {
		t.Errorf("status with a stale key: %v", err)
	}
}

// sayHello makes the node of a directory known at addr, as seek does at
// its start, without running it.
func sayHello(t *testing.T, dir, addr string) error {
	t.Helper()
	n, err := Open(Options{Dir: dir, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	recs, raws, err := n.winners(contract.ClassMembers)
	if err != nil {
		t.Fatal(err)
	}
	var own json.RawMessage
	for i, r := range recs {
		if r.ID == n.id {
			own = raws[i]
		}
	}
	c := meshClient(n.cert, func(ed25519.PublicKey) bool { return true }, 5*time.Second)
	defer c.CloseIdleConnections()
	var resp helloResponse
	return postJSON(context.Background(), c, "https://"+addr+pathHello, helloRequest{Record: own}, &resp)
}

func TestGroupIsFullAtSixteenGateways(t *testing.T) {
	nodes := []*testNode{newTestNode(t, "web-1")}
	for i := 2; i <= MaxGateways+1; i++ {
		nodes = append(nodes, newTestNode(t, fmt.Sprintf("web-%d", i)))
	}
	inGroup(t, testSecret, nodes...)
	a := nodes[0]
	a.peers = nil
	a.start()
	for _, n := range nodes[1:MaxGateways] {
		if err := sayHello(t, n.dir, a.addr); err != nil {
			t.Fatalf("%s: %v", n.name, err)
		}
	}
	if err := sayHello(t, nodes[MaxGateways].dir, a.addr); err == nil || !strings.Contains(err.Error(), "the group is full") {
		t.Fatalf("the seventeenth gateway: %v", err)
	}
	// A member already in the group is let in again (a restart).
	if err := sayHello(t, nodes[1].dir, a.addr); err != nil {
		t.Errorf("a member of the full group again: %v", err)
	}
}

// A node asks several members at once and each brings the same records. It
// is in step only when what it took is applied, not when a second answer
// found nothing new while the first was still at work.
func TestInStepOnlyAfterWhatWasTakenIsApplied(t *testing.T) {
	a, b, c := threeNodes(t)
	a.publishBlock("203.0.113.1")
	waitFor(t, "web-3 holds the first block", func() bool { return c.holds("203.0.113.1") == "block" })
	c.stop()
	a.publishBlock("203.0.113.2")
	waitFor(t, "web-2 holds the second block", func() bool { return b.holds("203.0.113.2") == "block" })
	// web-3 returns with a handler that takes its time, as an erasure does.
	n, err := Open(Options{Dir: c.dir, Listen: c.addr, Log: quiet(), Hold: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var applied atomic.Bool
	n.On(contract.ClassBlocks, func(*contract.Record) {
		time.Sleep(400 * time.Millisecond)
		applied.Store(true)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = n.Run(ctx) }()
	defer func() { cancel(); <-done; n.Close() }()
	deadline := time.Now().Add(10 * time.Second)
	for !n.Synced() {
		if time.Now().After(deadline) {
			t.Fatal("web-3 never in step")
		}
		time.Sleep(time.Millisecond)
	}
	if !applied.Load() {
		t.Error("web-3 says it is in step while it still applies what it took")
	}
}

// A task every node asks for runs once per interval for the group, on the
// node that keeps the locks; when that node is gone another takes over, and
// not before the interval is over.
func TestJobRunsOncePerIntervalForTheGroup(t *testing.T) {
	a, b, c := threeNodes(t)
	nodes := []*testNode{a, b, c}
	var mu sync.Mutex
	runs := map[string]int{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const every = 6 * time.Second
	start := func(tn *testNode, n *Node) {
		st, lead := n.Jobs()
		go jobs.Loop(ctx, st, lead, jobs.Task{Name: "test_job", Log: quiet(),
			Schedule: func() jobs.Schedule { return jobs.Schedule{Every: every} },
			Run: func(context.Context, *jobs.Run) error {
				mu.Lock()
				runs[tn.name]++
				mu.Unlock()
				return nil
			}})
	}
	for _, tn := range nodes {
		start(tn, tn.node)
	}
	total := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, v := range runs {
			n += v
		}
		return n
	}
	waitFor(t, "the job ran", func() bool { return total() >= 1 })
	time.Sleep(1500 * time.Millisecond)
	if n := total(); n != 1 {
		t.Fatalf("three nodes ran the job %d times in its first interval: %v", n, runs)
	}
	// Every node knows when it ran, also the ones that did not run it.
	for _, tn := range nodes {
		waitFor(t, tn.name+" knows when the job ran", func() bool { _, _, ok := tn.node.LastRun("test_job"); return ok })
	}
	// The node that ran it goes away: another one runs it when it is due,
	// once.
	var first *testNode
	mu.Lock()
	for _, tn := range nodes {
		if runs[tn.name] == 1 {
			first = tn
		}
	}
	mu.Unlock()
	first.stop()
	deadline := time.Now().Add(20 * time.Second)
	for total() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no other node took the job over")
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	if runs[first.name] != 1 {
		t.Errorf("the stopped node ran the job again: %v", runs)
	}
	mu.Unlock()
	time.Sleep(1200 * time.Millisecond)
	if n := total(); n != 2 {
		t.Errorf("after the take-over the job ran %d times in all, want 2: %v", n, runs)
	}
}

// frozen is a listener whose connections stop moving on command: the
// process is there, the port is open, nothing answers. A crash refuses
// connections and is seen at once; this is the case that is not.
type frozen struct {
	net.Listener
	stop atomic.Bool
}

type frozenConn struct {
	net.Conn
	f *frozen
}

func (f *frozen) Accept() (net.Conn, error) {
	c, err := f.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &frozenConn{Conn: c, f: f}, nil
}

func (c *frozenConn) hold() {
	for c.f.stop.Load() {
		time.Sleep(20 * time.Millisecond)
	}
}
func (c *frozenConn) Read(b []byte) (int, error)  { c.hold(); return c.Conn.Read(b) }
func (c *frozenConn) Write(b []byte) (int, error) { c.hold(); return c.Conn.Write(b) }

// A node that hangs is known as unreachable within a few seconds: the
// connection is watched with HTTP/2 pings, not only when a call times out.
func TestHangingPeerIsNoticedByPings(t *testing.T) {
	a, b := newTestNode(t, "web-1"), newTestNode(t, "web-2")
	inGroup(t, testSecret, a, b)
	// web-2 with a long hold, so a call alone would wait long for it.
	n, err := Open(Options{Dir: b.dir, Listen: b.addr, Log: quiet(), Hold: 4 * time.Second, Peers: b.peers})
	if err != nil {
		t.Fatal(err)
	}
	fz := &frozen{}
	n.wrapListener = func(ln net.Listener) net.Listener { fz.Listener = ln; return fz }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = n.Run(ctx) }()
	defer func() { fz.stop.Store(false); cancel(); <-done; n.Close() }()
	// web-1 asks with the same long hold.
	an, err := Open(Options{Dir: a.dir, Listen: a.addr, Log: quiet(), Hold: 4 * time.Second, Peers: a.peers})
	if err != nil {
		t.Fatal(err)
	}
	actx, acancel := context.WithCancel(context.Background())
	adone := make(chan struct{})
	go func() { defer close(adone); _ = an.Run(actx) }()
	defer func() { acancel(); <-adone; an.Close() }()
	waitFor(t, "web-1 reaches web-2", func() bool { return len(an.Reachable()) == 1 })

	fz.stop.Store(true)
	start := time.Now()
	deadline := start.Add(8 * time.Second)
	for len(an.Reachable()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("web-1 did not notice within 8 s that web-2 hangs (a call alone waits 9 s)")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("web-1 took %s to notice that web-2 hangs", d.Round(100*time.Millisecond))
	}
	// And it is back as soon as web-2 moves again.
	fz.stop.Store(false)
	waitFor(t, "web-1 reaches web-2 again", func() bool { return len(an.Reachable()) == 1 })
}

// A member removed by the command on the host (it writes into the store of
// the running node and tells the process nothing) is refused by the very
// next call, not after a timer: the node looks at the change counter of its
// store before every decision that rests on the member list.
func TestMemberRemovedByTheCommandLineIsRefusedAtOnce(t *testing.T) {
	a, b, c := threeNodes(t)
	waitFor(t, "web-1 knows web-3", func() bool { return a.node.IsMember(c.node.ID()) && b.node.IsMember(c.node.ID()) })
	key := c.node.pub
	// The node answers from what it holds while nothing was written.
	for i := 0; i < 50; i++ {
		if _, ok := a.node.activeKey(key, contract.RoleGateway); !ok {
			t.Fatal("web-3 is a member and was refused")
		}
	}
	if _, err := Remove(a.dir, "web-3", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.node.activeKey(key, contract.RoleGateway); ok {
		t.Fatal("web-1 still took web-3 for a member right after the command removed it")
	}
	if _, ok := a.node.activeKey(b.node.pub, contract.RoleGateway); !ok {
		t.Fatal("web-2 is still a member and was refused")
	}
}

// The vector a node hands out follows every write at once, although it is
// kept while the store stands.
func TestVectorFollowsEveryWrite(t *testing.T) {
	a, b, _ := threeNodes(t)
	waitFor(t, "web-2 reaches web-1", func() bool { return b.node.Synced() })
	before, err := a.node.vectorNow()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		a.publishBlock("203.0.113." + string(rune('1'+i)))
		now, err := a.node.vectorNow()
		if err != nil {
			t.Fatal(err)
		}
		if now[a.node.ID()] != before[a.node.ID()]+uint64(i+1) {
			t.Fatalf("after %d writes the vector of web-1 says %d, before them %d", i+1, now[a.node.ID()], before[a.node.ID()])
		}
		straight, _ := a.node.state.vector()
		if straight[a.node.ID()] != now[a.node.ID()] {
			t.Fatalf("kept vector %d, store %d", now[a.node.ID()], straight[a.node.ID()])
		}
	}
}
