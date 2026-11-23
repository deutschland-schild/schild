package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// runNode opens and runs the node of a directory with its own options, for
// tests that need a clock or a listener of their own.
func runNode(t *testing.T, tn *testNode, now func() time.Time, wrap func(net.Listener) net.Listener) *Node {
	t.Helper()
	n, err := Open(Options{Dir: tn.dir, Listen: tn.addr, Log: quiet(), Hold: 300 * time.Millisecond, Peers: tn.peers, Now: now})
	if err != nil {
		t.Fatalf("%s: open: %v", tn.name, err)
	}
	n.wrapListener = wrap
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = n.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done; n.Close() })
	waitFor(t, tn.name+" listens", func() bool { return n.Addr() != "" })
	return n
}

func ahead(d time.Duration) func() time.Time { return func() time.Time { return time.Now().Add(d) } }

// A write after a restart is later than every record the node holds,
// also one of a member whose clock is a little ahead: the restarted node
// forgot what its clock saw, and its lift lost against the block.
func TestWriteAfterARestartBeatsARecordOfAClockAhead(t *testing.T) {
	a, b := newTestNode(t, "web-1"), newTestNode(t, "web-2")
	inGroup(t, testSecret, a, b)
	a.start()
	bn := runNode(t, b, ahead(30*time.Second), nil)
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if _, err := bn.Publish(contract.ClassBlocks, "203.0.113.30", block("203.0.113.30", until), false, until); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "web-1 holds the block of web-2", func() bool { return a.holds("203.0.113.30") == "block" })
	a.stop()
	a.start()
	rec, err := a.node.Publish(contract.ClassBlocks, "203.0.113.30", &contract.Lift{Incident: "S-203.0.113.30", Node: "web-1"}, true, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("the lift after the restart: %v", err)
	}
	if got := a.holds("203.0.113.30"); got != "lift" {
		t.Fatalf("after the restart web-1 published a lift (hlc %d) and holds %q", rec.HLC, got)
	}
}

// `schild cluster remove` runs in a process of its own: its tombstone is
// later than the member record it ends, also when that record came from a
// clock a little ahead, and it never reports a removal that did not win.
func TestRemoveFromTheHostBeatsAMemberRecordOfAClockAhead(t *testing.T) {
	a, b, c := newTestNode(t, "web-1"), newTestNode(t, "web-2"), newTestNode(t, "web-3")
	inGroup(t, testSecret, a, b, c)
	// web-3 wrote its member record with a clock 30 s ahead.
	if _, _, err := Configure(c.dir, c.name, "127.0.0.1:1", testSecret, ahead(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	a.start()
	b.start()
	runNode(t, c, ahead(30*time.Second), nil)
	waitFor(t, "web-1 holds the member record of web-3", func() bool {
		cur, err := a.node.Get(contract.ClassMembers, contract.NodeID(mustOpenKey(t, c.dir)))
		if err != nil || cur == nil {
			return false
		}
		m, err := contract.DecodeMember(cur)
		return err == nil && m.Address == "127.0.0.1:1"
	})
	e, err := Remove(a.dir, "web-3", nil)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	waitFor(t, "web-1 holds web-3 as removed, as the command reported", func() bool {
		_ = a.node.reload()
		return !a.node.IsMember(e.ID)
	})
}

func mustOpenKey(t *testing.T, dir string) ed25519.PublicKey {
	t.Helper()
	s, err := openState(dir, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	return s.pub
}

// A write is later than every record the store holds, whoever wrote it:
// the clock of a process that just opened the store (a command on the host,
// a node after its start) has seen none of them.
func TestPublishIsLaterThanEveryRecordHeld(t *testing.T) {
	a := newTestNode(t, "web-1")
	inGroup(t, testSecret, a)
	s, err := openState(a.dir, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	// A lift of another node whose clock was 50 s ahead.
	held := &contract.Record{V: contract.Version, Group: s.group, Class: contract.ClassBlocks, ID: "203.0.113.31", Origin: "n-0000000000000000000000000000ffff", Seq: 1,
		HLC: contract.HLCOf(time.Now().Add(50 * time.Second)), Deleted: true}
	raw, _ := json.Marshal(held)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := put(tx, held, raw); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	rec, err := s.publish(contract.ClassBlocks, "203.0.113.31", block("203.0.113.31", until), false, until)
	if err != nil {
		t.Fatalf("a write after the record held: %v", err)
	}
	var origin string
	var deleted bool
	if err := s.db.QueryRow(`SELECT origin, deleted FROM records WHERE class = ? AND id = ? AND state = ?`, contract.ClassBlocks, "203.0.113.31", stateWinner).Scan(&origin, &deleted); err != nil {
		t.Fatal(err)
	}
	if origin != s.id || deleted || rec.HLC <= held.HLC {
		t.Fatalf("the write (hlc %d) lost against the record held (hlc %d)", rec.HLC, held.HLC)
	}
}

// Two fresh nodes do not make each other in step with nothing while a
// member of their group is away: they wait for it. When every named peer
// is there and none was ever in step, the group is new as a whole and the
// nodes come in step with each other.
func TestFreshNodesWaitForTheGroupUnlessItIsNew(t *testing.T) {
	a, b, c := newTestNode(t, "web-1"), newTestNode(t, "web-2"), newTestNode(t, "web-3")
	inGroup(t, testSecret, a, b, c)
	b.start()
	c.start()
	knowEachOther(t, b, c)
	waitFor(t, "web-2 and web-3 have asked each other", func() bool {
		return len(b.node.Reachable()) == 1 && len(c.node.Reachable()) == 1
	})
	time.Sleep(time.Second)
	if b.node.Synced() || c.node.Synced() {
		t.Fatalf("two fresh nodes called each other in step while web-1 is away: web-2 %v, web-3 %v", b.node.Synced(), c.node.Synced())
	}
	a.start()
	for _, n := range []*testNode{a, b, c} {
		waitFor(t, n.name+" is in step in the new group", func() bool { return n.node.Synced() })
	}
	if a.node.TakesGroupState() {
		t.Error("a node of a new group takes the state of a group")
	}
}

// slow delays every connection it accepts until released.
type slow struct {
	net.Listener
	open atomic.Bool
}

func (s *slow) Accept() (net.Conn, error) {
	c, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	for !s.open.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	return c, nil
}

// Records one member put off keep the node out of step although another
// member then answers with nothing: what web-2 held back is not cleared by
// the empty answer of web-3.
func TestRecordsPutOffByOneMemberAreNotClearedByAnother(t *testing.T) {
	a, b, c := newTestNode(t, "web-1"), newTestNode(t, "web-2"), newTestNode(t, "web-3")
	inGroup(t, testSecret, a, b, c)
	b.peers, c.peers = []string{b.addr, c.addr}, []string{b.addr, c.addr}
	// web-2's clock is two minutes ahead: its records wait on the others.
	bn := runNode(t, b, ahead(2*time.Minute), nil)
	gate := &slow{}
	gate.open.Store(true)
	cn := runNode(t, c, nil, func(ln net.Listener) net.Listener { gate.Listener = ln; return gate })
	t.Cleanup(func() { gate.open.Store(true) })
	waitFor(t, "web-2 and web-3 are in step", func() bool { return bn.Synced() && cn.Synced() })
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if _, err := bn.Publish(contract.ClassBlocks, "203.0.113.33", block("203.0.113.33", until), false, until); err != nil {
		t.Fatal(err)
	}
	// web-1 starts; web-3 answers only once web-2's record was put off.
	gate.open.Store(false)
	an := runNode(t, a, nil, nil)
	waitFor(t, "web-1 put off the record of web-2", func() bool { return an.Deferred.Load() > 0 })
	gate.open.Store(true)
	waitFor(t, "web-1 has an answer of web-3", func() bool {
		an.pmu.Lock()
		defer an.pmu.Unlock()
		p := an.peers[cn.ID()]
		if p == nil {
			return false
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		return !p.outOK.IsZero()
	})
	time.Sleep(500 * time.Millisecond)
	if an.Synced() {
		t.Fatal("web-1 is in step although the record of web-2 waits: the answer of web-3 cleared it")
	}
}

// fakeMesh answers every call on the mesh path with f, under a key of its
// own that is no member.
func fakeMesh(t *testing.T, f http.HandlerFunc) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := selfCert(key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(f)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// A 410 from a key that is no member does not remove a node, also when it
// names the node's group; one that names no group never does. And what a
// stranger answers to a hello is not stored when it cannot be checked.
func TestStrangerCannotRemoveANodeOrStoreRecords(t *testing.T) {
	a := newTestNode(t, "web-1")
	group := inGroup(t, testSecret, a)
	gone := func(header string) string {
		return fakeMesh(t, func(w http.ResponseWriter, r *http.Request) {
			if header != "" {
				w.Header().Set(headerGroup, header)
			}
			http.Error(w, "removed from the group", http.StatusGone)
		})
	}
	unread := &contract.Record{V: contract.Version + 1, Group: group, Class: contract.ClassMembers, ID: "n-0000000000000000000000000000ffff", Origin: "n-0000000000000000000000000000ffff", Seq: 1, HLC: contract.HLCOf(time.Now())}
	rawUnread, _ := json.Marshal(unread)
	answers := fakeMesh(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(helloResponse{Group: group, Records: []json.RawMessage{rawUnread}})
	})
	a.peers = []string{a.addr, gone(group), gone(""), answers}
	a.start()
	time.Sleep(2500 * time.Millisecond)
	if a.node.Removed() {
		t.Fatal("a 410 of a stranger removed the node")
	}
	var n int
	if err := a.node.db.QueryRow(`SELECT count(*) FROM records WHERE state = ?`, stateUnread).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a stranger's answer left %d unread records (%v)", n, err)
	}
}

// A hello is checked before anything is stored: a record the node cannot
// read, or one without the admission of the group, leaves nothing behind.
func TestHelloStoresNothingBeforeItIsChecked(t *testing.T) {
	a := newTestNode(t, "web-1")
	group := inGroup(t, testSecret, a)
	a.peers = nil
	a.start()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cert, err := selfCert(key)
	if err != nil {
		t.Fatal(err)
	}
	id := contract.NodeID(key.Public().(ed25519.PublicKey))
	c := meshClient(cert, func(ed25519.PublicKey) bool { return true }, 5*time.Second)
	defer c.CloseIdleConnections()
	for i, rec := range []*contract.Record{
		{V: contract.Version + 1, Group: group, Class: contract.ClassMembers, ID: id, Origin: id, Seq: 1, HLC: contract.HLCOf(time.Now())},
		{V: contract.Version, Group: group, Class: contract.ClassMembers, ID: id, Origin: id, Seq: 1, HLC: contract.HLCOf(time.Now())},
	} {
		raw, _ := json.Marshal(rec)
		var resp helloResponse
		if err := postJSON(context.Background(), c, "https://"+a.addr+pathHello, helloRequest{Record: raw}, &resp); err == nil {
			t.Errorf("hello %d was taken", i)
		}
	}
	var n int
	if err := a.node.db.QueryRow(`SELECT count(*) FROM records WHERE origin = ?`, id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a refused hello left %d records (%v)", n, err)
	}
}

// The address of a removed member is not asked every second.
func TestSeekAsksARemovedMemberOnceAMinute(t *testing.T) {
	var calls atomic.Int32
	addr := fakeMesh(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "no", http.StatusForbidden)
	})
	a, b := newTestNode(t, "web-1"), newTestNode(t, "web-2")
	inGroup(t, testSecret, a, b)
	// web-2 was at the address of the fake and is removed.
	if _, _, err := Configure(b.dir, b.name, addr, testSecret, nil); err != nil {
		t.Fatal(err)
	}
	a.peers = []string{a.addr, addr}
	a.start()
	if err := sayHello(t, b.dir, a.addr); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(a.dir, "web-2", nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // the sync loop of the member ends
	before := calls.Load()
	time.Sleep(3500 * time.Millisecond)
	if n := calls.Load() - before; n > 1 {
		t.Fatalf("the address of a removed member was asked %d times in 3.5 s", n)
	}
}

// An Ask of a kind the member does not know fails with a status error the
// caller can tell apart, not with a text to search.
func TestAskOfAnUnknownKindIsATypedError(t *testing.T) {
	a, b, _ := threeNodes(t)
	waitFor(t, "web-1 reaches web-2", func() bool { return len(a.node.Reachable()) == 2 })
	_, err := a.node.Ask(context.Background(), b.node.ID(), "no_such_kind", []byte("{}"))
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusNotFound {
		t.Fatalf("ask of an unknown kind: %v", err)
	}
}

// A node that was not in step for longer than a tombstone lives drops what
// it held of the shared classes at its start, takes them anew from a member
// from the first record on, and is marked to take the group's state.
func TestNodeAwayLongerThanATombstoneTakesTheGroupAnew(t *testing.T) {
	a, b := newTestNode(t, "web-1"), newTestNode(t, "web-2")
	inGroup(t, testSecret, a, b)
	a.start()
	b.start()
	knowEachOther(t, a, b)
	waitFor(t, "both are in step", func() bool { return a.node.Synced() && b.node.Synced() })
	gone := contract.NewValue(`["gone"]`, []byte(`1`), "web-2")
	kept := contract.NewValue(`["kept"]`, []byte(`2`), "web-1")
	if _, err := b.node.Publish(contract.ClassSettings, contract.EntryID("thing_v1", `["gone"]`), gone, false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.node.Publish(contract.ClassSettings, contract.EntryID("thing_v1", `["kept"]`), kept, false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both hold both entries", func() bool {
		ra, _ := a.node.State(contract.ClassSettings)
		rb, _ := b.node.State(contract.ClassSettings)
		return len(ra) == 2 && len(rb) == 2
	})
	b.stop()
	// While web-2 is away the entry is removed, and the tombstone ends.
	if _, err := a.node.Publish(contract.ClassSettings, contract.EntryID("thing_v1", `["gone"]`), &contract.Value{K: `["gone"]`, Node: "web-1"}, true, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.node.expire(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// web-2 returns 31 days after it was last in step (its clock is
	// right; the note of when it was in step is that old).
	if err := setMark(b.dir, markInStepAt, strconv.FormatInt(time.Now().Add(-31*24*time.Hour).UnixMilli(), 10)); err != nil {
		t.Fatal(err)
	}
	if err := setMark(b.dir, "entries:settings/thing_v1", `{"x":"y"}`); err != nil {
		t.Fatal(err)
	}
	bn := runNode(t, b, nil, nil)
	if !bn.Stale() {
		t.Fatal("web-2 does not know it was away too long")
	}
	if bn.Mark("entries:settings/thing_v1") != "" {
		t.Error("web-2 kept the marks of its entries")
	}
	waitFor(t, "web-2 is in step and takes the group's state", func() bool { return bn.Synced() && bn.TakesGroupState() })
	recs, err := bn.State(contract.ClassSettings)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ID != contract.EntryID("thing_v1", `["kept"]`) {
		t.Fatalf("web-2 holds %d records of settings after its return, want the one the group holds", len(recs))
	}
	if !bn.inStepAnswer() {
		t.Error("in step again, web-2 does not say so")
	}
}

func setMark(dir, key, value string) error {
	s, err := openState(dir, false, nil)
	if err != nil {
		return err
	}
	defer s.close()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := setMeta(tx, "mark:"+key, []byte(value)); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
