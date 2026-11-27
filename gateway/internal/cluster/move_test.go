package cluster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

func asideDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), filepath.Base(dir)+asideMark) {
			out = append(out, e.Name())
		}
	}
	return out
}

// A new group secret moves the nodes one after the other: each carries what
// it held, with the clocks the records had, so a lift that a later node
// brings still beats the block an earlier node brought, and a change made
// in the new group beats what a later node carries.
func TestNewSecretMovesANodeWithWhatItHeld(t *testing.T) {
	oldSecret, newSecret := []byte("the-same-file-on-every-node-0123456789"), []byte("a-new-file-after-the-old-one-leaked-01")
	a, b := newTestNode(t, "web-1"), newTestNode(t, "web-2")
	for _, n := range []*testNode{a, b} {
		if _, _, err := Configure(n.dir, n.name, n.addr, oldSecret, nil); err != nil {
			t.Fatal(err)
		}
		n.peers = []string{a.addr, b.addr}
	}
	a.start()
	b.start()
	a.publishBlock("203.0.113.7")
	a.publishBlock("203.0.113.8")
	a.publishBlock("203.0.113.9")
	for _, ip := range []string{"203.0.113.7", "203.0.113.8", "203.0.113.9"} {
		waitFor(t, "web-2 holds the block of "+ip, func() bool { return b.holds(ip) == "block" })
	}
	if err := b.node.SetMark("requests:"+a.node.ID(), "epoch:42"); err != nil {
		t.Fatal(err)
	}
	oldGroup, id := b.node.Group(), b.node.ID()
	var before *contract.Record
	recs, _ := b.node.State(testClass)
	for _, r := range recs {
		if r.ID == "203.0.113.7" {
			before = r
		}
	}

	// web-2 gets the new file and restarts.
	b.stop()
	group, moved, err := Configure(b.dir, b.name, b.addr, newSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	if moved == nil || moved.From != oldGroup || moved.To != group || group == oldGroup || moved.Carried != 3 {
		t.Fatalf("move: %+v, group %s (before %s)", moved, group, oldGroup)
	}
	if got := asideDirs(t, b.dir); len(got) != 1 {
		t.Fatalf("directories kept aside: %v", got)
	}
	// The same deployment again moves nothing.
	if _, again, err := Configure(b.dir, b.name, b.addr, newSecret, nil); err != nil || again != nil {
		t.Fatalf("a second start with the new secret: %+v, %v", again, err)
	}
	b.start()
	if b.node.ID() != id || b.node.Group() != group {
		t.Fatalf("web-2 is %s in %s, want %s in %s", b.node.ID(), b.node.Group(), id, group)
	}
	recs, _ = b.node.State(testClass)
	var after *contract.Record
	for _, r := range recs {
		if r.ID == "203.0.113.7" {
			after = r
		}
	}
	if after == nil || after.HLC != before.HLC || after.Origin != id || after.Group != group || after.Data != before.Data || after.Expires != before.Expires {
		t.Fatalf("carried record: %+v, from %+v", after, before)
	}
	if got := b.node.Mark("requests:" + a.node.ID()); got != "epoch:42" {
		t.Errorf("the note of how far web-2 read web-1 is %q after the move", got)
	}

	// Meanwhile: web-1, still in the old group, lifts one block; web-2, in the
	// new group, lifts another. Nothing crosses.
	if _, err := a.node.Publish(testClass, "203.0.113.8", lift("web-1"), true, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.node.Publish(testClass, "203.0.113.9", lift("web-2"), true, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if b.holds("203.0.113.8") != "block" || a.holds("203.0.113.9") != "block" {
		t.Fatal("a record crossed between the old and the new group")
	}
	if a.node.IsMember(id) && b.node.IsMember(a.node.ID()) {
		t.Fatal("a node of the old group and one of the new took each other for members")
	}

	// web-1 follows. Its lift beats the block web-2 carried, and the lift made
	// in the new group beats the block web-1 carries.
	a.stop()
	if _, moved, err := Configure(a.dir, a.name, a.addr, newSecret, nil); err != nil || moved == nil {
		t.Fatalf("web-1: %+v, %v", moved, err)
	}
	a.start()
	for _, n := range []*testNode{a, b} {
		waitFor(t, n.name+" holds the block that nobody lifted", func() bool { return n.holds("203.0.113.7") == "block" })
		waitFor(t, n.name+" holds the lift web-1 made in the old group", func() bool { return n.holds("203.0.113.8") == "lift" })
		waitFor(t, n.name+" holds the lift web-2 made in the new group", func() bool { return n.holds("203.0.113.9") == "lift" })
	}
	waitFor(t, "both are members of the new group", func() bool { return a.node.IsMember(id) && b.node.IsMember(a.node.ID()) })
}

func TestMoveKeepsTwoDirectoriesAsideAndLeavesTheOldGroupOnFailure(t *testing.T) {
	n := newTestNode(t, "web-1")
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	secret := func(i int) []byte { return []byte(strings.Repeat(string(rune('a'+i)), 40)) }
	var group string
	for i := 0; i < 4; i++ {
		now := func() time.Time { return at.Add(time.Duration(i) * time.Minute) }
		g, _, err := Configure(n.dir, n.name, n.addr, secret(i), now)
		if err != nil {
			t.Fatal(err)
		}
		group = g
	}
	if got := asideDirs(t, n.dir); len(got) != asideKeep {
		t.Fatalf("after three moves %d directories are kept aside, want %d: %v", len(got), asideKeep, got)
	}
	// A secret that is too short moves nothing.
	if _, _, err := Configure(n.dir, n.name, n.addr, []byte("short"), nil); err == nil {
		t.Fatal("a short secret was taken")
	}
	// A move that cannot finish (the name is no member name) leaves the node where it was.
	if _, _, err := Configure(n.dir, "Not A Name", n.addr, secret(9), nil); err == nil {
		t.Fatal("a move with a bad member name went through")
	}
	st, err := ReadStatus(n.dir, nil)
	if err != nil || st.Group != group {
		t.Fatalf("after the failed moves the node is in %v (%v), want %s", st, err, group)
	}
	if entries, _ := os.ReadDir(filepath.Dir(n.dir)); len(entries) != 1+asideKeep {
		t.Errorf("a failed move left files behind: %d entries", len(entries))
	}
}

// A node that was removed from the group before enters the new one when it
// is given the new secret, with nothing of what it held.
func TestRemovedNodeCarriesNothingIntoTheNewGroup(t *testing.T) {
	oldSecret, newSecret := []byte("the-same-file-on-every-node-0123456789"), []byte("a-new-file-after-the-old-one-leaked-01")
	a, b := newTestNode(t, "web-1"), newTestNode(t, "web-2")
	for _, n := range []*testNode{a, b} {
		if _, _, err := Configure(n.dir, n.name, n.addr, oldSecret, nil); err != nil {
			t.Fatal(err)
		}
		n.peers = []string{a.addr, b.addr}
	}
	a.start()
	b.start()
	a.publishBlock("203.0.113.7")
	waitFor(t, "web-2 holds the block", func() bool { return b.holds("203.0.113.7") == "block" })
	if _, err := Remove(a.dir, "web-2", nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "web-2 is told that it was removed", func() bool { return b.node.Removed() })
	b.stop()
	_, moved, err := Configure(b.dir, b.name, b.addr, newSecret, nil)
	if err != nil || moved == nil || moved.Carried != 0 {
		t.Fatalf("move of a removed node: %+v, %v", moved, err)
	}
	b.start()
	if b.node.Removed() || b.holds("203.0.113.7") != "" {
		t.Errorf("the removed node in the new group: removed %v, holds %q", b.node.Removed(), b.holds("203.0.113.7"))
	}
}
