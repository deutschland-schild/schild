package cluster

import (
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// A record a node dropped (Drop) and refuses (Refuse) is not stored when a
// member hands it over, not applied, and not asked for again: the vector of
// the node moves past it. A member asked for everything once more (Resync)
// hands it over again, and it stays out.
func TestDroppedRecordIsRefusedAndNotAskedForAgain(t *testing.T) {
	a, b := newTestNode(t, "web-1"), newTestNode(t, "web-2")
	inGroup(t, testSecret, a, b)
	a.start()
	b.start()
	knowEachOther(t, a, b)
	const kept, gone = "203.0.113.7", "203.0.113.8"
	refuse := func(r *contract.Record) bool { return r.ID == gone }
	b.node.Refuse(contract.ClassBlocks, refuse)
	a.publishBlock(gone)
	a.publishBlock(kept)
	waitFor(t, "web-2 holds the record it does not refuse", func() bool { return b.holds(kept) == "block" })
	if got := b.holds(gone); got != "" {
		t.Fatalf("web-2 stored the record it refuses: %q", got)
	}
	b.mu.Lock()
	for _, r := range b.seen {
		if r.ID == gone {
			t.Error("the refused record was applied")
		}
	}
	b.mu.Unlock()
	// Not asked for again: the vector of web-2 covers what web-1 wrote.
	av, _ := a.node.vector()
	waitFor(t, "the vector of web-2 moved past the refused record", func() bool {
		bv, _ := b.node.vector()
		return bv[a.node.ID()] == av[a.node.ID()]
	})
	if rejected := b.node.Rejected.Load(); rejected != 0 {
		t.Errorf("the refused record counts as one that failed a check: %d", rejected)
	}
	// Dropped where it was held, and refused from then on.
	a.node.Refuse(contract.ClassBlocks, refuse)
	gen := a.node.StoreGen()
	if err := a.node.Drop(contract.ClassBlocks, gone); err != nil {
		t.Fatal(err)
	}
	if got := a.holds(gone); got != "" || a.node.StoreGen() == gen {
		t.Fatalf("after the drop web-1 holds %q, store generation moved: %v", got, a.node.StoreGen() != gen)
	}
	for _, n := range []*testNode{a, b} {
		other := a
		if n == a {
			other = b
		}
		if _, err := n.node.Resync(t.Context(), other.node.ID()); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	for _, n := range []*testNode{a, b} {
		if got := n.holds(gone); got != "" {
			t.Errorf("%s holds the dropped record again after asking for everything: %q", n.name, got)
		}
		if got := n.holds(kept); got != "block" {
			t.Errorf("%s lost the other record: %q", n.name, got)
		}
	}
}
