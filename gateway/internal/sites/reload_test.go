package sites

import (
	"fmt"
	"testing"

	"github.com/deutschland-schild/schild/contract/websites"
)

func blocksOf(hosts ...string) websites.Input {
	in := websites.Input{Mode: websites.ModeIngress}
	for _, h := range hosts {
		in.Blocks = append(in.Blocks, websites.Block{Addresses: []string{h}, Schild: true, Proxies: true})
	}
	return in
}

// TestNewViewAfterKeepsSlots: a counter never moves to another website.
func TestNewViewAfterKeepsSlots(t *testing.T) {
	a := NewView(blocksOf("a.example", "b.example"))
	b := NewViewAfter(a, blocksOf("neu.example", "b.example"))
	if b.SlotOf("b.example") != 1 || b.SlotOf("neu.example") != 2 {
		t.Fatalf("slots: b %d, neu %d", b.SlotOf("b.example"), b.SlotOf("neu.example"))
	}
	// The website that is gone keeps its name for the buckets still open.
	if b.SlotName(0) != "a.example" || b.SlotOf("a.example") != NoSlot {
		t.Fatalf("slot 0: %q, slot of a: %d", b.SlotName(0), b.SlotOf("a.example"))
	}
	if c := NewViewAfter(b, blocksOf("a.example")); c.SlotOf("a.example") != 0 {
		t.Fatalf("a website that comes back: slot %d", c.SlotOf("a.example"))
	}
	var many []string
	for i := range websites.MaxTracked {
		many = append(many, fmt.Sprintf("m%d.example", i))
	}
	d := NewViewAfter(b, blocksOf(append(many, "b.example")...))
	if d.SlotOf("b.example") != 1 || d.SlotOf("m0.example") != 3 {
		t.Fatalf("slots: b %d, m0 %d", d.SlotOf("b.example"), d.SlotOf("m0.example"))
	}
	last := many[len(many)-1]
	if w, _ := d.Website(last); d.SlotOf(last) != OtherSlot || w.Tracked {
		t.Fatalf("without a free slot: %d, tracked %v", d.SlotOf(last), w.Tracked)
	}
	if w, _ := d.Website("b.example"); !w.Tracked {
		t.Fatal("b.example has a slot and is not tracked")
	}
	for i := range OtherSlot {
		if n := d.SlotName(i); n == "" {
			t.Fatalf("slot %d has no name", i)
		}
	}
}

// TestRegistrySwap: while a swap is under way both views name their hosts.
func TestRegistrySwap(t *testing.T) {
	r := NewRegistry(NewView(blocksOf("alt.example")))
	next := NewViewAfter(r.View(), blocksOf("neu.example"))
	commit, rollback := r.Swap(next)
	if r.ID("alt.example") != "alt.example" || r.ID("neu.example") != "neu.example" || !r.OwnHost("alt.example") {
		t.Fatal("a swap under way forgets a host")
	}
	rollback()
	if r.ID("neu.example") != "" || r.ID("alt.example") != "alt.example" {
		t.Fatal("rolled back")
	}
	commit, _ = r.Swap(next)
	commit()
	if r.ID("alt.example") != "" || r.ID("neu.example") != "neu.example" {
		t.Fatal("committed")
	}
}
