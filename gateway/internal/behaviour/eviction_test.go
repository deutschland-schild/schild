package behaviour

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
)

// D38: a full shard evicts entries the evictFirst predicate matches before
// any other.
func TestTableEvictsPreferredFirst(t *testing.T) {
	for round := 0; round < 50; round++ {
		tb := newTable[int, blockState](shards*4, func(k int) uint64 { return uint64(k) })
		tb.evictFirst = func() func(*blockState) bool { return func(b *blockState) bool { return b.until <= 100 } }
		// Shard 0: one ended block, three running ones.
		for i, until := range []int64{50, 200, 300, 400} {
			tb.with(i*shards, true, func(b *blockState) { b.until = until })
		}
		tb.with(4*shards, true, func(b *blockState) { b.until = 500 })
		for i := 1; i <= 4; i++ {
			var found bool
			tb.with(i*shards, false, func(b *blockState) { found = b != nil })
			if !found {
				t.Fatalf("round %d: running entry %d evicted", round, i)
			}
		}
		tb.with(0, false, func(b *blockState) {
			if b != nil {
				t.Fatalf("round %d: ended entry kept", round)
			}
		})
	}
}

// Without an ended block a full shard still evicts (bounded memory).
func TestTableEvictsRunningWhenNoneEnded(t *testing.T) {
	tb := newTable[int, blockState](shards*2, func(k int) uint64 { return uint64(k) })
	tb.evictFirst = func() func(*blockState) bool { return func(b *blockState) bool { return b.until <= 0 } }
	for i := 0; i < 5; i++ {
		tb.with(i*shards, true, func(b *blockState) { b.until = 100 })
	}
	if n := tb.len(); n != 2 || tb.evictions() != 3 {
		t.Fatalf("len %d evictions %d", n, tb.evictions())
	}
}

// The engine's block table prefers ended blocks: a flood of new blocks in
// a full shard never pushes out a running block while ended ones remain.
func TestEngineEvictsEndedBlocksFirst(t *testing.T) {
	e, _, c := newEngine(modes(nil))
	now := c.t.UnixNano()
	// Fill one shard: half ended, half running.
	var keys []Key
	for i := 0; len(keys) < e.blocks.per; i++ {
		k, _ := KeyOf(netip.MustParseAddr(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)))
		if e.blocks.hash(k)%shards == 0 {
			keys = append(keys, k)
		}
	}
	for i, k := range keys {
		until := now + int64(time.Hour)
		if i%2 == 0 {
			until = now - int64(time.Minute)
		}
		e.blocks.with(k, true, func(b *blockState) { b.until, b.lastUntil = until, until })
	}
	// New blocks for as many keys as there are ended ones.
	added := 0
	for i := 1 << 20; added < len(keys)/2; i++ {
		k, _ := KeyOf(netip.MustParseAddr(fmt.Sprintf("11.%d.%d.%d", i>>16&255, i>>8&255, i&255)))
		if e.blocks.hash(k)%shards == 0 {
			e.blocks.with(k, true, func(b *blockState) { b.until = now + int64(time.Hour) })
			added++
		}
	}
	for i, k := range keys {
		var found bool
		e.blocks.with(k, false, func(b *blockState) { found = b != nil })
		if i%2 == 1 && !found {
			t.Fatalf("running block %d evicted", i)
		}
		if i%2 == 0 && found {
			t.Fatalf("ended block %d kept while running ones were added", i)
		}
	}
}

// D38: a kept block evicted from the long map at its cap is deleted from
// schild.db too (Sink.Unpersist).
func TestLongBlockEvictionUnpersists(t *testing.T) {
	e, _, c := newEngine(modes(nil))
	e.long.max = 2
	var gone []string
	e.Sink.Unpersist = func(k string) { gone = append(gone, k) }
	e.Sink.Persist = func(events.ActiveBlock) {}
	for i, h := range []time.Duration{48, 24, 72} {
		ip := fmt.Sprintf("198.51.100.%d", 20+i)
		k, _ := KeyOf(netip.MustParseAddr(ip))
		e.keepLong(k, events.ActiveBlock{ClientKey: ip, KeyBits: 32, Until: c.t.Add(h * time.Hour).Format(time.RFC3339)}, "")
	}
	// The third block evicts the one ending first (198.51.100.21).
	if len(gone) != 1 || gone[0] != "198.51.100.21" {
		t.Fatalf("unpersisted %v", gone)
	}
	if n := len(e.LongBlocks()); n != 2 {
		t.Fatalf("%d kept blocks", n)
	}
}
