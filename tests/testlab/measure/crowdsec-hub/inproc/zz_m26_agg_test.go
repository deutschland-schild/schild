//go:build spec26measure

// TEST ONLY: D40 item 2.4 in process, at the real bound of 65,536: nobody takes hits out (a stalled store), the map must
// stop growing, the rest is counted, memory stays. Copied into a scratch copy of client/internal/gate.
package gate

import (
	"fmt"
	"runtime"
	"testing"
)

func TestM26AggBound(t *testing.T) {
	const max = 1 << 16
	a := newAggregator(max)
	draw := func() string { return "" }
	n := 0
	draw = func() string { n++; return fmt.Sprintf("INC-%d", n) }
	var m0, m1 runtime.MemStats
	const now = int64(1793356620000)
	for i := 0; i < max; i++ {
		a.assign(aggKey{client: fmt.Sprint(i), rule: "r"}, now, draw)
	}
	runtime.GC()
	runtime.ReadMemStats(&m0)
	for round := 0; round < 5; round++ {
		for i := 0; i < max; i++ {
			a.assign(aggKey{client: fmt.Sprint(i), rule: "r"}, now+1, draw)
		}
		// keys beyond the bound get their own incident, they never join
		for i := max; i < max+1000; i++ {
			a.assign(aggKey{client: fmt.Sprint(i), rule: "r"}, now+2, draw)
		}
		t.Logf("round %d: pending %d, open %d, dropped %d", round, len(a.pending), len(a.open), a.dropped.Load())
	}
	// pending at the bound: one more new key that joins must be dropped
	a2 := newAggregator(4)
	for i := 0; i < 6; i++ {
		a2.assign(aggKey{client: fmt.Sprint(i), rule: "r"}, now, draw)
	}
	for r := 0; r < 3; r++ {
		for i := 0; i < 6; i++ {
			a2.assign(aggKey{client: fmt.Sprint(i), rule: "r"}, now+1, draw)
		}
	}
	t.Logf("small bound 4: pending %d, open %d, dropped %d", len(a2.pending), len(a2.open), a2.dropped.Load())
	// the same with open not full but pending full
	a3 := newAggregator(max)
	a3.max = 100
	for i := 0; i < 1000; i++ {
		a3.open[aggKey{client: fmt.Sprint(i), rule: "r"}] = fmt.Sprintf("X%d", i)
	}
	a3.newest = now - now%60000
	for i := 0; i < 1000; i++ {
		a3.assign(aggKey{client: fmt.Sprint(i), rule: "r"}, now+1, draw)
	}
	t.Logf("pending bound 100, 1000 open aggregates hit: pending %d, dropped %d", len(a3.pending), a3.dropped.Load())
	runtime.GC()
	runtime.ReadMemStats(&m1)
	t.Logf("heap growth while hits kept coming: %d KiB", (int64(m1.HeapAlloc)-int64(m0.HeapAlloc))/1024)
}
