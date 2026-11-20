//go:build spec26measure

// TEST ONLY: D40 item 2.3, independent of machine load. How many expensive evaluations can one IPv6 /48 hold, by slot
// count, with the defaults the gateway derives? Copied into a scratch copy of client/internal/gate.
package gate

import (
	"fmt"
	"testing"
	"time"
)

func TestM26Net48(t *testing.T) {
	for _, n := range []int{2, 4, 8, 12, 16, 18, 24, 32, 40, 64, 128, 1024} {
		l := EvalLimits{MaxConcurrent: n, QueueWait: time.Millisecond}.norm()
		p := newEvalPool(l)
		got := 0
		var rel []func()
		for i := 0; i < l.MaxHeavy+4; i++ {
			c := Cost{Heavy: true, Mem: 1 << 20, Client: fmt.Sprintf("2001:db8:a:%x::/64", i), Net: "2001:db8:a::/48"}
			r, ok := p.acquire(c)
			if !ok {
				break
			}
			got++
			rel = append(rel, r)
		}
		// a second /48 now
		_, other := p.acquire(Cost{Heavy: true, Mem: 1 << 20, Client: "2001:db8:b:1::/64", Net: "2001:db8:b::/48"})
		t.Logf("slots %4d: MaxHeavy %3d PerClient %2d cap %3d -> one /48 got %3d expensive evaluations, other /48 still gets one: %v", n, l.MaxHeavy, l.PerClient, min(l.MaxHeavy, l.PerClient*SharedFactor), got, other)
		for _, r := range rel {
			r()
		}
	}
}
