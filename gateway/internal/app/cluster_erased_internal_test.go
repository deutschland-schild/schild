package app

import (
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
)

// A record carries since in whole seconds, the engine knows it finer. The
// node that decided a block and the nodes that are handed its record give
// the same answer on whether an erasure ended it, also in the second in
// which the bound of the clocks ends (contracts/cluster.md section 5).
func TestErasureAnswersTheSameForTheNodeThatDecidedAndTheOthers(t *testing.T) {
	key, _ := behaviour.KeyOf(netip.MustParseAddr("203.0.113.77"))
	at := time.Date(2026, 11, 27, 10, 0, 0, 500e6, time.UTC)
	a := &App{}
	a.groupBlocks.erased = map[behaviour.Key]erasure{key: {at: at, until: at.Add(time.Hour)}}
	since := at.Add(60*time.Second + 300*time.Millisecond) // 10:01:00.800, in the record 10:01:00
	if own, others := a.erasedBefore(key, since), a.erasedBefore(key, since.Truncate(time.Second)); own != others || !own {
		t.Errorf("the deciding node says %v, a node with the record says %v; both must say that the erasure ended the block", own, others)
	}
	if a.erasedBefore(key, at.Add(61*time.Second+500*time.Millisecond)) {
		t.Error("a block of the second after the bound counts as erased")
	}
}
