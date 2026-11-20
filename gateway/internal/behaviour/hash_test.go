package behaviour

import (
	"fmt"
	"hash/fnv"
	"testing"
)

// Tests hash under a fixed key instead of the per-process random maphash
// seed. The sketches (HyperLogLog) estimate distinct user names and senders
// from these hashes; several tests send exactly as many distinct items as a
// threshold needs, and with a random seed a register collision now and then
// put the estimate one below it (TestCredentialStuffing: 10 names in a
// 64-register sketch) or let one detector fire a request earlier and tighten
// the route before another reached its count
// (TestRotatingCredentialStuffingOneStack). With a fixed key every run sees
// the same estimates. TestFixedKeyHashSpreads checks that the test hash
// still spreads like a keyed hash should.
func init() {
	keyedBytes = testHash
	keyedString = func(s string) uint64 { return testHash([]byte(s)) }
}

// testHash is FNV-1a under a fixed key with a splitmix64 finaliser, so that
// the high bits (register index) and the low bits (run length) are mixed.
func testHash(b []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("schild-test-key\x00"))
	_, _ = h.Write(b)
	x := h.Sum64()
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func TestFixedKeyHashSpreads(t *testing.T) {
	const n = 1 << 16
	var regs [64]int
	runs := 0
	for i := range n {
		x := hashString(fmt.Sprintf("victim%d@example.org", i))
		regs[x>>58]++
		if x<<6>>63 == 1 { // first bit after the register index
			runs++
		}
	}
	for i, c := range regs {
		if c < n/64*8/10 || c > n/64*12/10 {
			t.Fatalf("register %d gets %d of %d", i, c, n)
		}
	}
	if runs < n*45/100 || runs > n*55/100 {
		t.Fatalf("run bit set in %d of %d", runs, n)
	}
}
