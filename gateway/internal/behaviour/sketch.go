package behaviour

import (
	"hash/maphash"
	"math"
	"math/bits"
	"net/netip"
)

// Key is the client key the counters use: the IPv4 address (/32, never
// coarser than /24) or the IPv6 /64 (MVP-17).
type Key = netip.Prefix

// KeyOf returns the client key of addr and its prefix length.
func KeyOf(addr netip.Addr) (Key, int) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return Key{}, 0
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), 32
	}
	p, _ := addr.WithZone("").Prefix(64)
	return p, 64
}

// hll is a small HyperLogLog sketch (registers of 6 bits stored in bytes).
// It answers "how many distinct items" without keeping the items: only the
// maximum run of leading zeros per register is stored, from which no input
// can be recovered. Used for user names (credential stuffing) and for the
// number of active clients (crawl baseline).
type hll struct {
	p   uint8
	reg []uint8
}

func newHLL(p uint8) *hll { return &hll{p: p, reg: make([]uint8, 1<<p)} }

// add inserts a 64-bit hash.
func (h *hll) add(x uint64) {
	idx := x >> (64 - h.p)
	w := x<<h.p | 1<<(h.p-1) // guard bit so the run is bounded
	rho := uint8(bits.LeadingZeros64(w)) + 1
	if rho > h.reg[idx] {
		h.reg[idx] = rho
	}
}

// estimate returns the estimated cardinality (linear counting for small sets).
func (h *hll) estimate() float64 {
	m := float64(len(h.reg))
	sum, zeros := 0.0, 0
	for _, r := range h.reg {
		sum += math.Ldexp(1, -int(r))
		if r == 0 {
			zeros++
		}
	}
	var alpha float64
	switch len(h.reg) {
	case 16:
		alpha = 0.673
	case 32:
		alpha = 0.697
	case 64:
		alpha = 0.709
	default:
		alpha = 0.7213 / (1 + 1.079/m)
	}
	e := alpha * m * m / sum
	if e <= 2.5*m && zeros > 0 {
		return m * math.Log(m/float64(zeros))
	}
	return e
}

func (h *hll) reset() {
	clear(h.reg)
}

var seed = maphash.MakeSeed()

// keyedBytes and keyedString are the keyed hashes behind hashKey and
// hashString: maphash with the per-process random seed. Tests replace them
// with a hash under a fixed key (hash_test.go). The sketches estimate from
// these hashes, so with a random seed an estimate right at a threshold
// differs from run to run; a fixed key makes the package's tests
// reproducible (MVP-19 measurement, finding 6).
var (
	keyedBytes  = func(b []byte) uint64 { return maphash.Bytes(seed, b) }
	keyedString = func(s string) uint64 { return maphash.String(seed, s) }
)

// hashKey spreads a client key over shards.
func hashKey(k Key) uint64 {
	a := k.Addr().As16()
	return keyedBytes(a[:]) ^ uint64(k.Bits())
}

// hashString is a keyed hash with a per-process random seed: the same
// string gives the same value only inside this process (never stored).
func hashString(s string) uint64 { return keyedString(s) }
