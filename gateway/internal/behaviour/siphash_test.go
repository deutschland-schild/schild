package behaviour

import "testing"

// The reference vectors of SipHash-2-4 (key 00 01 .. 0f, input 00 01 ..).
func TestSipHashReferenceVectors(t *testing.T) {
	const k0, k1 = 0x0706050403020100, 0x0f0e0d0c0b0a0908
	want := map[int]uint64{0: 0x726fdb47dd0e0e31, 1: 0x74f839c593dc67fd, 8: 0x93f5f5799a932462, 15: 0xa129ca6149be45e5}
	in := make([]byte, 16)
	for i := range in {
		in[i] = byte(i)
	}
	for n, w := range want {
		if got := sipHash(k0, k1, in[:n]); got != w {
			t.Errorf("%d bytes: %016x, want %016x", n, got, w)
		}
	}
}
