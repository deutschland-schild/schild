package config

import "testing"

// D43: the share of one /48 is a real part of the expensive slots at every
// slot count, and leaves the rest to others as soon as there is a rest.
func TestNetEvalShare(t *testing.T) {
	for _, c := range []struct{ heavy, share int }{{1, 1}, {2, 1}, {3, 2}, {4, 2}, {6, 3}, {12, 6}, {512, 256}} {
		if got := NetEvalShare(c.heavy); got != c.share {
			t.Errorf("heavy=%d: %d, want %d", c.heavy, got, c.share)
		}
	}
	for n := MinEvalSlots; n <= 1024; n++ {
		h := ExpensiveEvalSlots(n)
		if s := NetEvalShare(h); s < 1 || (h > 1 && s >= h) {
			t.Errorf("n=%d: share %d of %d", n, s, h)
		}
	}
}

func TestEvalSlots(t *testing.T) {
	for _, c := range []struct{ n, expensive, reserved int }{
		{0, 1, 1}, {1, 1, 1}, {2, 1, 1}, {3, 1, 2}, {4, 2, 2}, {5, 2, 3}, {8, 4, 4}, {12, 6, 6}, {1024, 512, 512},
	} {
		if e, r := ExpensiveEvalSlots(c.n), ReservedEvalSlots(c.n); e != c.expensive || r != c.reserved {
			t.Errorf("n=%d: expensive %d reserved %d, want %d %d", c.n, e, r, c.expensive, c.reserved)
		}
	}
	for n := MinEvalSlots; n <= 1024; n++ {
		e, r := ExpensiveEvalSlots(n), ReservedEvalSlots(n)
		if e < 1 || r < min(2, n-1) || e+r != n || e > n/2 {
			t.Fatalf("n=%d: expensive %d reserved %d break the rule", n, e, r)
		}
	}
}
