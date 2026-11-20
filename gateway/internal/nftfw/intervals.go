package nftfw

import (
	"net/netip"
	"slices"
	"time"
)

// v6Item is one IPv6 prefix block to place into the interval set.
type v6Item struct {
	Prefix  netip.Prefix
	Timeout time.Duration
}

// v6Range is a half-open IPv6 interval [Start, End) (or [Start, max] when
// HasEnd is false) ready for an nftables interval set without AutoMerge.
type v6Range struct {
	Start   netip.Addr
	End     netip.Addr
	HasEnd  bool
	Timeout time.Duration
}

// mergeIPv6 sorts IPv6 prefixes numerically and merges overlapping or adjacent
// intervals so nftables never sees duplicate boundary keys or out-of-order
// elements. Merged intervals keep the longest timeout.
func mergeIPv6(items []v6Item) []v6Range {
	if len(items) == 0 {
		return nil
	}
	rs := make([]v6Range, 0, len(items))
	for _, it := range items {
		p := it.Prefix.Masked()
		if !p.IsValid() || p.Addr().Is4() {
			continue
		}
		timeout := it.Timeout.Truncate(time.Second)
		if timeout < time.Second {
			continue
		}
		end, ok := after(p)
		rs = append(rs, v6Range{Start: p.Addr(), End: end, HasEnd: ok, Timeout: timeout})
	}
	if len(rs) == 0 {
		return nil
	}
	slices.SortFunc(rs, func(a, b v6Range) int {
		if c := a.Start.Compare(b.Start); c != 0 {
			return c
		}
		switch {
		case !a.HasEnd && b.HasEnd:
			return -1
		case a.HasEnd && !b.HasEnd:
			return 1
		case a.HasEnd && b.HasEnd:
			return b.End.Compare(a.End)
		}
		return 0
	})
	out := make([]v6Range, 0, len(rs))
	cur := rs[0]
	for _, next := range rs[1:] {
		if !cur.HasEnd {
			cur.Timeout = max(cur.Timeout, next.Timeout)
			continue
		}
		if next.Start.Compare(cur.End) <= 0 {
			cur.Timeout = max(cur.Timeout, next.Timeout)
			if !next.HasEnd {
				cur.HasEnd = false
				cur.End = netip.Addr{}
			} else if next.End.Compare(cur.End) > 0 {
				cur.End = next.End
			}
			continue
		}
		out = append(out, cur)
		cur = next
	}
	out = append(out, cur)
	return out
}

// batchV6Ranges splits merged intervals into chunks whose netlink element count
// stays within maxElems without ever splitting a (Start, IntervalEnd) pair
// across two SetAddElements calls.
func batchV6Ranges(ranges []v6Range, maxElems int) [][]v6Range {
	if len(ranges) == 0 {
		return nil
	}
	if maxElems < 2 {
		maxElems = 2
	}
	var batches [][]v6Range
	start, count := 0, 0
	for i, r := range ranges {
		need := 1
		if r.HasEnd {
			need = 2
		}
		if count > 0 && count+need > maxElems {
			batches = append(batches, ranges[start:i])
			start, count = i, 0
		}
		count += need
	}
	if start < len(ranges) {
		batches = append(batches, ranges[start:])
	}
	return batches
}

// after is the first address after prefix p; ok false at the end of the
// address space.
func after(p netip.Prefix) (netip.Addr, bool) {
	b := p.Masked().Addr().As16()
	bits := p.Bits()
	// Add 1 at the last bit of the prefix.
	for i := bits - 1; i >= 0; i-- {
		byteI, bit := i/8, byte(1)<<(7-i%8)
		if b[byteI]&bit == 0 {
			b[byteI] |= bit
			for j := i + 1; j < bits; j++ {
				b[j/8] &^= byte(1) << (7 - j%8)
			}
			return netip.AddrFrom16(b), true
		}
	}
	return netip.Addr{}, false
}
