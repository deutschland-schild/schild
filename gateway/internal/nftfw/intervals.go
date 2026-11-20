package nftfw

import (
	"encoding/binary"
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

// mergeIPv6 sorts IPv6 prefixes by address and makes one interval of
// prefixes that overlap or touch, so that the set gets every boundary once,
// in order, and each start with an end of its own: the kernel couples an end
// to the start before it when it removes expired elements. A merged interval
// lives as long as its longest part. That only matters while the gateway is
// away: as long as it answers, a block that ends there changes the revision
// and the set is written again without it.
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

// clients64 lists the /64 clients of the interval [start, end), or from start
// to the end of the address space without an end: what Replace merged reads
// back as the clients it was made of. At most limit clients are listed.
func clients64(start, end netip.Addr, hasEnd bool, limit int) []netip.Prefix {
	s16 := start.As16()
	lo := binary.BigEndian.Uint64(s16[:8])
	n := -lo // up to the end of the address space; 0 stands for all 2^64
	if hasEnd {
		e16 := end.As16()
		n = max(binary.BigEndian.Uint64(e16[:8])-lo, 1)
	}
	if n == 0 || n > uint64(limit) {
		n = uint64(limit)
	}
	out := make([]netip.Prefix, 0, n)
	for i := uint64(0); i < n; i++ {
		var b [16]byte
		binary.BigEndian.PutUint64(b[:8], lo+i)
		out = append(out, netip.PrefixFrom(netip.AddrFrom16(b), 64))
	}
	return out
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
