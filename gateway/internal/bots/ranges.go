package bots

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/requests"
)

// rangeTable is one range set as sorted, merged address intervals: a
// lookup is a binary search without allocation.
type rangeTable struct {
	id, operator string
	fetched      time.Time
	source       string // release | fetch
	v4           []span4
	v6           []span6
}

type span4 struct{ lo, hi uint32 }

type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }

type span6 struct{ lo, hi u128 }

// rangeState is the set of range tables in use; swapped as a whole when
// the optional fetch brings new snapshots.
type rangeState struct {
	sets []rangeTable // in catalogue order
}

func buildTable(r *bots.RangeSet, source string) (rangeTable, error) {
	t := rangeTable{id: r.ID, operator: r.Operator, source: source}
	f, err := msg.ParseTime(r.FetchedAt)
	if err != nil {
		return t, fmt.Errorf("range set %s: %w", r.ID, err)
	}
	t.fetched = f
	for _, s := range r.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return t, fmt.Errorf("range set %s: %w", r.ID, err)
		}
		p = p.Masked()
		if p.Addr().Is4() {
			lo := binary.BigEndian.Uint32(p.Addr().AsSlice())
			hi := lo | uint32(uint64(1)<<(32-p.Bits())-1)
			t.v4 = append(t.v4, span4{lo, hi})
			continue
		}
		b := p.Addr().As16()
		lo := u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
		hi := lo
		host := 128 - p.Bits()
		switch {
		case host >= 128:
			hi = u128{^uint64(0), ^uint64(0)}
		case host >= 64:
			hi.lo = ^uint64(0)
			hi.hi |= uint64(1)<<(host-64) - 1
		default:
			hi.lo |= uint64(1)<<host - 1
		}
		t.v6 = append(t.v6, span6{lo, hi})
	}
	sort.Slice(t.v4, func(i, j int) bool { return t.v4[i].lo < t.v4[j].lo })
	sort.Slice(t.v6, func(i, j int) bool { return t.v6[i].lo.less(t.v6[j].lo) })
	t.v4 = merge4(t.v4)
	t.v6 = merge6(t.v6)
	return t, nil
}

func merge4(s []span4) []span4 {
	out := s[:0]
	for _, x := range s {
		if n := len(out); n > 0 && (x.lo <= out[n-1].hi || out[n-1].hi != ^uint32(0) && x.lo == out[n-1].hi+1) {
			if x.hi > out[n-1].hi {
				out[n-1].hi = x.hi
			}
			continue
		}
		out = append(out, x)
	}
	return out
}

func merge6(s []span6) []span6 {
	out := s[:0]
	for _, x := range s {
		if n := len(out); n > 0 && !out[n-1].hi.less(x.lo) {
			if out[n-1].hi.less(x.hi) {
				out[n-1].hi = x.hi
			}
			continue
		}
		out = append(out, x)
	}
	return out
}

// contains: a must be unmapped.
func (t *rangeTable) contains(a netip.Addr) bool {
	switch {
	case a.Is4():
		b := a.As4()
		x := binary.BigEndian.Uint32(b[:])
		s := t.v4
		i, j := 0, len(s) // first span with lo > x
		for i < j {
			h := int(uint(i+j) >> 1)
			if s[h].lo <= x {
				i = h + 1
			} else {
				j = h
			}
		}
		return i > 0 && x <= s[i-1].hi
	case a.Is6():
		b := a.As16()
		x := u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
		s := t.v6
		i, j := 0, len(s)
		for i < j {
			h := int(uint(i+j) >> 1)
			if !x.less(s[h].lo) {
				i = h + 1
			} else {
				j = h
			}
		}
		return i > 0 && !s[i-1].hi.less(x)
	}
	return false
}

func (t *rangeTable) info(now time.Time) requests.RangeInfo {
	return requests.RangeInfo{ID: t.id, Operator: t.operator, FetchedAt: msg.FormatTime(t.fetched), Stale: now.Sub(t.fetched) > bots.StaleAfter, Source: t.source}
}
