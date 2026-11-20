package monitoring

import (
	"math"
	"math/bits"
	"sort"
	"strings"
	"sync/atomic"
	"unicode/utf8"
	"unsafe"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// ---------------------------------------------------------------- space-saving

// topEntry is one counted key of a space-saving table.
type topEntry struct {
	key, label                    string
	req, stopped, would, det, err int64
}

// MaxTopKeyBytes bounds a key and a label of a top list (D36 fix round 1,
// finding B.4.6): a longer one keeps its first bytes (cut at a UTF-8
// boundary) and ends with TruncMarker, at most MaxTopKeyBytes in all. The
// contract allows keys up to 512 bytes; 64 (128 until D36 fix round 2:
// with 32 websites metrics.db reached 1.4 times its documented size)
// keeps the worst case of
// metrics.db (random long paths, referrers, AS names) near the realistic
// one. Two keys that share the first bytes are counted as one.
const MaxTopKeyBytes = 64

// TruncMarker ends a cut key or label.
const TruncMarker = "\u2026"

// truncKey cuts s to MaxTopKeyBytes with the marker (allocates).
func truncKey(s string) string {
	var buf [MaxTopKeyBytes]byte
	return string(appendTrunc(buf[:0], s))
}

// unsafeTruncKey returns the cut key as a string that shares buf: valid
// only while buf lives and only for map lookups or a following Clone.
func unsafeTruncKey(buf []byte, s string) string {
	b := appendTrunc(buf, s)
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func appendTrunc(dst []byte, s string) []byte {
	n := MaxTopKeyBytes - len(TruncMarker)
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	dst = append(dst, s[:n]...)
	return append(dst, TruncMarker...)
}

// topTable is a space-saving table with a fixed capacity: an existing key
// is counted in place (no allocation), a new key takes a free slot or
// replaces the entry with the smallest count. floor is an upper bound of the
// true count of any key that is not in the table; a new key starts at floor
// and carries it as overcount (err). So every entry satisfies
// req - err <= true count <= req, also across merges (MVP-21 measurement
// finding 3b). Not safe for concurrent use.
type topTable struct {
	cap     int
	idx     map[string]int
	entries []topEntry
	floor   int64
}

func newTopTable(capacity int) *topTable {
	return &topTable{cap: capacity, idx: make(map[string]int, capacity), entries: make([]topEntry, 0, capacity)}
}

func (t *topTable) reset() {
	clear(t.idx)
	t.entries = t.entries[:0]
	t.floor = 0
}

// add counts n requests (stopped, would, det of them) for key; base is the
// overcount of the incoming value (merges of other tables).
func (t *topTable) add(key, label string, n, stopped, would, det, base int64) {
	var buf [MaxTopKeyBytes]byte
	if len(key) > MaxTopKeyBytes {
		// A long key is counted under its first bytes plus the marker
		// (the map lookup of string(bytes) does not allocate).
		key = unsafeTruncKey(buf[:0], key)
	}
	if i, ok := t.idx[key]; ok {
		e := &t.entries[i]
		e.req += n
		e.stopped += stopped
		e.would += would
		e.det += det
		e.err += base
		if label != "" && e.label == "" {
			e.label = label
		}
		return
	}
	if len(label) > MaxTopKeyBytes {
		label = truncKey(label)
	}
	if len(t.entries) < t.cap {
		t.entries = append(t.entries, topEntry{key: strings.Clone(key), label: label, req: t.floor + n, stopped: stopped, would: would, det: det, err: t.floor + base})
		t.idx[t.entries[len(t.entries)-1].key] = len(t.entries) - 1
		return
	}
	m := 0
	for i := 1; i < len(t.entries); i++ {
		if t.entries[i].req < t.entries[m].req {
			m = i
		}
	}
	old := t.entries[m]
	delete(t.idx, old.key)
	// The evicted key may have counted up to old.req.
	t.floor = max(t.floor, old.req)
	k := strings.Clone(key)
	t.entries[m] = topEntry{key: k, label: label, req: t.floor + n, stopped: stopped, would: would, det: det, err: t.floor + base}
	t.idx[k] = m
}

// merge adds every entry of o. A key of t that o does not list may have
// counted up to o.floor there: it gets o.floor as count and overcount, so
// req stays an upper bound. A key only o lists gets t.floor the same way.
func (t *topTable) merge(o *topTable) {
	ft, fo := t.floor, o.floor
	if fo > 0 {
		for i := range t.entries {
			e := &t.entries[i]
			if _, ok := o.idx[e.key]; !ok {
				e.req += fo
				e.err += fo
			}
		}
	}
	for i := range o.entries {
		e := &o.entries[i]
		t.add(e.key, e.label, e.req, e.stopped, e.would, e.det, e.err)
	}
	t.floor = max(t.floor, ft+fo)
}

// top returns the k largest entries as wire entries (detections only for
// paths).
func (t *topTable) top(k int, withDet bool) []cm.TopEntry {
	es := make([]topEntry, len(t.entries))
	copy(es, t.entries)
	sort.Slice(es, func(i, j int) bool {
		if es[i].req != es[j].req {
			return es[i].req > es[j].req
		}
		return es[i].key < es[j].key
	})
	if len(es) > k {
		es = es[:k]
	}
	out := make([]cm.TopEntry, len(es))
	for i, e := range es {
		out[i] = cm.TopEntry{Key: e.key, Label: e.label, Requests: e.req, Stopped: e.stopped, WouldBlock: e.would, Error: e.err}
		if withDet {
			out[i].Detections = e.det
		}
	}
	return out
}

// ---------------------------------------------------------------- HyperLogLog

const hllP = 10
const hllM = 1 << hllP

// hll is a HyperLogLog sketch with precision 10 (±3.3 %).
type hll [hllM]uint8

func (h *hll) add(x uint64) {
	i := x >> (64 - hllP)
	r := uint8(bits.LeadingZeros64(x<<hllP|1<<(hllP-1)) + 1)
	if r > h[i] {
		h[i] = r
	}
}

func (h *hll) merge(o *hll) {
	for i, v := range o {
		if v > h[i] {
			h[i] = v
		}
	}
}

func (h *hll) reset() { *h = hll{} }

func (h *hll) empty() bool {
	for _, v := range h {
		if v != 0 {
			return false
		}
	}
	return true
}

// estimate returns the cardinality estimate (linear counting for small sets).
func (h *hll) estimate() int64 {
	sum := 0.0
	zeros := 0
	for _, v := range h {
		sum += math.Ldexp(1, -int(v))
		if v == 0 {
			zeros++
		}
	}
	m := float64(hllM)
	alpha := 0.7213 / (1 + 1.079/m)
	e := alpha * m * m / sum
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros))
	}
	return int64(math.Round(e))
}

// ---------------------------------------------------------------- Bloom filters

// bloomBits per daily filter (1 MiB): about 1 % false positives at 870 000
// clients a day with 7 hash functions.
const (
	bloomBits  = 1 << 23
	bloomWords = bloomBits / 64
	bloomK     = 7
	bloomDays  = 7
)

// seenFilter remembers client hashes for seven days (one filter per UTC
// day, in memory only). Lock-free: bits are set with atomic OR; a racing
// reset of the oldest day only loses bits that are about to expire anyway.
type seenFilter struct {
	days [bloomDays][]atomic.Uint64
	cur  atomic.Int64 // UTC day number of days[day % 7]
}

func newSeenFilter(day int64) *seenFilter {
	f := &seenFilter{}
	for i := range f.days {
		f.days[i] = make([]atomic.Uint64, bloomWords)
	}
	f.cur.Store(day)
	return f
}

// rotate moves to UTC day and clears the filters of days that ended more
// than seven days ago.
func (f *seenFilter) rotate(day int64) {
	cur := f.cur.Load()
	if day <= cur {
		return
	}
	for d := cur + 1; d <= day && d <= cur+bloomDays; d++ {
		w := f.days[d%bloomDays]
		for i := range w {
			w[i].Store(0)
		}
	}
	f.cur.Store(day)
}

// seen reports whether x was seen in the last seven days and records it for
// today.
func (f *seenFilter) seen(x uint64) bool {
	h1, h2 := x, x>>33|x<<31|1
	today := f.days[f.cur.Load()%bloomDays]
	var pos [bloomK]uint64
	for i := range pos {
		pos[i] = (h1 + uint64(i)*h2) % bloomBits
	}
	found := false
	for d := range f.days {
		w := f.days[d]
		all := true
		for _, p := range pos {
			if w[p/64].Load()&(1<<(p%64)) == 0 {
				all = false
				break
			}
		}
		if all {
			found = true
			break
		}
	}
	for _, p := range pos {
		today[p/64].Or(1 << (p % 64))
	}
	return found
}
