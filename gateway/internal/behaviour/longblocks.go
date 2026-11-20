package behaviour

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
)

// D29 amendment (2026-10-29): blocks over PersistOver (7 days for
// data-centre addresses that come back) are kept in schild.db through
// Sink.Persist and restored at start (RestoreBlocks). They also live in a
// small map of their own, so a flood of distinct addresses that evicts
// entries of the block table can never end one of them early.

type longBlock struct {
	ab      events.ActiveBlock
	eventID string
	until   int64
}

type longBlocks struct {
	n  atomic.Int32 // len(m); Check skips the map while it is 0
	mu sync.Mutex
	m  map[Key]longBlock
	// max overrides MaxLongBlocks (tests; 0: MaxLongBlocks).
	max int
}

// MaxLongBlocks bounds the kept blocks; at the cap the one ending first is
// replaced (it still ends by itself in the block table) and its row in
// schild.db is deleted (D38: Sink.Unpersist).
const MaxLongBlocks = 65536

// put stores lb and returns the key it evicted at the cap (ok false: none).
func (l *longBlocks) put(key Key, lb longBlock) (evicted Key, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[Key]longBlock{}
	}
	limit := MaxLongBlocks
	if l.max > 0 {
		limit = l.max
	}
	if _, had := l.m[key]; !had && len(l.m) >= limit {
		var first Key
		var fu int64
		for k, v := range l.m {
			if fu == 0 || v.until < fu {
				first, fu = k, v.until
			}
		}
		delete(l.m, first)
		evicted, ok = first, true
	}
	l.m[key] = lb
	l.n.Store(int32(len(l.m)))
	return evicted, ok
}

// putLong keeps lb and deletes the stored row of a block it evicted.
func (e *Engine) putLong(key Key, lb longBlock) {
	if k, ok := e.long.put(key, lb); ok && e.Sink.Unpersist != nil {
		e.Sink.Unpersist(k.Addr().String())
	}
}

func (e *Engine) keepLong(key Key, ab events.ActiveBlock, eventID string) {
	until, err := time.Parse(time.RFC3339, ab.Until)
	if err != nil {
		return
	}
	e.putLong(key, longBlock{ab: ab, eventID: eventID, until: until.UnixNano()})
	if e.Sink.Persist != nil {
		e.Sink.Persist(ab)
	}
}

// longCheck returns the kept block of key that runs at now.
func (e *Engine) longCheck(key Key, now int64) (longBlock, bool) {
	if e.long.n.Load() == 0 {
		return longBlock{}, false
	}
	e.long.mu.Lock()
	defer e.long.mu.Unlock()
	lb, ok := e.long.m[key]
	return lb, ok && lb.until > now
}

// dropLong removes the kept block of key and reports whether there was one.
func (e *Engine) dropLong(key Key) bool {
	if e.long.n.Load() == 0 {
		return false
	}
	e.long.mu.Lock()
	_, ok := e.long.m[key]
	delete(e.long.m, key)
	e.long.n.Store(int32(len(e.long.m)))
	e.long.mu.Unlock()
	if ok && e.Sink.Unpersist != nil {
		e.Sink.Unpersist(key.Addr().String())
	}
	return ok
}

// sweepLong drops kept blocks that ended.
func (e *Engine) sweepLong(now int64) {
	if e.long.n.Load() == 0 {
		return
	}
	var gone []Key
	e.long.mu.Lock()
	for k, v := range e.long.m {
		if v.until <= now {
			delete(e.long.m, k)
			gone = append(gone, k)
		}
	}
	e.long.n.Store(int32(len(e.long.m)))
	e.long.mu.Unlock()
	if e.Sink.Unpersist != nil {
		for _, k := range gone {
			e.Sink.Unpersist(k.Addr().String())
		}
	}
}

// LongBlocks returns the kept blocks that run now (tests, API).
func (e *Engine) LongBlocks() []events.ActiveBlock {
	now := e.now().UnixNano()
	e.long.mu.Lock()
	defer e.long.mu.Unlock()
	out := make([]events.ActiveBlock, 0, len(e.long.m))
	for _, v := range e.long.m {
		if v.until > now {
			out = append(out, v.ab)
		}
	}
	return out
}

// ParseClientKey parses the client key of a kept block (IPv4 address or the
// first address of an IPv6 /64).
func ParseClientKey(s string, bits int) (Key, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return Key{}, false
	}
	k, b := KeyOf(a)
	return k, k.IsValid() && b == bits && k.Addr() == a.Unmap()
}

// RestoreBlocks loads kept blocks at start. Rows that ended, that are not
// over PersistOver or over the hosting cap, whose key does not parse or
// whose address skip reports (allowlisted) are left out; their client keys
// are returned so the caller deletes the rows.
func (e *Engine) RestoreBlocks(rows []events.ActiveBlock, skip func(netip.Addr) bool) (restored int, drop []string) {
	now := e.now().UnixNano()
	for _, ab := range rows {
		key, ok := ParseClientKey(ab.ClientKey, ab.KeyBits)
		until, err := time.Parse(time.RFC3339, ab.Until)
		since, err2 := time.Parse(time.RFC3339, ab.Since)
		// The duration must be the ladder step of the row's net class and
		// level (a residential row of 7 days is refused, D36 measurement C).
		if !ok || err != nil || err2 != nil || until.UnixNano() <= now || ab.DurationS <= events.PersistOverS ||
			ab.DurationS > events.MaxBlockHostingS || !validKept(ab) ||
			until.Sub(since) > MaxBlock || (skip != nil && skip(key.Addr())) {
			drop = append(drop, ab.ClientKey)
			continue
		}
		scenario := strings.TrimPrefix(ab.Source, "behaviour:")
		e.blocks.with(key, true, func(b *blockState) {
			*b = blockState{until: until.UnixNano(), lastUntil: until.UnixNano(), level: ab.Level, scenario: scenario, incident: ab.Incident,
				started: since.UnixNano(), netClass: ab.NetClass, persisted: true}
		})
		e.putLong(key, longBlock{ab: ab, until: until.UnixNano()})
		restored++
	}
	return restored, drop
}

// DropBlocks ends every running block whose client key allowed reports
// (the operator allowlisted it) and removes kept ones. It returns the number
// of client keys whose block ended.
func (e *Engine) DropBlocks(allowed func(netip.Addr) bool) int {
	now := e.now().UnixNano()
	ended := map[Key]bool{}
	var incidents []string
	e.blocks.sweep(func(k Key, b *blockState) bool {
		if b.until > now && allowed(k.Addr()) {
			b.until = now
			ended[k] = true
			incidents = append(incidents, b.incident)
		}
		return false
	})
	if e.long.n.Load() > 0 {
		e.long.mu.Lock()
		var more []Key
		for k, v := range e.long.m {
			if v.until > now && allowed(k.Addr()) {
				more = append(more, k)
				incidents = append(incidents, v.ab.Incident)
			}
		}
		e.long.mu.Unlock()
		for _, k := range more {
			e.dropLong(k)
			ended[k] = true
		}
	}
	e.reportEnded(now, incidents...)
	return len(ended)
}

// longIncident is the incident of the running kept block of key ("" none).
func (e *Engine) longIncident(key Key, now int64) string {
	if e.long.n.Load() == 0 {
		return ""
	}
	e.long.mu.Lock()
	defer e.long.mu.Unlock()
	if v, ok := e.long.m[key]; ok && v.until > now {
		return v.ab.Incident
	}
	return ""
}

// reportEnded hands the incidents of blocks the operator ended to
// Sink.Ended, each once.
func (e *Engine) reportEnded(now int64, incidents ...string) {
	if e.Sink.Ended == nil {
		return
	}
	seen := map[string]bool{"": true}
	at := time.Unix(0, now).UTC()
	for _, in := range incidents {
		if !seen[in] {
			seen[in] = true
			e.Sink.Ended(in, at)
		}
	}
}

// Forget removes everything the engine holds about the client key of ip
// (Art. 17 deletion): blocks, kept blocks, counters, buckets and the
// release time. It returns the number of blocks that ended.
func (e *Engine) Forget(ip netip.Addr) int {
	key, _ := KeyOf(ip)
	if !key.IsValid() {
		return 0
	}
	now := e.now().UnixNano()
	ended := 0
	e.blocks.with(key, false, func(b *blockState) {
		if b != nil && b.until > now {
			ended++
		}
	})
	e.blocks.delete(key)
	if e.dropLong(key) && ended == 0 {
		ended++
	}
	e.clients.delete(key)
	for _, l := range e.cfg.Load().limits {
		e.buckets.delete(bucketKey{key, l.idx})
	}
	e.released.delete(key)
	return ended
}

// durationText is a block duration for incident reasons (15 min, 4 h, 7 d).
func durationText(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return strconv.Itoa(int(d/(24*time.Hour))) + " d"
	case d >= time.Hour && d%time.Hour == 0:
		return strconv.Itoa(int(d/time.Hour)) + " h"
	default:
		return strconv.Itoa(int(d/time.Minute)) + " min"
	}
}
