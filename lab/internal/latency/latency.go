// Package latency keeps a sliding window of durations in log-linear buckets
// and answers quantile queries (ack p50/p99 for the dashboard, M6).
package latency

import (
	"math"
	"sync"
	"time"
)

const (
	slots      = 30               // window = slots * slotWidth
	slotWidth  = 10 * time.Second // 30 * 10 s = 300 s window
	subBuckets = 16               // per power of two
	minExp     = -4               // 2^-4 ms = 62.5 µs
	maxExp     = 16               // 2^16 ms = 65 s
	nBuckets   = (maxExp - minExp) * subBuckets
)

type slot struct {
	start  int64 // slot index (unix / slotWidth)
	counts [nBuckets + 2]uint32
	max    float64
	n      uint64
}

// Window tracks durations of the last 300 s.
type Window struct {
	mu    sync.Mutex
	slots [slots]slot
	now   func() time.Time
}

// New returns a window using clock now (nil = time.Now).
func New(now func() time.Time) *Window {
	if now == nil {
		now = time.Now
	}
	return &Window{now: now}
}

// WindowSeconds is the length of the window.
func WindowSeconds() int { return int(slots * slotWidth / time.Second) }

func bucketOf(ms float64) int {
	if ms <= math.Ldexp(1, minExp) {
		return 0
	}
	e := math.Log2(ms)
	if e >= maxExp {
		return nBuckets + 1
	}
	pos := (e - minExp) * subBuckets
	return int(pos) + 1
}

func upperOf(b int) float64 {
	if b <= 0 {
		return math.Ldexp(1, minExp)
	}
	return math.Exp2(float64(b)/subBuckets + minExp)
}

// Observe records one duration.
func (w *Window) Observe(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	idx := w.now().UnixNano() / int64(slotWidth)
	w.mu.Lock()
	s := &w.slots[idx%slots]
	if s.start != idx {
		*s = slot{start: idx}
	}
	s.counts[bucketOf(ms)]++
	s.n++
	if ms > s.max {
		s.max = ms
	}
	w.mu.Unlock()
}

// Summary is a quantile summary in milliseconds.
type Summary struct {
	P50, P99, Max float64
	N             uint64
}

// Summary returns quantiles over the window (upper bucket bounds, so the
// values are conservative by at most ~4.4 %).
func (w *Window) Summary() Summary {
	idx := w.now().UnixNano() / int64(slotWidth)
	var counts [nBuckets + 2]uint64
	var out Summary
	w.mu.Lock()
	for i := range w.slots {
		s := &w.slots[i]
		if s.n == 0 || idx-s.start >= slots || s.start > idx {
			continue
		}
		for b, c := range s.counts {
			counts[b] += uint64(c)
		}
		out.N += s.n
		if s.max > out.Max {
			out.Max = s.max
		}
	}
	w.mu.Unlock()
	if out.N == 0 {
		return out
	}
	q := func(p float64) float64 {
		target := uint64(math.Ceil(p * float64(out.N)))
		var cum uint64
		for b, c := range counts {
			cum += c
			if cum >= target {
				return math.Min(upperOf(b), out.Max)
			}
		}
		return out.Max
	}
	out.P50, out.P99 = q(0.5), q(0.99)
	return out
}

// Rate counts events per second over a sliding minute (ingest rate).
type Rate struct {
	mu   sync.Mutex
	secs [60]struct{ at, n int64 }
	now  func() time.Time
}

// NewRate returns a rate counter.
func NewRate(now func() time.Time) *Rate {
	if now == nil {
		now = time.Now
	}
	return &Rate{now: now}
}

// Add records n events now.
func (r *Rate) Add(n int) {
	s := r.now().Unix()
	r.mu.Lock()
	e := &r.secs[s%60]
	if e.at != s {
		e.at, e.n = s, 0
	}
	e.n += int64(n)
	r.mu.Unlock()
}

// PerSecond returns the average over the last 60 s.
func (r *Rate) PerSecond() float64 {
	s := r.now().Unix()
	var n int64
	r.mu.Lock()
	for _, e := range r.secs {
		if e.at > s-60 && e.at <= s {
			n += e.n
		}
	}
	r.mu.Unlock()
	return float64(n) / 60
}

// Day counts events per hour over a sliding 24 h (quotas, *_24h numbers).
type Day struct {
	mu    sync.Mutex
	hours [24]struct{ at, n int64 }
}

// Add records n events at t.
func (d *Day) Add(t time.Time, n int64) {
	h := t.Unix() / 3600
	d.mu.Lock()
	e := &d.hours[h%24]
	if e.at != h {
		e.at, e.n = h, 0
	}
	e.n += n
	d.mu.Unlock()
}

// Sum returns the count of the last 24 h at t.
func (d *Day) Sum(t time.Time) int64 {
	h := t.Unix() / 3600
	var n int64
	d.mu.Lock()
	for _, e := range d.hours {
		if e.at > h-24 && e.at <= h {
			n += e.n
		}
	}
	d.mu.Unlock()
	return n
}
