// Package stats keeps small rolling in-memory counters: 24 h counters for
// the overview, per-rule hit counts and WAF latency quantiles.
package stats

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Counter kinds for the overview.
const (
	Requests = iota
	Evaluated
	Blocked
	WouldBlock
	Incidents
	numKinds
)

const day = 1440 // minutes

type slot struct {
	minute int64
	n      [numKinds]int64
}

// Rolling counts events per minute over 24 hours.
type Rolling struct {
	mu    sync.Mutex
	slots [day]slot
}

func minuteOf(t time.Time) int64 { return t.Unix() / 60 }

// Add counts n events of kind at now.
func (r *Rolling) Add(kind int, n int64, now time.Time) {
	m := minuteOf(now)
	r.mu.Lock()
	s := &r.slots[m%day]
	if s.minute != m {
		*s = slot{minute: m}
	}
	s.n[kind] += n
	r.mu.Unlock()
}

// Sum returns the count of kind within the last window.
func (r *Rolling) Sum(kind int, window time.Duration, now time.Time) int64 {
	m := minuteOf(now)
	from := m - int64(window/time.Minute) + 1
	var total int64
	r.mu.Lock()
	for i := range r.slots {
		s := &r.slots[i]
		if s.minute >= from && s.minute <= m {
			total += s.n[kind]
		}
	}
	r.mu.Unlock()
	return total
}

// Hourly returns 24 hourly sums of kind, oldest first; the last bucket ends
// with the current minute (Overview.series_24h, contracts v0.1).
func (r *Rolling) Hourly(kind int, now time.Time) []int64 {
	m := minuteOf(now)
	from := m - day + 1
	out := make([]int64, 24)
	r.mu.Lock()
	for i := range r.slots {
		s := &r.slots[i]
		if s.minute >= from && s.minute <= m {
			out[(s.minute-from)/60] += s.n[kind]
		}
	}
	r.mu.Unlock()
	return out
}

// Hits counts matches per rule id per hour over 24 hours and remembers the
// last message of each rule.
type Hits struct {
	mu    sync.Mutex
	rules map[string]*[24]hourSlot
	msgs  map[string]string
}

type hourSlot struct {
	hour int64
	n    int64
}

// NewHits returns an empty counter.
func NewHits() *Hits { return &Hits{rules: map[string]*[24]hourSlot{}, msgs: map[string]string{}} }

// Note remembers the message of a rule (first one wins, bounded).
func (h *Hits) Note(rule, msg string) {
	if msg == "" {
		return
	}
	h.mu.Lock()
	if _, ok := h.msgs[rule]; !ok && len(h.msgs) < 10000 {
		h.msgs[rule] = msg
	}
	h.mu.Unlock()
}

// Msg returns the remembered message of a rule.
func (h *Hits) Msg(rule string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.msgs[rule]
}

// Rules lists every rule with hits in the last 24 hours.
func (h *Hits) Rules(now time.Time) map[string]int64 {
	hr := now.Unix() / 3600
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]int64{}
	for r, s := range h.rules {
		var n int64
		for _, c := range s {
			if c.hour > hr-24 && c.hour <= hr {
				n += c.n
			}
		}
		if n > 0 {
			out[r] = n
		}
	}
	return out
}

// Add counts one hit of rule at now.
func (h *Hits) Add(rule string, now time.Time) {
	hr := now.Unix() / 3600
	h.mu.Lock()
	s, ok := h.rules[rule]
	if !ok {
		s = &[24]hourSlot{}
		h.rules[rule] = s
	}
	c := &s[hr%24]
	if c.hour != hr {
		*c = hourSlot{hour: hr}
	}
	c.n++
	h.mu.Unlock()
}

// Count returns the hits of rule in the last 24 hours.
func (h *Hits) Count(rule string, now time.Time) int64 {
	hr := now.Unix() / 3600
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.rules[rule]
	if !ok {
		return 0
	}
	var n int64
	for _, c := range s {
		if c.hour > hr-24 && c.hour <= hr {
			n += c.n
		}
	}
	return n
}

// Latency keeps per-minute histograms over the last hour.
type Latency struct {
	mu    sync.Mutex
	slots [60]latSlot
}

// bucket upper bounds in milliseconds (exponential, 0.05 ms .. ~13 s).
var bounds = func() []float64 {
	var b []float64
	for v := 0.05; v < 15000; v *= 1.25 {
		b = append(b, v)
	}
	return b
}()

type latSlot struct {
	minute int64
	counts []int64
}

// Observe records one duration.
func (l *Latency) Observe(d time.Duration, now time.Time) {
	ms := float64(d) / float64(time.Millisecond)
	i := sort.SearchFloat64s(bounds, ms)
	m := minuteOf(now)
	l.mu.Lock()
	s := &l.slots[m%60]
	if s.minute != m || s.counts == nil {
		s.minute = m
		s.counts = make([]int64, len(bounds)+1)
	}
	s.counts[i]++
	l.mu.Unlock()
}

// Quantile returns the q-quantile in milliseconds over the last hour (NaN if empty).
func (l *Latency) Quantile(q float64, now time.Time) float64 {
	m := minuteOf(now)
	agg := make([]int64, len(bounds)+1)
	var total int64
	l.mu.Lock()
	for i := range l.slots {
		s := &l.slots[i]
		if s.counts == nil || s.minute <= m-60 || s.minute > m {
			continue
		}
		for j, c := range s.counts {
			agg[j] += c
			total += c
		}
	}
	l.mu.Unlock()
	if total == 0 {
		return math.NaN()
	}
	target := int64(math.Ceil(q * float64(total)))
	var cum int64
	for j, c := range agg {
		cum += c
		if cum >= target {
			if j < len(bounds) {
				return bounds[j]
			}
			return bounds[len(bounds)-1]
		}
	}
	return bounds[len(bounds)-1]
}
