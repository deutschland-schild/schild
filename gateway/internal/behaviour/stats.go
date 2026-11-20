package behaviour

import (
	"sync"
	"time"
)

// statsRing keeps hourly counts for the last 24 h per name (scenario hits,
// rate-limit excesses) and hourly distinct sketches (client keys per limit).
// Names come from the configuration only, so the map is bounded by it; no
// address is kept, only sketch registers.
type statsRing struct {
	mu sync.Mutex
	m  map[string]*ring
}

type ring struct {
	hour [24]int64
	n    [24]int64
	hll  [24]*hll
}

func newStatsRing() *statsRing { return &statsRing{m: map[string]*ring{}} }

func (s *statsRing) slot(name string, t time.Time) (*ring, int, int64) {
	h := t.Unix() / 3600
	r := s.m[name]
	if r == nil {
		if len(s.m) >= 4096 {
			for k := range s.m {
				delete(s.m, k)
				break
			}
		}
		r = &ring{}
		s.m[name] = r
	}
	i := int(h % 24)
	if r.hour[i] != h {
		r.hour[i], r.n[i] = h, 0
		if r.hll[i] != nil {
			r.hll[i].reset()
		}
	}
	return r, i, h
}

func (s *statsRing) add(name string, t time.Time, n int64) {
	s.mu.Lock()
	r, i, _ := s.slot(name, t)
	r.n[i] += n
	s.mu.Unlock()
}

func (s *statsRing) addDistinct(name string, t time.Time, x uint64) {
	s.mu.Lock()
	r, i, _ := s.slot(name, t)
	if r.hll[i] == nil {
		r.hll[i] = newHLL(6)
	}
	r.hll[i].add(x)
	s.mu.Unlock()
}

func (s *statsRing) sum(name string, now time.Time) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.m[name]
	if r == nil {
		return 0
	}
	h := now.Unix() / 3600
	var total int64
	for i := range r.hour {
		if r.hour[i] > h-24 && r.hour[i] <= h {
			total += r.n[i]
		}
	}
	return total
}

// distinct merges the hourly sketches of the last 24 h.
func (s *statsRing) distinct(name string, now time.Time) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.m[name]
	if r == nil {
		return 0
	}
	h := now.Unix() / 3600
	merged := newHLL(6)
	any := false
	for i := range r.hour {
		if r.hll[i] == nil || r.hour[i] <= h-24 || r.hour[i] > h {
			continue
		}
		any = true
		for j, v := range r.hll[i].reg {
			if v > merged.reg[j] {
				merged.reg[j] = v
			}
		}
	}
	if !any {
		return 0
	}
	return merged.estimate()
}
