package stats

import (
	"math"
	"testing"
	"time"
)

func TestRolling(t *testing.T) {
	var r Rolling
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	r.Add(Requests, 5, now.Add(-25*time.Hour))
	r.Add(Requests, 3, now.Add(-23*time.Hour))
	r.Add(Requests, 2, now)
	if got := r.Sum(Requests, 24*time.Hour, now); got != 5 {
		t.Fatalf("got %d", got)
	}
	if got := r.Sum(Requests, time.Hour, now); got != 2 {
		t.Fatalf("got %d", got)
	}
}

func TestHits(t *testing.T) {
	h := NewHits()
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	h.Add("930120", now.Add(-30*time.Hour))
	h.Add("930120", now.Add(-time.Hour))
	h.Add("930120", now)
	if got := h.Count("930120", now); got != 2 {
		t.Fatal(got)
	}
}

func TestLatency(t *testing.T) {
	var l Latency
	now := time.Now()
	if !math.IsNaN(l.Quantile(0.95, now)) {
		t.Fatal("empty must be NaN")
	}
	for i := 0; i < 95; i++ {
		l.Observe(500*time.Microsecond, now)
	}
	for i := 0; i < 5; i++ {
		l.Observe(20*time.Millisecond, now)
	}
	if q := l.Quantile(0.95, now); q < 0.5 || q > 0.7 {
		t.Fatalf("p95 %v", q)
	}
	if q := l.Quantile(0.99, now); q < 20 || q > 26 {
		t.Fatalf("p99 %v", q)
	}
}

func TestHourly(t *testing.T) {
	var r Rolling
	now := time.Date(2026, 10, 26, 12, 30, 0, 0, time.UTC)
	r.Add(Requests, 2, now)
	r.Add(Requests, 3, now.Add(-59*time.Minute))
	r.Add(Requests, 5, now.Add(-60*time.Minute))
	r.Add(Requests, 7, now.Add(-23*time.Hour-59*time.Minute))
	r.Add(Requests, 11, now.Add(-26*time.Hour-7*time.Minute)) // outside the window (an unused ring slot)
	h := r.Hourly(Requests, now)
	if len(h) != 24 || h[23] != 5 || h[22] != 5 || h[0] != 7 {
		t.Fatalf("hourly %v", h)
	}
	var sum int64
	for _, v := range h {
		sum += v
	}
	if sum != r.Sum(Requests, 24*time.Hour, now) {
		t.Fatalf("hourly sum %d differs from Sum %d", sum, r.Sum(Requests, 24*time.Hour, now))
	}
}
