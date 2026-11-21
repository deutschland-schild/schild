package cluster

import (
	"sync"
	"time"
)

// Clock is a hybrid logical clock (Kulkarni et al. 2014) in 64 bits: the
// wall clock in milliseconds in the upper 48 bits, a counter in the lower
// 16. It never goes back, also when the wall clock does, and a write made
// after a record was seen is always later than that record.
type Clock struct {
	mu   sync.Mutex
	last uint64
}

// HLCOf is the clock value of the wall time t with counter 0.
func HLCOf(t time.Time) uint64 { return uint64(t.UnixMilli()) << 16 }

// HLCTime is the wall part of a clock value.
func HLCTime(h uint64) time.Time { return time.UnixMilli(int64(h >> 16)).UTC() }

// Next returns the clock value of a write at the wall time now.
func (c *Clock) Next(now time.Time) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if w := HLCOf(now); w > c.last {
		c.last = w
	} else {
		c.last++
	}
	return c.last
}

// Observe moves the clock past a value seen in a record.
func (c *Clock) Observe(h uint64) {
	c.mu.Lock()
	if h > c.last {
		c.last = h
	}
	c.mu.Unlock()
}

// Last is the latest value given or seen.
func (c *Clock) Last() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}
