// Package ratelog rate-limits process log lines that a request or an event
// can trigger (D38, contracts/storage-bounds.md section 5). Per message the
// first occurrence is logged at once; after that at most one line per
// Interval, with the number of occurrences suppressed since the last line
// appended as "(n suppressed)". A flood therefore writes a bounded number
// of lines instead of one per request (D36 re-measurement C: 589,781
// lines, 89 MB in 3 min).
//
// Two forms: a Limiter per call site (lock-free, Allow does not allocate,
// for request paths), and a Group keyed by message for components with
// several warnings.
package ratelog

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Interval is the minimum time between two lines of one message.
const Interval = time.Minute

// Limiter rate-limits one message. The zero value is ready to use and safe
// for concurrent use.
type Limiter struct {
	suppressed atomic.Int64 // occurrences not logged since the last line
	last       atomic.Int64 // unix nanoseconds of the last line, 0 never
}

// Allow records one occurrence at now. ok reports whether a line is due;
// then n is the number of occurrences suppressed since the last line (to
// pass to Msg). Otherwise the occurrence is counted as suppressed. Allow
// does not allocate.
func (l *Limiter) Allow(now time.Time) (n int64, ok bool) {
	if !l.take(now) {
		l.suppressed.Add(1)
		return 0, false
	}
	return l.suppressed.Swap(0), true
}

// Due reports, without recording an occurrence, whether suppressed
// occurrences are waiting and the interval is over; then it returns their
// number and starts a new interval. Call it periodically so the tail of a
// flood is reported (Flush).
func (l *Limiter) Due(now time.Time) (n int64, ok bool) {
	if l.suppressed.Load() == 0 || !l.take(now) {
		return 0, false
	}
	n = l.suppressed.Swap(0)
	return n, n > 0
}

// Suppressed returns the occurrences counted since the last line.
func (l *Limiter) Suppressed() int64 { return l.suppressed.Load() }

func (l *Limiter) take(now time.Time) bool {
	last := l.last.Load()
	t := now.UnixNano()
	if t == 0 {
		t = 1 // 0 means "never logged"
	}
	if last != 0 && t-last < int64(Interval) {
		return false
	}
	return l.last.CompareAndSwap(last, t)
}

// Msg returns msg with " (n suppressed)" appended when n > 0.
func Msg(msg string, n int64) string {
	if n <= 0 {
		return msg
	}
	return msg + " (" + strconv.FormatInt(n, 10) + " suppressed)"
}

// Log writes msg at level when a line is due (time.Now). log may be nil.
func (l *Limiter) Log(log *slog.Logger, level slog.Level, msg string, args ...any) {
	l.LogAt(log, time.Now(), level, msg, args...)
}

// LogAt is Log at a given time.
func (l *Limiter) LogAt(log *slog.Logger, now time.Time, level slog.Level, msg string, args ...any) {
	n, ok := l.Allow(now)
	if !ok || log == nil {
		return
	}
	log.Log(context.Background(), level, Msg(msg, n), args...)
}

// Warn logs msg at warn level when a line is due.
func (l *Limiter) Warn(log *slog.Logger, msg string, args ...any) {
	l.LogAt(log, time.Now(), slog.LevelWarn, msg, args...)
}

// Error logs msg at error level when a line is due.
func (l *Limiter) Error(log *slog.Logger, msg string, args ...any) {
	l.LogAt(log, time.Now(), slog.LevelError, msg, args...)
}

// Flush writes "msg (n suppressed)" when suppressed occurrences wait and
// the interval is over.
func (l *Limiter) Flush(log *slog.Logger, now time.Time, level slog.Level, msg string) {
	n, ok := l.Due(now)
	if !ok || log == nil {
		return
	}
	log.Log(context.Background(), level, Msg(msg, n))
}

// Group rate-limits by message: every distinct msg has its own Limiter.
// Messages must be constant strings (not formatted per occurrence), so the
// number of keys stays bounded. The zero value is ready to use.
type Group struct {
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	m   sync.Map // msg -> *entry
}

type entry struct {
	Limiter
	level atomic.Int64
	log   atomic.Pointer[slog.Logger] // logger of the latest occurrence, for Flush
}

func (g *Group) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Group) entry(msg string) *entry {
	if e, ok := g.m.Load(msg); ok {
		return e.(*entry)
	}
	e, _ := g.m.LoadOrStore(msg, &entry{})
	return e.(*entry)
}

// Log writes msg at level when a line for msg is due. log may be nil.
func (g *Group) Log(log *slog.Logger, level slog.Level, msg string, args ...any) {
	e := g.entry(msg)
	e.level.Store(int64(level))
	if log != nil && e.log.Load() != log {
		e.log.Store(log)
	}
	e.LogAt(log, g.now(), level, msg, args...)
}

// Warn logs msg at warn level when due.
func (g *Group) Warn(log *slog.Logger, msg string, args ...any) {
	g.Log(log, slog.LevelWarn, msg, args...)
}

// Error logs msg at error level when due.
func (g *Group) Error(log *slog.Logger, msg string, args ...any) {
	g.Log(log, slog.LevelError, msg, args...)
}

// Flush reports the suppressed tail of every message whose interval is
// over, through the logger of its latest occurrence.
func (g *Group) Flush() { g.flushAt(g.now()) }

func (g *Group) flushAt(now time.Time) {
	g.m.Range(func(k, v any) bool {
		e := v.(*entry)
		e.Flush(e.log.Load(), now, slog.Level(e.level.Load()), k.(string))
		return true
	})
}

// Run flushes the group every Interval until ctx ends, then reports every
// remaining tail regardless of the interval.
func (g *Group) Run(ctx context.Context) {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			g.flushAt(g.now().Add(Interval))
			return
		case <-t.C:
			g.Flush()
		}
	}
}

// Default is the process-wide group for warnings that have no component of
// their own.
var Default Group

// Warn logs msg at warn level through Default when due.
func Warn(log *slog.Logger, msg string, args ...any) { Default.Warn(log, msg, args...) }

// Error logs msg at error level through Default when due.
func Error(log *slog.Logger, msg string, args ...any) { Default.Error(log, msg, args...) }
