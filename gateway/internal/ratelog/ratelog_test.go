package ratelog

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func lines(buf *bytes.Buffer) []string {
	s := strings.TrimSpace(buf.String())
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// TestLimiterFirstThenPerInterval: the first occurrence is logged at once,
// later ones inside the interval are counted, and the next line after the
// interval carries the count.
func TestLimiterFirstThenPerInterval(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var l Limiter
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < 1000; i++ {
		l.LogAt(log, t0.Add(time.Duration(i)*time.Millisecond), slog.LevelWarn, "geo download failed", "reason", "x")
	}
	got := lines(&buf)
	if len(got) != 1 || !strings.Contains(got[0], `msg="geo download failed"`) || strings.Contains(got[0], "suppressed") {
		t.Fatalf("first: %q", got)
	}
	l.LogAt(log, t0.Add(Interval), slog.LevelWarn, "geo download failed", "reason", "y")
	got = lines(&buf)
	if len(got) != 2 || !strings.Contains(got[1], `msg="geo download failed (999 suppressed)"`) || !strings.Contains(got[1], "reason=y") {
		t.Fatalf("second: %q", got)
	}
	// Quiet for longer than the interval: the next occurrence is logged
	// without a count.
	l.LogAt(log, t0.Add(3*Interval), slog.LevelWarn, "geo download failed")
	got = lines(&buf)
	if len(got) != 3 || strings.Contains(got[2], "suppressed") {
		t.Fatalf("after quiet: %q", got)
	}
}

// TestLimiterFlush: the tail of a flood is reported by Flush once the
// interval is over, and only then.
func TestLimiterFlush(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var l Limiter
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < 6; i++ {
		l.LogAt(log, t0, slog.LevelWarn, "write events")
	}
	l.Flush(log, t0.Add(time.Second), slog.LevelWarn, "write events")
	if n := len(lines(&buf)); n != 1 {
		t.Fatalf("flush inside the interval logged: %d lines", n)
	}
	l.Flush(log, t0.Add(Interval), slog.LevelWarn, "write events")
	got := lines(&buf)
	if len(got) != 2 || !strings.Contains(got[1], "write events (5 suppressed)") {
		t.Fatalf("flush: %q", got)
	}
	l.Flush(log, t0.Add(5*Interval), slog.LevelWarn, "write events")
	if n := len(lines(&buf)); n != 2 {
		t.Fatalf("flush without occurrences logged: %d lines", n)
	}
}

// TestLogVolumeBounded (D38 section 5): 100k triggers of each of five
// messages over ten minutes write at most first line + one per minute per
// message, and no occurrence goes unreported.
func TestLogVolumeBounded(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	t0 := time.Unix(1_800_000_000, 0)
	now := t0
	g := &Group{Now: func() time.Time { return now }}
	msgs := []string{"incident queue full", "kept behaviour block queue full", "geo download failed", "schild handler panic recovered", "write events"}
	const n = 100_000
	span := 10 * time.Minute
	for i := 0; i < n; i++ {
		now = t0.Add(time.Duration(i) * span / n)
		for _, m := range msgs {
			g.Warn(log, m, "i", i)
		}
	}
	now = t0.Add(span + Interval)
	g.Flush()
	got := lines(&buf)
	limit := len(msgs) * (int(span/Interval) + 2)
	if len(got) > limit {
		t.Fatalf("%d lines for %d triggers, want at most %d", len(got), n*len(msgs), limit)
	}
	if buf.Len() > 64<<10 {
		t.Fatalf("%d bytes of log", buf.Len())
	}
	// Every occurrence is either a line or counted in a line.
	for _, m := range msgs {
		var total int64
		for _, ln := range got {
			if !strings.Contains(ln, `msg="`+m) {
				continue
			}
			total++
			if i := strings.Index(ln, m+" ("); i >= 0 {
				var k int64
				rest := ln[i+len(m)+2:]
				for _, c := range rest {
					if c < '0' || c > '9' {
						break
					}
					k = k*10 + int64(c-'0')
				}
				total += k
			}
		}
		// A flush line reports the tail but is no occurrence itself.
		if total < n || total > n+1 {
			t.Fatalf("%s: %d occurrences reported, want %d", m, total, n)
		}
	}
}

// TestAllowNoAlloc: a suppressed occurrence on the request path does not
// allocate.
func TestAllowNoAlloc(t *testing.T) {
	var l Limiter
	t0 := time.Unix(1_800_000_000, 0)
	l.Allow(t0)
	if a := testing.AllocsPerRun(1000, func() { l.Allow(t0) }); a != 0 {
		t.Fatalf("Allow allocates: %v", a)
	}
}

// TestConcurrent: under contention exactly one line per interval is
// written and the counts add up.
func TestConcurrent(t *testing.T) {
	var l Limiter
	t0 := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	var allowed, reported int64
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10_000; i++ {
				if n, ok := l.Allow(t0); ok {
					mu.Lock()
					allowed++
					reported += n
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if allowed != 1 {
		t.Fatalf("%d lines in one interval", allowed)
	}
	n, ok := l.Allow(t0.Add(Interval))
	if !ok || n+reported != 80_000-1 {
		t.Fatalf("suppressed %d (ok %v), want %d", n, ok, 80_000-1)
	}
}

// TestGroupRunFlushesOnStop: Run reports the remaining tail when ctx ends.
func TestGroupRunFlushesOnStop(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	t0 := time.Unix(1_800_000_000, 0)
	g := &Group{Now: func() time.Time { return t0 }}
	for i := 0; i < 3; i++ {
		g.Error(log, "store incident", "err", "x")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.Run(ctx)
	got := lines(&buf)
	if len(got) != 2 || !strings.Contains(got[1], "level=ERROR") || !strings.Contains(got[1], "store incident (2 suppressed)") {
		t.Fatalf("%q", got)
	}
}
