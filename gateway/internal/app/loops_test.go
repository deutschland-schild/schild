package app

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// A panic in a background loop is logged and the loop starts again; it never
// ends the process, and Run's wait for the loops still ends with ctx.
func TestLoopPanicRestarts(t *testing.T) {
	old := loopRestart
	loopRestart = time.Millisecond
	t.Cleanup(func() { loopRestart = old })
	a := &App{log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	var runs atomic.Int32
	a.goLoop(ctx, "test", func(ctx context.Context) {
		if runs.Add(1) < 3 {
			panic("parser bug")
		}
		<-ctx.Done()
	})
	deadline := time.Now().Add(5 * time.Second)
	for runs.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := runs.Load(); n != 3 {
		t.Fatalf("loop ran %d times, want 3 (two panics, then running)", n)
	}
	if a.waitLoops(50 * time.Millisecond) {
		t.Fatal("waitLoops returned while the loop still runs")
	}
	cancel()
	if !a.waitLoops(5 * time.Second) {
		t.Fatal("loop did not end with its context")
	}
}

// A loop that panics while ctx ends does not start again.
func TestLoopNoRestartAfterCancel(t *testing.T) {
	old := loopRestart
	loopRestart = time.Hour
	t.Cleanup(func() { loopRestart = old })
	a := &App{log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	a.goLoop(ctx, "test", func(context.Context) {
		cancel()
		panic("during shutdown")
	})
	if !a.waitLoops(5 * time.Second) {
		t.Fatal("loop waited for its restart after the context ended")
	}
}
