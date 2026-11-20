package app

import (
	"context"
	"runtime/debug"
	"time"
)

// loopRestart is the pause before a crashed background loop starts again (a
// variable for tests).
var loopRestart = time.Minute

// goLoop runs a background loop in its own goroutine until ctx ends. A panic
// in it is logged with its stack and the loop starts again after loopRestart:
// rule updates, geo downloads and retention read data from outside, and none
// of them may take the proxy down, nor stop for good without a trace. Run
// waits for every loop before it closes the stores.
func (a *App) goLoop(ctx context.Context, name string, f func(context.Context)) {
	a.loops.Add(1)
	go func() {
		defer a.loops.Done()
		for a.runLoop(ctx, name, f) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(loopRestart):
			}
		}
	}()
}

// runLoop runs f once and reports whether it panicked.
func (a *App) runLoop(ctx context.Context, name string, f func(context.Context)) (panicked bool) {
	defer func() {
		if p := recover(); p != nil {
			panicked = true
			a.log.Error("background loop crashed, starts again in a minute (request handling is not affected)",
				"loop", name, "panic", p, "stack", string(debug.Stack()))
		}
	}()
	f(ctx)
	return false
}

// waitLoops waits until every loop of goLoop returned, at most d; it reports
// whether they all did.
func (a *App) waitLoops(d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		a.loops.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// tick adapts a periodic function to goLoop: f every d until ctx ends.
func tick(d time.Duration, f func()) func(context.Context) {
	return func(ctx context.Context) { every(ctx, d, f) }
}
