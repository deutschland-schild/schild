package app

import (
	"context"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/jobs"
)

// OncePerPeriod is oncePerPeriod (jobs.go).
func (a *App) OncePerPeriod(ctx context.Context, name string, schedule func() jobs.Schedule, run func(context.Context, *jobs.Run) error) {
	a.oncePerPeriod(ctx, name, schedule, run)
}

// SetJobsClock gives the tasks started from now on another clock and pace,
// and returns how to undo it.
func SetJobsClock(now func() time.Time, look time.Duration) (undo func()) {
	oldNow, oldLook := jobsNow, jobsLook
	jobsNow, jobsLook = now, look
	return func() { jobsNow, jobsLook = oldNow, oldLook }
}

// SetHumanCheckKeysLook changes how often the age of the browser check's
// keys is looked at, and returns how to undo it.
func SetHumanCheckKeysLook(d time.Duration) (undo func()) {
	old := humanCheckKeysLook
	humanCheckKeysLook = d
	return func() { humanCheckKeysLook = old }
}
