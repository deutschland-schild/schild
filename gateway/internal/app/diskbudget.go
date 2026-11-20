package app

import (
	"context"
	"time"

	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/gateway/internal/diskbudget"
)

// StorageBudget returns the last disk budget check (D38; nil before the
// first one).
func (a *App) StorageBudget() *diskbudget.Figures { return a.budget.Load() }

// checkStorageBudget compares the bounds with the file system of
// storage.path and hands the storage_budget hint to the monitor (at start
// and once an hour). `schild run` refused to start before when the budget
// exceeds the file system; a verdict change is logged once.
func (a *App) checkStorageBudget() {
	n := 0
	if a.Sites != nil {
		if v := a.Sites.View(); v != nil {
			n = len(v.Websites())
		}
	}
	f, err := diskbudget.Check(a.Config(), a.dataDir, n)
	if err != nil {
		a.log.Warn("storage budget not checked", "err", err)
		return
	}
	prev := a.budget.Swap(&f)
	a.Monitor.SetStorageBudget(f.Hint())
	if prev != nil && prev.Verdict == f.Verdict {
		return
	}
	args := []any{"path", f.Path, "budget", diskbudget.MiB(f.BudgetBytes), "used", diskbudget.MiB(f.UsedBytes),
		"available", diskbudget.MiB(f.AvailBytes), "total", diskbudget.MiB(f.TotalBytes), "reserve", diskbudget.MiB(f.ReserveBytes)}
	switch f.Verdict {
	case storage.BudgetOK:
		a.log.Info("storage budget fits", args...)
	case storage.BudgetHint:
		a.log.Warn("storage budget: filling schild's bounds would leave less than the reserve available (hint storage_budget)", args...)
	default:
		a.log.Warn("storage budget exceeds the file system", append(args, "err", f.Err())...)
	}
}

// storageBudgetLoop checks the budget at start and once an hour.
func (a *App) storageBudgetLoop(ctx context.Context) {
	a.checkStorageBudget()
	every(ctx, time.Hour, a.checkStorageBudget)
}
