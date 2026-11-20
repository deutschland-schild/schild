package app

import (
	"context"
	"os"

	"github.com/deutschland-schild/schild/contract/rules"
)

// ReloadOnSignal syncs rules.d on every signal of c (SIGHUP, D46). Signals
// that arrive during a sync wait in the buffer of c, so a burst costs one
// more build at most.
func (a *App) ReloadOnSignal(ctx context.Context, c <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c:
			// The result is logged, counted and an event: nobody is there to
			// read an error.
			_, _ = a.Repos.Sync(ctx, rules.RepoLocal)
		}
	}
}
