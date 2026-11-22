//go:build !release

package app

import (
	"context"
	"time"
)

// SharedRounds counts the rounds of the loop of the shared things that
// worked (cluster_state.go syncShared).
func (a *App) SharedRounds() int64 { return a.sharedRounds.Load() }

// StateHashesComputed counts how often the fingerprint of the state was
// computed anew (cluster_fingerprint.go stateHashes).
func (a *App) StateHashesComputed() int64 { return a.stateWatch.computed.Load() }

// MetricsAnswerHits counts the answers to members' questions for metric
// buckets that were given from what was kept.
func (a *App) MetricsAnswerHits() int64 {
	if a.groupMetrics == nil {
		return 0
	}
	return a.groupMetrics.answerHits.Load()
}

// SetSharedSafety sets after how long the loop of the shared things works
// although nothing changed, and returns how to undo it.
func SetSharedSafety(d time.Duration) (undo func()) {
	old := sharedSafety
	sharedSafety = d
	return func() { sharedSafety = old }
}

// StateHashes are the hashes of this node's state right now.
func (a *App) StateHashes() map[string]string {
	return a.stateHashes(context.Background(), time.Now())
}
