package app

import (
	"context"
	"time"
)

// A node whose clock is more than a minute off the group's does harm while
// it serves: the others put off its blocks, lifts, logins and erasures (a
// record more than 60 s ahead is not taken), never store its requests, or,
// when it is behind, it holds nothing the others write. Every gateway knows
// how far the clock of each member it reaches is off its own
// (cluster_status.go). When a node can know that it is the odd one, it
// takes itself out of traffic until its clock is right (MVP-27, D103).
//
// It can know with two other gateways in reach whose clocks agree with each
// other and differ from its own by a minute or more. With one other gateway
// nobody can tell whose clock is wrong: both serve on, and the dashboard
// names the difference. If the members in reach do not agree among
// themselves, nobody leaves either, so the rule never takes every node of a
// group out at once: of nodes that leave, each saw at least two that agree,
// and those two see each other as right.

const (
	// clockAgree: clocks within this of each other count as the same.
	clockAgree = 5 * time.Second
	// clockOff is the difference from which a node leaves traffic: the
	// bound of the roster for a record's time (contract/cluster, 60 s).
	clockOff = 60 * time.Second
	// clockSkewFresh: how old the word of a member about its clock may be.
	// A member tells every five seconds.
	clockSkewFresh = 20 * time.Second
	// clockLook: how often the node looks.
	clockLook = 2 * time.Second
)

// clockOdd reports whether a node is the one whose clock is wrong: skews are
// the clocks of the gateways it reaches minus its own.
func clockOdd(skews []time.Duration) bool {
	if len(skews) < 2 {
		return false
	}
	lo, hi := skews[0], skews[0]
	for _, s := range skews[1:] {
		lo, hi = min(lo, s), max(hi, s)
	}
	if hi-lo > clockAgree {
		return false // they do not agree among themselves
	}
	return lo >= clockOff || hi <= -clockOff
}

// reachedClocks are the clock differences of the gateways this node reaches
// and heard of lately.
func (a *App) reachedClocks(now time.Time) []time.Duration {
	if f := a.testClocks.Load(); f != nil {
		return (*f)()
	}
	node := a.Cluster
	if node == nil {
		return nil
	}
	reach := node.Reachable()
	a.groupVersions.mu.Lock()
	defer a.groupVersions.mu.Unlock()
	var out []time.Duration
	for _, id := range reach {
		if v, ok := a.groupVersions.told[id]; ok && v.hasSkew && now.Sub(v.at) < clockSkewFresh {
			out = append(out, v.skew)
		}
	}
	return out
}

// startClockWatch takes the node out of traffic while its clock is the odd
// one (inService reads clockOut), says so in the log and notes it for
// `schild cluster status`.
func (a *App) startClockWatch(ctx context.Context) {
	var noted time.Time
	a.goLoop(ctx, "cluster-clock", tick(clockLook, func() {
		node := a.Cluster
		if node == nil || node.Removed() || node.Paused() {
			a.clockOut.Store(false)
			return
		}
		now := time.Now()
		skews := a.reachedClocks(now)
		odd := clockOdd(skews)
		was := a.clockOut.Swap(odd)
		switch {
		case odd && !was:
			a.log.Error("cluster: the clock of this node is a minute or more off the clocks of the other gateways, which agree with each other: it leaves traffic until its clock is right (set it by NTP)",
				"difference", (-skews[0]).Round(time.Second).String(), "gateways", len(skews))
		case !odd && was:
			a.log.Info("cluster: the clock of this node agrees with the group again, it takes traffic")
		}
		// Noted while it lasts, and once when it ends.
		if odd != was || (odd && now.Sub(noted) > time.Minute) {
			noted = now
			_ = node.NoteClockOut(odd)
		}
	}))
}
