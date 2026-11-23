package app

import (
	"context"
	"slices"
	"time"
)

// A node whose clock is more than a minute off the group's does harm while
// it serves: the others put off its blocks, lifts, logins and erasures (a
// record more than 60 s ahead is not taken), never store its requests, or,
// when it is behind, it holds nothing the others write. Every gateway knows
// how far the clock of each member it reaches is off its own
// (cluster_status.go). When a node can know that it is the odd one, it
// takes itself out of traffic until its clock is right (MVP-27, D105).
//
// It can know when most of the gateways in its view agree with each other
// and differ from it by a minute or more: the largest group of gateways in
// reach whose clocks lie within clockAgree of each other has at least two
// members and is more than half of the gateways in view, this node counted
// (so more than half of the group in a full mesh), and this node's clock is
// clockOff or more on the same side of every one of them. With one other
// gateway nobody can tell whose clock is wrong: both serve on, and the
// dashboard names the difference. Two against two is no majority either.
// So the rule never takes every node of a group out at once: a node that
// leaves saw a majority that agrees, two majorities of one view share a
// member, and the members of a majority see each other as right.

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
	_, odd := clockMajority(skews)
	return odd
}

// clockMajority finds the largest group of skews within clockAgree of each
// other (sorted, a sliding window) and reports whether this node is odd by
// it; group is that window, for the log.
func clockMajority(skews []time.Duration) (group []time.Duration, odd bool) {
	if len(skews) < 2 {
		return nil, false
	}
	s := slices.Clone(skews)
	slices.Sort(s)
	best, bestLo := 0, 0
	lo := 0
	for hi := range s {
		for s[hi]-s[lo] > clockAgree {
			lo++
		}
		if n := hi - lo + 1; n > best {
			best, bestLo = n, lo
		}
	}
	group = s[bestLo : bestLo+best]
	// A strict majority of the gateways in view, this node among them.
	if best < 2 || 2*best <= len(s)+1 {
		return group, false
	}
	first, last := group[0], group[len(group)-1]
	return group, first >= clockOff || last <= -clockOff
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
		if node == nil || node.Removed() {
			a.clockOut.Store(false)
			return
		}
		now := time.Now()
		skews := a.reachedClocks(now)
		group, odd := clockMajority(skews)
		was := a.clockOut.Swap(odd)
		switch {
		case odd && !was:
			a.log.Error("cluster: the clock of this node is a minute or more off the clocks of most other gateways, which agree with each other: it leaves traffic until its clock is right (set it by NTP)",
				"difference", (-group[len(group)/2]).Round(time.Second).String(), "agree", len(group), "gateways", len(skews))
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
