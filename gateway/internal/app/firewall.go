package app

import (
	"slices"
	"time"

	"github.com/deutschland-schild/schild/contract/firewall"
)

// firewallBlocks are the blocks that run, for `schild firewall run` (D87):
// every client key with its end (excluding own addresses, allowlisted
// addresses and trusted proxies). Above firewall.MaxBlocks the longest-running
// blocks stay in the kernel and the shortest-lived ones are left to schild;
// the final list is sorted by client.
func (a *App) firewallBlocks() []firewall.Block {
	if a.Behaviour == nil {
		return nil
	}
	run := a.Behaviour.RunningBlocks()
	out := make([]firewall.Block, 0, len(run))
	for _, b := range run {
		if a.ownAddress(b.Key.Addr()) {
			continue
		}
		out = append(out, firewall.Block{Client: firewall.ClientOf(b.Key), Until: b.Until.UTC().Truncate(time.Second), Incident: b.Incident})
	}
	slices.SortFunc(out, func(x, y firewall.Block) int {
		if c := y.Until.Compare(x.Until); c != 0 {
			return c
		}
		switch {
		case x.Client < y.Client:
			return -1
		case x.Client > y.Client:
			return 1
		}
		return 0
	})
	out = out[:min(len(out), firewall.MaxBlocks)]
	slices.SortFunc(out, func(x, y firewall.Block) int {
		switch {
		case x.Client < y.Client:
			return -1
		case x.Client > y.Client:
			return 1
		}
		return 0
	})
	return out
}
