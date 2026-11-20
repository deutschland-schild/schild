package app

import (
	"slices"
	"time"

	"github.com/deutschland-schild/schild/contract/firewall"
)

// firewallBlocks are the blocks that run, for `schild firewall run` (D87):
// every client key with its end, the ones ending last left out above
// firewall.MaxBlocks (they still run in schild), sorted by client.
func (a *App) firewallBlocks() []firewall.Block {
	if a.Behaviour == nil {
		return nil
	}
	run := a.Behaviour.RunningBlocks()
	out := make([]firewall.Block, 0, len(run))
	for _, b := range run {
		out = append(out, firewall.Block{Client: firewall.ClientOf(b.Key), Until: b.Until.UTC().Truncate(time.Second), Incident: b.Incident})
	}
	slices.SortFunc(out, func(x, y firewall.Block) int { return x.Until.Compare(y.Until) })
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
