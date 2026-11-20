package app

import (
	"slices"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/firewall"
)

// firewallBlocks are the blocks that run, for `schild firewall run` (D87):
// every client key with its end, sorted by client. Keys that share an address
// with the allowlist, a trusted proxy or this host are left out: the firewall
// drops before schild is asked, so there the allowlist could not win (D42).
// Above firewall.MaxBlocks the ones ending last are left out (they still run
// in schild); among blocks with the same end the client decides, so the cut
// and with it the revision are the same at every call.
func (a *App) firewallBlocks() []firewall.Block {
	if a.Behaviour == nil {
		return nil
	}
	run := a.Behaviour.RunningBlocks()
	own := a.ownFilter()
	out := make([]firewall.Block, 0, len(run))
	for _, b := range run {
		if own(b.Key) {
			continue
		}
		out = append(out, firewall.Block{Client: firewall.ClientOf(b.Key), Until: b.Until.UTC().Truncate(time.Second), Incident: b.Incident})
	}
	byClient := func(x, y firewall.Block) int { return strings.Compare(x.Client, y.Client) }
	if len(out) > firewall.MaxBlocks {
		slices.SortFunc(out, func(x, y firewall.Block) int {
			if c := x.Until.Compare(y.Until); c != 0 {
				return c
			}
			return byClient(x, y)
		})
		out = out[:firewall.MaxBlocks]
	}
	slices.SortFunc(out, byClient)
	return out
}
