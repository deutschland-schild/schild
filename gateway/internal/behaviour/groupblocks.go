package behaviour

import (
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
)

// ApplyBlock starts a block another node of the group decided (MVP-27,
// D103): the same client key, source, step, incident and end, so the block
// page shows the incident number of the node that decided, and the block
// ends on every node at the same second. Nothing is counted and no event or
// incident is written: the deciding node did that.
//
// It reports false, and changes nothing, when the block ended or a block of
// this client key runs already; that one stands, as with SetAgentBlock.
func (e *Engine) ApplyBlock(key Key, bits int, bi BlockInfo) bool {
	now := e.now().UnixNano()
	until := bi.Until.UnixNano()
	if !key.IsValid() || until <= now || bi.Level < 1 {
		return false
	}
	offLadder := strings.HasPrefix(bi.Scenario, AgentSource) || bi.Scenario == DashboardSource
	persist := bi.Duration > PersistOver
	created := false
	e.blocks.with(key, true, func(b *blockState) {
		if b.until > now {
			return
		}
		next := blockState{until: until, lastUntil: until, level: bi.Level, scenario: bi.Scenario, incident: bi.Incident, eventID: bi.EventID,
			started: bi.Since.UnixNano(), netClass: bi.NetClass, persisted: persist}
		if offLadder {
			// As SetAgentBlock: the ladder of the client stays where it was.
			next.lastUntil, next.ladder = b.lastUntil, b.ladderLevel()
		}
		*b = next
		created = true
	})
	if created && persist {
		e.keepLong(key, events.ActiveBlock{ClientKey: key.Addr().String(), KeyBits: bits, NetClass: bi.NetClass, Source: BlockSource(bi.Scenario), Level: bi.Level,
			DurationS: int(bi.Duration / time.Second), Since: bi.Since.UTC().Truncate(time.Second).Format(time.RFC3339), Until: bi.Until.UTC().Format("2006-01-02T15:04:05Z"),
			Incident: bi.Incident}, bi.EventID)
	}
	return created
}
