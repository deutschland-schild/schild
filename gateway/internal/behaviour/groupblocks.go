package behaviour

import (
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
)

// ApplyBlock starts a block from a record of the group (MVP-27, D105): the
// same client key, source, step, incident and end, so the block page shows
// the incident number of the node that decided, and the block ends on every
// node at the same second. Nothing is counted and no event or incident is
// written: the deciding node did that. bi.Taken says whether another node
// decided it; it stays with the block, also over a restart.
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
			started: bi.Since.UnixNano(), netClass: bi.NetClass, persisted: persist, taken: bi.Taken}
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
			Incident: bi.Incident}, bi.EventID, bi.Taken)
	}
	return created
}

// BlockRoom returns a look at the block table for one round of starts:
// whether a block of a client can start without dropping a block that runs.
// A node of a group asks before it starts a block it holds a record of and
// does not run: with a full table it would drop another block for each it
// starts, round after round. A part of the table found full is not looked
// through again by the same look.
func (e *Engine) BlockRoom() func(Key) bool {
	var full [shards]bool
	now := e.now().UnixNano()
	return func(key Key) bool {
		part := e.blocks.hash(key) % shards
		if full[part] {
			has := false
			e.blocks.with(key, false, func(b *blockState) { has = b != nil })
			return has
		}
		ok := e.blocks.room(key, func(b *blockState) bool { return b.until <= now })
		full[part] = !ok
		return ok
	}
}

// DropIncident ends the running block of an incident and removes its kept
// row, and reports nothing (no Sink.Ended): the block is not lifted, this
// node only must not run it. It reports whether a block ended.
func (e *Engine) DropIncident(incident string) bool {
	if incident == "" {
		return false
	}
	now := e.now().UnixNano()
	ended := false
	e.blocks.sweep(func(_ Key, b *blockState) bool {
		if b.incident == incident && b.until > now {
			b.until = now
			ended = true
		}
		return false
	})
	if k := e.longKey(incident, now); k.IsValid() {
		e.dropLong(k)
		ended = true
	}
	return ended
}

// KnownIncidents sets what a node of a group asks before it gives a block
// an incident number: whether it holds an incident, a block record or a
// lift of that number already (contracts/cluster.md, incident_blocks).
func (e *Engine) KnownIncidents(known func(incident string) bool) { e.known.Store(&known) }

// DrawIncidents replaces the generator of incident numbers (tests).
func (e *Engine) DrawIncidents(draw func() string) { e.draw.Store(&draw) }

// incidentDraws bounds the draws of one number. A number is 40 random bits;
// a second one that is known too means the generator is broken, and the
// block is not held up for it.
const incidentDraws = 8

// NewIncident draws the incident number of a new block. On a node of a
// group a number the node knows already is drawn again: in the group the
// number is the identity of the block (D109).
func (e *Engine) NewIncident() string {
	draw := events.NewIncident
	if f := e.draw.Load(); f != nil {
		draw = *f
	}
	id := draw()
	if known := e.known.Load(); known != nil {
		for i := 1; i < incidentDraws && (*known)(id); i++ {
			id = draw()
		}
	}
	return id
}
