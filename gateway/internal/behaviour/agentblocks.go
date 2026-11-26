package behaviour

import (
	"net/netip"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
)

// Blocks set through the agent API (D42). They live in the same table as the
// blocks of the scenarios, so every request meets them in Check, but they stand
// outside the ladder: an agent chooses the duration, and neither setting nor
// lifting one moves the counters or the ladder of a client.

// AgentSource is the prefix of a block an agent set: agent:<token id>. Such a
// block keeps the source in the scenario field of its state.
const AgentSource = "agent:"

// DashboardSource is the source of a block the operator set by hand (D88).
const DashboardSource = "dashboard"

// BlockSource is the decision source of a block with this scenario field.
func BlockSource(scenario string) string {
	if strings.HasPrefix(scenario, AgentSource) || scenario == DashboardSource {
		return scenario
	}
	return "behaviour:" + scenario
}

// IsBlockSource reports whether a decision source of an incident names a
// block: one of a scenario, of an agent or set by hand. The incident of a
// single refused request (a rule, a rate limit, a limit of the gate) has
// no such source, and no block to lift.
func IsBlockSource(source string) bool {
	return strings.HasPrefix(source, "behaviour:") || strings.HasPrefix(source, AgentSource) || source == DashboardSource
}

// AgentBlock is what an agent asks for, after every check. Source set to
// DashboardSource is a block the operator set by hand (D88), without a token.
type AgentBlock struct {
	IP       netip.Addr
	TokenID  string
	Source   string
	NetClass string
	Duration time.Duration
	Incident string
	EventID  string
	Time     time.Time
}

// SetAgentBlock starts the block before it returns. created is false when a
// block of this client key runs already: that one stands, its end does not
// move.
func (e *Engine) SetAgentBlock(a AgentBlock) (info BlockInfo, created bool) {
	key, bits := KeyOf(a.IP)
	if !key.IsValid() {
		return BlockInfo{}, false
	}
	now := a.Time.UnixNano()
	until := a.Time.Truncate(time.Second).Add(a.Duration)
	scenario := AgentSource + a.TokenID
	if a.Source != "" {
		scenario = a.Source
	}
	persist := a.Duration > PersistOver
	e.blocks.with(key, true, func(b *blockState) {
		if b.until > now {
			return
		}
		*b = blockState{until: until.UnixNano(), lastUntil: b.lastUntil, level: 1, ladder: b.ladderLevel(), scenario: scenario, incident: a.Incident,
			eventID: a.EventID, started: now, netClass: a.NetClass, persisted: persist}
		created = true
	})
	if !created {
		info, _ = e.ActiveBlock(a.IP)
		return info, false
	}
	if persist {
		e.keepLong(key, events.ActiveBlock{ClientKey: key.Addr().String(), KeyBits: bits, NetClass: a.NetClass, Source: scenario, Level: 1,
			DurationS: int(a.Duration / time.Second), Since: a.Time.UTC().Truncate(time.Second).Format(time.RFC3339), Until: until.UTC().Format("2006-01-02T15:04:05Z"),
			Incident: a.Incident}, a.EventID, false)
	}
	return BlockInfo{Scenario: scenario, Since: a.Time.UTC(), Until: until.UTC(), Level: 1, Incident: a.Incident, EventID: a.EventID, NetClass: a.NetClass,
		Duration: a.Duration, Persisted: persist}, true
}

// ladderLevel is the step of the ladder this client stands on: an agent block
// and a block by hand (D88) show level 1 and keep the step they replaced.
func (b *blockState) ladderLevel() int {
	if strings.HasPrefix(b.scenario, AgentSource) || b.scenario == DashboardSource {
		return b.ladder
	}
	return b.level
}

// IncidentRunning reports whether the block of an incident runs. The stored
// address is not needed: retention may have shortened it, the block still runs.
func (e *Engine) IncidentRunning(incident string) bool {
	if incident == "" {
		return false
	}
	now := e.now().UnixNano()
	running := false
	e.blocks.sweep(func(_ Key, b *blockState) bool {
		running = running || (b.incident == incident && b.until > now)
		return false
	})
	return running || e.longKey(incident, now).IsValid()
}

// longKey is the client key of the kept block of an incident that runs.
func (e *Engine) longKey(incident string, now int64) Key {
	if e.long.n.Load() == 0 {
		return Key{}
	}
	e.long.mu.Lock()
	defer e.long.mu.Unlock()
	for k, v := range e.long.m {
		if v.ab.Incident == incident && v.until > now {
			return k
		}
	}
	return Key{}
}

// LiftIncident ends the running block of an incident and nothing else: no
// exception, and counters, buckets, ladder and release time stay, unlike
// Release. It reports whether a block ended.
func (e *Engine) LiftIncident(incident string) bool {
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
	if ended {
		e.reportEnded(now, incident)
	}
	return ended
}

// IncidentKey is the client key of the running block of an incident.
func (e *Engine) IncidentKey(incident string) (Key, bool) {
	if incident == "" {
		return Key{}, false
	}
	now := e.now().UnixNano()
	var key Key
	e.blocks.sweep(func(k Key, b *blockState) bool {
		if b.incident == incident && b.until > now {
			key = k
		}
		return false
	})
	if !key.IsValid() {
		key = e.longKey(incident, now)
	}
	return key, key.IsValid()
}

// AgentBlocks counts the agent blocks that run now.
func (e *Engine) AgentBlocks() int {
	now := e.now().UnixNano()
	seen := map[Key]bool{}
	e.blocks.sweep(func(k Key, b *blockState) bool {
		if b.until > now && strings.HasPrefix(b.scenario, AgentSource) {
			seen[k] = true
		}
		return false
	})
	if e.long.n.Load() > 0 {
		e.long.mu.Lock()
		for k, v := range e.long.m {
			if v.until > now && strings.HasPrefix(v.ab.Source, AgentSource) {
				seen[k] = true
			}
		}
		e.long.mu.Unlock()
	}
	return len(seen)
}

// validKept reports whether the duration of a kept row fits its source: the
// step of the ladder, for an agent block anything up to the cap of the net
// class, for a block by hand (D88) up to 7 days, at level 1.
func validKept(ab events.ActiveBlock) bool {
	if ab.Source == DashboardSource {
		return ab.Level == 1 && ab.DurationS <= events.MaxBlockHostingS
	}
	if strings.HasPrefix(ab.Source, AgentSource) {
		limit := events.MaxBlockDefaultS
		if ab.NetClass == "hosting" {
			limit = events.MaxBlockHostingS
		}
		return ab.Level == 1 && ab.DurationS <= limit
	}
	return ab.DurationS == events.BlockDurationS(ab.NetClass, ab.Level)
}
