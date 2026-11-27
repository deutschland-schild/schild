package behaviour

import (
	"slices"
	"strings"
	"time"
)

// RunningBlock is one address block that runs (D87): the list of the
// dashboard and the handoff to the host's firewall.
type RunningBlock struct {
	Key Key
	BlockInfo
}

// RunningBlocks returns every block that runs at the engine's now, from the
// block table and the kept blocks over 24 h, newest first.
func (e *Engine) RunningBlocks() []RunningBlock {
	now := e.now().UnixNano()
	seen := map[Key]bool{}
	var out []RunningBlock
	e.blocks.sweep(func(k Key, b *blockState) bool {
		if b.until > now {
			st := time.Unix(0, b.started).UTC()
			out = append(out, RunningBlock{Key: k, BlockInfo: BlockInfo{Scenario: b.scenario, Since: st, Until: time.Unix(0, b.until).UTC(), Level: b.level,
				Incident: b.incident, EventID: b.eventID, NetClass: b.netClass, Duration: time.Unix(0, b.until).Sub(st.Truncate(time.Second)), Persisted: b.persisted, Taken: b.taken}})
			seen[k] = true
		}
		return false
	})
	if e.long.n.Load() > 0 {
		e.long.mu.Lock()
		for k, lb := range e.long.m {
			if seen[k] || lb.until <= now {
				continue
			}
			st, _ := time.Parse(time.RFC3339, lb.ab.Since)
			out = append(out, RunningBlock{Key: k, BlockInfo: BlockInfo{Scenario: strings.TrimPrefix(lb.ab.Source, "behaviour:"), Since: st, Until: time.Unix(0, lb.until).UTC(),
				Level: lb.ab.Level, Incident: lb.ab.Incident, EventID: lb.eventID, NetClass: lb.ab.NetClass, Duration: time.Duration(lb.ab.DurationS) * time.Second, Persisted: true, Taken: lb.taken}})
		}
		e.long.mu.Unlock()
	}
	slices.SortFunc(out, func(a, b RunningBlock) int {
		if c := b.Since.Compare(a.Since); c != 0 {
			return c
		}
		return strings.Compare(a.Key.String(), b.Key.String())
	})
	return out
}
