// Package crawlers applies the crawler policy of each website in the gate
// (D57, MVP-29). The rules are contract/crawlers; this package compiles a
// policy into a table of one byte per catalogue bot id plus the
// impersonator switch, so the request path reads one pointer, one map entry
// and one byte, takes no lock and allocates nothing. It also counts per
// website, bot and outcome what the rules did since the start.
//
// The state lives in schild.db (StoreKey); the app loads it, changes it and
// swaps the compiled tables in with Set.
package crawlers

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	cc "github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
)

// StoreKey is the schild.db row of the policies.
const StoreKey = "crawler_policies_v1"

// Entry is the policy of one website as stored.
type Entry struct {
	Policy     cc.Policy `json:"policy"`
	UpdatedAt  time.Time `json:"updated_at"`
	Actor      string    `json:"actor"` // dashboard | agent
	User       string    `json:"user,omitempty"`
	TokenID    string    `json:"token_id,omitempty"`
	TokenLabel string    `json:"token_label,omitempty"`
}

// State is everything stored: the policies by website id. A State in use is
// never changed; Clone it.
type State struct {
	Entries map[string]*Entry `json:"entries"`
}

// NewState returns an empty state.
func NewState() *State { return &State{Entries: map[string]*Entry{}} }

// Clone copies s deep enough to change entries.
func (s *State) Clone() *State {
	c := &State{Entries: make(map[string]*Entry, len(s.Entries))}
	for k, e := range s.Entries {
		x := *e
		x.Policy = e.Policy.Clone()
		c.Entries[k] = &x
	}
	return c
}

// Rules a table answers.
const (
	RuleNone uint8 = iota
	RuleBot
	RuleCategory
	RuleImpersonator
)

// Outcomes counted per bot.
const (
	OutBlocked = iota
	OutWouldBlock
	nOut
)

// Table is the compiled policy of one website.
type Table struct {
	// act holds per bot id RuleNone, RuleBot or RuleCategory.
	act []uint8
	// imp: impersonators block.
	imp bool
	// ranges: per bot id, its operator publishes ranges (only those can be
	// impersonated).
	ranges []bool
	eng    *bots.Engine
	counts *Counts
}

// Counts are the outcomes of the rules of one website per bot id. They
// outlive a change of the policy.
type Counts struct {
	n [][nOut]atomic.Uint64
}

func newCounts(n int) *Counts { return &Counts{n: make([][nOut]atomic.Uint64, n+1)} }

// Add counts one request of bot id with outcome out (OutBlocked,
// OutWouldBlock). It does not allocate.
func (t *Table) Add(id uint16, out int) {
	if t == nil || int(id) >= len(t.counts.n) || out < 0 || out >= nOut {
		return
	}
	t.counts.n[id][out].Add(1)
}

// Rule returns the rule of t that blocks a request from address a that
// names bot id (0: no catalogue entry). The address is verified only when
// the impersonator rule needs it. Precedence as contract/crawlers.RuleFor:
// impersonator, then the bot, then its category. It does not allocate.
func (t *Table) Rule(id uint16, a netip.Addr) uint8 {
	if t == nil || id == 0 || int(id) >= len(t.act) {
		return RuleNone
	}
	if t.imp && t.ranges[id] && t.eng.Verify(id, a) == bots.VerMismatch {
		return RuleImpersonator
	}
	return t.act[id]
}

// Control holds the compiled tables of every website.
type Control struct {
	eng *bots.Engine
	cur atomic.Pointer[snapshot]

	mu     sync.Mutex
	counts map[string]*Counts
	since  time.Time
	// ua caches the bot id of recent user agents for a gate without a
	// monitor (the monitor has its own cache, shared with the record).
	ua *uaCache
}

// BotID returns the catalogue entry a User-Agent names (0: none) from a
// small cache of recent user agents. It does not allocate.
func (c *Control) BotID(ua string) uint16 { return c.ua.id(ua) }

type snapshot struct {
	state  *State
	tables map[string]*Table // only websites whose policy blocks something
}

// New returns a control without policies for the bot engine e (its ids
// and categories; nil: the shipped catalogue).
func New(e *bots.Engine, now time.Time) *Control {
	if e == nil {
		e = bots.Default()
	}
	c := &Control{eng: e, counts: map[string]*Counts{}, since: now.UTC(), ua: newUACache(e)}
	c.cur.Store(&snapshot{state: NewState(), tables: map[string]*Table{}})
	return c
}

// Since is the start of the counts.
func (c *Control) Since() time.Time { return c.since }

// Engine is the bot engine of the tables.
func (c *Control) Engine() *bots.Engine { return c.eng }

// Known reports whether id is a catalogue bot id.
func (c *Control) Known(id string) bool { return c.eng.ID(id) != 0 }

// State returns the state in force. Do not change it.
func (c *Control) State() *State { return c.cur.Load().state }

// Lookup returns the table of a website, nil when its policy blocks
// nothing (the request goes on unchanged). It does not allocate.
func (c *Control) Lookup(website string) *Table {
	if c == nil {
		return nil
	}
	s := c.cur.Load()
	if len(s.tables) == 0 {
		return nil
	}
	return s.tables[website]
}

// Set compiles s and swaps it in; it is in force for the next request.
// Rules for bot ids the catalogue does not know (a later catalogue dropped
// them) are removed from the state in force and returned, so the stored
// policy can be changed again: the next write stores it without them.
func (c *Control) Set(s *State) (unknown []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, unknown = c.prune(s)
	tables := map[string]*Table{}
	for site, e := range s.Entries {
		t := c.compile(e.Policy)
		if t == nil {
			continue
		}
		t.counts = c.counts[site]
		if t.counts == nil {
			t.counts = newCounts(c.eng.NumBots())
			c.counts[site] = t.counts
		}
		tables[site] = t
	}
	c.cur.Store(&snapshot{state: s, tables: tables})
	return unknown
}

// prune returns s without rules for bot ids the catalogue does not know
// (a copy when there were any) and those ids, sorted.
func (c *Control) prune(s *State) (*State, []string) {
	var unknown []string
	for _, e := range s.Entries {
		for id := range e.Policy.Bots {
			if c.eng.ID(id) == 0 {
				unknown = append(unknown, id)
			}
		}
	}
	if len(unknown) == 0 {
		return s, nil
	}
	s = s.Clone()
	for _, e := range s.Entries {
		for id := range e.Policy.Bots {
			if c.eng.ID(id) == 0 {
				delete(e.Policy.Bots, id)
			}
		}
		e.Policy = e.Policy.Normalize()
	}
	sort.Strings(unknown)
	return s, unknown
}

// compile builds the table of a policy; nil when it blocks nothing.
func (c *Control) compile(p cc.Policy) *Table {
	if !p.Blocks() {
		return nil
	}
	n := c.eng.NumBots()
	t := &Table{act: make([]uint8, n+1), ranges: make([]bool, n+1), imp: p.Impersonators == cc.Block, eng: c.eng}
	blocked := false
	for id := 1; id <= n; id++ {
		b := c.eng.Bot(uint16(id))
		t.ranges[id] = b.Verify.Ranges != ""
		switch {
		case p.Bots[b.ID] == cc.Block:
			t.act[id] = RuleBot
		case p.Bots[b.ID] == cc.Allow:
		case p.Categories[b.Category] == cc.Block:
			t.act[id] = RuleCategory
		}
		blocked = blocked || t.act[id] != RuleNone
	}
	if !blocked && !t.imp {
		return nil
	}
	return t
}

// Entry returns the stored policy of a website, nil without one.
func (c *Control) Entry(website string) *Entry {
	return c.State().Entries[website]
}

// Count is what the rules did with one bot on one website.
type Count struct {
	Bot        uint16
	Blocked    uint64
	WouldBlock uint64
}

// Counts returns the non-zero counts of a website by bot id.
func (c *Control) Counts(website string) []Count {
	c.mu.Lock()
	n := c.counts[website]
	c.mu.Unlock()
	if n == nil {
		return nil
	}
	var out []Count
	for id := range n.n {
		b, w := n.n[id][OutBlocked].Load(), n.n[id][OutWouldBlock].Load()
		if b != 0 || w != 0 {
			out = append(out, Count{Bot: uint16(id), Blocked: b, WouldBlock: w})
		}
	}
	return out
}

// Totals returns the counts of every website summed per bot id (metrics).
func (c *Control) Totals() []Count {
	c.mu.Lock()
	defer c.mu.Unlock()
	sum := map[uint16]*Count{}
	for _, n := range c.counts {
		for id := range n.n {
			b, w := n.n[id][OutBlocked].Load(), n.n[id][OutWouldBlock].Load()
			if b == 0 && w == 0 {
				continue
			}
			x := sum[uint16(id)]
			if x == nil {
				x = &Count{Bot: uint16(id)}
				sum[uint16(id)] = x
			}
			x.Blocked += b
			x.WouldBlock += w
		}
	}
	out := make([]Count, 0, len(sum))
	for _, x := range sum {
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bot < out[j].Bot })
	return out
}
