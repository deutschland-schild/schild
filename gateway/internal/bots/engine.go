package bots

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/gateway/internal/bots/rangesrc"
)

// catalogueJSON is the catalogue shipped with this release, written by
// `make bot-snapshot` (internal/bots/gen) and checked in.
//
//go:embed catalogue.json
var catalogueJSON []byte

// Category indices into contract/monitoring BotCategories of the two
// categories of user agents no entry matches.
var (
	CategoryLikelyAutomated = indexOf(cm.BotCategories, cm.CategoryLikelyAutomated)
	CategoryLikelyBrowser   = indexOf(cm.BotCategories, cm.CategoryLikelyBrowser)
)

// MaxUABytes: only this prefix of a User-Agent is matched (contract).
const MaxUABytes = bots.MaxUABytes

// Verification states returned by Verify: 0 is "not a bot", 1..4 are
// index+1 into contract/bots Verifications.
const (
	VerNone uint8 = iota
	VerVerified
	VerClaimed
	VerMismatch
	VerUnknownStale
)

// VerificationName returns the contract name of a Verify state ("" for
// VerNone).
func VerificationName(v uint8) string {
	if v == VerNone || int(v) > len(bots.Verifications) {
		return ""
	}
	return bots.Verifications[v-1]
}

// Engine matches user agents to the catalogue and verifies addresses. It is
// safe for concurrent use; MatchUA, MatchLower and Verify do not allocate.
type Engine struct {
	cat   *bots.Catalogue
	m     *matcher
	cats  []uint8    // bot id -> category index
	set   []int16    // bot id -> range set index (-1 none)
	rdns  [][]string // bot id -> lower-case rdns suffixes
	ids   map[string]uint16
	now   func() time.Time
	opt   bots.Options
	fetch bool

	state atomic.Pointer[rangeState]
	fc    *fcrdns // nil unless bots.verify.fcrdns

	// Optional range fetch (bots.ranges_fetch); tests replace them.
	client  *http.Client
	sources []rangesrc.Source
	every   time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New loads the catalogue shipped in the binary. It does no I/O; Start
// runs the optional FCrDNS worker and range fetch.
func New(cfg config.Bots, now func() time.Time) (*Engine, error) {
	c, err := bots.Parse(catalogueJSON)
	if err != nil {
		return nil, fmt.Errorf("bot catalogue: %w", err)
	}
	return newEngine(c, cfg, now)
}

var (
	defaultOnce sync.Once
	defaultEng  *Engine
)

// Default is an engine with the shipped catalogue, ranges on, FCrDNS and
// fetch off (it is shared and never fetches, unlike the default config). Bot ids are the same in every engine
// built from the shipped catalogue. It panics if the shipped catalogue
// does not load (a build error the package tests catch).
func Default() *Engine {
	defaultOnce.Do(func() {
		off := false
		e, err := New(config.Bots{RangesFetch: &off}, time.Now)
		if err != nil {
			panic(err)
		}
		defaultEng = e
	})
	return defaultEng
}

// NewFromCatalogue builds an engine for a checked catalogue (tests and
// tools; the gateway uses New).
func NewFromCatalogue(c *bots.Catalogue, cfg config.Bots, now func() time.Time) (*Engine, error) {
	return newEngine(c, cfg, now)
}

func newEngine(c *bots.Catalogue, cfg config.Bots, now func() time.Time) (*Engine, error) {
	if now == nil {
		now = time.Now
	}
	if len(c.Bots) > 1<<15 {
		return nil, fmt.Errorf("bot catalogue: %d bots", len(c.Bots))
	}
	e := &Engine{cat: c, m: newMatcher(c), now: now, ids: map[string]uint16{},
		opt:   bots.Options{Ranges: cfg.RangesOn(), FCrDNS: cfg.FCrDNSOn()},
		fetch: cfg.FetchOn(), sources: rangesrc.Sources, every: 24 * time.Hour, client: rangesrc.HTTPClient(30 * time.Second)}
	setIdx := map[string]int{}
	st := &rangeState{}
	for i := range c.Ranges {
		t, err := buildTable(&c.Ranges[i], "release")
		if err != nil {
			return nil, err
		}
		setIdx[c.Ranges[i].ID] = i
		st.sets = append(st.sets, t)
	}
	e.state.Store(st)
	e.cats = make([]uint8, len(c.Bots)+1)
	e.set = make([]int16, len(c.Bots)+1)
	e.rdns = make([][]string, len(c.Bots)+1)
	e.set[0] = -1
	for i := range c.Bots {
		b := &c.Bots[i]
		id := i + 1
		ci := indexOf(cm.BotCategories, b.Category)
		if ci < 0 {
			return nil, fmt.Errorf("bot %s: category %s", b.ID, b.Category)
		}
		e.cats[id] = uint8(ci)
		e.set[id] = -1
		if s, ok := setIdx[b.Verify.Ranges]; ok && b.Verify.Ranges != "" {
			e.set[id] = int16(s)
		}
		for _, s := range b.Verify.RDNSSuffixes {
			e.rdns[id] = append(e.rdns[id], strings.Map(lowerASCII, s))
		}
		e.ids[b.ID] = uint16(id)
	}
	if e.opt.FCrDNS {
		e.fc = newFCrDNS(now)
	}
	return e, nil
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return -1
}

// Verify checks the client address of a request whose User-Agent named
// bot id (contract/bots VerifyAddr). With FCrDNS on, only a cached answer
// is used; a missing one is queued for the background worker and the
// result is what the ranges say. It does not allocate.
func (e *Engine) Verify(id uint16, a netip.Addr) uint8 {
	if id == 0 || int(id) >= len(e.cats) {
		return VerNone
	}
	a = a.Unmap()
	fc := 0 // 1 match, 2 nomatch
	if e.fc != nil && len(e.rdns[id]) > 0 && a.IsValid() {
		fc = e.fc.check(a, e.rdns[id])
	}
	rg := 0 // 1 in, 2 out, 3 stale
	if si := e.set[id]; e.opt.Ranges && si >= 0 {
		t := &e.state.Load().sets[si]
		switch {
		case e.now().Sub(t.fetched) > bots.StaleAfter:
			rg = 3
		case t.contains(a):
			rg = 1
		default:
			rg = 2
		}
	}
	switch {
	case fc == 1 || rg == 1:
		return VerVerified
	case fc == 2 || rg == 2:
		return VerMismatch
	case rg == 3:
		return VerUnknownStale
	}
	return VerClaimed
}

// Bot returns the catalogue entry of an id (nil for 0 or unknown).
func (e *Engine) Bot(id uint16) *bots.Bot {
	if id == 0 || int(id) > len(e.cat.Bots) {
		return nil
	}
	return &e.cat.Bots[id-1]
}

// ID returns the id of a catalogue entry by its catalogue id (0: unknown).
func (e *Engine) ID(botID string) uint16 { return e.ids[botID] }

// Category returns the category index of a bot id (contract/monitoring
// BotCategories), -1 for 0 or unknown.
func (e *Engine) Category(id uint16) int {
	if id == 0 || int(id) >= len(e.cats) {
		return -1
	}
	return int(e.cats[id])
}

// NumBots is the number of catalogue entries; ids are 1..NumBots.
func (e *Engine) NumBots() int { return len(e.cat.Bots) }

// CatalogueVersion is the version of the catalogue in use.
func (e *Engine) CatalogueVersion() string { return e.cat.Version }

// Catalogue returns the catalogue (read only).
func (e *Engine) Catalogue() *bots.Catalogue { return e.cat }

// Ranges describes the range snapshots in use at now.
func (e *Engine) Ranges() []requests.RangeInfo {
	now := e.now()
	st := e.state.Load()
	out := make([]requests.RangeInfo, 0, len(st.sets))
	for i := range st.sets {
		out = append(out, st.sets[i].info(now))
	}
	return out
}

// Settings are the bots switches as running.
func (e *Engine) Settings() requests.VerificationSettings {
	return requests.VerificationSettings{Ranges: e.opt.Ranges, FCrDNS: e.opt.FCrDNS, RangesFetch: e.fetch}
}

// Start runs the background parts that are switched on: the FCrDNS worker
// (bots.verify.fcrdns) and the daily range fetch (bots.ranges_fetch). With
// both off it starts nothing.
func (e *Engine) Start(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil || (e.fc == nil && !e.fetch) {
		return
	}
	ctx, e.cancel = context.WithCancel(ctx)
	if e.fc != nil {
		e.wg.Add(1)
		go func() { defer e.wg.Done(); e.fc.run(ctx) }()
	}
	if e.fetch {
		e.wg.Add(1)
		go func() { defer e.wg.Done(); e.fetchLoop(ctx) }()
	}
}

// Close stops what Start started and waits for it.
func (e *Engine) Close() {
	e.mu.Lock()
	c := e.cancel
	e.mu.Unlock()
	if c != nil {
		c()
	}
	e.wg.Wait()
}
