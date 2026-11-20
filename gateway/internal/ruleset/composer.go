package ruleset

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// Id ranges of the repositories (D73). local takes everything else.
const (
	crsMin, crsMax         = 900000, 999999
	builtinMin, builtinMax = 200000, 200099 // the engine's own rules, part of crs
)

// ErrIDRange: a rule has an id outside the range of its repository.
var ErrIDRange = errors.New("ruleset: rule id outside the range of its repository")

// ErrBusy: the other repositories kept changing the WAF while a build ran.
var ErrBusy = errors.New("ruleset: other rule changes kept running, try again")

// rangeOf names the repository that owns id, "" for local.
func rangeOf(id int) string {
	switch {
	case id >= crsMin && id <= crsMax, id >= builtinMin && id <= builtinMax:
		return "crs"
	case id >= contract.HubRuleIDMin && id <= contract.HubRuleIDMax:
		return "crowdsec"
	case id >= agentapi.ExceptionIDMin && id <= agentapi.ExceptionIDMax:
		return "agent exceptions"
	case id >= waf.NetworkMin && id <= waf.NetworkMax:
		return "the Schild network (reserved)"
	}
	return ""
}

// CheckRanges checks that every repository keeps to its id range: local
// rules outside the others, agent exceptions in theirs, crowdsec rules in
// theirs. The CRS brings its own ids.
func CheckRanges(cfg waf.Config) error {
	for id := range waf.LocalRuleKinds(cfg.LocalRules) {
		if owner := rangeOf(id); owner != "" {
			return fmt.Errorf("%w: local rule %d is in the range of %s", ErrIDRange, id, owner)
		}
	}
	for id := range waf.LocalRuleKinds(cfg.Exceptions) {
		if id < agentapi.ExceptionIDMin || id > agentapi.ExceptionIDMax {
			return fmt.Errorf("%w: agent exception %d", ErrIDRange, id)
		}
	}
	for i := range cfg.Hub {
		r := &cfg.Hub[i]
		for g := range r.Groups {
			if id := r.BaseID + g; id < contract.HubRuleIDMin || id > contract.HubRuleIDMax {
				return fmt.Errorf("%w: crowdsec rule %s has id %d", ErrIDRange, r.Name, id)
			}
		}
	}
	return nil
}

// Composer owns the running WAF configuration of every repository. Every
// change builds a new instance outside the lock and swaps it atomically; a
// build that fails changes nothing, and a build that another change overtook
// starts again with that change, so no swap undoes another (D46). Requests
// in flight keep the instance they started with (B07).
type Composer struct {
	mu     sync.Mutex
	engine *waf.Engine
	cfg    waf.Config
	log    *slog.Logger
	m      *metrics.Metrics
	// builds counts the swaps, so a build that ran outside the lock can tell
	// that another change moved on meanwhile.
	builds uint64
	// OnSwap is called after each WAF swap with the build time.
	OnSwap func(d time.Duration)
	// afterBuild runs between the build and the commit of a rebuild (tests).
	afterBuild func()
}

// NewComposer returns a composer. cfg holds the engine limits and the agent
// exceptions; the repositories add their rules before Start.
func NewComposer(engine *waf.Engine, cfg waf.Config, log *slog.Logger, m *metrics.Metrics) *Composer {
	if log == nil {
		log = slog.Default()
	}
	return &Composer{engine: engine, cfg: cfg, log: log, m: m}
}

// Init changes the configuration of the first build (before Start).
func (c *Composer) Init(change func(*waf.Config)) {
	c.mu.Lock()
	change(&c.cfg)
	c.mu.Unlock()
}

// Config returns a copy of the running configuration.
func (c *Composer) Config() waf.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

func build(cfg waf.Config) (*waf.Instance, error) {
	if err := CheckRanges(cfg); err != nil {
		return nil, err
	}
	return waf.Build(cfg)
}

// Start builds the first WAF instance. A start never fails because of the
// crowdsec rules (D39): without them the gateway runs with CRS and local
// rules (baseline protection). Local rules that do not build stop the start.
func (c *Composer) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	inst, err := build(c.cfg)
	if err != nil && len(c.cfg.Hub) > 0 {
		c.log.Error("WAF does not build with the crowdsec rules, starting without them", "err", err)
		c.cfg.Hub = nil
		inst, err = build(c.cfg)
	}
	if err != nil {
		return err
	}
	c.swapLocked(inst)
	return nil
}

// Prepare compiles an instance with change applied, outside the lock: the
// compile may take seconds and must not hold up the dashboard. Hand the
// result to Commit with the same change.
func (c *Composer) Prepare(change func(*waf.Config)) (*waf.Instance, uint64, error) {
	c.mu.Lock()
	cfg := c.cfg
	change(&cfg)
	gen := c.builds
	c.mu.Unlock()
	inst, err := build(cfg)
	return inst, gen, err
}

// Commit swaps in an instance of Prepare. false: another swap came first,
// inst is released and the caller builds again, or it would undo that swap.
func (c *Composer) Commit(inst *waf.Instance, gen uint64, change func(*waf.Config)) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.builds {
		inst.Close()
		return false
	}
	change(&c.cfg)
	c.swapLocked(inst)
	return true
}

// Rebuild applies change and swaps the result in, trying again when another
// change came first. A build that fails changes nothing, the running instance
// goes on.
func (c *Composer) Rebuild(change func(*waf.Config)) (*waf.Instance, error) {
	for range 3 {
		inst, gen, err := c.Prepare(change)
		if err != nil {
			return nil, err
		}
		if c.afterBuild != nil {
			c.afterBuild()
		}
		if c.Commit(inst, gen, change) {
			return inst, nil
		}
	}
	return nil, ErrBusy
}

// SetExceptions builds an instance with new agent exceptions and swaps it in
// (D54). A build that fails changes nothing.
func (c *Composer) SetExceptions(text string) (*waf.Instance, error) {
	return c.Rebuild(func(cfg *waf.Config) { cfg.Exceptions = text })
}

func (c *Composer) swapLocked(inst *waf.Instance) {
	c.engine.Swap(inst)
	c.builds++
	if c.m != nil {
		c.m.RuleSwaps.Inc()
		c.m.RuleSwapSeconds.Observe(inst.BuildTime.Seconds())
	}
	if c.OnSwap != nil {
		c.OnSwap(inst.BuildTime)
	}
}

// hubBuilder is the composer as internal/hub sees it: the crowdsec rules
// enter the WAF through the same build and swap as every other change.
type hubBuilder struct{ c *Composer }

func setHub(h []waf.HubRule) func(*waf.Config) { return func(cfg *waf.Config) { cfg.Hub = h } }

func (b hubBuilder) SetHub(h []waf.HubRule) { b.c.Init(setHub(h)) }

func (b hubBuilder) HubLoaded() int { return len(b.c.Config().Hub) }

func (b hubBuilder) PrepareHub(h []waf.HubRule) (*waf.Instance, uint64, error) {
	return b.c.Prepare(setHub(h))
}

func (b hubBuilder) CommitHub(inst *waf.Instance, gen uint64, h []waf.HubRule) bool {
	return b.c.Commit(inst, gen, setHub(h))
}

// HubBuilder returns the composer as the builder of internal/hub.
func (c *Composer) HubBuilder() hub.Builder { return hubBuilder{c} }
