// Package behaviour implements MVP-17: fixed scenarios over several requests
// (login_bruteforce, credential_stuffing, path_probing, aggressive_crawl,
// waf_repeat) and per-route token-bucket rate limits, decided locally at
// HTTP level.
//
// Guarantees:
//   - Everything stays on this server. Counters, sketches and blocks live in
//     memory; hits are local events (schild.behaviour.triggered.v1,
//     schild.ratelimit.exceeded.v1). Nothing here leaves the server.
//   - Bounded memory: every table has a fixed capacity with eviction, so a
//     flood of distinct addresses cannot grow it (see Capacity*).
//   - No request body is stored. Login failures are read from the status
//     code, redirect target and cookie names of the app's answer; a user
//     name is only hashed into a HyperLogLog sketch (keyed per process) and
//     never kept.
//   - net_class cgnat, mobile and tor are never blocked,
//     allowlisted and released senders never; every block expires, the
//     longest after 24 h, or 7 days for data-centre addresses (net_class
//     hosting) that come back (D29 amendment). Blocks over 24 h are handed
//     to Sink.Persist so a restart does not end them early.
//
// Default thresholds are adapted from CrowdSec hub scenarios (MIT,
// Copyright (c) 2025 CrowdSecurity; see client/NOTICE).
package behaviour

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/redact"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Capacities of the in-memory tables (entries). With every sub-state in use
// a client entry is below 400 bytes, so the client table stays below ~26 MB
// and the whole package well below 40 MB, whatever the traffic.
const (
	CapacityClients = 65536
	CapacityBuckets = 65536
	CapacityBlocks  = 16384
	CapacitySites   = 256
	CapacityRelease = 4096
)

// Defaults per scenario. login_bruteforce follows the spec (5 failures in
// 1 min or 30 in 1 h; CrowdSec http-bf-wordpress_bf: capacity 5, leak 10 s);
// path_probing 20 distinct 404/403 paths in 1 min (CrowdSec http-probing:
// distinct paths, capacity 10, leak 10 s, statuses 404/403/400, no static
// files); aggressive_crawl 120 non-static GET/HEAD in 1 min, i.e. 2 per
// second (CrowdSec http-crawl-non_statics: capacity 40, leak 0.5 s) and 10
// times the site's own per-client baseline; waf_repeat 2 distinct rules in
// 1 min (MVP-15); credential_stuffing 10 distinct user names in 10 min.
var Defaults = map[string]config.Thresholds{
	config.ScenarioLoginBruteforce:    {Count: 5, WindowS: 60, SlowCount: 30, SlowWindowS: 3600},
	config.ScenarioCredentialStuffing: {Count: 10, WindowS: 600},
	config.ScenarioPathProbing:        {Count: 20, WindowS: 60},
	config.ScenarioAggressiveCrawl:    {Count: 120, WindowS: 60, BaselineFactor: 10},
	config.ScenarioWAFRepeat:          {Count: 2, WindowS: 60},
}

// SiteStuffingFactor: credential stuffing across the whole site triggers at
// this multiple of the per-client threshold of distinct user names.
const SiteStuffingFactor = 5

// BlockDuration is the block of a ladder level (1-based) for a net class.
func BlockDuration(netClass string, level int) time.Duration {
	return time.Duration(events.BlockDurationS(netClass, level)) * time.Second
}

// BlockCap is the longest block of every net class but hosting;
// HostingBlockCap the longest block of a data-centre address; MaxBlock the
// longest block at all (every block expires by itself).
const (
	BlockCap        = time.Duration(events.MaxBlockDefaultS) * time.Second
	HostingBlockCap = time.Duration(events.MaxBlockHostingS) * time.Second
	MaxBlock        = HostingBlockCap
	// PersistOver: longer blocks are handed to Sink.Persist (schild.db).
	PersistOver = time.Duration(events.PersistOverS) * time.Second
)

// Cooldown between two hits of one scenario for one client key (CrowdSec
// "blackhole" 5 min): further events only count.
const Cooldown = 5 * time.Minute

// repeatMemory: a new block within this time after the last one ends
// climbs one step of the ladder.
const repeatMemory = 24 * time.Hour

// Actions and reasons (events.schema.json).
const (
	ActionObserve = "observe"
	ActionBlock   = "block"

	ReasonNetClass      = "net_class"
	ReasonAllowlisted   = "allowlisted"
	ReasonReleased      = "released"
	ReasonUnverifiedBot = "unverified_bot"
	ReasonSiteScope     = "site_scope"
)

// SharedNetClass reports whether many people share one address (concept 18
// G1): cgnat, mobile and tor exits (tor decided by the initiator 2026-10-28).
// Such addresses are never blocked by behaviour or limits.
func SharedNetClass(nc string) bool { return nc == "cgnat" || nc == "mobile" || nc == "tor" }

// Decide is the action ladder of one hit (pure function).
//
//	mode:   configured mode (observe | block)
//	exempt: "" or ReasonAllowlisted / ReasonReleased / ReasonUnverifiedBot
//
// It returns the action taken, the action mode block would take for this
// client ("hätte gesperrt"), and why the action stayed below the mode.
func Decide(mode, netClass, exempt string) (action, would, reason string) {
	would = ActionBlock
	if SharedNetClass(netClass) || exempt != "" {
		would = ActionObserve
	}
	if mode == ActionBlock {
		switch {
		case exempt != "":
			return ActionObserve, would, exempt
		case SharedNetClass(netClass):
			return ActionObserve, would, ReasonNetClass
		}
		return ActionBlock, would, ""
	}
	return ActionObserve, would, exempt
}

// Request is what the gate knows about a request before it is forwarded.
type Request struct {
	Time        time.Time
	Client      events.Client // full IP and geo (local only)
	IP          netip.Addr
	Allowlisted bool
	// TrustedProxy marks a client address that is itself a configured trusted
	// proxy (e.g. after attribution fell back to the TCP peer): never blocked
	// or rate-limited, so a malformed forwarding header cannot lock out every
	// visitor behind the proxy.
	TrustedProxy bool
	// BotImpersonator reports that bot verification proved the client's IP
	// does not belong to the bot named in User-Agent (bots.VerMismatch).
	BotImpersonator bool
	Method          string
	Host            string
	Path            string
	RawQuery        string
	UserAgent       string
	// MVP-18: client stack fingerprint (local id), whether it is a strong
	// one (JA4 from a trusted terminator), stage-0 inconsistency and the
	// names (never values) of the cookies the request sends.
	Fingerprint  string
	FPKind       string
	StrongFP     bool
	Inconsistent bool
	CookieNames  []string
	// Except reports whether the operator excepted this IP from a source
	// ("behaviour", "behaviour:<scenario>", "ratelimit", "ratelimit:<id>").
	Except func(source string) bool

	// login is the login route of the request as ResolveLogin found it with
	// the body at hand; resolved tells that it ran.
	login    *loginRoute
	resolved bool
}

func (r *Request) except(src string) bool { return r.Except != nil && r.Except(src) }

// Outcome is what happened after the request.
type Outcome struct {
	Forwarded bool // the app answered (not stopped by schild)
	Response  Response
	// UserHash is the keyed hash of the login user name (HasUser), taken
	// from the body by the gate; the name itself is never kept.
	UserHash uint64
	HasUser  bool
	// WAFRules are the distinct rule ids that matched with blocking intent
	// (CRS with points, local rules, CrowdSec Hub rules that blocked).
	WAFRules []int
	// Shape is the request_sig of a request with blocking-intent WAF
	// matches and ShapeRules its rules (MVP-18 shape_wave).
	Shape      string
	ShapeRules []int
}

// Verdict of Check.
type Verdict struct {
	// Block: the client key is blocked by a scenario (403 + block page).
	Block    bool
	Scenario string
	Until    time.Time
	Incident string
	// RateLimited: answer 429 with Retry-After.
	RateLimited bool
	LimitID     string
	RetryAfter  time.Duration
	// WaveID names the MVP-18 wave whose route_tighten answered.
	WaveID string
	// WouldRateLimit: a rate limit of the route was exceeded but not
	// enforced (mode observe, gateway observe, learning or an exemption);
	// the request goes on and counts as would_rate_limit (MVP-21).
	WouldRateLimit bool
}

// Sink receives local events and incidents (never blocking).
type Sink struct {
	Emit     func(id, typ string, t time.Time, data any, idx eventlog.Index)
	Incident func(*store.Incident)
	// Persist keeps a block over PersistOver (schild.db, D29 amendment);
	// Unpersist removes the kept block of a client key (released, deleted
	// under Art. 17, allowlisted). Both must not block the caller.
	Persist   func(events.ActiveBlock)
	Unpersist func(clientKey string)
	// PersistTaken is Persist for a block this node took from its group
	// (blockState.taken), so the mark holds over a restart; nil: Persist.
	PersistTaken func(events.ActiveBlock)
	// Ended reports the incident of a block the operator ended early
	// (Release, DropBlocks: dashboard release, allowlist, schild allow), so
	// the incident is stored as unblocked (D36 fix round 2: released
	// behaviour incidents still said "Gesperrt"). Must not block.
	Ended func(incident string, at time.Time)
}

// Config is the effective behaviour configuration.
type Config struct {
	Behaviour config.Behaviour
	// Dashboard lists the ids of rate limits created in the dashboard.
	Dashboard map[string]bool
	// GatewayObserve: the gateway runs in mode observe (stage 3, test
	// profile). Then nothing is blocked or limited; scenarios and limits
	// only count what they would have done.
	GatewayObserve bool
	// InstalledAt is the first start of the data directory (MVP-18
	// learning period); zero means unknown and keeps learning.
	InstalledAt time.Time
}

// Limit is a compiled rate limit.
type Limit struct {
	config.RateLimit
	Source string // preset | config | dashboard
	Preset string
	// Recommended is the mode a preset limit takes when none is configured
	// (D95); empty for own limits.
	Recommended string
	Query       string
	PerS        int
	rate        float64 // tokens per second
	re          *regexp.Regexp
	prefix      string // route "/x/**": everything below /x/, without a regexp
	statMatched string // stats name of the requests that fall under the limit
	method      map[string]bool
	site        string
	idx         uint16
}

// matches reports whether a request falls under the limit; canon is
// canonPath(p).
func (l *Limit) matches(method, host, p, canon, rawQuery string) bool {
	if l.Mode == config.BehaviourOff {
		return false
	}
	if len(l.method) > 0 && !l.method[method] {
		return false
	}
	if l.site != "" && l.site != host {
		return false
	}
	if l.prefix != "" {
		if !strings.HasPrefix(p, l.prefix) && (canon == "" || !strings.HasPrefix(canon, l.prefix)) {
			return false
		}
	} else if l.re != nil {
		if !l.re.MatchString(p) && (canon == "" || !l.re.MatchString(canon)) {
			return false
		}
	} else if !routeIs(l.Route, p, canon) {
		return false
	}
	if l.Query != "" && !hasQuery(rawQuery, l.Query) {
		return false
	}
	return true
}

type compiled struct {
	mode    map[string]string
	thr     map[string]config.Thresholds
	presets map[string]bool
	limits  []*Limit
	observe bool // gateway mode observe: act on nothing
	dist    *distCompiled
}

// Engine holds all counters. Safe for concurrent use.
type Engine struct {
	Sink Sink
	Now  func() time.Time
	// KnownHost, when set, restricts per-site state (crawl baselines, site
	// credential-stuffing sketches, learned session cookies) to configured
	// website hosts so arbitrary Host headers cannot evict real sites.
	KnownHost func(host string) bool

	cfg      atomic.Pointer[compiled]
	clients  *table[Key, clientState]
	buckets  *table[bucketKey, bucket]
	blocks   *table[Key, blockState]
	released *table[Key, int64]
	long     longBlocks
	sitesMu  sync.Mutex
	sites    map[string]*siteState
	stats    *statsRing
	d        *dist
	// share notes what the engine counts for the other nodes of a group
	// (shared.go); nil on a single gateway.
	share atomic.Pointer[sharer]
	// draw and known: see NewIncident (groupblocks.go).
	draw  atomic.Pointer[func() string]
	known atomic.Pointer[func(incident string) bool]
}

// New returns an engine with cfg.
func New(cfg Config) *Engine {
	e := &Engine{Now: time.Now,
		clients:  newTable[Key, clientState](CapacityClients, hashKey),
		buckets:  newTable[bucketKey, bucket](CapacityBuckets, func(k bucketKey) uint64 { return hashKey(k.key) ^ uint64(k.limit)*0x9e3779b97f4a7c15 }),
		blocks:   newTable[Key, blockState](CapacityBlocks, hashKey),
		released: newTable[Key, int64](CapacityRelease, hashKey),
		sites:    map[string]*siteState{},
		stats:    newStatsRing(),
		d:        newDist(),
	}
	// D38: a full block table evicts ended blocks (kept for the escalation
	// memory) before running ones.
	e.blocks.evictFirst = func() func(*blockState) bool {
		now := e.now().UnixNano()
		return func(b *blockState) bool { return b.until <= now }
	}
	e.SetConfig(cfg)
	return e
}

// SetConfig swaps the configuration (counters are kept).
func (e *Engine) SetConfig(cfg Config) {
	b := cfg.Behaviour
	c := &compiled{mode: map[string]string{}, thr: map[string]config.Thresholds{}, presets: map[string]bool{}, observe: cfg.GatewayObserve,
		dist: compileDistributed(b.Distributed, cfg.InstalledAt)}
	for _, id := range config.ScenarioIDs {
		s := b.Scenarios.Get(id)
		c.mode[id] = s.Mode
		if c.mode[id] == "" {
			c.mode[id] = config.BehaviourObserve
		}
		c.thr[id] = Effective(id, s.Thresholds)
	}
	presets := b.Presets
	if len(presets) == 0 {
		presets = config.BehaviourPresets
	}
	for _, p := range presets {
		c.presets[p] = true
	}
	add := func(l *Limit) {
		if compileLimit(l) != nil || len(c.limits) >= 1<<16-1 {
			return
		}
		l.idx = uint16(len(c.limits))
		c.limits = append(c.limits, l)
	}
	for _, p := range PresetLimits(presets) {
		l := &Limit{RateLimit: p.RateLimit, Source: "preset", Preset: p.Preset, Query: p.Query, Recommended: p.Recommended}
		// D95: its own entry, else the one mode for all, else its recommendation.
		l.Mode = p.Recommended
		if b.PresetLimits != "" {
			l.Mode = b.PresetLimits
		}
		if m := b.PresetLimitModes[p.ID]; m != "" {
			l.Mode = m
		}
		add(l)
	}
	for _, r := range b.RateLimits {
		src := "config"
		if cfg.Dashboard[r.ID] {
			src = "dashboard"
		}
		add(&Limit{RateLimit: r, Source: src})
	}
	e.cfg.Store(c)
}

func compileLimit(l *Limit) error {
	per, err := config.ParsePer(l.Per)
	if err != nil {
		return err
	}
	if l.Limit <= 0 {
		return fmt.Errorf("limit %d", l.Limit)
	}
	if l.Burst <= 0 {
		l.Burst = l.Limit
	}
	if l.Mode == "" {
		l.Mode = config.BehaviourObserve
	}
	l.PerS = int(per / time.Second)
	l.rate = float64(l.Limit) / per.Seconds()
	if base, ok := strings.CutSuffix(l.Route, "/**"); ok && !strings.Contains(base, "*") {
		// The common form "/api/**" is a prefix; the request path has no line
		// break, so this equals the regexp.
		l.prefix = base + "/"
	} else if strings.Contains(l.Route, "*") {
		l.re = routeRe(l.Route)
	}
	l.statMatched = "rlm:" + l.ID
	if len(l.Methods) > 0 {
		l.method = map[string]bool{}
		for _, m := range l.Methods {
			l.method[m] = true
		}
	}
	l.site = strings.ToLower(l.Site)
	return nil
}

// CompileLimit compiles a rate limit outside the engine (dry run).
func CompileLimit(r config.RateLimit) (*Limit, error) {
	l := &Limit{RateLimit: r}
	l.Mode = config.BehaviourObserve
	return l, compileLimit(l)
}

// Matches reports whether a request falls under the limit.
func (l *Limit) Matches(method, hostHeader, p, rawQuery string) bool {
	return l.matches(method, host(hostHeader), p, canonPath(p), rawQuery)
}

// DryRun replays requests (oldest first) through a fresh token bucket per
// client key and counts matching requests, requests over the limit and the
// client keys concerned. At most maxKeys keys are tracked.
func (l *Limit) DryRun(reqs func(yield func(t time.Time, ip netip.Addr, method, host, path string) bool)) (matching, over, clients int) {
	const maxKeys = 100000
	type tb struct {
		tokens float64
		last   time.Time
		over   bool
	}
	keys := map[Key]*tb{}
	reqs(func(t time.Time, ip netip.Addr, method, h, p string) bool {
		if !l.Matches(method, h, p, "") {
			return true
		}
		matching++
		k, _ := KeyOf(ip)
		if !k.IsValid() {
			return true
		}
		b := keys[k]
		if b == nil {
			if len(keys) >= maxKeys {
				return true
			}
			b = &tb{tokens: float64(l.Burst), last: t}
			keys[k] = b
		}
		b.tokens = min(float64(l.Burst), b.tokens+t.Sub(b.last).Seconds()*l.rate)
		b.last = t
		if b.tokens >= 1 {
			b.tokens--
			return true
		}
		over++
		if !b.over {
			b.over = true
			clients++
		}
		return true
	})
	return matching, over, clients
}

// Effective returns the thresholds of a scenario with defaults filled in.
func Effective(id string, t config.Thresholds) config.Thresholds {
	d := Defaults[id]
	if t.Count > 0 {
		d.Count = t.Count
	}
	if t.WindowS > 0 {
		d.WindowS = t.WindowS
	}
	if t.SlowCount > 0 {
		d.SlowCount = t.SlowCount
	}
	if t.SlowWindowS > 0 {
		d.SlowWindowS = t.SlowWindowS
	}
	if t.BaselineFactor > 0 {
		d.BaselineFactor = t.BaselineFactor
	}
	return d
}

// Limits returns the compiled rate limits (presets first).
func (e *Engine) Limits() []*Limit { return e.cfg.Load().limits }

// Mode returns the configured mode of a scenario.
func (e *Engine) Mode(id string) string { return e.cfg.Load().mode[id] }

// EffectiveMode is the mode that acts: observe while the gateway observes.
func (e *Engine) EffectiveMode(id string) string {
	c := e.cfg.Load()
	return c.effective(c.mode[id])
}

// GatewayObserve reports whether the gateway mode caps everything to observe.
func (e *Engine) GatewayObserve() bool { return e.cfg.Load().observe }

func (c *compiled) effective(mode string) string {
	if mode == config.BehaviourOff {
		return mode
	}
	if c.observe {
		return config.BehaviourObserve
	}
	return mode
}

// Thresholds returns the effective thresholds of a scenario.
func (e *Engine) Thresholds(id string) config.Thresholds { return e.cfg.Load().thr[id] }

// ResolveLogin decides, once the body is buffered, whether r is a login
// attempt of an enabled preset, and keeps the answer on r for Observe. form
// is called at most once, and only for a route whose meaning hangs on a
// body field (wp-login.php). It returns the body fields that carry the user
// name, for the gate to hash it (nil for no login attempt and with
// credential_stuffing off).
func (e *Engine) ResolveLogin(r *Request, form func() Form) []string {
	c := e.cfg.Load()
	r.login, r.resolved = matchLogin(c.presets, r.Method, r.Path, r.RawQuery, form), true
	if r.login == nil || c.mode[config.ScenarioCredentialStuffing] == config.BehaviourOff {
		return nil
	}
	return r.login.UserFields
}

// loginOf is the login route of r: what ResolveLogin found, else what the
// request line alone says (a body nobody read counts as unclear).
func loginOf(c *compiled, r *Request) *loginRoute {
	if r.resolved {
		return r.login
	}
	return matchLogin(c.presets, r.Method, r.Path, r.RawQuery, nil)
}

// HashUser turns a user name into the value fed into the sketches. The
// name is normalised and hashed with a per-process random key; the caller
// drops the name right away.
func HashUser(name string) uint64 { return hashString(strings.ToLower(strings.TrimSpace(name))) }

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func host(h string) string {
	h = strings.ToLower(h)
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.HasSuffix(h, "]") {
		h = h[:i]
	}
	return strings.Trim(h, "[]")
}

// ---------------------------------------------------------------- blocks

type blockState struct {
	until     int64 // unix nanos; 0 = none
	lastUntil int64
	level     int
	// ladder: the step an agent block replaced (D42); it stays for the next
	// scenario block, which is on the ladder.
	ladder    int
	scenario  string
	incident  string
	eventID   string
	started   int64
	netClass  string
	persisted bool // handed to Sink.Persist (and kept in long)
	// taken: another node of the group decided this block and this node
	// took it from the group's record (ApplyBlock). A node writes only the
	// blocks it decided itself to its group.
	taken bool
}

// Check runs before the WAF: an active block of the client key, then the
// rate limits of the route. It never blocks allowlisted senders or trusted
// proxies.
func (e *Engine) Check(r *Request) Verdict {
	key, bits := KeyOf(r.IP)
	if !key.IsValid() || r.Allowlisted || r.TrustedProxy {
		return Verdict{WouldRateLimit: e.observeLimits(r, key, bits, false).WouldRateLimit}
	}
	now := r.Time.UnixNano()
	var v Verdict
	e.blocks.with(key, false, func(b *blockState) {
		if b == nil || b.until <= now {
			return
		}
		if r.except("behaviour") || r.except(BlockSource(b.scenario)) {
			return
		}
		v = Verdict{Block: true, Scenario: b.scenario, Until: time.Unix(0, b.until), Incident: b.incident}
	})
	if !v.Block {
		// A kept block over 24 h whose table entry was evicted.
		if lb, ok := e.longCheck(key, now); ok {
			sc := strings.TrimPrefix(lb.ab.Source, "behaviour:")
			if !r.except("behaviour") && !r.except(BlockSource(sc)) {
				v = Verdict{Block: true, Scenario: sc, Until: time.Unix(0, lb.until), Incident: lb.ab.Incident}
			}
		}
	}
	if v.Block {
		return v
	}
	if dv := e.checkDistributed(e.cfg.Load(), r); dv.RateLimited {
		return dv
	}
	return e.observeLimits(r, key, bits, true)
}

// ---------------------------------------------------------------- rate limits

type bucketKey struct {
	key   Key
	limit uint16
}

type bucket struct {
	tokens    float64
	last      int64
	over      int
	lastEvent int64
}

type limitHit struct {
	l       *Limit
	count   int
	action  string
	reason  string
	retry   time.Duration
	observe bool
}

// observeLimits takes one token from every matching limit. enforce=false
// (allowlisted or no key) only counts.
func (e *Engine) observeLimits(r *Request, key Key, bits int, enforce bool) Verdict {
	c := e.cfg.Load()
	if len(c.limits) == 0 || !key.IsValid() {
		return Verdict{}
	}
	h := host(r.Host)
	canon := canonPath(r.Path)
	now := r.Time.UnixNano()
	var v Verdict
	var hits []limitHit
	observed := false // an exceeded limit that was not enforced
	for _, l := range c.limits {
		if !l.matches(r.Method, h, r.Path, canon, r.RawQuery) {
			continue
		}
		e.stats.add(l.statMatched, r.Time, 1)
		var exceeded, took bool
		var retry time.Duration
		var emitCount int
		e.buckets.with(bucketKey{key, l.idx}, true, func(b *bucket) {
			if b.last == 0 {
				b.tokens, b.last = float64(l.Burst), now
			}
			// Wall-clock time: a clock that steps back adds nothing, it never
			// takes tokens away.
			b.tokens = min(float64(l.Burst), b.tokens+float64(max(now-b.last, 0))/1e9*l.rate)
			b.last = now
			if b.tokens >= 1 {
				b.tokens--
				took = true
				return
			}
			exceeded = true
			retry = time.Duration((1 - b.tokens) / l.rate * 1e9)
			b.over++
			if now-b.lastEvent >= int64(time.Minute) {
				emitCount, b.over, b.lastEvent = b.over, 0, now
			}
		})
		// The other nodes of a group are told the requests that took a
		// token, as this node counts them: a refused request takes none.
		if took {
			if sh := e.share.Load(); sh != nil {
				sh.limit(key, l.ID)
			}
		}
		if !exceeded {
			continue
		}
		e.stats.add("rl:"+l.ID, r.Time, 1)
		e.stats.addDistinct("rlc:"+l.ID, r.Time, hashKey(key))
		exempt := ""
		switch {
		case r.Allowlisted || r.TrustedProxy:
			exempt = ReasonAllowlisted
		case r.except("ratelimit") || r.except("ratelimit:"+l.ID):
			exempt = ReasonReleased
		case SharedNetClass(r.Client.Geo.NetClass):
			exempt = ReasonNetClass
		}
		action := ActionObserve
		if l.Mode == config.BehaviourBlock && enforce && exempt == "" && !c.observe {
			action = ActionBlock
			if !v.RateLimited || retry > v.RetryAfter {
				v = Verdict{RateLimited: true, LimitID: l.ID, RetryAfter: retry}
			}
		} else {
			observed = true
		}
		if emitCount > 0 {
			hits = append(hits, limitHit{l: l, count: emitCount, action: action, reason: exempt, retry: retry, observe: c.observe})
		}
	}
	for _, h := range hits {
		e.emitLimit(r, bits, h)
	}
	if !v.RateLimited && observed {
		v.WouldRateLimit = true
	}
	return v
}

func (e *Engine) emitLimit(r *Request, bits int, h limitHit) {
	if e.Sink.Emit == nil {
		return
	}
	mode := ActionObserve
	if h.l.Mode == config.BehaviourBlock && !h.observe {
		mode = ActionBlock
	}
	d := events.RateLimitExceededData{LimitID: h.l.ID, Source: h.l.Source, Route: trim(h.l.Route, 256), Methods: h.l.Methods, Host: trim(r.Host, 253),
		Path: trim(redact.Path(r.Path), 512), Client: r.Client, KeyBits: bits, Limit: h.l.Limit, PerS: h.l.PerS, Burst: h.l.Burst,
		Count: h.count, Mode: mode, Action: h.action, Reason: h.reason}
	if h.action == ActionBlock {
		d.RetryAfterS = RetryAfterSeconds(h.retry)
	}
	e.Sink.Emit("", events.RateLimitExceeded, r.Time, d, eventlog.Index{IP: r.Client.IP, Country: r.Client.Geo.Country, ASN: r.Client.Geo.ASN,
		Method: r.Method, Host: d.Host, Path: d.Path, Outcome: h.action, Summary: "rate limit " + h.l.ID + " " + h.action})
}

// RetryAfterSeconds rounds up to whole seconds (at least 1).
func RetryAfterSeconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	return min(max(s, 1), 86400)
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------------------------------------------------------------- scenarios

// window is a sliding-window counter approximated by two fixed windows.
type window struct {
	start     int64 // unix nanos of the current window
	cur, prev float32
}

func (w *window) roll(now, size int64) {
	if w.start == 0 {
		w.start = now
		return
	}
	switch k := (now - w.start) / size; {
	case k == 1:
		w.prev, w.cur, w.start = w.cur, 0, w.start+size
	case k > 1:
		w.prev, w.cur, w.start = 0, 0, now
	}
}

func (w *window) add(now, size int64, n float32) float64 {
	w.roll(now, size)
	w.cur += n
	frac := float64(now-w.start) / float64(size)
	return float64(w.prev)*(1-frac) + float64(w.cur)
}

// distinct counts distinct ids (with weights) in a fixed window. Beyond its
// capacity new ids still add their weight without de-duplication.
type distinct[T comparable] struct {
	start  int64
	n      int
	ids    []T
	weight int
	hits   int    // requests in this window (waf_repeat)
	last   string // route shown in the hit (redacted path)
}

func (d *distinct[T]) add(now, size int64, id T, w, capacity int) int {
	if d.start == 0 || now-d.start >= size {
		d.start, d.n, d.weight, d.hits = now, 0, 0, 0
		d.ids = d.ids[:0]
	}
	for _, x := range d.ids {
		if x == id {
			return d.weight
		}
	}
	if len(d.ids) < capacity {
		d.ids = append(d.ids, id)
	}
	d.weight += w
	return d.weight
}

type userSketch struct {
	start int64
	h     *hll
}

type clientState struct {
	seen      int64
	loginFast window
	loginSlow window
	loginN    int
	users     *userSketch
	probe     *distinct[uint32]
	crawl     window
	waf       *distinct[int]
	lastHit   [5]int64
}

type siteState struct {
	mu       sync.Mutex
	users    userSketch
	lastHit  int64
	start    int64
	total    float64
	clients  *hll
	baseline float64
}

func scenarioIndex(id string) int {
	for i, s := range config.ScenarioIDs {
		if s == id {
			return i
		}
	}
	return 0
}

type trigger struct {
	scenario  string
	count     int
	threshold int
	window    int
	route     string
	preset    string
	baseline  float64
	exempt    string
}

const (
	probeCapacity = 64
	wafCapacity   = 16
)

// Observe feeds a finished request into the scenarios.
func (e *Engine) Observe(r *Request, o Outcome) {
	key, bits := KeyOf(r.IP)
	if !key.IsValid() {
		return
	}
	c := e.cfg.Load()
	e.observeDistributed(c, r, o, key)
	now := r.Time.UnixNano()
	h := host(r.Host)
	var lr *loginRoute
	if o.Forwarded {
		lr = loginOf(c, r)
	}
	loginFailed := lr != nil && lr.Failed(o.Response)
	probing := o.Forwarded && (o.Response.Status == 404 || o.Response.Status == 403) && !IsStatic(r.Path)
	crawl := (r.Method == "GET" || r.Method == "HEAD") && !IsStatic(r.Path)
	waf := len(o.WAFRules) > 0
	if !loginFailed && !probing && !crawl && !waf {
		return
	}
	var site *siteState
	if crawl || (loginFailed && o.HasUser) {
		site = e.site(h)
	}
	var baseline float64
	if crawl && site != nil {
		baseline = site.observeCrawl(now, int64(c.thr[config.ScenarioAggressiveCrawl].WindowS)*int64(time.Second), hashKey(key))
	}
	if sh := e.share.Load(); sh != nil {
		e.noteShared(sh, r, o, key, h, site != nil, loginFailed, probing, crawl, waf)
	}
	var trig []trigger
	e.clients.with(key, true, func(s *clientState) {
		s.seen = now
		hit := func(id string, t trigger) {
			i := scenarioIndex(id)
			if c.mode[id] == config.BehaviourOff || now-s.lastHit[i] < int64(Cooldown) {
				return
			}
			s.lastHit[i] = now
			t.scenario = id
			trig = append(trig, t)
		}
		if loginFailed {
			t := c.thr[config.ScenarioLoginBruteforce]
			fast := s.loginFast.add(now, int64(t.WindowS)*int64(time.Second), 1)
			slow := s.loginSlow.add(now, int64(t.SlowWindowS)*int64(time.Second), 1)
			s.loginN++
			switch {
			case fast >= float64(t.Count)-1e-9:
				hit(config.ScenarioLoginBruteforce, trigger{count: int(fast + 0.5), threshold: t.Count, window: t.WindowS, route: lr.Path, preset: lr.Preset})
			case t.SlowCount > 0 && slow >= float64(t.SlowCount)-1e-9:
				hit(config.ScenarioLoginBruteforce, trigger{count: int(slow + 0.5), threshold: t.SlowCount, window: t.SlowWindowS, route: lr.Path, preset: lr.Preset})
			}
			if o.HasUser {
				ct := c.thr[config.ScenarioCredentialStuffing]
				if s.users == nil {
					s.users = &userSketch{h: newHLL(6)}
				}
				n := s.users.add(now, int64(ct.WindowS)*int64(time.Second), o.UserHash)
				if n >= ct.Count {
					hit(config.ScenarioCredentialStuffing, trigger{count: n, threshold: ct.Count, window: ct.WindowS, route: lr.Path, preset: lr.Preset})
				}
			}
		}
		if probing {
			t := c.thr[config.ScenarioPathProbing]
			if s.probe == nil {
				s.probe = &distinct[uint32]{}
			}
			w := 1
			p := redact.Path(r.Path)
			if IsProbePath(r.Path) {
				w = probeWeight
				s.probe.last = p
			} else if s.probe.last == "" {
				s.probe.last = p
			}
			n := s.probe.add(now, int64(t.WindowS)*int64(time.Second), uint32(hashString(r.Path)), w, probeCapacity)
			if n >= t.Count {
				hit(config.ScenarioPathProbing, trigger{count: n, threshold: t.Count, window: t.WindowS, route: s.probe.last})
				s.probe.last = ""
			}
		}
		if crawl {
			t := c.thr[config.ScenarioAggressiveCrawl]
			n := s.crawl.add(now, int64(t.WindowS)*int64(time.Second), 1)
			thr := max(float64(t.Count), t.BaselineFactor*baseline)
			if n >= thr {
				tg := trigger{count: int(n + 0.5), threshold: int(thr + 0.5), window: t.WindowS, route: redact.Path(r.Path), baseline: baseline}
				if ClaimsSearchBot(r.UserAgent) && !r.BotImpersonator {
					tg.exempt = ReasonUnverifiedBot
				}
				hit(config.ScenarioAggressiveCrawl, tg)
			}
		}
		if waf {
			t := c.thr[config.ScenarioWAFRepeat]
			if s.waf == nil {
				s.waf = &distinct[int]{}
			}
			var n int
			for _, id := range o.WAFRules {
				n = s.waf.add(now, int64(t.WindowS)*int64(time.Second), id, 1, wafCapacity)
			}
			s.waf.hits++
			// Repeat: distinct rules over at least two requests (one request
			// that matches several CRS rules is no repeat).
			if n >= t.Count && s.waf.hits >= 2 {
				hit(config.ScenarioWAFRepeat, trigger{count: n, threshold: t.Count, window: t.WindowS, route: redact.Path(r.Path)})
			}
		}
	})
	if loginFailed && o.HasUser && site != nil {
		e.observeSiteUsers(r, c, site, lr, o.UserHash)
	}
	for _, t := range trig {
		e.fire(r, c, key, bits, t)
	}
}

func (u *userSketch) add(now, size int64, x uint64) int {
	if u.start == 0 || now-u.start >= size {
		u.start = now
		u.h.reset()
	}
	u.h.add(x)
	return int(u.h.estimate() + 0.5)
}

func (e *Engine) site(h string) *siteState {
	if e.KnownHost != nil && !e.KnownHost(h) {
		return nil
	}
	e.sitesMu.Lock()
	defer e.sitesMu.Unlock()
	s := e.sites[h]
	if s == nil {
		if len(e.sites) >= CapacitySites {
			for k := range e.sites {
				delete(e.sites, k)
				break
			}
		}
		s = &siteState{users: userSketch{h: newHLL(10)}, clients: newHLL(10)}
		e.sites[h] = s
	}
	return s
}

// observeCrawl counts a non-static request for the site baseline: requests
// per active client per window, smoothed over windows.
func (s *siteState) observeCrawl(now, size int64, client uint64) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.start == 0 {
		s.start = now
	}
	if now-s.start >= size {
		if n := s.clients.estimate(); n >= 5 {
			per := s.total / n
			if s.baseline == 0 {
				s.baseline = per
			} else {
				s.baseline = 0.9*s.baseline + 0.1*per
			}
		}
		s.start, s.total = now, 0
		s.clients.reset()
	}
	s.total++
	s.clients.add(client)
	return s.baseline
}

// observeSiteUsers: distinct user names of failed logins across the whole
// site (credential stuffing from a pool of addresses). Observed only: there
// is no single client to act on.
func (e *Engine) observeSiteUsers(r *Request, c *compiled, s *siteState, lr *loginRoute, uh uint64) {
	t := c.thr[config.ScenarioCredentialStuffing]
	mode := c.mode[config.ScenarioCredentialStuffing]
	now := r.Time.UnixNano()
	s.mu.Lock()
	n := s.users.add(now, int64(t.WindowS)*int64(time.Second), uh)
	thr := t.Count * SiteStuffingFactor
	fire := mode != config.BehaviourOff && n >= thr && now-s.lastHit >= int64(Cooldown)
	if fire {
		s.lastHit = now
	}
	s.mu.Unlock()
	if !fire {
		return
	}
	e.stats.add("hit:"+config.ScenarioCredentialStuffing, r.Time, 1)
	if e.Sink.Emit == nil {
		return
	}
	d := events.BehaviourTriggeredData{Scenario: config.ScenarioCredentialStuffing, Scope: "site", Host: trim(r.Host, 253), Route: lr.Path, Preset: lr.Preset,
		Count: n, Threshold: thr, WindowS: t.WindowS, Mode: mode, Action: ActionObserve, Reason: ReasonSiteScope}
	e.Sink.Emit("", events.BehaviourTriggered, r.Time, d, eventlog.Index{Host: d.Host, Path: d.Route, Outcome: ActionObserve,
		Summary: "behaviour credential_stuffing site observe"})
}

// fire applies the ladder to one hit and records it.
func (e *Engine) fire(r *Request, c *compiled, key Key, bits int, t trigger) {
	mode := c.mode[t.scenario]
	if c.observe {
		mode = config.BehaviourObserve // the gateway observes: count only
	}
	exempt := t.exempt
	switch {
	case r.Allowlisted || r.TrustedProxy:
		exempt = ReasonAllowlisted
	case r.except("behaviour") || r.except("behaviour:"+t.scenario):
		exempt = ReasonReleased
	}
	action, would, reason := Decide(mode, r.Client.Geo.NetClass, exempt)
	if action != ActionObserve && c.Learning(r.Time) {
		// Learning period (MVP-17 "all scenarios in observe for 14 days",
		// MVP-19, D31): a scenario the operator set to block
		// acts only after learning_days, like the distributed detectors.
		// Until then it records what it would have done. The event keeps
		// the configured mode, with reason learning (v0.4 addendum
		// 2026-10-28). Rate limits never get here: they act from day 0.
		action, reason = ActionObserve, ReasonLearning
	}
	id := msg.NewID()
	d := events.BehaviourTriggeredData{Scenario: t.scenario, Scope: "client", KeyBits: bits, Host: trim(r.Host, 253), Route: trim(t.route, 512), Preset: t.preset,
		Count: t.count, Threshold: max(t.threshold, 1), WindowS: max(t.window, 1), Baseline: round2(t.baseline), Mode: mode, Action: action, WouldAction: would, Reason: reason}
	cl := r.Client
	d.Client = &cl
	if action == ActionBlock {
		var level int
		var until time.Time
		var dur time.Duration
		nc := r.Client.Geo.NetClass
		created := false
		now := r.Time.UnixNano()
		// The number is drawn before the table is locked, because on a node
		// of a group the draw looks into its stores; and only for a client
		// that is not blocked, so a request of a blocked client reads none.
		blocked := false
		e.blocks.with(key, false, func(b *blockState) { blocked = b != nil && b.until > now })
		if blocked {
			return
		}
		incident := e.NewIncident()
		e.blocks.with(key, true, func(b *blockState) {
			if b.until > now {
				return // already blocked
			}
			level = 1
			if b.lastUntil != 0 && now-b.lastUntil < int64(repeatMemory) {
				level = min(b.ladderLevel()+1, len(events.Ladder(nc)))
			}
			dur = BlockDuration(nc, level)
			until = r.Time.Truncate(time.Second).Add(dur)
			*b = blockState{until: until.UnixNano(), lastUntil: until.UnixNano(), level: level, scenario: t.scenario, incident: incident, eventID: id, started: now,
				netClass: nc, persisted: dur > PersistOver}
			created = true
		})
		if !created {
			return
		}
		d.Level, d.Until, d.Incident = level, until.UTC().Format("2006-01-02T15:04:05Z"), incident
		d.DurationS = int(dur / time.Second)
		if dur > PersistOver {
			ab := events.ActiveBlock{ClientKey: key.Addr().String(), KeyBits: bits, NetClass: nc, Source: "behaviour:" + t.scenario, Level: level,
				DurationS: d.DurationS, Since: r.Time.UTC().Truncate(time.Second).Format(time.RFC3339), Until: d.Until, Incident: incident}
			e.keepLong(key, ab, id, false)
		}
		if e.Sink.Incident != nil {
			e.Sink.Incident(&store.Incident{Incident: incident, EventID: id, Time: r.Time.UTC(), IP: r.Client.IP, Status: "blocked", Host: r.Host,
				Reason: fmt.Sprintf("behaviour %s: %d in %d s (step %d, %s)", t.scenario, t.count, t.window, level, durationText(dur)), Sources: []string{"behaviour:" + t.scenario}})
		}
	}
	e.stats.add("hit:"+t.scenario, r.Time, 1)
	if action == ActionObserve && would == ActionBlock {
		e.stats.add("would:"+t.scenario, r.Time, 1)
	}
	if e.Sink.Emit == nil {
		return
	}
	e.Sink.Emit(id, events.BehaviourTriggered, r.Time, d, eventlog.Index{IP: cl.IP, Country: cl.Geo.Country, ASN: cl.Geo.ASN, Method: r.Method, Host: d.Host, Path: d.Route,
		Outcome: action, Incident: d.Incident, Summary: "behaviour " + t.scenario + " " + action})
}

func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }

// ---------------------------------------------------------------- operator

// Release ends every block of the client key of ip, resets its counters and
// rate-limit buckets, and remembers the release time (hits before it show
// as released). It returns the number of blocks that ended.
func (e *Engine) Release(ip netip.Addr) int {
	ended, _ := e.ReleaseIncidents(ip)
	return ended
}

// ReleaseIncidents is Release and names the incidents of the blocks it
// ended: on a node of a group each of them is lifted for the group.
func (e *Engine) ReleaseIncidents(ip netip.Addr) (int, []string) {
	key, _ := KeyOf(ip)
	if !key.IsValid() {
		return 0, nil
	}
	now := e.now().UnixNano()
	ended := 0
	var incidents []string
	e.blocks.with(key, false, func(b *blockState) {
		if b != nil && b.until > now {
			ended++
			b.until = now
			incidents = append(incidents, b.incident)
		}
	})
	incidents = append(incidents, e.longIncident(key, now))
	if e.dropLong(key) && ended == 0 {
		ended++
	}
	e.reportEnded(now, incidents...)
	e.clients.delete(key)
	for _, l := range e.cfg.Load().limits {
		e.buckets.delete(bucketKey{key, l.idx})
	}
	e.released.with(key, true, func(t *int64) { *t = now })
	var named []string
	for _, in := range incidents {
		if in != "" && !slices.Contains(named, in) {
			named = append(named, in)
		}
	}
	return ended, named
}

// BlockInfo describes a running block.
type BlockInfo struct {
	Scenario string
	Since    time.Time
	Until    time.Time
	Level    int
	Incident string
	EventID  string
	// NetClass whose ladder set the duration, Duration the whole block and
	// Persisted whether it is kept in schild.db (D29 amendment).
	NetClass  string
	Duration  time.Duration
	Persisted bool
	// Taken: another node of the group decided the block (blockState.taken).
	Taken bool
}

// ActiveBlock returns the running block of the client key of ip.
func (e *Engine) ActiveBlock(ip netip.Addr) (BlockInfo, bool) {
	key, _ := KeyOf(ip)
	var bi BlockInfo
	ok := false
	if !key.IsValid() {
		return bi, false
	}
	now := e.now().UnixNano()
	e.blocks.with(key, false, func(b *blockState) {
		if b != nil && b.until > now {
			st := time.Unix(0, b.started).UTC()
			bi, ok = BlockInfo{Scenario: b.scenario, Since: st, Until: time.Unix(0, b.until).UTC(), Level: b.level, Incident: b.incident, EventID: b.eventID,
				NetClass: b.netClass, Duration: time.Unix(0, b.until).Sub(st.Truncate(time.Second)), Persisted: b.persisted, Taken: b.taken}, true
		}
	})
	if !ok {
		if lb, found := e.longCheck(key, now); found {
			st, _ := time.Parse(time.RFC3339, lb.ab.Since)
			bi, ok = BlockInfo{Scenario: strings.TrimPrefix(lb.ab.Source, "behaviour:"), Since: st, Until: time.Unix(0, lb.until).UTC(), Level: lb.ab.Level,
				Incident: lb.ab.Incident, EventID: lb.eventID, NetClass: lb.ab.NetClass, Duration: time.Duration(lb.ab.DurationS) * time.Second, Persisted: true,
				Taken: lb.taken}, true
		}
	}
	return bi, ok
}

// ReleasedSince reports whether the client key of ip was released after t.
func (e *Engine) ReleasedSince(ip netip.Addr, t time.Time) bool {
	key, _ := KeyOf(ip)
	if !key.IsValid() {
		return false
	}
	var at int64
	e.released.with(key, false, func(v *int64) {
		if v != nil {
			at = *v
		}
	})
	return at != 0 && at >= t.UnixNano()
}

// ActiveBlocks counts running blocks per scenario.
func (e *Engine) ActiveBlocks() map[string]int {
	now := e.now().UnixNano()
	out := map[string]int{}
	e.blocks.sweep(func(_ Key, b *blockState) bool {
		if b.until > now {
			out[b.scenario]++
		}
		return false
	})
	return out
}

// Counts24h returns hits and would-block hits of a scenario in the last 24 h.
func (e *Engine) Counts24h(scenario string) (hits, would int) {
	now := e.now()
	return int(e.stats.sum("hit:"+scenario, now)), int(e.stats.sum("would:"+scenario, now))
}

// LimitMatched24h returns the requests that fell under a limit in the last
// 24 h, over it or not (D96). A limit that is off counts nothing.
func (e *Engine) LimitMatched24h(id string) int { return int(e.stats.sum("rlm:"+id, e.now())) }

// LimitCounts24h returns requests over a limit and distinct client keys in
// the last 24 h.
func (e *Engine) LimitCounts24h(id string) (exceeded, clients int) {
	now := e.now()
	return int(e.stats.sum("rl:"+id, now)), int(e.stats.distinct("rlc:"+id, now) + 0.5)
}

// Sweep drops idle entries: clients idle longer than an hour (or the slow
// login window), buckets that refilled, blocks a day after they ended.
func (e *Engine) Sweep() {
	now := e.now().UnixNano()
	c := e.cfg.Load()
	idle := int64(time.Hour)
	if s := int64(c.thr[config.ScenarioLoginBruteforce].SlowWindowS) * int64(time.Second); s > idle {
		idle = s
	}
	e.clients.sweep(func(_ Key, s *clientState) bool { return now-s.seen > idle })
	e.buckets.sweep(func(_ bucketKey, b *bucket) bool { return now-b.last > int64(24*time.Hour) })
	// A block that runs is never dropped: one set by hand or by an agent has
	// no ladder memory (lastUntil 0) and went with the first sweep.
	e.blocks.sweep(func(_ Key, b *blockState) bool { return b.until <= now && now-b.lastUntil > int64(repeatMemory) })
	e.sweepLong(now)
	e.released.sweep(func(_ Key, t *int64) bool { return now-*t > int64(30*24*time.Hour) })
	e.sweepDistributed(time.Unix(0, now))
}

// Sizes reports the number of entries per table (tests, metrics).
func (e *Engine) Sizes() (clients, buckets, blocks int) {
	return e.clients.len(), e.buckets.len(), e.blocks.len()
}
