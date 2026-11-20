// Package gate is the request path of `schild run`: client attribution,
// allowlist, hard limits, the timed WAF phases, the decision, the block page
// and the local bookkeeping (events, counters, incidents).
//
// Guarantees (MVP-02):
//   - A request that could not be inspected never reaches the backend: body
//     and parse limits are rejected, and a WAF evaluation that exceeds
//     eval_timeout_ms is answered with 503 (never passed) and cancelled.
//   - WAF work is bounded: a fixed number of evaluation slots (EvalLimits);
//     without a free slot within a short wait the answer is 503.
//   - Storage is never in the request path: events and incidents are handed
//     to background goroutines with non-blocking sends.
//   - The WAF instance is read once per request (atomic pointer), so a rule
//     swap never affects a request in flight.
package gate

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/deutschland-schild/schild/gateway/internal/accesslock"
	"io"
	"log/slog"
	"math"
	mrand "math/rand/v2"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3/types"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/geo"
	"github.com/deutschland-schild/schild/gateway/internal/humancheck"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/redact"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/stats"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// Settings can change at runtime (dashboard) and are swapped atomically.
type Settings struct {
	Mode   string
	Limits waf.Limits
	// Body are the body limits of D41 (bodylimit). Unset values take the
	// defaults, MaxInFlight bodylimit.FallbackInFlight.
	Body bodylimit.Limits
	// Requests are the limits of waiting requests of D45. Unset values take the
	// defaults, Max bodylimit.FallbackWaitingRequests.
	Requests    bodylimit.RequestLimits
	EvalTimeout time.Duration
	Resolver    *clientip.Resolver
	// EventsPerSecond: unremarkable requests are recorded up to this rate,
	// above it only SampleRate of them.
	EventsPerSecond int
	SampleRate      float64
}

// Counters are the in-memory statistics shared with the dashboard.
type Counters struct {
	Rolling stats.Rolling
	Hits    *stats.Hits
	Latency stats.Latency
}

// NewCounters returns empty counters.
func NewCounters() *Counters {
	return &Counters{Hits: stats.NewHits()}
}

// RuleEffects says what a matched rule does right now (contract/rules, D73):
// the one per-request lookup of every repository. For crs and local id is
// any rule of the repository, for crowdsec the base id.
type RuleEffects interface {
	Effect(repository string, id int, mode string, now time.Time) rules.Rule
}

// Gate is the request handler.
type Gate struct {
	Engine     *waf.Engine
	Rules      RuleEffects // the rule repositories (D73); nil: every repository blocks, a crowdsec match only logs
	Allow      *allowlist.List
	Geo        *geo.DB
	Events     *eventlog.Log
	Counters   *Counters
	Metrics    *metrics.Metrics
	Exceptions *Exceptions
	// Proxies notices a proxy in front that is not trusted (D91).
	Proxies clientip.Watch
	Log     *slog.Logger
	Now     func() time.Time
	// TestHook runs inside the timed WAF phases (tests only).
	TestHook func(phase string)
	// Summary counts every request into hourly summaries without IPs.
	Summary func(outcome, country string, t time.Time)
	// Behaviour is MVP-17 (scenarios over several requests, rate limits);
	// nil disables it. Local only.
	Behaviour *behaviour.Engine
	// Monitor counts every finished request (MVP-21); nil disables it.
	Monitor *monitoring.Monitor
	// Sites resolves the website of an incident (v0.5, D36) and the
	// website name of the waiting page (D37).
	Sites *sites.Registry
	// Access is the access lock (D56, MVP-14 step 1); nil disables it.
	Access *accesslock.Lock
	// HumanCheck is browser verification and Under Attack (MVP-12 v1_cut); nil disables it.
	HumanCheck *humancheck.Gate
	// Crawlers is the crawler policy of the websites (D57, MVP-29); nil
	// disables it.
	Crawlers *crawlers.Control

	// waitingOff is waiting_page.enabled false (D37; the default is on).
	waitingOff atomic.Bool
	// siteID and jitter override the website lookup and the Retry-After
	// draw of the waiting page decision (tests only).
	siteID func(host string) string
	jitter func() uint32

	settings   atomic.Pointer[Settings]
	incidents  chan *store.Incident
	flushes    chan chan struct{} // FlushIncidents requests
	agg        *aggregator        // D38 incident aggregation
	drops      ratelog.Limiter    // "incident queue full" (D38 section 5)
	storeErrs  ratelog.Limiter    // "store incident"
	hitErrs    ratelog.Limiter    // "store incident hits"
	evals      atomic.Pointer[evalPool]
	bodies     bodyLimiter
	sessionKey []byte
	ready      atomic.Bool
	rate       struct {
		mu     sync.Mutex
		second int64
		n      int
	}
}

// New returns a gate. Call Run to start the incident writer.
func New(s Settings) *Gate {
	g := &Gate{Now: time.Now, incidents: make(chan *store.Incident, 4096), flushes: make(chan chan struct{}), Exceptions: NewExceptions(),
		agg: newAggregator(storage.MaxOpenAggregates)}
	g.sessionKey = make([]byte, 32)
	_, _ = rand.Read(g.sessionKey)
	g.SetSettings(s)
	g.SetEvalLimits(EvalLimits{})
	return g
}

// SetSettings swaps the runtime settings.
func (g *Gate) SetSettings(s Settings) {
	if s.EvalTimeout <= 0 {
		s.EvalTimeout = time.Second
	}
	if s.EventsPerSecond == 0 {
		s.EventsPerSecond = 20
	}
	if s.SampleRate == 0 {
		s.SampleRate = 0.01
	}
	s.Body = normBody(s.Body)
	s.Requests = normRequests(s.Requests)
	g.settings.Store(&s)
}

// Settings returns the current settings.
func (g *Gate) Settings() Settings { return *g.settings.Load() }

// SetReady marks the gate ready (after the first WAF instance exists).
func (g *Gate) SetReady(v bool) { g.ready.Store(v) }

// Ready reports readiness.
func (g *Gate) Ready() bool { return g.ready.Load() && g.Engine != nil && g.Engine.Current() != nil }

// RunIncidents writes incidents until ctx ends.
func (g *Gate) RunIncidents(ctx context.Context, st *store.Store) {
	tick := time.NewTicker(ratelog.Interval)
	defer tick.Stop()
	hits := time.NewTicker(aggFlushInterval)
	defer hits.Stop()
	insert := func(ctx context.Context, in *store.Incident) {
		if in.Site == "" && in.Host != "" && g.Sites != nil {
			in.Site = g.Sites.ID(in.Host)
		}
		if err := st.InsertIncident(ctx, in); err != nil {
			g.storeErrs.LogAt(g.Log, g.Now(), slog.LevelError, "store incident", "err", err)
		}
	}
	// drain inserts what is queued now, so the hits of a flush find the
	// rows of their incidents.
	drain := func(ctx context.Context) {
		for {
			select {
			case in := <-g.incidents:
				insert(ctx, in)
			default:
				return
			}
		}
	}
	for {
		select {
		case <-tick.C:
			g.drops.Flush(g.Log, g.Now(), slog.LevelWarn, msgIncidentQueueFull)
		case <-hits.C:
			drain(ctx)
			g.flushHits(ctx, st)
		case done := <-g.flushes:
			drain(ctx)
			g.flushHits(ctx, st)
			close(done)
		case <-ctx.Done():
			g.drops.Flush(g.Log, g.Now().Add(ratelog.Interval), slog.LevelWarn, msgIncidentQueueFull)
			drain(context.Background())
			g.flushHits(context.Background(), st)
			return
		case in := <-g.incidents:
			insert(ctx, in)
		}
	}
}

// FlushIncidents has the incident writer (RunIncidents) store every queued
// incident and fold every pending aggregation hit now, and waits for it
// or ctx. Tests and harnesses use it instead of waiting for the next
// aggFlushInterval tick.
func (g *Gate) FlushIncidents(ctx context.Context) {
	done := make(chan struct{})
	select {
	case g.flushes <- done:
	case <-ctx.Done():
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Health paths answered on the proxy port without inspection.
const (
	HealthPath = "/.schild/healthz"
	ReadyPath  = "/.schild/readyz"
)

// Handler wraps next (the reverse proxy).
func (g *Gate) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.Serve(w, r, next) })
}

type reqInfo struct {
	start     time.Time
	eventID   string
	requestID string // X-Request-Id of a trusted proxy, else the event id
	client    clientip.Result
	geo       geo.Info
	allow     string
	analysis  *waf.Analysis
	wafTime   time.Duration
	limit     *waf.LimitError
	decision  decide.Output
	hits      []decide.Hit
	status    int
	incident  string
	mode      string
	sampled   bool
	params    []string
	evaluated bool
	// MVP-17
	breq      *behaviour.Request
	stopped   bool // answered by a behaviour block or a rate limit
	forwarded bool
	resp      behaviour.Response
	userHash  uint64
	hasUser   bool
	// MVP-18
	shape      string
	shapeRules []int
	// MVP-21 monitoring: the response writer and body counter live in the
	// request info, so counting adds no allocation.
	sw          statusWriter
	body        countingBody
	upstreamDur time.Duration
	notReady    bool
	wouldRL     bool // an exceeded rate limit was only observed
	// waiting: answered with the waiting page (D37): no incident, and its
	// event is sampled like an unremarkable request.
	waiting bool
	// closeNow: a refused body under memory pressure ends its connection with
	// the answer (closeRefused, D45).
	closeNow bool
	// quiet: refused by the body limits (D41): no incident, and its event is
	// sampled like an unremarkable request.
	quiet bool
	// admission counts this request's body while it is read (D41).
	admission *admission
	// waitAdmission counts this request until it ended (D45).
	waitAdmission *requestAdmission
	// D38: joined is a WAF or limit block that joined the open incident of
	// its aggregate key (no row of its own).
	joined bool
	aggKey aggKey
	// D33 amendment: the request's re-check state (Caddy adapter; nil in
	// proxy mode), this evaluation's place in it and whether it left it;
	// the request as inspected; rechecked and checkedPaths of the combined
	// record (combine).
	recheck      *Recheck
	seq          int
	left         bool
	req          *http.Request
	rechecked    bool
	checkedPaths []string
	// end and timed are taken when the evaluation finishes (the record may
	// be written after the response, see Recheck).
	end   time.Time
	timed bool
	// D57 crawler control: crawlerNone, crawlerWould or crawlerBlocked,
	// the rule that hit, the reason of a would_block, and whether the
	// outcome would_block is the crawler rule's alone (crawlerOutcome).
	crawler       uint8
	crawlerRule   uint8
	crawlerReason string
	crawlerOnly   bool
	// site is the website of the request once reqSite looked it up, or
	// the website of the Caddy route from the start (ServeRouted).
	site      string
	siteKnown bool
}

// countingBody counts the request body bytes the gate reads (bytes_in).
type countingBody struct {
	rc io.ReadCloser
	n  int64
	// ended: the body gave its end or an error, nothing is left to drain.
	ended bool
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n += int64(n)
	c.ended = c.ended || err != nil
	return n, err
}

func (c *countingBody) Close() error { return c.rc.Close() }

// Serve handles one request.
func (g *Gate) Serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	g.serve(w, r, next, nil, "")
}

func (g *Gate) serve(w http.ResponseWriter, r *http.Request, next http.Handler, st *Recheck, website string) {
	if r.URL.Path == HealthPath || r.URL.Path == ReadyPath {
		g.health(w, r)
		return
	}
	set := g.settings.Load()
	ri := &reqInfo{start: g.Now(), eventID: msg.NewID(), mode: set.Mode}
	if website != "" {
		ri.site, ri.siteKnown = website, true
	}
	if st != nil {
		ri.recheck, ri.req = st, inspected(r)
		st.enter(ri)
		defer g.leaveUnfinished(ri, r)
	}
	ri.sw = statusWriter{ResponseWriter: w, status: http.StatusOK}
	w = &ri.sw
	if r.Body != nil && r.Body != http.NoBody {
		ri.body.rc = r.Body
		r.Body = &ri.body
	}
	ri.client = set.Resolver.Resolve(r)
	g.Proxies.Note(ri.start, ri.client.Ignored)
	ri.requestID = ri.eventID
	// A trusted front proxy's request id joins the local event to the proxy's
	// logs (and the test lab's ground truth). Local only.
	if v := r.Header.Get("X-Request-Id"); v != "" && requestIDRe.MatchString(v) && ri.client.Peer.IsValid() && set.Resolver.Trusted(ri.client.Peer) {
		ri.requestID = v
	}
	if g.Geo != nil {
		ri.geo = g.Geo.Lookup(ri.client.IP)
	} else {
		ri.geo = geo.Unknown
	}
	if g.Allow != nil {
		ri.allow, _ = g.Allow.Match(ri.client.IP, ri.start)
	}
	// The access lock comes before everything that could pass a request on
	// (D56): nothing of a locked website reaches the app without a way in.
	if g.Access != nil && g.accessStop(w, r, ri) {
		return
	}
	// Browser verification endpoints ({prefix}verify and {prefix}continue).
	if g.HumanCheck != nil && g.humanCheckEndpoint(w, r, ri) {
		return
	}
	// Crawlers that name themselves, before any work for them (D57).
	if g.Crawlers != nil && g.crawlerStop(w, r, ri) {
		return
	}
	var bv behaviour.Verdict
	if g.Behaviour != nil && ri.client.IP.IsValid() {
		ri.breq = g.behaviourRequest(r, ri)
		bv = g.Behaviour.Check(ri.breq)
		if bv.Block || bv.RateLimited {
			g.behaviourStop(w, r, ri, bv)
			return
		}
		ri.wouldRL = bv.WouldRateLimit
	}
	// Browser verification ("Kurze Prüfung") and Under Attack (MVP-12 v1_cut).
	if g.HumanCheck != nil && g.humanCheckStop(w, r, ri, bv) {
		return
	}
	// Comes before any WAF work and before the allowlist level that skips it:
	// the memory of a waiting request does not depend on who sent it (D45).
	if !g.admitRequest(w, r, ri, set) {
		return
	}
	defer ri.endRequest()
	if ri.allow == allowlist.BypassWAF {
		ri.decision = decide.Output{Outcome: decide.Passed}
		g.forward(w, r, next, ri)
		return
	}
	inst := g.Engine.Current()
	if inst == nil {
		// No WAF yet (startup): fail closed, never pass uninspected.
		ri.limit = waf.ErrTimeout
		ri.notReady = true
		g.block(w, r, ri)
		return
	}
	if waf.HasBody(r) {
		// Admission comes before any WAF work, so a refused client costs no
		// transaction (D41). The count ends with the read, at the latest here.
		if !g.admitBody(w, r, ri, set) {
			return
		}
		defer ri.endRead()
	}
	ri.evaluated = true
	if err := waf.Precheck(r, set.Limits); err != nil {
		ri.limit, _ = waf.IsLimit(err)
		g.block(w, r, ri)
		return
	}
	tx, cancel := inst.NewTransaction()
	owned := true
	var guard *bodyGuard
	// Closing removes the temp files of the body, so its held bytes end here,
	// also when a background goroutine closes after a timeout.
	closeTx := func() {
		_ = tx.Close()
		guard.release()
	}
	defer func() {
		if owned {
			closeTx()
		}
	}()
	ipStr := ""
	if ri.client.IP.IsValid() {
		ipStr = ri.client.IP.String()
	}
	pool := g.evals.Load()
	shape := Shape{QueryArgs: waf.QueryArgs(r.URL.RawQuery), QueryBytes: len(r.URL.RawQuery), TargetBytes: waf.TargetBytes(r) + len(r.Host), Cookies: waf.CookieCount(r)}
	cost := g.cost(pool.lim, shape, ri)
	t0 := time.Now()
	res := g.runEval(cost, set.EvalTimeout, cancel, func() {
		if g.TestHook != nil {
			g.TestHook("headers")
		}
		waf.ProcessHeaders(tx, r, ipStr, ri.client.Port)
	}, closeTx)
	ri.wafTime = time.Since(t0)
	if res != evalDone {
		g.evalFailed(w, r, ri, res, &owned)
		return
	}
	// The body is read outside the evaluation budget and without a slot, but
	// under the admission and held bytes of D41, within the hard size limit:
	// an over-limit body is rejected while it streams in (declared sizes
	// already in Precheck), before phase 2 ever runs. How long the read lasts
	// is bounded by the server: read_body in the Caddyfile of ingress mode,
	// the read timeout in proxy mode. Coraza keeps up to 128 KiB in memory and
	// spills the rest to a temporary file.
	orig := r.Body
	if waf.HasBody(r) {
		guard = g.newBodyGuard(r, ri, set)
		r.Body = guard
	}
	body, info, err := waf.ReadBodyInfo(tx, r, set.Limits)
	if guard != nil {
		guard.finish()
		r.Body = orig
	}
	ri.endRead()
	if err != nil {
		ri.limit = guard.verdict(r, err)
		if ri.limit == waf.ErrClientGone {
			g.clientGone(w, r, ri)
			return
		}
		ri.quiet = ri.limit == waf.ErrBodyBusy
		g.block(w, r, ri)
		return
	}
	var mrs []types.MatchedRule
	t1 := time.Now()
	// Phase 2 gets what is left of eval_timeout after phase 1, plus the
	// allowance for a text body; expensive requests take a heavy slot.
	shape.Body = info
	cost = g.cost(pool.lim, shape, ri)
	res = g.runEval(cost, bodyBudget(pool.lim, set.EvalTimeout, shape)-ri.wafTime, cancel, func() {
		if g.TestHook != nil {
			g.TestHook("body")
		}
		_, _ = tx.ProcessRequestBody()
		mrs = tx.MatchedRules()
		if g.TestHook != nil {
			g.TestHook("body-done")
		}
	}, closeTx)
	ri.wafTime += time.Since(t1)
	if res != evalDone {
		g.evalFailed(w, r, ri, res, &owned)
		return
	}
	ri.analysis = inst.Analyze(mrs)
	g.applyRules(ri, set)
	if ri.analysis.BodyError {
		ri.limit = waf.ErrBodyUnparseable
		g.block(w, r, ri)
		return
	}
	if ri.analysis.ArgsLimit {
		// Coraza >= 3.8 drops arguments beyond SecArgumentsLimit, so the
		// tail of the request was never inspected (M1, K3).
		ri.limit = waf.ErrTooManyArgs
		g.block(w, r, ri)
		return
	}
	ri.decision = decide.Decide(decide.Input{Allow: ri.allow, Hits: ri.hits, AnyMatch: len(ri.analysis.Matches) > 0})
	if len(ri.analysis.Matches) > 0 && ri.allow == "" {
		ri.params = paramNames(r, tx)
	}
	if ri.decision.Outcome == decide.Blocked {
		g.block(w, r, ri)
		return
	}
	if ri.breq != nil {
		// MVP-18 shape_block: a malicious request shape seen from many
		// senders is stopped for any sender while its wave runs.
		if rules := wafRuleIDs(ri); len(rules) > 0 && ri.allow == "" {
			ri.shapeRules = sortedUnique(rules)
			ri.shape = requestShapeSig(r, ri.params, ri.shapeRules)
			if inc, ok := g.Behaviour.ShapeBlocked(ri.shape, ri.start); ok {
				g.shapeStop(w, r, ri, inc)
				return
			}
		}
		if fields := g.Behaviour.LoginUserFields(ri.breq.Method, ri.breq.Path, ri.breq.RawQuery); len(fields) > 0 {
			ri.userHash, ri.hasUser = loginUserHash(r, tx, fields)
			if ri.hasUser && ri.allow == "" {
				// MVP-18 account_slowdown: an attacked account waits, never locks.
				if v := g.Behaviour.AccountWait(ri.breq, ri.userHash); v.RateLimited {
					g.behaviourStop(w, r, ri, v)
					return
				}
			}
		}
	}
	// The transaction holds every transformed argument value of the
	// evaluation (Coraza's per-phase cache, tens of MiB for a request with
	// many arguments) and a text body as a string. Close it before the backend
	// answers, so a slow backend does not keep that memory alive. The body
	// leaves it first and stays counted until the request ended (D44).
	var wb *waitingBody
	if body != nil {
		var err error
		if wb, err = newWaitingBody(body, info.Bytes); err != nil {
			// The copy failed on our disk: the client is not at fault.
			ri.limit, ri.quiet = waf.ErrBodyBusy, true
			g.block(w, r, ri)
			return
		}
		defer g.bodies.wait(ri.client.IP, info.Bytes, g.Metrics).end()
		orig := r.Body
		r.Body = struct {
			io.Reader
			io.Closer
		}{wb, orig}
	}
	owned = false
	_ = tx.Close()
	guard.settle(info.Bytes)
	defer func() {
		wb.remove()
		guard.release()
	}()
	g.forward(w, r, next, ri)
}

// CrowdsecSource is the decision source of a crowdsec rule (incidents,
// exceptions).
func CrowdsecSource(baseID int) string { return rules.RepoCrowdsec + ":" + strconv.Itoa(baseID) }

// effect is what a rule of repository does now; without repositories (tests)
// crs and local block in their mode and a crowdsec rule only detects.
func (g *Gate) effect(repository string, id int, mode string, now time.Time) rules.Rule {
	if g.Rules != nil {
		return g.Rules.Effect(repository, id, mode, now)
	}
	in := rules.Input{Mode: mode, State: rules.StateBlock, Origin: rules.OriginRelease, Now: now.Unix()}
	if repository == rules.RepoCrowdsec {
		in.State = rules.StateDetect
	}
	return rules.Compute(in)
}

// applyRules decides what every matched repository does on this request
// (contract/rules, D73): the CRS by its anomaly score, local rules when one of
// them blocks, every crowdsec rule on its own. A crowdsec rule without effect
// leaves the analysis: it does not count for anything. Only a match that may
// block feeds behaviour counters (Match.Counts); a repository in detect never
// blocks, also not indirectly. The CRS score was computed before and stays.
func (g *Gate) applyRules(ri *reqInfo, set *Settings) {
	a := ri.analysis
	ip := ri.client.IP
	q := rules.Request{Allow: ri.allow}
	act := func(src string, r rules.Rule) rules.Action {
		q.Excepted = g.Exceptions.Has(ip, src, ri.start)
		x := rules.Apply(r, q)
		if x.Action != rules.ActionNone {
			ri.hits = append(ri.hits, decide.Hit{Source: src, Action: x.Action, WouldBlockReason: x.WouldBlockReason})
		}
		return x
	}
	crs := g.effect(rules.RepoCRS, 0, set.Mode, ri.start)
	local := g.effect(rules.RepoLocal, 0, set.Mode, ri.start)
	if a.CRSBlock {
		act("crs", crs)
	}
	if a.LocalBlock {
		act("local", local)
	}
	feeds := func(r rules.Rule) bool { return r.Effect == rules.EffectBlock || r.Effect == rules.EffectWouldBlock }
	kept := a.Matches[:0]
	for _, m := range a.Matches {
		switch m.Source {
		case waf.SourceCrowdsec:
			x := act(CrowdsecSource(m.Hub.BaseID), g.effect(rules.RepoCrowdsec, m.Hub.BaseID, set.Mode, ri.start))
			if x.Action == rules.ActionNone {
				continue
			}
			m.Counts = x.CountsAsHit
		case waf.SourceCRS:
			m.Counts = feeds(crs)
		case waf.SourceLocal:
			m.Counts = feeds(local)
		}
		kept = append(kept, m)
	}
	a.Matches = kept
}

// cost estimates one evaluation phase and keys it to the client.
func (g *Gate) cost(l EvalLimits, s Shape, ri *reqInfo) Cost {
	c := l.Estimate(s)
	c.Client, c.Net = clientKey(ri.client.IP), netKey(ri.client.IP)
	c.Shared = ri.geo.NetClass == "cgnat" || ri.geo.NetClass == "mobile"
	return c
}

// clientKey is the address for IPv4 and the /64 for IPv6 ("" without one).
func clientKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return ip.String()
	}
	p, _ := ip.Prefix(64)
	return p.String()
}

// netKey is the /48 of an IPv6 address ("" otherwise). It cannot collide with
// clientKey: that is a /64 or an IPv4 address.
func netKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return ""
	}
	p, _ := ip.Prefix(48)
	return p.String()
}

// bodyBudget is the evaluation budget of a request: eval_timeout, plus
// BodyAllowance per KiB of body the rules read as text, at most MaxBudget
// (never less than eval_timeout). CRS cost grows with the text it reads
// (about 3 ms per KiB on the measurement machine), so with a fixed second a
// harmless 388 KB form was answered 503 every time (MVP-19 re-measurement,
// finding 4). Such bodies run on the heavy slots within the memory budget,
// so the longer budget never takes slots from ordinary requests. A body the
// rules cannot finish within MaxBudget is answered 503 (waf_timeout) as
// before: never passed uninspected.
func bodyBudget(l EvalLimits, base time.Duration, s Shape) time.Duration {
	text := s.textBytes()
	if text <= 0 {
		return base
	}
	b := base + time.Duration(text>>10)*l.BodyAllowance
	return max(base, min(b, l.MaxBudget))
}

// evalFailed answers a phase that did not finish: 503 + Retry-After, never
// passed. After a timeout the background goroutine owns the transaction.
func (g *Gate) evalFailed(w http.ResponseWriter, r *http.Request, ri *reqInfo, res evalResult, owned *bool) {
	switch res {
	case evalTimedOut:
		*owned = false
		ri.limit = waf.ErrTimeout
	case evalBusy:
		ri.limit = waf.ErrBusy
	default:
		ri.limit = waf.ErrTimeout
	}
	g.block(w, r, ri)
}

func (g *Gate) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == ReadyPath && !g.Ready() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "not ready\n")
		return
	}
	_, _ = io.WriteString(w, "ok\n")
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
	bytes  int64
	// upstream: monitoring.UpstreamError or UpstreamTimeout when the proxy
	// got no (timely) answer (NoteUpstream).
	upstream uint8
	// forwarding: the request went to the next handler (backend); its
	// response headers lose a Schild-Waiting marker (stripMarker) unless
	// own is set.
	forwarding bool
	// own: a schild handler further down the chain (a re-check, D33) wrote
	// its own waiting answer through this writer (markOwn).
	own bool
}

func (s *statusWriter) WriteHeader(code int) {
	s.stripMarker()
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.stripMarker()
		s.status, s.wrote = http.StatusOK, true
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Flush() {
	if !s.wrote {
		s.stripMarker() // a flush sends the headers
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		// A proxy writes the 101 headers itself after the hijack.
		s.stripMarker()
		s.status, s.wrote = http.StatusSwitchingProtocols, true
		return h.Hijack()
	}
	return nil, nil, errors.New("hijack not supported")
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// NoteStatus records the status that an outer handler will write for this
// response (Caddy's error handling, MVP-19 ingress mode) when the next
// handler returned an error without writing. w is the writer the gate passed
// to the next handler; other writers are ignored.
func NoteStatus(w http.ResponseWriter, code int) {
	if s, ok := w.(*statusWriter); ok && !s.wrote {
		s.status = code
	}
}

// NoteUpstream records that the proxy got no response (status 502 or any
// other handler error) or none in time (504) for this request (MVP-21
// upstream_errors, upstream_timeouts). A 5xx the app itself sends is not an
// upstream error. w is the writer the gate passed to the next handler.
func NoteUpstream(w http.ResponseWriter, status int) {
	if s, ok := w.(*statusWriter); ok {
		if status == http.StatusGatewayTimeout {
			s.upstream = monitoring.UpstreamTimeout
		} else {
			s.upstream = monitoring.UpstreamError
		}
	}
}

func (g *Gate) forward(_ http.ResponseWriter, r *http.Request, next http.Handler, ri *reqInfo) {
	sw := &ri.sw
	dropTunnelUpgrades(r.Header)
	t0 := time.Now()
	sw.forwarding = true
	next.ServeHTTP(sw, r)
	ri.upstreamDur = time.Since(t0)
	ri.status = sw.status
	ri.forwarded = true
	if ri.breq != nil {
		// Status, redirect target and cookie names only (login failure
		// patterns of the presets); never a body or a cookie value.
		h := sw.Header()
		ri.resp = behaviour.Response{Status: sw.status, Location: h.Get("Location"), CookieNames: cookieNames(h)}
	}
	g.finish(r, ri)
}

func (g *Gate) block(w http.ResponseWriter, r *http.Request, ri *reqInfo) {
	g.countAbort(ri)
	if g.overload(w, r, ri) {
		return
	}
	if !ri.quiet {
		g.drawIncident(ri)
	}
	status := 403
	if ri.limit != nil {
		status = ri.limit.Status
		ri.decision = decide.Output{Outcome: decide.Blocked, Status: status, Sources: []string{"limit:" + ri.limit.Code}}
		if g.Metrics != nil {
			g.Metrics.HardLimits.WithLabelValues(ri.limit.Code).Inc()
		}
	} else if ri.decision.Status != 0 {
		status = ri.decision.Status
	}
	ri.status = status
	g.drain(w, r, ri)
	blockpage.Write(w, r, status, ri.incident, ri.start)
	g.finish(r, ri)
}

// requestIDRe is the events.schema.json request_id format.
var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

var protocols = map[string]string{"HTTP/1.0": "http/1.0", "HTTP/1.1": "http/1.1", "HTTP/2.0": "h2", "HTTP/3.0": "h3"}

var methodRe = regexp.MustCompile(`^[A-Z]{1,16}$`)

// finish ends one evaluation and records the request (complete), once
// every evaluation of it is done (Recheck).
func (g *Gate) finish(r *http.Request, ri *reqInfo) {
	if ri.closeNow {
		closeRefused(&ri.sw)
	}
	ri.end = g.Now()
	ri.timed = timedOf(ri)
	ri.crawlerOnly = crawlerOutcome(ri)
	if ri.recheck != nil {
		g.finishChecked(ri, r)
		return
	}
	g.complete(r, ri)
}

// complete records one request: counters, monitoring, metrics, behaviour,
// incident and event. r is the request as schild inspected it.
func (g *Gate) complete(r *http.Request, ri *reqInfo) {
	now := ri.end
	dur := now.Sub(ri.start)
	set := g.settings.Load()
	c := g.Counters
	outcome := ri.decision.Outcome
	if ri.limit == waf.ErrClientGone {
		// Nobody blocked this request: the client left or stalled (D46).
		outcome = bodylimit.OutcomeClientGone
	}
	if c != nil {
		c.Rolling.Add(stats.Requests, 1, now)
		if ri.evaluated {
			c.Rolling.Add(stats.Evaluated, 1, now)
			c.Latency.Observe(ri.wafTime, now)
		}
		switch outcome {
		case decide.Blocked:
			c.Rolling.Add(stats.Blocked, 1, now)
			if !ri.stopped && !ri.waiting && !ri.quiet && !ri.joined {
				c.Rolling.Add(stats.Incidents, 1, now)
			}
		case decide.WouldBlock:
			c.Rolling.Add(stats.WouldBlock, 1, now)
		}
	}
	if g.Summary != nil {
		g.Summary(outcome, ri.geo.Country, now)
	}
	// Whether an event is written is decided here, before the monitor
	// records the request, so the MVP-22 request ring can carry the event
	// id. Requests stopped by a running behaviour block or a rate limit are
	// sampled like unremarkable ones: the hit itself is its own event, and a
	// flood from a blocked address must not flood the event store.
	emitted := false
	if g.Events != nil {
		a := ri.analysis
		// A would_block of the crawler policy alone is sampled too (D57):
		// a crawler must not fill the event store.
		interesting := !ri.stopped && !ri.waiting && !ri.quiet && (outcome != decide.Passed && !ri.crawlerOnly || ri.allow != "" || (a != nil && len(a.Matches) > 0))
		// A client that left leaves no event at all (D41).
		emitted = ri.limit != waf.ErrClientGone && (interesting || g.sample(now, set))
		ri.sampled = emitted && !interesting
	}
	if g.Monitor != nil {
		g.record(r, ri, dur, emitted)
	}
	if g.Metrics != nil {
		g.Metrics.Requests.WithLabelValues(outcome).Inc()
		if ri.evaluated {
			g.Metrics.WAFSeconds.Observe(ri.wafTime.Seconds())
		}
	}
	a := ri.analysis
	var ruleIDs []string
	if a != nil {
		for i := range a.Matches {
			m := &a.Matches[i]
			id := m.Key()
			ruleIDs = append(ruleIDs, id)
			if c != nil {
				c.Hits.Add(id, now)
				c.Hits.Note(id, redact.Text(m.Msg))
			}
		}
	}
	if ri.breq != nil && !ri.stopped {
		ri.breq.Time = now
		g.Behaviour.Observe(ri.breq, behaviour.Outcome{Forwarded: ri.forwarded, Response: ri.resp, UserHash: ri.userHash, HasUser: ri.hasUser, WAFRules: wafRuleIDs(ri),
			Shape: ri.shape, ShapeRules: ri.shapeRules})
	}
	if ri.decision.Outcome == decide.Blocked && !ri.stopped && !ri.waiting && !ri.quiet && !ri.joined {
		g.writeIncident(ri, ruleIDs, r.Host)
	}
	if !emitted {
		return
	}
	g.emit(r, ri, ruleIDs, now, dur)
}

func (g *Gate) sample(now time.Time, set *Settings) bool {
	sec := now.Unix()
	g.rate.mu.Lock()
	if g.rate.second != sec {
		g.rate.second, g.rate.n = sec, 0
	}
	g.rate.n++
	n := g.rate.n
	g.rate.mu.Unlock()
	if n <= set.EventsPerSecond {
		return true
	}
	return mrand.Float64() < set.SampleRate
}

// QueueIncident stores an incident in the background (MVP-17 behaviour
// blocks create one incident per block, not per request). Never blocks.
func (g *Gate) QueueIncident(in *store.Incident) {
	select {
	case g.incidents <- in:
	default:
		g.dropIncident(in.Incident)
	}
}

func (g *Gate) writeIncident(ri *reqInfo, ruleIDs []string, host string) {
	reason := ""
	sources := ri.decision.Sources
	if ri.limit != nil {
		reason = "limit " + ri.limit.Code
	} else if ri.analysis != nil {
		reason = ri.analysis.TopMsg
		ids := blockRuleIDs(ri.analysis)
		if len(ids) > 0 {
			reason = strings.Join(ids, ", ") + " " + reason
		}
	}
	if len(reason) > 300 {
		reason = reason[:300]
	}
	ip := ""
	if ri.client.IP.IsValid() {
		ip = ri.client.IP.String()
	}
	in := &store.Incident{Incident: ri.incident, EventID: ri.eventID, Time: ri.start.UTC(), IP: ip, Status: "blocked",
		Reason: redact.Text(reason), Sources: sources, Host: host}
	select {
	case g.incidents <- in:
	default:
		g.dropIncident(ri.incident)
		if g.agg != nil && ri.aggKey.client != "" {
			g.agg.forget(ri.aggKey, ri.incident)
		}
	}
}

// msgIncidentQueueFull is the rate-limited warning of a full incident queue.
const msgIncidentQueueFull = "incident queue full, incidents not stored"

// dropIncident counts an incident that was not stored and logs it at most
// once per ratelog.Interval with the number suppressed (D36 fix round 2,
// re-measurement C: a flood wrote 589,781 lines, 89 MB in 3 min; D38
// section 5). Lock-free and allocation-free when suppressed.
func (g *Gate) dropIncident(incident string) {
	if n, ok := g.drops.Allow(g.Now()); ok && g.Log != nil {
		g.Log.Warn(ratelog.Msg(msgIncidentQueueFull, n), "incident", incident)
	}
}

var contentTypes = map[string]string{
	"application/x-www-form-urlencoded": "application/x-www-form-urlencoded", "multipart/form-data": "multipart/form-data",
	"application/json": "application/json", "application/xml": "application/xml", "text/xml": "application/xml", "text/plain": "text/plain",
}

func shapeContentType(ct string) string {
	if ct == "" {
		return "none"
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return "other"
	}
	if v, ok := contentTypes[mt]; ok {
		return v
	}
	if strings.HasSuffix(mt, "+json") {
		return "application/json"
	}
	return "other"
}

func (g *Gate) emit(r *http.Request, ri *reqInfo, ruleIDs []string, now time.Time, dur time.Duration) {
	ip := ""
	if ri.client.IP.IsValid() {
		ip = ri.client.IP.String()
	}
	method := strings.ToUpper(r.Method)
	if !methodRe.MatchString(method) {
		method = "OTHER"
	}
	host := r.Host
	if len(host) > 253 {
		host = host[:253]
	}
	path := redact.Path(r.URL.EscapedPath())
	ua := redact.UserAgent(r.UserAgent())
	session := g.session(ri.client.IP, r.UserAgent(), ri.start)
	data := events.Request{
		RequestID: ri.requestID, Incident: ri.incident,
		Client: events.Client{IP: ip, Port: ri.client.Port, Attribution: ri.client.Attribution, Allowlisted: ri.allow != "",
			Geo: events.Geo{Country: ri.geo.Country, City: trim(ri.geo.City, 128), ASN: ri.geo.ASN, ASOrg: trim(ri.geo.ASOrg, 256), NetClass: ri.geo.NetClass}},
		Method: method, Host: host, Path: path, Query: redact.Query(r.URL.RawQuery), Protocol: protocols[r.Proto],
		Status: ri.status, UserAgent: ua, SessionID: session, Rules: []events.MatchedRule{}, Outcome: ri.decision.Outcome, Mode: ri.mode,
		DurationMS: round3(float64(dur) / float64(time.Millisecond)), WAFMS: round3(float64(ri.wafTime) / float64(time.Millisecond)),
		Sampled: ri.sampled,
	}
	if ri.client.Port <= 0 || ri.client.Attribution != clientip.TCPPeer {
		data.Client.Port = 0
	}
	if data.Status < 100 || data.Status > 599 {
		data.Status = 502
	}
	if ri.decision.Outcome == decide.WouldBlock {
		data.WouldBlockReason = ri.decision.WouldBlockReason
	}
	score := 0
	if a := ri.analysis; a != nil {
		score = a.Score
		ct := shapeContentType(r.Header.Get("Content-Type"))
		for _, m := range a.Matches {
			if len(data.Rules) >= 128 {
				break
			}
			mr := events.MatchedRule{ID: m.ID, Repository: m.Source, Msg: trim(redact.Text(m.Msg), 512), Severity: m.Severity}
			if m.Source == waf.SourceInternal {
				mr.Repository = rules.RepoCRS // the engine's own rules (200000..200099)
			}
			if m.Hub != nil {
				mr.Crowdsec = &events.CrowdsecRuleRef{Name: m.Hub.Name, Version: m.Hub.Version, Label: m.Hub.Label, CVEs: m.Hub.CVEs}
			}
			if m.Location != "" {
				mr.MatchShape = &msg.MatchShape{Location: m.Location, ContentType: ct, LenBucket: msg.LenBucket(m.ValueLen)}
			}
			data.Rules = append(data.Rules, mr)
		}
	}
	data.Score = score
	typ := events.RequestEvaluated
	if ri.decision.Outcome == decide.Blocked && ri.incident != "" {
		typ = events.RequestBlocked
	}
	summary := ""
	if ri.limit != nil {
		summary = "hard limit " + ri.limit.Code
	}
	var body any = data
	if len(ri.checkedPaths) > 0 {
		body = eventlog.RequestData{Request: data, CheckedPaths: ri.checkedPaths}
	}
	g.Events.EmitWithID(ri.eventID, typ, ri.start, body, eventlog.Index{
		IP: ip, Country: ri.geo.Country, ASN: ri.geo.ASN, Method: method, Host: host, Path: path, Status: data.Status, Score: score,
		Outcome: ri.decision.Outcome, Rules: ruleIDs, Incident: ri.incident, Session: session, UA: ua, Summary: summary,
	})
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func round3(v float64) float64 {
	if v < 0 || math.IsNaN(v) {
		return 0
	}
	return math.Round(v*1000) / 1000
}

// session derives a local, daily pseudonymous session id from address and
// user agent (local only, never sent).
func (g *Gate) session(ip netip.Addr, ua string, t time.Time) string {
	if !ip.IsValid() {
		return ""
	}
	m := hmac.New(sha256.New, g.sessionKey)
	m.Write([]byte(ip.String()))
	m.Write([]byte{0})
	m.Write([]byte(ua))
	m.Write([]byte{0})
	m.Write([]byte(t.UTC().Format("2006-01-02")))
	return "s_" + hex.EncodeToString(m.Sum(nil))[:16]
}

var multipartName = regexp.MustCompile(`(?i)content-disposition:[^\r\n]*\bname="([^"\r\n]{1,64})"`)

// paramNames returns query and body parameter names for the request shape
// (names only, never values).
func paramNames(r *http.Request, tx types.Transaction) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if n == "" || len(n) > 64 || seen[n] || len(out) >= 64 {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	if q, err := url.ParseQuery(r.URL.RawQuery); err == nil {
		for k := range q {
			add(k)
		}
	}
	rd, err := tx.RequestBodyReader()
	if err != nil || rd == nil {
		return out
	}
	head, _ := io.ReadAll(io.LimitReader(rd, 64<<10))
	if len(head) == 0 {
		return out
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch {
	case mt == "application/x-www-form-urlencoded":
		if q, err := url.ParseQuery(string(head)); err == nil {
			for k := range q {
				add(k)
			}
		}
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		var obj map[string]json.RawMessage
		if json.Unmarshal(head, &obj) == nil {
			for k := range obj {
				add(k)
			}
		}
	case strings.HasPrefix(mt, "multipart/"):
		for _, m := range multipartName.FindAllSubmatch(head, -1) {
			add(string(m[1]))
		}
	}
	return out
}

// Exceptions let one client past the sources that blocked an incident
// (unblock in the dashboard). A client is an IPv4 address or an IPv6 /64, as
// for incidents and blocks: an incident folds the requests of a whole /64, so
// its unblock frees that /64, not the one address of its first request
// (D43). Local only.
type Exceptions struct {
	mu sync.RWMutex
	m  map[netip.Addr][]exception
}

type exception struct {
	sources []string
	until   time.Time
}

// exceptionKey is the client of an address: IPv4 as it is, IPv6 as its /64.
func exceptionKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return ip
}

// NewExceptions returns an empty set.
func NewExceptions() *Exceptions { return &Exceptions{m: map[netip.Addr][]exception{}} }

// Add stores an exception.
func (e *Exceptions) Add(ip netip.Addr, sources []string, until time.Time) {
	k := exceptionKey(ip)
	e.mu.Lock()
	e.m[k] = append(e.m[k], exception{sources: sources, until: until})
	e.mu.Unlock()
}

// Load replaces all exceptions.
func (e *Exceptions) Load(xs []store.Exception) {
	m := map[netip.Addr][]exception{}
	for _, x := range xs {
		a, err := netip.ParseAddr(x.IP)
		if err != nil {
			continue
		}
		k := exceptionKey(a)
		m[k] = append(m[k], exception{sources: x.Sources, until: x.Expires})
	}
	e.mu.Lock()
	e.m = m
	e.mu.Unlock()
}

// Running reports whether any exception of ip runs at now: the operator
// released this client (D42, G6).
func (e *Exceptions) Running(ip netip.Addr, now time.Time) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, x := range e.m[exceptionKey(ip)] {
		if !now.After(x.until) {
			return true
		}
	}
	return false
}

// Has reports whether source is excepted for ip at now.
func (e *Exceptions) Has(ip netip.Addr, source string, now time.Time) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, x := range e.m[exceptionKey(ip)] {
		if now.After(x.until) {
			continue
		}
		for _, s := range x.sources {
			if s == source {
				return true
			}
		}
	}
	return false
}
