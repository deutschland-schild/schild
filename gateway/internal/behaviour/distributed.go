package behaviour

// MVP-18: distributed attacks through residential proxies. Senders rotate
// IP and user agent, so per-sender counters (MVP-17) never fill up. These
// detectors count by target (route, account), by request shape and by
// client fingerprint, and respond per route or per account, time-boxed,
// never by address. Everything is in memory and bounded; wave events carry
// no address, user name or account key.

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/redact"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Capacities of the distributed tables.
const (
	CapacityRoutes      = 1024
	CapacityAccounts    = 65536
	CapacityFPs         = 16384
	CapacityShapes      = 16384
	CapacityWaves       = 256
	bloomBits           = 1 << 20
	minRouteWaveSenders = 3
)

// DistributedDefaults per detector (conservative; open question of the spec:
// tune in the testlab).
var DistributedDefaults = map[string]config.DetectorThresholds{
	config.DetectorRouteWave:          {Count: 30, WindowS: 60, Factor: 5},
	config.DetectorAccountWave:        {Count: 10, WindowS: 600},
	config.DetectorShapeWave:          {Count: 20, WindowS: 60},
	config.DetectorFingerprintCluster: {Count: 20, WindowS: 300},
	config.DetectorInconsistency:      {Count: 20, WindowS: 300},
}

// Responses.
const (
	RespRouteTighten    = "route_tighten"
	RespAccountSlowdown = "account_slowdown"
	RespShapeBlock      = "shape_block"

	ReasonLearning       = "learning"
	ReasonGatewayObserve = "gateway_observe"

	// AccountWaitCap is the hard cap of account_slowdown: never a lockout.
	AccountWaitCap = 5 * time.Minute
)

var detectorResponse = map[string]string{
	config.DetectorRouteWave: RespRouteTighten, config.DetectorFingerprintCluster: RespRouteTighten, config.DetectorInconsistency: RespRouteTighten,
	config.DetectorAccountWave: RespAccountSlowdown, config.DetectorShapeWave: RespShapeBlock,
}

type distCompiled struct {
	mode       map[string]string
	thr        map[string]config.DetectorThresholds
	routes     []*regexp.Regexp
	routeSrc   []string
	tighten    config.RouteTighten
	slowdown   config.AccountSlowdown
	learnUntil time.Time
	ja4Header  string
}

func compileDistributed(d config.Distributed, installed time.Time) *distCompiled {
	c := &distCompiled{mode: map[string]string{}, thr: map[string]config.DetectorThresholds{}, tighten: d.Responses.RouteTighten, slowdown: d.Responses.AccountSlowdown,
		ja4Header: d.Fingerprint.JA4Header}
	for _, id := range config.DetectorIDs {
		det := d.Detectors.Get(id)
		c.mode[id] = det.Mode
		if c.mode[id] == "" {
			c.mode[id] = config.DistributedObserve
		}
		t := DistributedDefaults[id]
		if det.Thresholds.Count > 0 {
			t.Count = det.Thresholds.Count
		}
		if det.Thresholds.WindowS > 0 {
			t.WindowS = det.Thresholds.WindowS
		}
		if det.Thresholds.Factor > 0 {
			t.Factor = det.Thresholds.Factor
		}
		c.thr[id] = t
	}
	for _, r := range d.Routes {
		c.routes = append(c.routes, routeRe(r))
		c.routeSrc = append(c.routeSrc, r)
	}
	if c.tighten.Minutes <= 0 {
		c.tighten.Minutes = 20
	}
	if c.tighten.MaxMinutes <= 0 {
		c.tighten.MaxMinutes = 120
	}
	if c.tighten.LimitPerMinute <= 0 {
		c.tighten.LimitPerMinute = 10
	}
	if c.slowdown.StartS <= 0 {
		c.slowdown.StartS = 5
	}
	if c.slowdown.MaxS <= 0 {
		c.slowdown.MaxS = 60
	}
	days := d.LearningDays
	if days < 14 {
		days = 14
	}
	if !installed.IsZero() {
		c.learnUntil = installed.Add(time.Duration(days) * 24 * time.Hour)
	} else {
		c.learnUntil = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC) // unknown install date: keep learning
	}
	return c
}

// ---------------------------------------------------------------- state

type routeState struct {
	start      int64
	failures   float64
	successes  float64
	senders    *hll
	newSenders float64
	baseline   float64
	windows    int
	incStart   int64
	incFails   int
	incAll     int
	lastSeen   int64
}

type accountState struct {
	start    int64
	failures int
	senders  [4]uint64
	nSenders int
	flagged  int64 // until (unix nanos) the account counts as attacked
	attempts int   // failed attempts while flagged
	next     int64 // next allowed attempt without a session cookie
	lastSeen int64
}

type fpState struct {
	start    int64
	senders  *hll
	uas      []uint32
	lastSeen int64
}

type shapeState struct {
	start    int64
	senders  *hll
	lastSeen int64
}

// Wave is one detected distributed attack.
type Wave struct {
	ID, Detector, Host, Route, Response string
	Mode, Action, Reason                string
	Started, Until, Ended               time.Time
	EndReason                           string
	Senders, Count, Threshold, WindowS  int
	Baseline                            float64
	Fingerprint, FPKind                 string
	UserAgents                          int
	RequestSig                          string
	WAFRules                            []int
	Stopped                             int
	Incident                            string
	clusterFPs                          map[string]bool
	strongCluster                       bool
	// foreign: another node of the group detected the wave and wrote its
	// event; this node holds it (shared_dist.go).
	foreign bool
	tokens  float64
	last    int64
}

// Active reports whether the response is enforced at t.
func (w *Wave) Active(t time.Time) bool {
	return w.Action == config.DistributedRespond && w.Ended.IsZero() && t.Before(w.Until)
}

type dist struct {
	routes   *table[string, routeState]
	accounts *table[uint64, accountState]
	fps      *table[string, fpState]
	shapes   *table[string, shapeState]
	bloomMu  sync.Mutex
	bloom    [2][]uint64
	bloomAt  int64

	mu      sync.Mutex
	waves   map[string]*Wave // by id, at most CapacityWaves
	byKey   map[string]*Wave // detector|host|route (or sig), running or cooling down
	cookies map[string]map[string]bool
}

func newDist() *dist {
	return &dist{
		routes:   newTable[string, routeState](CapacityRoutes, func(k string) uint64 { return hashString(k) }),
		accounts: newTable[uint64, accountState](CapacityAccounts, func(k uint64) uint64 { return k }),
		fps:      newTable[string, fpState](CapacityFPs, func(k string) uint64 { return hashString(k) }),
		shapes:   newTable[string, shapeState](CapacityShapes, func(k string) uint64 { return hashString(k) }),
		bloom:    [2][]uint64{make([]uint64, bloomBits/64), make([]uint64, bloomBits/64)},
		waves:    map[string]*Wave{},
		byKey:    map[string]*Wave{},
		cookies:  map[string]map[string]bool{},
	}
}

// seenBefore reports whether this sender was seen on this route before
// (two generations of a bloom filter, rotated daily) and records it.
func (d *dist) seenBefore(x uint64, now int64) bool {
	d.bloomMu.Lock()
	defer d.bloomMu.Unlock()
	if d.bloomAt == 0 {
		d.bloomAt = now
	}
	if now-d.bloomAt > int64(24*time.Hour) {
		d.bloom[1], d.bloom[0] = d.bloom[0], d.bloom[1]
		clear(d.bloom[0])
		d.bloomAt = now
	}
	seen := true
	for i := uint64(0); i < 3; i++ {
		h := (x ^ (i * 0x9e3779b97f4a7c15)) * 0xbf58476d1ce4e5b9
		bit := (h >> 7) % bloomBits
		w, m := bit/64, uint64(1)<<(bit%64)
		if d.bloom[0][w]&m == 0 && d.bloom[1][w]&m == 0 {
			seen = false
		}
		d.bloom[0][w] |= m
	}
	return seen
}

// LearnCookies records the names of cookies the app set on a site. A
// request that sends one of them back carries a session cookie.
func (e *Engine) LearnCookies(hostHeader string, names []string) {
	if len(names) == 0 {
		return
	}
	h := host(hostHeader)
	if e.KnownHost != nil && !e.KnownHost(h) {
		return
	}
	d := e.d
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.cookies[h]
	if m == nil {
		if len(d.cookies) >= CapacitySites {
			for k := range d.cookies {
				delete(d.cookies, k)
				break
			}
		}
		m = map[string]bool{}
		d.cookies[h] = m
	}
	for _, n := range names {
		if len(m) < 64 && n != "" && len(n) <= 128 {
			m[n] = true
		}
	}
}

// HasSession reports whether a request sends back a cookie the app set.
func (e *Engine) HasSession(r *Request) bool {
	if len(r.CookieNames) == 0 {
		return false
	}
	h := host(r.Host)
	e.d.mu.Lock()
	defer e.d.mu.Unlock()
	m := e.d.cookies[h]
	for _, n := range r.CookieNames {
		if m[n] {
			return true
		}
	}
	return false
}

// routeKey returns the distributed route of a request (login route of an
// enabled preset or an operator-marked route) or "".
func (e *Engine) routeKey(c *compiled, r *Request) (string, bool) {
	p := r.Path
	canon := canonPath(p)
	for i := range loginRoutes {
		lr := &loginRoutes[i]
		if c.presets[lr.Preset] && routeIs(lr.Path, p, canon) {
			return lr.Path, true
		}
	}
	for i, re := range c.dist.routes {
		if re.MatchString(p) || canon != "" && re.MatchString(canon) {
			return c.dist.routeSrc[i], false
		}
	}
	return "", false
}

func waveKey(detector, host, route string) string { return detector + "|" + host + "|" + route }

// cutWaveKey is the reverse of waveKey (a host holds no "|").
func cutWaveKey(k string) (detector, host, route string) {
	detector, rest, _ := strings.Cut(k, "|")
	host, route, _ = strings.Cut(rest, "|")
	return detector, host, route
}

// ---------------------------------------------------------------- enforce

// checkDistributed runs in Check for unsafe methods on a tightened route.
func (e *Engine) checkDistributed(c *compiled, r *Request) Verdict {
	if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
		return Verdict{} // the login form itself stays reachable
	}
	route, _ := e.routeKey(c, r)
	if route == "" {
		return Verdict{}
	}
	h := host(r.Host)
	now := r.Time
	session := e.HasSession(r)
	d := e.d
	d.mu.Lock()
	defer d.mu.Unlock()
	var v Verdict
	for _, det := range []string{config.DetectorRouteWave, config.DetectorFingerprintCluster, config.DetectorInconsistency} {
		w := d.byKey[waveKey(det, h, route)]
		if w == nil || !w.Active(now) {
			continue
		}
		// Who is limited: requests without a session cookie the app set, and
		// requests of the cluster when the fingerprint is strong (JA4). A
		// header-set fingerprint is shared by many ordinary browsers, so it
		// never overrides a session cookie.
		inCluster := r.StrongFP && w.clusterFPs[r.Fingerprint]
		if session && !inCluster {
			continue
		}
		rate := float64(c.dist.tighten.LimitPerMinute) / 60
		burst := float64(c.dist.tighten.LimitPerMinute)
		t := now.UnixNano()
		if w.last == 0 {
			w.tokens, w.last = burst, t
		}
		w.tokens = min(burst, w.tokens+float64(max(t-w.last, 0))/1e9*rate) // a clock stepping back adds nothing
		w.last = t
		if w.tokens >= 1 {
			w.tokens--
			return Verdict{}
		}
		w.Stopped++
		retry := time.Duration((1 - w.tokens) / rate * 1e9)
		v = Verdict{RateLimited: true, LimitID: "distributed", WaveID: w.ID, RetryAfter: retry}
		return v
	}
	return v
}

// AccountWait is checked after the gate read the login user name: an
// attacked account answers attempts without a session cookie with 429
// until the growing wait has passed (at most AccountWaitCap). Attempts with
// a session cookie always pass, so nobody can lock the real user out.
func (e *Engine) AccountWait(r *Request, userHash uint64) Verdict {
	c := e.cfg.Load()
	if c.dist.mode[config.DetectorAccountWave] != config.DistributedRespond || e.distAction(c, r.Time) != config.DistributedRespond {
		return Verdict{}
	}
	if e.HasSession(r) {
		return Verdict{}
	}
	now := r.Time.UnixNano()
	var wait time.Duration
	e.d.accounts.with(userHash, false, func(a *accountState) {
		if a == nil || a.flagged <= now || a.next <= now {
			return
		}
		wait = min(time.Duration(a.next-now), AccountWaitCap)
	})
	if wait <= 0 {
		return Verdict{}
	}
	route, _ := e.routeKey(c, r)
	e.d.mu.Lock()
	if w := e.d.byKey[waveKey(config.DetectorAccountWave, host(r.Host), route)]; w != nil {
		w.Stopped++
	}
	e.d.mu.Unlock()
	return Verdict{RateLimited: true, LimitID: "distributed", RetryAfter: wait}
}

// ShapeBlocked reports a running shape_block for a request shape.
func (e *Engine) ShapeBlocked(sig string, t time.Time) (incident string, ok bool) {
	if sig == "" {
		return "", false
	}
	e.d.mu.Lock()
	defer e.d.mu.Unlock()
	w := e.d.byKey[waveKey(config.DetectorShapeWave, "", sig)]
	if w == nil || !w.Active(t) {
		return "", false
	}
	w.Stopped++
	return w.Incident, true
}

// Learning reports whether t is inside the learning period of a fresh
// installation (at least learning_days from the first start; an unknown
// first start keeps learning). Scenarios and distributed detectors act only
// after it.
func (c *compiled) Learning(t time.Time) bool { return t.Before(c.dist.learnUntil) }

// distAction is respond only after the learning period and never while the
// gateway observes.
func (e *Engine) distAction(c *compiled, t time.Time) string {
	if c.observe || t.Before(c.dist.learnUntil) {
		return config.DistributedObserve
	}
	return config.DistributedRespond
}

func (e *Engine) distReason(c *compiled, t time.Time) string {
	switch {
	case c.observe:
		return ReasonGatewayObserve
	case t.Before(c.dist.learnUntil):
		return ReasonLearning
	}
	return ""
}

// ---------------------------------------------------------------- observe

func (e *Engine) observeDistributed(c *compiled, r *Request, o Outcome, key Key) {
	now := r.Time.UnixNano()
	h := host(r.Host)
	if o.Forwarded {
		e.LearnCookies(r.Host, o.Response.CookieNames)
	}
	sender := hashKey(key)
	// sh: in a group, what the detectors count is noted for the other nodes.
	sh := e.share.Load()
	if o.Shape != "" && len(o.ShapeRules) > 0 && c.dist.mode[config.DetectorShapeWave] != config.DistributedOff {
		t := c.dist.thr[config.DetectorShapeWave]
		var n int
		e.d.shapes.with(o.Shape, true, func(s *shapeState) {
			if s.senders == nil {
				s.senders = newHLL(6)
			}
			if s.start == 0 || now-s.start >= int64(t.WindowS)*int64(time.Second) {
				s.start = now
				s.senders.reset()
			}
			s.lastSeen = now
			s.senders.add(sender)
			n = int(s.senders.estimate() + 0.5)
		})
		if sh != nil {
			sh.distShape(o.Shape, sender)
		}
		if n >= t.Count {
			e.fireWave(c, r, config.DetectorShapeWave, "", o.Shape, trigger2{count: n, threshold: t.Count, window: t.WindowS, senders: n, sig: o.Shape, rules: o.ShapeRules,
				route: redact.Path(r.Path)})
		}
	}
	if !o.Forwarded {
		return
	}
	route, isLogin := e.routeKey(c, r)
	if route == "" || r.Method == "GET" || r.Method == "HEAD" {
		return
	}
	var failed bool
	if isLogin {
		lr := loginOf(c, r)
		if lr == nil {
			return
		}
		failed = lr.Failed(o.Response)
	} else {
		failed = loginFailedGeneric(o.Response) || statusIn(o.Response.Status, 400, 404)
	}
	rk := h + "|" + route
	first := !e.d.seenBefore(hashString(rk)^sender, now)

	// route_wave and inconsistency share the route state.
	rt := c.dist.thr[config.DetectorRouteWave]
	it := c.dist.thr[config.DetectorInconsistency]
	var rw, inc *trigger2
	e.d.routes.with(rk, true, func(s *routeState) {
		s.roll(now, rt)
		s.lastSeen = now
		s.senders.add(sender)
		if first {
			s.newSenders++
		}
		if !failed {
			s.successes++
		} else {
			s.failures++
			thr := max(float64(rt.Count), rt.Factor*s.baseline)
			senders := s.senders.estimate()
			failShare := s.failures / (s.failures + s.successes)
			newShare := s.newSenders / max(senders, 1)
			// Require multiple distinct senders so one client cannot trigger
			// route_tighten and throttle the whole login route globally.
			if s.failures >= thr && int(senders+0.5) >= minRouteWaveSenders && (failShare >= 0.7 || newShare >= 0.7) {
				rw = &trigger2{count: int(s.failures), threshold: int(thr + 0.5), window: rt.WindowS, senders: int(senders + 0.5), baseline: s.baseline, route: route}
			}
		}
		isize := int64(it.WindowS) * int64(time.Second)
		if s.incStart == 0 || now-s.incStart >= isize {
			s.incStart, s.incFails, s.incAll = now, 0, 0
		}
		if failed {
			s.incAll++
			if r.Inconsistent {
				s.incFails++
			}
			senders := int(s.senders.estimate() + 0.5)
			if s.incFails >= it.Count && s.incFails*2 >= s.incAll && senders >= minRouteWaveSenders {
				inc = &trigger2{count: s.incFails, threshold: it.Count, window: it.WindowS, senders: senders, route: route}
			}
		}
	})
	if sh != nil {
		sh.distRoute(h, route, func(rc *RouteCount) {
			sh.sender(&rc.Senders, sender)
			if first {
				rc.New++
			}
			if !failed {
				rc.Passed++
				return
			}
			rc.Failed++
			rc.IncAll++
			if r.Inconsistent {
				rc.IncFailed++
			}
		})
	}
	if rw != nil && c.dist.mode[config.DetectorRouteWave] != config.DistributedOff {
		e.fireWave(c, r, config.DetectorRouteWave, h, route, *rw)
	}
	if inc != nil && c.dist.mode[config.DetectorInconsistency] != config.DistributedOff {
		e.fireWave(c, r, config.DetectorInconsistency, h, route, *inc)
	}
	if !failed {
		if o.HasUser && e.HasSession(r) {
			e.d.accounts.delete(o.UserHash) // success with a session cookie resets the account
		}
		return
	}
	// fingerprint_cluster: one client stack, many senders, rotating agents.
	if r.Fingerprint != "" && c.dist.mode[config.DetectorFingerprintCluster] != config.DistributedOff {
		ft := c.dist.thr[config.DetectorFingerprintCluster]
		var tg *trigger2
		e.d.fps.with(r.Fingerprint+"|"+rk, true, func(s *fpState) {
			if s.senders == nil {
				s.senders = newHLL(6)
			}
			if s.start == 0 || now-s.start >= int64(ft.WindowS)*int64(time.Second) {
				s.start = now
				s.senders.reset()
				s.uas = s.uas[:0]
			}
			s.lastSeen = now
			s.senders.add(sender)
			ua := uint32(hashString(r.UserAgent))
			found := false
			for _, x := range s.uas {
				if x == ua {
					found = true
					break
				}
			}
			if !found && len(s.uas) < 16 {
				s.uas = append(s.uas, ua)
			}
			if sh != nil {
				sh.distFP(r.Fingerprint, h, route, sender, ua)
			}
			n := int(s.senders.estimate() + 0.5)
			if n >= ft.Count && len(s.uas) >= 3 {
				tg = &trigger2{count: n, threshold: ft.Count, window: ft.WindowS, senders: n, fp: r.Fingerprint, fpKind: r.FPKind, strong: r.StrongFP, uas: len(s.uas), route: route}
			}
		})
		if tg != nil {
			e.fireWave(c, r, config.DetectorFingerprintCluster, h, route, *tg)
		}
	}
	// account_wave: one account, many senders.
	if o.HasUser && c.dist.mode[config.DetectorAccountWave] != config.DistributedOff {
		at := c.dist.thr[config.DetectorAccountWave]
		size := int64(at.WindowS) * int64(time.Second)
		var tg *trigger2
		e.d.accounts.with(o.UserHash, true, func(a *accountState) {
			if a.start == 0 || now-a.start >= size {
				a.start, a.failures, a.nSenders = now, 0, 0
			}
			a.lastSeen = now
			a.failures++
			a.addSender(sender)
			if sh != nil {
				defer func() { sh.distAccount(o.UserHash, sender, a.flagged > now) }()
			}
			if a.flagged > now {
				// every failed attempt while attacked doubles the wait
				a.attempts++
				a.next = now + int64(c.dist.accountWait(a.attempts))
				a.flagged = now + size
				return
			}
			if a.failures >= at.Count && a.nSenders >= 3 {
				a.flagged, a.attempts = now+size, 1
				a.next = now + int64(min(time.Duration(c.dist.slowdown.StartS)*time.Second, AccountWaitCap))
				tg = &trigger2{count: a.failures, threshold: at.Count, window: at.WindowS, senders: a.nSenders, route: route}
			}
		})
		if tg != nil {
			e.fireWave(c, r, config.DetectorAccountWave, h, route, *tg)
		}
	}
}

type trigger2 struct {
	count, threshold, window, senders int
	baseline                          float64
	fp, fpKind                        string
	strong                            bool
	uas                               int
	sig                               string
	rules                             []int
	route                             string
}

// fireWave starts a wave or extends a running one (never beyond
// max_minutes after its start).
func (e *Engine) fireWave(c *compiled, r *Request, detector, h, key string, t trigger2) {
	d := e.d
	now := r.Time
	mins := time.Duration(c.dist.tighten.Minutes) * time.Minute
	maxDur := time.Duration(c.dist.tighten.MaxMinutes) * time.Minute
	d.mu.Lock()
	k := waveKey(detector, h, key)
	if w := d.byKey[k]; w != nil && w.Ended.IsZero() && now.Before(w.Until.Add(Cooldown)) {
		if t.fp != "" {
			if len(w.clusterFPs) < 16 {
				w.clusterFPs[t.fp] = true
			}
			w.strongCluster = w.strongCluster || t.strong
		}
		before := w.Until
		if w.Action == config.DistributedRespond {
			w.Until = minTime(now.Add(mins), w.Started.Add(maxDur)).Truncate(time.Second)
		}
		w.Senders, w.Count = max(w.Senders, t.senders), max(w.Count, t.count)
		if !w.Until.Equal(before) {
			e.noteWave(w, key) // the other nodes of a group extend it too
		}
		d.mu.Unlock()
		return
	}
	action := e.distAction(c, now)
	if c.dist.mode[detector] != config.DistributedRespond {
		action = config.DistributedObserve
	}
	id := msg.NewID()
	if e.share.Load() != nil {
		// In a group every node that detects this wave names it the same, so
		// it is one wave and one event (shared_dist.go).
		id = groupWaveID(detector, h, key, now)
		// A wave of this target that started in the same five minutes and
		// was ended since (by the operator) keeps its id; this is the next.
		for n := 1; d.waves[id] != nil && n < 8; n++ {
			id = derivedID("schild-wave-again", id)
		}
	}
	w := &Wave{ID: id, Detector: detector, Host: h, Route: t.route, Response: detectorResponse[detector], Mode: c.dist.mode[detector], Action: action,
		Started: now, Senders: t.senders, Count: t.count, Threshold: max(t.threshold, 1), WindowS: max(t.window, 1), Baseline: round2(t.baseline),
		Fingerprint: t.fp, FPKind: t.fpKind, UserAgents: t.uas, RequestSig: t.sig, WAFRules: t.rules, clusterFPs: map[string]bool{}, strongCluster: t.strong}
	if action == config.DistributedObserve {
		w.Reason = e.distReason(c, now)
		w.Until = now.Add(mins).Truncate(time.Second) // cooldown reference only
	} else {
		w.Until = now.Add(mins).Truncate(time.Second)
	}
	if t.fp != "" {
		w.clusterFPs[t.fp] = true
	}
	if detector == config.DetectorShapeWave && action == config.DistributedRespond {
		w.Incident = events.NewIncident()
		if e.share.Load() != nil {
			w.Incident = groupIncident(w.ID) // one number on every node
		}
	}
	e.storeWave(w, k, now)
	e.noteWave(w, key)
	d.mu.Unlock()
	e.stats.add("wave:"+detector, now, 1)
	if w.Incident != "" && e.Sink.Incident != nil {
		e.Sink.Incident(&store.Incident{Incident: w.Incident, EventID: w.ID, Time: now.UTC(), Status: "blocked", Host: w.Host,
			Reason: "distributed shape_block " + t.sig, Sources: []string{"distributed:shape"}})
	}
	e.emitWave(w, r.Time)
}

// storeWave puts a wave into the tables, within CapacityWaves. Called with
// dist.mu held.
func (e *Engine) storeWave(w *Wave, k string, now time.Time) {
	d := e.d
	if len(d.waves) >= CapacityWaves {
		oldest := ""
		for id, x := range d.waves {
			if !x.Active(now) && (oldest == "" || x.Started.Before(d.waves[oldest].Started)) {
				oldest = id
			}
		}
		if oldest == "" {
			for id := range d.waves {
				oldest = id
				break
			}
		}
		e.dropWave(oldest)
	}
	d.waves[w.ID] = w
	d.byKey[k] = w
}

// roll closes the window of a route when its time is over, and learns the
// baseline outside waves.
func (s *routeState) roll(now int64, rt config.DetectorThresholds) {
	if s.senders == nil {
		s.senders = newHLL(8)
	}
	if s.start == 0 {
		s.start = now
	}
	if now-s.start < int64(rt.WindowS)*int64(time.Second) {
		return
	}
	if s.failures < max(float64(rt.Count), rt.Factor*s.baseline) {
		if s.windows == 0 {
			s.baseline = s.failures
		} else {
			s.baseline = 0.9*s.baseline + 0.1*s.failures
		}
		s.windows++
	}
	s.start, s.failures, s.successes, s.newSenders = now, 0, 0, 0
	s.senders.reset()
}

func (e *Engine) dropWave(id string) {
	w := e.d.waves[id]
	delete(e.d.waves, id)
	if w == nil {
		return
	}
	for k, x := range e.d.byKey {
		if x == w {
			delete(e.d.byKey, k)
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (e *Engine) emitWave(w *Wave, t time.Time) {
	if e.Sink.Emit == nil {
		return
	}
	mode := config.DistributedObserve
	if w.Mode == config.DistributedRespond {
		mode = config.DistributedRespond
	}
	d := events.DistributedDetectedData{WaveID: w.ID, Detector: w.Detector, Host: trim(w.Host, 253), Route: trim(w.Route, 512), Senders: w.Senders, Count: w.Count,
		Threshold: w.Threshold, WindowS: w.WindowS, Baseline: w.Baseline, Fingerprint: w.Fingerprint, FingerprintKind: w.FPKind, UserAgents: w.UserAgents,
		RequestSig: w.RequestSig, WAFRules: capInts(w.WAFRules, 32), Response: w.Response, Mode: mode, Action: w.Action, Reason: w.Reason}
	if w.Action == config.DistributedRespond {
		d.Until = w.Until.UTC().Format("2006-01-02T15:04:05Z")
	}
	e.Sink.Emit(w.ID, events.DistributedDetected, t, d, eventlog.Index{Host: d.Host, Path: d.Route, Outcome: w.Action, Incident: w.Incident,
		Summary: "distributed " + w.Detector + " " + w.Action})
}

func capInts(x []int, n int) []int {
	x = append([]int(nil), x...)
	sort.Ints(x)
	if len(x) > n {
		x = x[:n]
	}
	return x
}

// endWave records the end of a response.
func (e *Engine) endWave(w *Wave, at time.Time, reason string) {
	w.Ended, w.EndReason = at, reason
	// A wave another node detected ends at its time on every node; the node
	// that detected it writes the event.
	if e.Sink.Emit == nil || (w.foreign && reason == "expired") {
		return
	}
	dur := int(at.Sub(w.Started) / time.Second)
	d := events.DistributedEndedData{WaveID: w.ID, Detector: w.Detector, Host: trim(w.Host, 253), Route: trim(w.Route, 512), Reason: reason,
		DurationS: min(max(dur, 0), 7200), Stopped: w.Stopped}
	id := ""
	if e.share.Load() != nil {
		id = derivedID("schild-wave-ended", w.ID) // one end per wave in a group
	}
	e.Sink.Emit(id, events.DistributedEnded, at, d, eventlog.Index{Host: d.Host, Path: d.Route, Summary: "distributed " + w.Detector + " ended " + reason})
}

// EndWave ends a running response early (operator). ok is false when the
// wave is unknown; active false when it was not running.
func (e *Engine) EndWave(id string) (w Wave, ok, active bool) {
	now := e.now()
	e.d.mu.Lock()
	defer e.d.mu.Unlock()
	x := e.d.waves[id]
	if x == nil {
		return Wave{}, false, false
	}
	if !x.Active(now) {
		return x.copy(), true, false
	}
	e.endWave(x, now, "operator")
	for k, y := range e.d.byKey {
		if y == x {
			_, _, key := cutWaveKey(k)
			e.noteWave(x, key) // it ends on every node of a group
		}
	}
	return x.copy(), true, true
}

func (w *Wave) copy() Wave {
	c := *w
	c.clusterFPs = nil
	c.WAFRules = append([]int(nil), w.WAFRules...)
	return c
}

// WaveByID returns the in-memory state of a wave (lost on restart).
func (e *Engine) WaveByID(id string) (Wave, bool) {
	e.d.mu.Lock()
	defer e.d.mu.Unlock()
	w := e.d.waves[id]
	if w == nil {
		return Wave{}, false
	}
	return w.copy(), true
}

// Waves24h counts waves per detector in the last 24 h.
func (e *Engine) Waves24h(detector string) int { return int(e.stats.sum("wave:"+detector, e.now())) }

// LearnUntil is the end of the learning period (zero when unknown).
func (e *Engine) LearnUntil() time.Time {
	t := e.cfg.Load().dist.learnUntil
	if t.Year() == 9999 {
		return time.Time{}
	}
	return t
}

// DistributedMode returns the configured and the effective mode.
func (e *Engine) DistributedMode(id string) (mode, effective string) {
	c := e.cfg.Load()
	mode = c.dist.mode[id]
	effective = mode
	if mode == config.DistributedRespond && e.distAction(c, e.now()) != config.DistributedRespond {
		effective = config.DistributedObserve
	}
	return mode, effective
}

// DistributedThresholds returns the effective thresholds of a detector.
func (e *Engine) DistributedThresholds(id string) config.DetectorThresholds {
	return e.cfg.Load().dist.thr[id]
}

// sweepDistributed ends expired responses and drops idle state.
func (e *Engine) sweepDistributed(now time.Time) {
	n := now.UnixNano()
	d := e.d
	d.mu.Lock()
	for id, w := range d.waves {
		if w.Action == config.DistributedRespond && w.Ended.IsZero() && !now.Before(w.Until) {
			e.endWave(w, w.Until, "expired")
		}
		if now.Sub(w.Started) > 24*time.Hour {
			e.dropWave(id)
		}
	}
	d.mu.Unlock()
	d.routes.sweep(func(_ string, s *routeState) bool { return n-s.lastSeen > int64(7*24*time.Hour) })
	d.accounts.sweep(func(_ uint64, a *accountState) bool { return n-a.lastSeen > int64(time.Hour) && a.flagged < n })
	d.fps.sweep(func(_ string, s *fpState) bool { return n-s.lastSeen > int64(time.Hour) })
	d.shapes.sweep(func(_ string, s *shapeState) bool { return n-s.lastSeen > int64(time.Hour) })
}

// JA4Header is the configured header of a trusted TLS terminator ("" = none).
func (e *Engine) JA4Header() string { return e.cfg.Load().dist.ja4Header }

// DistSizes reports table sizes (tests).
func (e *Engine) DistSizes() (routes, accounts, fps, shapes, waves int) {
	e.d.mu.Lock()
	waves = len(e.d.waves)
	e.d.mu.Unlock()
	return e.d.routes.len(), e.d.accounts.len(), e.d.fps.len(), e.d.shapes.len(), waves
}
