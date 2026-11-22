package behaviour

import (
	"time"

	"github.com/deutschland-schild/schild/contract/config"
)

// A node of a group that starts knows nothing of what the group counted in
// the windows that are still open: the per-second counts of shared.go tell
// it only what comes after. A client four failed logins into a window of
// five would get a fresh allowance on it. So before it serves, a starting
// node takes the running state from one member (MVP-27, D103): the tokens
// used of every rate limit, what the scenarios count per client and per
// website, what the detectors of distributed attacks hold per route and
// account and have learned, and the waves that run.
//
// The state is a snapshot at one moment, the counts that follow are what
// was counted after their last word. They do not join exactly: what the
// member counted and had not told yet is in the snapshot and comes again
// with its next word, and a count a third node told both the member and the
// starting node is on both sides. A first pass therefore adds (ApplyWarm
// with raise false) and errs on counting about a second of the group twice;
// a second pass a few seconds later only raises what is below the member's
// state (raise true) and adds nothing twice: it brings what was counted
// while the others did not tell the starting node yet. Sets and sketches
// (probed paths, rule ids, user names, senders) join by union and are exact
// either way. A counter taken over starts a window of its own on the node,
// so it lasts at most one window longer than on the member. Nothing here
// decides or writes an event.
//
// Like the counts, the state holds client addresses in memory and on the
// wire between members only.

// Warm is one page of the running state of a node.
type Warm struct {
	Limits   []WarmLimit   `json:"limits,omitempty"`
	Clients  []WarmClient  `json:"clients,omitempty"`
	Sites    []WarmSite    `json:"sites,omitempty"`
	Routes   []WarmRoute   `json:"routes,omitempty"`
	Accounts []WarmAccount `json:"accounts,omitempty"`
	Waves    []WaveNote    `json:"waves,omitempty"`
}

// WarmLimit: the tokens one client key has used of one rate limit, now.
type WarmLimit struct {
	Client string  `json:"client"`
	Limit  string  `json:"limit"`
	Used   float64 `json:"used"`
}

// WarmClient: what the scenarios hold of one client key within their
// windows. Users are the registers of the sketch of user names.
type WarmClient struct {
	Client    string   `json:"client"`
	LoginFast float64  `json:"login_fast,omitempty"`
	LoginSlow float64  `json:"login_slow,omitempty"`
	LoginN    int      `json:"login_n,omitempty"`
	Users     []byte   `json:"users,omitempty"`
	Probe     []uint32 `json:"probe,omitempty"`
	ProbeW    int      `json:"probe_w,omitempty"`
	Crawl     float64  `json:"crawl,omitempty"`
	WAF       []int    `json:"waf,omitempty"`
	WAFHits   int      `json:"waf_hits,omitempty"`
}

// WarmSite: the crawl window of a website, its learned baseline and the
// sketches of its clients and of the user names of failed logins.
type WarmSite struct {
	Host     string  `json:"host"`
	Crawl    float64 `json:"crawl,omitempty"`
	Baseline float64 `json:"baseline,omitempty"`
	Clients  []byte  `json:"clients,omitempty"`
	Users    []byte  `json:"users,omitempty"`
}

// WarmRoute: the window of one route (route_wave) and what was learned of
// it: the baseline and over how many windows.
type WarmRoute struct {
	Host     string  `json:"host"`
	Route    string  `json:"route"`
	Failed   float64 `json:"failed,omitempty"`
	Passed   float64 `json:"passed,omitempty"`
	New      float64 `json:"new,omitempty"`
	Baseline float64 `json:"baseline,omitempty"`
	Windows  int     `json:"windows,omitempty"`
	Senders  []byte  `json:"senders,omitempty"`
}

// WarmAccount: failed attempts on one account (account_wave); FlaggedMS:
// for how long it still counts as attacked.
type WarmAccount struct {
	User      uint64   `json:"user"`
	Failed    int      `json:"failed,omitempty"`
	Senders   []uint64 `json:"senders,omitempty"`
	FlaggedMS int64    `json:"flagged_ms,omitempty"`
	Attempts  int      `json:"attempts,omitempty"`
}

// Bounds of a page and of what a node takes of one.
const (
	// WarmPageEntries is about how many entries one page holds: a page ends
	// after the shard that reaches it.
	WarmPageEntries = 2000
	// warmMaxEntries bounds each list of a page a node takes: one shard of
	// the largest table and the page before it.
	warmMaxEntries = 4 * WarmPageEntries
	warmMaxFlagged = 24 * time.Hour
)

// The steps of the cursor: one shard of a table each, then the websites and
// the waves.
const (
	warmBuckets  = 0
	warmClients  = warmBuckets + shards
	warmSites    = warmClients + shards
	warmRoutes   = warmSites + 1
	warmAccounts = warmRoutes + shards
	warmWaves    = warmAccounts + shards
	warmEnd      = warmWaves + 1
)

func (w *Warm) entries() int {
	return len(w.Limits) + len(w.Clients) + len(w.Sites) + len(w.Routes) + len(w.Accounts) + len(w.Waves)
}

// value is the sliding count of the window now.
func (w *window) value(now, size int64) float64 {
	if w.start == 0 || size <= 0 {
		return 0
	}
	w.roll(now, size)
	frac := float64(now-w.start) / float64(size)
	return float64(w.prev)*(1-frac) + float64(w.cur)
}

// take adds v to the window, or with raise only what the window is below v.
func (w *window) take(now, size int64, v float64, raise bool) {
	if v <= 0 || size <= 0 {
		return
	}
	if raise {
		v -= w.value(now, size)
		if v <= 0 {
			return
		}
	}
	w.add(now, size, float32(v))
}

func (h *hll) registers() []byte { return append([]byte(nil), h.reg...) }

// merge is the union with the sketch of the same size these registers come
// from; anything else is left out.
func (h *hll) merge(reg []byte) {
	if len(reg) != len(h.reg) {
		return
	}
	for i, r := range reg {
		if r > h.reg[i] && r <= 64 {
			h.reg[i] = r
		}
	}
}

func (h *hll) blank() bool {
	for _, r := range h.reg {
		if r != 0 {
			return false
		}
	}
	return true
}

// WarmPage returns the running state from cursor on (0: the start), about
// WarmPageEntries entries, and the cursor of the page after it; next below
// zero: this was the last. Entries that hold nothing within their windows
// are left out.
func (e *Engine) WarmPage(cursor int) (page *Warm, next int) {
	page = &Warm{}
	if cursor < 0 || cursor >= warmEnd {
		return page, -1
	}
	cfg := e.cfg.Load()
	now := e.now().UnixNano()
	sec := int64(time.Second)
	limits := map[uint16]*Limit{}
	for _, l := range cfg.limits {
		limits[l.idx] = l
	}
	size := func(id string) int64 { return int64(cfg.thr[id].WindowS) * sec }
	for ; cursor < warmEnd && page.entries() < WarmPageEntries; cursor++ {
		switch {
		case cursor < warmClients:
			e.buckets.each(cursor-warmBuckets, func(k bucketKey, b *bucket) {
				l := limits[k.limit]
				if l == nil || b.last == 0 {
					return
				}
				tokens := min(float64(l.Burst), b.tokens+float64(max(now-b.last, 0))/1e9*l.rate)
				if used := float64(l.Burst) - tokens; used >= 0.5 {
					page.Limits = append(page.Limits, WarmLimit{Client: k.key.String(), Limit: l.ID, Used: used})
				}
			})
		case cursor < warmSites:
			login, stuffing, probing, crawl, waf := cfg.thr[config.ScenarioLoginBruteforce], size(config.ScenarioCredentialStuffing), size(config.ScenarioPathProbing), size(config.ScenarioAggressiveCrawl), size(config.ScenarioWAFRepeat)
			e.clients.each(cursor-warmClients, func(k Key, s *clientState) {
				c := WarmClient{Client: k.String(),
					LoginFast: s.loginFast.value(now, int64(login.WindowS)*sec), LoginSlow: s.loginSlow.value(now, int64(login.SlowWindowS)*sec),
					Crawl: s.crawl.value(now, crawl)}
				if c.LoginFast > 0 || c.LoginSlow > 0 {
					c.LoginN = s.loginN
				}
				if u := s.users; u != nil && u.start != 0 && now-u.start < stuffing && !u.h.blank() {
					c.Users = u.h.registers()
				}
				if p := s.probe; p != nil && p.start != 0 && now-p.start < probing && p.weight > 0 {
					c.Probe, c.ProbeW = append([]uint32(nil), p.ids...), p.weight
				}
				if w := s.waf; w != nil && w.start != 0 && now-w.start < waf && (len(w.ids) > 0 || w.hits > 0) {
					c.WAF, c.WAFHits = append([]int(nil), w.ids...), w.hits
				}
				if c.LoginFast > 0 || c.LoginSlow > 0 || c.Crawl > 0 || c.Users != nil || c.ProbeW > 0 || c.WAF != nil || c.WAFHits > 0 {
					page.Clients = append(page.Clients, c)
				}
			})
		case cursor == warmSites:
			e.sitesMu.Lock()
			sites := make(map[string]*siteState, len(e.sites))
			for h, s := range e.sites {
				sites[h] = s
			}
			e.sitesMu.Unlock()
			stuffing := size(config.ScenarioCredentialStuffing)
			for h, s := range sites {
				s.mu.Lock()
				ws := WarmSite{Host: h, Crawl: s.total, Baseline: s.baseline}
				if s.clients != nil && !s.clients.blank() {
					ws.Clients = s.clients.registers()
				}
				if u := &s.users; u.h != nil && u.start != 0 && now-u.start < stuffing && !u.h.blank() {
					ws.Users = u.h.registers()
				}
				s.mu.Unlock()
				if ws.Crawl > 0 || ws.Baseline > 0 || ws.Clients != nil || ws.Users != nil {
					page.Sites = append(page.Sites, ws)
				}
			}
		case cursor < warmAccounts:
			rt := cfg.dist.thr[config.DetectorRouteWave]
			e.d.routes.each(cursor-warmRoutes, func(k string, s *routeState) {
				host, route, ok := cutKey(k)
				if !ok {
					return
				}
				s.roll(now, rt)
				wr := WarmRoute{Host: host, Route: route, Failed: s.failures, Passed: s.successes, New: s.newSenders, Baseline: s.baseline, Windows: s.windows}
				if s.senders != nil && !s.senders.blank() {
					wr.Senders = s.senders.registers()
				}
				if wr.Failed > 0 || wr.Passed > 0 || wr.Windows > 0 || wr.Senders != nil {
					page.Routes = append(page.Routes, wr)
				}
			})
		case cursor < warmWaves:
			win := int64(cfg.dist.thr[config.DetectorAccountWave].WindowS) * sec
			e.d.accounts.each(cursor-warmAccounts, func(user uint64, a *accountState) {
				wa := WarmAccount{User: user}
				if a.start != 0 && now-a.start < win {
					wa.Failed = a.failures
					wa.Senders = append([]uint64(nil), a.senders[:min(a.nSenders, len(a.senders))]...)
				}
				if a.flagged > now {
					wa.FlaggedMS, wa.Attempts = (a.flagged-now)/int64(time.Millisecond), a.attempts
				}
				if wa.Failed > 0 || wa.FlaggedMS > 0 {
					page.Accounts = append(page.Accounts, wa)
				}
			})
		default:
			t := e.now()
			e.d.mu.Lock()
			for key, w := range e.d.byKey {
				if !w.Ended.IsZero() || !t.Before(w.Until) {
					continue
				}
				_, _, noteKey := cutWaveKey(key)
				n := WaveNote{ID: w.ID, Detector: w.Detector, Host: w.Host, Key: noteKey, Route: w.Route, Action: w.Action, Started: w.Started.UnixMilli(), Until: w.Until.UnixMilli(),
					Senders: w.Senders, Count: w.Count, Threshold: w.Threshold, WindowS: w.WindowS, Baseline: w.Baseline, Fingerprint: w.Fingerprint, FPKind: w.FPKind,
					UserAgents: w.UserAgents, RequestSig: w.RequestSig, WAFRules: capInts(w.WAFRules, 32), Incident: w.Incident, Strong: w.strongCluster}
				for fp := range w.clusterFPs {
					n.ClusterFPs = append(n.ClusterFPs, fp)
				}
				page.Waves = append(page.Waves, n)
			}
			e.d.mu.Unlock()
		}
	}
	if cursor >= warmEnd {
		return page, -1
	}
	return page, cursor
}

// cutKey splits the key of a route state, "host|route".
func cutKey(k string) (host, route string, ok bool) {
	for i := 0; i < len(k); i++ {
		if k[i] == '|' {
			return k[:i], k[i+1:], true
		}
	}
	return "", "", false
}

// ApplyWarm takes a page of the running state of another node into this
// engine's counters: it adds, or with raise brings up only what is below
// (see the top of this file). skip leaves a client key out (an address that
// was erased meanwhile). It decides nothing and writes no event. What does
// not parse or names something this node does not have is left out, lists
// are cut at their bounds and numbers at the bounds of the counts.
func (e *Engine) ApplyWarm(w *Warm, raise bool, skip func(Key) bool) {
	if w == nil {
		return
	}
	cfg := e.cfg.Load()
	t := e.now()
	now := t.UnixNano()
	sec := int64(time.Second)
	num := func(v float64) float64 { return min(max(v, 0), shareMaxN) }
	key := func(s string) (Key, bool) {
		k, ok := sharedKey(s)
		return k, ok && (skip == nil || !skip(k))
	}
	byID := make(map[string]*Limit, len(cfg.limits))
	for _, l := range cfg.limits {
		byID[l.ID] = l
	}
	for _, wl := range cut(w.Limits, warmMaxEntries) {
		l := byID[wl.Limit]
		k, ok := key(wl.Client)
		if !ok || l == nil || !(wl.Used > 0) {
			continue
		}
		// Never more than two bursts, as a count never brings a bucket
		// further below zero than one.
		used := min(wl.Used, 2*float64(l.Burst))
		e.buckets.with(bucketKey{k, l.idx}, true, func(b *bucket) {
			if b.last == 0 {
				b.tokens, b.last = float64(l.Burst), now
			}
			b.tokens = min(float64(l.Burst), b.tokens+float64(max(now-b.last, 0))/1e9*l.rate)
			b.last = now
			if raise {
				b.tokens = min(b.tokens, float64(l.Burst)-used)
			} else {
				b.tokens = max(b.tokens-used, -float64(l.Burst))
			}
		})
	}
	login := cfg.thr[config.ScenarioLoginBruteforce]
	size := func(id string) int64 { return int64(cfg.thr[id].WindowS) * sec }
	count := func(own, theirs int) int {
		theirs = bounded(theirs)
		if raise {
			return max(own, theirs)
		}
		return min(own+theirs, shareMaxN)
	}
	for i := range cut(w.Clients, warmMaxEntries) {
		wc := &w.Clients[i]
		k, ok := key(wc.Client)
		if !ok {
			continue
		}
		e.clients.with(k, true, func(s *clientState) {
			s.seen = now
			s.loginFast.take(now, int64(login.WindowS)*sec, num(wc.LoginFast), raise)
			s.loginSlow.take(now, int64(login.SlowWindowS)*sec, num(wc.LoginSlow), raise)
			s.loginN = count(s.loginN, wc.LoginN)
			s.crawl.take(now, size(config.ScenarioAggressiveCrawl), num(wc.Crawl), raise)
			if len(wc.Users) > 0 {
				if s.users == nil {
					s.users = &userSketch{h: newHLL(6)}
				}
				if s.users.start == 0 || now-s.users.start >= size(config.ScenarioCredentialStuffing) {
					s.users.start = now
					s.users.h.reset()
				}
				s.users.h.merge(wc.Users)
			}
			if ids := cut(wc.Probe, shareProbes); len(ids) > 0 {
				if s.probe == nil {
					s.probe = &distinct[uint32]{}
				}
				// The member keeps the sum of the weights, not one per path:
				// a path new to this node weighs the average, rounded up.
				each := min(max((bounded(wc.ProbeW)+len(ids)-1)/len(ids), 1), probeWeight)
				for _, id := range ids {
					s.probe.add(now, size(config.ScenarioPathProbing), id, each, probeCapacity)
				}
			}
			if ids := cut(wc.WAF, shareWAF); len(ids) > 0 || wc.WAFHits > 0 {
				if s.waf == nil {
					s.waf = &distinct[int]{}
				}
				for _, id := range ids {
					s.waf.add(now, size(config.ScenarioWAFRepeat), id, 1, wafCapacity)
				}
				if s.waf.start != 0 {
					s.waf.hits = count(s.waf.hits, wc.WAFHits)
				}
			}
		})
	}
	for i := range cut(w.Sites, CapacitySites) {
		ws := &w.Sites[i]
		s := e.site(ws.Host)
		if s == nil {
			continue
		}
		s.mu.Lock()
		if s.start == 0 {
			s.start = now
		}
		if v := num(ws.Crawl); raise {
			s.total = max(s.total, v)
		} else {
			s.total += v
		}
		// What a website's normal is was learned over days: a node that has
		// none takes the member's, a node that has one keeps it.
		if s.baseline == 0 && ws.Baseline > 0 {
			s.baseline = num(ws.Baseline)
		}
		s.clients.merge(ws.Clients)
		if len(ws.Users) > 0 {
			if s.users.start == 0 || now-s.users.start >= size(config.ScenarioCredentialStuffing) {
				s.users.start = now
				s.users.h.reset()
			}
			s.users.h.merge(ws.Users)
		}
		s.mu.Unlock()
	}
	rt := cfg.dist.thr[config.DetectorRouteWave]
	for i := range cut(w.Routes, CapacityRoutes) {
		wr := &w.Routes[i]
		if !e.knownHost(wr.Host) || !knownRoute(cfg, wr.Route) {
			continue
		}
		e.d.routes.with(wr.Host+"|"+wr.Route, true, func(s *routeState) {
			s.roll(now, rt)
			s.lastSeen = now
			if raise {
				s.failures, s.successes, s.newSenders = max(s.failures, num(wr.Failed)), max(s.successes, num(wr.Passed)), max(s.newSenders, num(wr.New))
			} else {
				s.failures, s.successes, s.newSenders = s.failures+num(wr.Failed), s.successes+num(wr.Passed), s.newSenders+num(wr.New)
			}
			s.senders.merge(wr.Senders)
			// The baseline of a route, like a website's: taken when this
			// node has learned none.
			if s.windows == 0 && wr.Windows > 0 {
				s.baseline, s.windows = num(wr.Baseline), bounded(wr.Windows)
			}
		})
	}
	if cfg.dist.mode[config.DetectorAccountWave] != config.DistributedOff {
		win := int64(cfg.dist.thr[config.DetectorAccountWave].WindowS) * sec
		for i := range cut(w.Accounts, warmMaxEntries) {
			wa := &w.Accounts[i]
			e.d.accounts.with(wa.User, true, func(a *accountState) {
				if a.start == 0 || now-a.start >= win {
					a.start, a.failures, a.nSenders = now, 0, 0
				}
				a.lastSeen = now
				a.failures = count(a.failures, wa.Failed)
				for _, x := range cut(wa.Senders, len(a.senders)) {
					a.addSender(x)
				}
				if wa.FlaggedMS > 0 {
					until := now + min(wa.FlaggedMS*int64(time.Millisecond), int64(warmMaxFlagged), win)
					a.flagged = max(a.flagged, until)
					a.attempts = min(max(a.attempts, bounded(wa.Attempts)), 64)
					a.next = max(a.next, now+int64(cfg.dist.accountWait(a.attempts)))
				}
			})
		}
	}
	for i := range cut(w.Waves, CapacityWaves) {
		e.adoptWave(cfg, &w.Waves[i], t)
	}
}
