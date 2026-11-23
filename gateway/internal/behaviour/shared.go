package behaviour

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
)

// Counting across the nodes of a group (MVP-27, D105). Behind a balancer a
// client's requests land on every node, so a limit or a scenario that
// counts on one node sees a part of them. There is no shared counter and
// nothing in the request path asks another node: every node counts as on a
// single gateway and, once a second, tells the others what it counted in
// that second (Counts). A node adds what the others tell it to its own
// counters, as if those requests had come to it, without deciding anything:
// the next request of the client that reaches this node meets the sum.
//
// So a limit of n lets a client pass n plus what the nodes take in the
// second a count travels, and a scenario fires on the first node that sees
// a request after the sum is over its threshold. Each node tells only what
// it counted itself, so nothing is added twice.
//
// The sketches of user names and clients are merged by the hashes
// themselves, which is why the nodes of a group hash under one key
// (SetHashKey).

// Counts is what one node counted in about one second.
type Counts struct {
	Limits  []LimitCount  `json:"limits,omitempty"`
	Clients []ClientCount `json:"clients,omitempty"`
	Sites   []SiteCount   `json:"sites,omitempty"`
	// Dist is what the detectors of distributed attacks counted
	// (shared_dist.go).
	Dist *DistCounts `json:"dist,omitempty"`
}

// LimitCount: requests of one client key that matched one rate limit.
type LimitCount struct {
	Client string `json:"client"`
	Limit  string `json:"limit"`
	N      int    `json:"n"`
}

// ProbeCount is one probed path: its hash and its weight.
type ProbeCount struct {
	ID uint32 `json:"id"`
	W  int    `json:"w"`
}

// ClientCount: what the scenarios counted of one client key.
type ClientCount struct {
	Client      string       `json:"client"`
	LoginFailed int          `json:"login_failed,omitempty"`
	Crawl       int          `json:"crawl,omitempty"`
	Users       []uint64     `json:"users,omitempty"`
	Probe       []ProbeCount `json:"probe,omitempty"`
	WAF         []int        `json:"waf,omitempty"`
	WAFHits     int          `json:"waf_hits,omitempty"`
}

// SiteCount: what counts per website, the crawl baseline (requests and the
// clients that made them) and the user names of failed logins.
type SiteCount struct {
	Host    string   `json:"host"`
	Crawl   int      `json:"crawl,omitempty"`
	Clients []uint64 `json:"clients,omitempty"`
	Users   []uint64 `json:"users,omitempty"`
}

// Bounds of what one node tells per second, and of each list in it. What
// is over stays counted on its node only.
const (
	shareEntries = 2000
	shareUsers   = 32
	shareProbes  = probeCapacity
	shareWAF     = wafCapacity
	shareSiteIDs = 512
	shareMaxN    = 1 << 20
)

type limitShare struct {
	key   Key
	limit string
}

type sharer struct {
	mu      sync.Mutex
	limits  map[limitShare]int
	clients map[Key]*ClientCount
	sites   map[string]*SiteCount
	dist    distShare
	// notShared counts what did not fit.
	notShared atomic.Uint64
}

func newSharer() *sharer {
	return &sharer{limits: map[limitShare]int{}, clients: map[Key]*ClientCount{}, sites: map[string]*SiteCount{}}
}

// EnableSharing makes the engine note what it counts, for TakeCounts. A
// single gateway never calls it and notes nothing.
func (e *Engine) EnableSharing() { e.share.Store(newSharer()) }

// NotShared is how many counts did not fit into what this node told.
func (e *Engine) NotShared() uint64 {
	if sh := e.share.Load(); sh != nil {
		return sh.notShared.Load()
	}
	return 0
}

func (sh *sharer) limit(key Key, id string) {
	sh.mu.Lock()
	k := limitShare{key, id}
	if _, ok := sh.limits[k]; ok || len(sh.limits) < shareEntries {
		sh.limits[k]++
	} else {
		sh.notShared.Add(1)
	}
	sh.mu.Unlock()
}

func (sh *sharer) client(key Key, f func(*ClientCount)) {
	sh.mu.Lock()
	c := sh.clients[key]
	if c == nil {
		if len(sh.clients) >= shareEntries {
			sh.mu.Unlock()
			sh.notShared.Add(1)
			return
		}
		c = &ClientCount{}
		sh.clients[key] = c
	}
	f(c)
	sh.mu.Unlock()
}

func (sh *sharer) site(host string, f func(*SiteCount)) {
	sh.mu.Lock()
	s := sh.sites[host]
	if s == nil {
		if len(sh.sites) >= CapacitySites {
			sh.mu.Unlock()
			sh.notShared.Add(1)
			return
		}
		s = &SiteCount{Host: host}
		sh.sites[host] = s
	}
	f(s)
	sh.mu.Unlock()
}

// TakeCounts returns what the engine counted since the last call and starts
// anew; nil: nothing.
func (e *Engine) TakeCounts() *Counts {
	sh := e.share.Load()
	if sh == nil {
		return nil
	}
	sh.mu.Lock()
	limits, clients, sites := sh.limits, sh.clients, sh.sites
	if len(limits)+len(clients)+len(sites) == 0 && sh.dist.empty() {
		sh.mu.Unlock()
		return nil
	}
	sh.limits, sh.clients, sh.sites = map[limitShare]int{}, map[Key]*ClientCount{}, map[string]*SiteCount{}
	dist := sh.takeDist()
	sh.mu.Unlock()
	out := &Counts{Dist: dist}
	for k, n := range limits {
		out.Limits = append(out.Limits, LimitCount{Client: k.key.String(), Limit: k.limit, N: n})
	}
	for k, c := range clients {
		c.Client = k.String()
		out.Clients = append(out.Clients, *c)
	}
	for _, s := range sites {
		out.Sites = append(out.Sites, *s)
	}
	return out
}

func sharedKey(s string) (Key, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return Key{}, false
	}
	k, bits := KeyOf(p.Addr())
	return k, k.IsValid() && bits == p.Bits() && k == p
}

func bounded(n int) int { return min(max(n, 0), shareMaxN) }

// ApplyCounts adds what another node counted to this engine's counters. It
// decides nothing and writes no event. What does not parse or names a limit
// this node does not have is left out; lists are cut at their bounds.
func (e *Engine) ApplyCounts(c *Counts) {
	if c == nil {
		return
	}
	cfg := e.cfg.Load()
	e.applyDist(cfg, c.Dist)
	t := e.now()
	now := t.UnixNano()
	if len(c.Limits) > shareEntries {
		c.Limits = c.Limits[:shareEntries]
	}
	if len(c.Clients) > shareEntries {
		c.Clients = c.Clients[:shareEntries]
	}
	if len(c.Sites) > CapacitySites {
		c.Sites = c.Sites[:CapacitySites]
	}
	byID := make(map[string]*Limit, len(cfg.limits))
	for _, l := range cfg.limits {
		byID[l.ID] = l
	}
	for _, lc := range c.Limits {
		l, key := byID[lc.Limit], Key{}
		var ok bool
		if key, ok = sharedKey(lc.Client); !ok || l == nil || lc.N <= 0 {
			continue
		}
		n := float64(bounded(lc.N))
		e.buckets.with(bucketKey{key, l.idx}, true, func(b *bucket) {
			if b.last == 0 {
				b.tokens, b.last = float64(l.Burst), now
			}
			b.tokens = min(float64(l.Burst), b.tokens+float64(max(now-b.last, 0))/1e9*l.rate)
			b.last = now
			// Never further below zero than one burst: a node that tells
			// too much cannot lock a client out for long.
			b.tokens = max(b.tokens-n, -float64(l.Burst))
		})
	}
	sec := int64(time.Second)
	for i := range c.Clients {
		cc := &c.Clients[i]
		key, ok := sharedKey(cc.Client)
		if !ok {
			continue
		}
		e.clients.with(key, true, func(s *clientState) {
			s.seen = now
			if n := bounded(cc.LoginFailed); n > 0 {
				th := cfg.thr[config.ScenarioLoginBruteforce]
				s.loginFast.add(now, int64(th.WindowS)*sec, float32(n))
				s.loginSlow.add(now, int64(th.SlowWindowS)*sec, float32(n))
				s.loginN += n
			}
			if len(cc.Users) > 0 {
				th := cfg.thr[config.ScenarioCredentialStuffing]
				if s.users == nil {
					s.users = &userSketch{h: newHLL(6)}
				}
				for _, u := range cc.Users[:min(len(cc.Users), shareUsers)] {
					s.users.add(now, int64(th.WindowS)*sec, u)
				}
			}
			if len(cc.Probe) > 0 {
				th := cfg.thr[config.ScenarioPathProbing]
				if s.probe == nil {
					s.probe = &distinct[uint32]{}
				}
				for _, p := range cc.Probe[:min(len(cc.Probe), shareProbes)] {
					s.probe.add(now, int64(th.WindowS)*sec, p.ID, min(max(p.W, 1), probeWeight), probeCapacity)
				}
			}
			if n := bounded(cc.Crawl); n > 0 {
				s.crawl.add(now, int64(cfg.thr[config.ScenarioAggressiveCrawl].WindowS)*sec, float32(n))
			}
			if len(cc.WAF) > 0 {
				th := cfg.thr[config.ScenarioWAFRepeat]
				if s.waf == nil {
					s.waf = &distinct[int]{}
				}
				for _, id := range cc.WAF[:min(len(cc.WAF), shareWAF)] {
					s.waf.add(now, int64(th.WindowS)*sec, id, 1, wafCapacity)
				}
				s.waf.hits += bounded(cc.WAFHits)
			}
		})
	}
	for i := range c.Sites {
		sc := &c.Sites[i]
		s := e.site(sc.Host)
		if s == nil {
			continue
		}
		if n := bounded(sc.Crawl); n > 0 {
			s.addCrawl(now, int64(cfg.thr[config.ScenarioAggressiveCrawl].WindowS)*sec, n, sc.Clients[:min(len(sc.Clients), shareSiteIDs)])
		}
		if len(sc.Users) > 0 {
			th := cfg.thr[config.ScenarioCredentialStuffing]
			s.mu.Lock()
			for _, u := range sc.Users[:min(len(sc.Users), shareSiteIDs)] {
				s.users.add(now, int64(th.WindowS)*sec, u)
			}
			s.mu.Unlock()
		}
	}
}

// addCrawl is observeCrawl for what another node counted: n requests of
// these clients.
func (s *siteState) addCrawl(now, size int64, n int, clients []uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.start == 0 {
		s.start = now
	}
	s.total += float64(n)
	for _, c := range clients {
		s.clients.add(c)
	}
}

// noteShared notes what Observe counts of one request, for the other nodes.
func (e *Engine) noteShared(sh *sharer, r *Request, o Outcome, key Key, h string, site, loginFailed, probing, crawl, waf bool) {
	sh.client(key, func(c *ClientCount) {
		if loginFailed {
			c.LoginFailed++
			if o.HasUser && len(c.Users) < shareUsers {
				c.Users = append(c.Users, o.UserHash)
			}
		}
		if probing && len(c.Probe) < shareProbes {
			w := 1
			if IsProbePath(r.Path) {
				w = probeWeight
			}
			c.Probe = append(c.Probe, ProbeCount{ID: uint32(hashString(r.Path)), W: w})
		}
		if crawl {
			c.Crawl++
		}
		if waf {
			c.WAFHits++
			for _, id := range o.WAFRules {
				if len(c.WAF) < shareWAF {
					c.WAF = append(c.WAF, id)
				}
			}
		}
	})
	if !site || !(crawl || (loginFailed && o.HasUser)) {
		return
	}
	sh.site(h, func(s *SiteCount) {
		if crawl {
			s.Crawl++
			if len(s.Clients) < shareSiteIDs {
				s.Clients = append(s.Clients, hashKey(key))
			}
		}
		if loginFailed && o.HasUser && len(s.Users) < shareSiteIDs {
			s.Users = append(s.Users, o.UserHash)
		}
	})
}
