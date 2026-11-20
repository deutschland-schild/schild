package bots

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// FCrDNS (bots.verify.fcrdns, default off). Switched on, schild asks the
// system resolver for the reverse name of the client address of a request
// that claims a bot with rdns_suffixes and confirms it forward. This sends
// visitor addresses (of requests with a bot User-Agent only) to the
// configured resolver, which is why it is off by default.
//
// Lookups never run on the request path: Verify reads only a bounded
// in-memory cache and queues a missing address; one background worker
// resolves the queue at a fixed rate. Until an answer is cached the state
// is what the ranges say.
const (
	fcQueue     = 256              // queued addresses; more are dropped
	fcMaxEntry  = 8192             // cached addresses
	fcTTL       = time.Hour        // a confirmed or refuted name
	fcNegTTL    = 10 * time.Minute // no reverse name, or lookup failed
	fcInterval  = 50 * time.Millisecond
	fcTimeout   = 2 * time.Second
	fcMaxNames  = 4 // reverse names checked per address
	fcKeepNames = 2 // confirmed names kept per address
)

type fcEntry struct {
	names [fcKeepNames]string // forward-confirmed, lower case, no trailing dot
	n     uint8
	exp   int64 // unix seconds
}

type fcrdns struct {
	mu  sync.RWMutex
	m   map[netip.Addr]fcEntry
	q   chan netip.Addr
	now func() time.Time

	// Resolver functions (tests replace them).
	lookupAddr func(ctx context.Context, addr string) ([]string, error)
	lookupIP   func(ctx context.Context, network, host string) ([]netip.Addr, error)
	interval   time.Duration
}

func newFCrDNS(now func() time.Time) *fcrdns {
	r := net.DefaultResolver
	return &fcrdns{m: map[netip.Addr]fcEntry{}, q: make(chan netip.Addr, fcQueue), now: now,
		lookupAddr: r.LookupAddr, lookupIP: r.LookupNetIP, interval: fcInterval}
}

// check answers from the cache: 1 a confirmed name ends in a suffix, 2
// confirmed names end in none, 0 no answer (queued).
func (f *fcrdns) check(a netip.Addr, suffixes []string) int {
	f.mu.RLock()
	e, ok := f.m[a]
	f.mu.RUnlock()
	if !ok || e.exp < f.now().Unix() {
		select {
		case f.q <- a:
		default: // queue full: try again with a later request
		}
		return 0
	}
	if e.n == 0 {
		return 0
	}
	for _, n := range e.names[:e.n] {
		for _, s := range suffixes {
			if n == s || len(n) > len(s) && strings.HasSuffix(n, s) && n[len(n)-len(s)-1] == '.' {
				return 1
			}
		}
	}
	return 2
}

func (f *fcrdns) run(ctx context.Context) {
	t := time.NewTicker(f.interval)
	defer t.Stop()
	for {
		var a netip.Addr
		select {
		case <-ctx.Done():
			return
		case a = <-f.q:
		}
		f.mu.RLock()
		e, ok := f.m[a]
		f.mu.RUnlock()
		if ok && e.exp >= f.now().Unix() {
			continue // answered meanwhile (queued twice)
		}
		select { // rate limit
		case <-ctx.Done():
			return
		case <-t.C:
		}
		f.store(a, f.resolve(ctx, a))
	}
}

func (f *fcrdns) resolve(ctx context.Context, a netip.Addr) fcEntry {
	ctx, cancel := context.WithTimeout(ctx, fcTimeout)
	defer cancel()
	var e fcEntry
	names, err := f.lookupAddr(ctx, a.String())
	if err != nil {
		names = nil
	}
	if len(names) > fcMaxNames {
		names = names[:fcMaxNames]
	}
	for _, n := range names {
		if e.n == fcKeepNames {
			break
		}
		ips, err := f.lookupIP(ctx, "ip", n)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.Unmap() == a {
				e.names[e.n] = strings.TrimSuffix(strings.Map(lowerASCII, n), ".")
				e.n++
				break
			}
		}
	}
	ttl := fcTTL
	if e.n == 0 {
		ttl = fcNegTTL
	}
	e.exp = f.now().Add(ttl).Unix()
	return e
}

func (f *fcrdns) store(a netip.Addr, e fcEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.m) >= fcMaxEntry {
		now := f.now().Unix()
		for k, v := range f.m {
			if v.exp < now {
				delete(f.m, k)
			}
		}
		for k := range f.m { // still full: drop an arbitrary eighth
			if len(f.m) < fcMaxEntry*7/8 {
				break
			}
			delete(f.m, k)
		}
	}
	f.m[a] = e
}

func (f *fcrdns) size() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.m)
}
