package bots

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/deutschland-schild/schild/contract/websites"
)

// Robots observes the robots.txt of each website (spec MVP-22 bots
// robots_txt; observation only, never enforced). Once an hour it reads
// /robots.txt of every website from the website's own upstream through a
// FetchFunc, never through the gateway's listener, so the fetch is not
// inspected, counted or logged as a request. Disallowed answers from the
// last good copy without allocation.
//
// Answers per website:
//   - 2xx: the parsed file (at most MaxRobotsBytes are read);
//   - 4xx except 429: known, everything allowed (RFC 9309 "unavailable");
//   - 3xx the fetch did not follow, 429, 5xx, network errors: the last good
//     copy stays; without one the website is unknown (Disallowed known
//     false: "unklar").
type Robots struct {
	fetch   FetchFunc
	sites   atomic.Pointer[map[string]*robotsSite]
	now     func() time.Time
	every   time.Duration
	timeout time.Duration
	// delay before the first fetch after Start (the gateway does not
	// hit every backend while it starts).
	delay time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// RobotsSite is one website whose robots.txt is observed: ID is the
// website id (contract/websites, the site of the request ring), Host the
// Host header sent to the upstream ("" keeps the upstream's own host).
type RobotsSite struct {
	ID   string
	Host string
}

// FetchFunc fetches /robots.txt of the website with the given Host header.
// The caller closes the body. It must not go through the gateway's own
// listener (the WAF, the counters and the event log).
type FetchFunc func(ctx context.Context, host string) (*http.Response, error)

// RobotsSitesOf lists the websites schild sees (protected or partial) with
// the first host that is not a wildcard as the Host header. The proxy-mode
// website "default" (no upstream.site_hosts) keeps the upstream's own host;
// other websites without a usable host are left out.
func RobotsSitesOf(ws []websites.Website) []RobotsSite {
	var out []RobotsSite
	for _, w := range ws {
		if w.Protection == websites.Unprotected {
			continue
		}
		host := ""
		for _, h := range w.Hosts {
			if !strings.Contains(h, "*") {
				host = h
				break
			}
		}
		if host == "" && w.ID != websites.DefaultID {
			continue
		}
		out = append(out, RobotsSite{ID: w.ID, Host: host})
	}
	return out
}

// RobotsInterval is how often each robots.txt is read.
const RobotsInterval = time.Hour

// RobotsUA is the User-Agent of the robots.txt fetch.
const RobotsUA = "schild-robots/0.1 (robots.txt observation)"

type robotsSite struct {
	host string
	cur  atomic.Pointer[robotsState]
}

type robotsState struct {
	file    *robotsFile
	fetched time.Time
}

// NewRobots observes the robots.txt of sites through fetch. Nothing is
// fetched before Start (or Refresh).
func NewRobots(sites []RobotsSite, fetch FetchFunc) *Robots {
	r := &Robots{fetch: fetch, now: time.Now, every: RobotsInterval, timeout: 10 * time.Second, delay: RobotsFirstDelay}
	r.SetSites(sites)
	return r
}

// SetSites replaces the observed websites (e.g. after a configuration
// change); websites kept keep their last copy.
func (r *Robots) SetSites(sites []RobotsSite) {
	old := r.sites.Load()
	m := make(map[string]*robotsSite, len(sites))
	for _, s := range sites {
		if s.ID == "" {
			continue
		}
		if old != nil {
			if o := (*old)[s.ID]; o != nil && o.host == s.Host {
				m[s.ID] = o
				continue
			}
		}
		m[s.ID] = &robotsSite{host: s.Host}
	}
	r.sites.Store(&m)
}

// Disallowed reports whether the robots.txt of site disallows path for the
// robots token (catalogue robots_token, ASCII case-insensitive; the "*"
// group applies when the file names no group for it). known is false while
// schild has no copy of the site's robots.txt. path is the request path
// (no query). It does not allocate for tokens up to 64 bytes and paths up
// to 2 KiB.
func (r *Robots) Disallowed(site, robotsToken, path string) (disallowed bool, known bool) {
	m := r.sites.Load()
	if m == nil {
		return false, false
	}
	s := (*m)[site]
	if s == nil {
		return false, false
	}
	st := s.cur.Load()
	if st == nil {
		return false, false
	}
	if st.file == nil {
		return false, true // 4xx: everything allowed
	}
	var tb [64]byte
	tok := tb[:0]
	if len(robotsToken) <= len(tb) {
		for i := 0; i < len(robotsToken); i++ {
			tok = append(tok, byte(lowerASCII(rune(robotsToken[i]))))
		}
	}
	if needsNormalize(path) {
		var pb [2048]byte
		n := appendNormalized(pb[:0], path)
		path = unsafe.String(unsafe.SliceData(n), len(n))
		return st.file.disallowedB(tok, path), true
	}
	return st.file.disallowedB(tok, path), true
}

// disallowedB is disallowed with the token as lower-case bytes (the map
// lookup with string(b) does not allocate).
func (f *robotsFile) disallowedB(tok []byte, path string) bool {
	if path == "/robots.txt" {
		return false
	}
	g := f.groups[string(tok)]
	if g == nil {
		g = f.star
	}
	if g == nil {
		return false
	}
	best, allow := -1, true
	for i := range g.rules {
		ru := &g.rules[i]
		if ru.n < best || ru.n == best && !ru.allow {
			continue
		}
		if ru.match(path) {
			best, allow = ru.n, ru.allow
		}
	}
	return !allow
}

// FetchedAt is when the robots.txt of site was last read successfully
// (zero: never).
func (r *Robots) FetchedAt(site string) time.Time {
	m := r.sites.Load()
	if m == nil {
		return time.Time{}
	}
	if s := (*m)[site]; s != nil {
		if st := s.cur.Load(); st != nil {
			return st.fetched
		}
	}
	return time.Time{}
}

// RobotsFirstDelay: the first fetch after Start.
const RobotsFirstDelay = time.Minute

// Start reads every robots.txt after RobotsFirstDelay and then once an
// hour until ctx ends or Close.
func (r *Robots) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if r.delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(r.delay):
			}
		}
		t := time.NewTicker(r.every)
		defer t.Stop()
		for {
			r.Refresh(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// Close stops the hourly fetch and waits for it.
func (r *Robots) Close() {
	r.mu.Lock()
	c := r.cancel
	r.mu.Unlock()
	if c != nil {
		c()
	}
	r.wg.Wait()
}

// Refresh reads the robots.txt of every website once, one after the other.
func (r *Robots) Refresh(ctx context.Context) {
	m := r.sites.Load()
	if m == nil {
		return
	}
	for _, s := range *m {
		if ctx.Err() != nil {
			return
		}
		r.refreshOne(ctx, s)
	}
}

func (r *Robots) refreshOne(ctx context.Context, s *robotsSite) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	resp, err := r.fetch(ctx, s.host)
	if err != nil {
		return // keep the last good copy
	}
	defer resp.Body.Close()
	switch c := resp.StatusCode; {
	case c >= 200 && c < 300:
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxRobotsBytes))
		if err != nil {
			return
		}
		s.cur.Store(&robotsState{file: parseRobots(body), fetched: r.now()})
	case c >= 400 && c < 500 && c != http.StatusTooManyRequests:
		s.cur.Store(&robotsState{fetched: r.now()})
	}
}

// ProxyFetch reads /robots.txt from the upstream of proxy mode
// (schild.yaml upstream.url) with the website's Host header, as the
// gateway's reverse proxy would forward it, but directly and not through
// the gateway: no proxy from the environment, at most 5 redirects and only
// to the same upstream (a redirect to the public host would come back
// through the gateway and is not followed; that website stays unknown).
func ProxyFetch(upstreamURL string, timeout time.Duration) (FetchFunc, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("robots: upstream must be http(s)://host[:port]")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	target := u.ResolveReference(&url.URL{Path: "/robots.txt"})
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
	}
	c := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != u.Scheme || req.URL.Host != u.Host {
			return http.ErrUseLastResponse
		}
		req.Host = via[0].Host
		return nil
	}}
	return func(ctx context.Context, host string) (*http.Response, error) {
		return get(ctx, c, target.String(), host)
	}, nil
}

func get(ctx context.Context, c *http.Client, target, host string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if host != "" {
		req.Host = host
		req.Header.Set("X-Forwarded-Host", host)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("User-Agent", RobotsUA)
	req.Header.Set("Accept", "text/plain, */*;q=0.5")
	return c.Do(req)
}
