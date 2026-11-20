package hosts

import (
	"container/list"
	"crypto/tls"
	"log"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Limits of the agent listener (host-check.md section 6). Together they
// bound what the listener can cost, whatever the number of senders:
//
//   - connections: at most MaxConns open at once and MaxConnsPerPeer per
//     address (IPv6: per /64); excess connections from one peer are closed
//     at accept, before the TLS handshake; at the global cap the oldest
//     connection still waiting for its request headers makes room for the
//     new one (see limitListener);
//   - time: TLS handshake and headers within HeaderTimeout, the body at
//     MinBodyRate or faster, idle keep-alive connections closed after
//     IdleTimeout;
//   - memory: a body is read only when its Content-Length is declared, not
//     above the endpoint's limit, and fits into the in-flight body budget
//     (BodyBudget shared by everyone, LaneBudget reserved for enrolled
//     agents); otherwise the answer comes before a single body byte is read;
//   - CPU: at most VerifyConcurrency verifications at once.
//
// Worst case with the defaults: 512 connections x ~70 KiB TLS/HTTP state +
// 6 MiB bodies + 4 verifications of a 768 KiB envelope (~30 MiB) stays far
// below 100 MiB.
type Limits struct {
	MaxConns          int
	MaxConnsPerPeer   int
	HeaderTimeout     time.Duration
	IdleTimeout       time.Duration
	MinBodyRate       int64 // bytes per second
	BodyBudget        int64
	LaneBudget        int64
	VerifyConcurrency int
	PeerRequests      int // per 15 minutes and address (prefix)
	AgentRequests     int // per 15 minutes and enrolled agent
}

// DefaultLimits are used by New.
var DefaultLimits = Limits{
	MaxConns:          512,
	MaxConnsPerPeer:   8,
	HeaderTimeout:     5 * time.Second,
	IdleTimeout:       30 * time.Second,
	MinBodyRate:       64 << 10,
	BodyBudget:        4 << 20,
	LaneBudget:        2 << 20,
	VerifyConcurrency: 4,
	PeerRequests:      120,
	AgentRequests:     120,
}

// AgentKeyHeader carries an agent's key id with each report (lane hint).
const AgentKeyHeader = "Schild-Agent-Key"

// slogErrorLog routes net/http's own messages (TLS handshake errors of
// scanners, timeouts) to debug level: a flood must not flood the log.
func slogErrorLog(l *slog.Logger) *log.Logger { return slog.NewLogLogger(l.Handler(), slog.LevelDebug) }

// peerKey is the rate and connection key of a remote address: the IPv4
// address, or the /64 prefix of an IPv6 address (one host usually owns a
// whole /64, so per-address keys would be free to multiply).
func peerKey(r *http.Request) string { return peerOf(r.RemoteAddr) }

func peerOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		h = addr
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return h
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// ---------------------------------------------------------------- connections

// evictMinAge: a connection that has not sent complete request headers for
// at least this long may be closed to make room for a new one when the
// global cap is reached. An agent needs a few milliseconds for the TLS
// handshake and its headers, so it is never the oldest waiting connection.
const evictMinAge = 500 * time.Millisecond

// limitListener closes connections over the per-peer cap at accept time.
// At the global cap it first closes the oldest connection that is still
// waiting for its request headers (TLS handshake, slow headers, idle
// keep-alive) and older than evictMinAge; only when there is none is the
// new connection closed. So many addresses that each hold their share of
// half-open connections (distributed slowloris) cannot lock agents out:
// a new connection always replaces the oldest waiting one, and a request
// whose headers are complete is never evicted.
type limitListener struct {
	net.Listener
	max, perPeer int

	mu    sync.Mutex
	open  int
	peers map[string]int
	conns map[*limitConn]struct{}
	// dropped counts refused connections, evicted the waiting connections
	// closed for a new one (tests, logs).
	dropped, evicted int64
	now              func() time.Time
}

func newLimitListener(l net.Listener, max, perPeer int) *limitListener {
	return &limitListener{Listener: l, max: max, perPeer: perPeer, peers: map[string]int{}, conns: map[*limitConn]struct{}{}, now: time.Now}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		key := peerOf(c.RemoteAddr().String())
		now := l.now()
		l.mu.Lock()
		if l.peers[key] >= l.perPeer {
			l.dropped++
			l.mu.Unlock()
			_ = c.Close()
			continue
		}
		var victim *limitConn
		if l.open >= l.max {
			if victim = l.evictOldestWaiting(now); victim == nil {
				l.dropped++
				l.mu.Unlock()
				_ = c.Close()
				continue
			}
			l.evicted++
		}
		lc := &limitConn{Conn: c, l: l, key: key}
		lc.since.Store(now.UnixNano())
		l.open++
		l.peers[key]++
		l.conns[lc] = struct{}{}
		l.mu.Unlock()
		if victim != nil {
			_ = victim.Conn.Close()
		}
		return lc, nil
	}
}

// evictOldestWaiting picks the oldest connection without complete request
// headers that waits for at least evictMinAge, marks it evicted and
// releases its slot; the caller closes it after unlocking. nil when there
// is none. Caller holds l.mu.
func (l *limitListener) evictOldestWaiting(now time.Time) *limitConn {
	limit := now.Add(-evictMinAge).UnixNano()
	for tries := 0; tries < 4; tries++ {
		var best *limitConn
		var bestSince int64
		for c := range l.conns {
			if c.state.Load() != connWaiting {
				continue
			}
			if s := c.since.Load(); s <= limit && (best == nil || s < bestSince) {
				best, bestSince = c, s
			}
		}
		if best == nil {
			return nil
		}
		// Lost the race against its request headers: it is busy now, try
		// the next one.
		if !best.state.CompareAndSwap(connWaiting, connEvicted) {
			continue
		}
		best.released.Store(true)
		l.releaseLocked(best)
		return best
	}
	return nil
}

func (l *limitListener) releaseLocked(c *limitConn) {
	l.open--
	if l.peers[c.key]--; l.peers[c.key] <= 0 {
		delete(l.peers, c.key)
	}
	delete(l.conns, c)
}

func (l *limitListener) release(c *limitConn) {
	if !c.released.CompareAndSwap(false, true) {
		return
	}
	l.mu.Lock()
	l.releaseLocked(c)
	l.mu.Unlock()
}

type limitConn struct {
	net.Conn
	l        *limitListener
	key      string
	released atomic.Bool
	// state: connWaiting (TLS handshake, headers, idle keep-alive),
	// connBusy (headers complete, request served: http.StateActive) or
	// connEvicted; since: when the connection started waiting (accept, or
	// the end of the last request of a keep-alive connection).
	state atomic.Int32
	since atomic.Int64
}

const (
	connWaiting int32 = iota
	connBusy
	connEvicted
)

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.l.release(c)
	return err
}

// trackConnState is the http.Server ConnState hook of the agent listener:
// it marks which connections are serving a request (never evicted) and
// which are waiting for headers.
func trackConnState(c net.Conn, s http.ConnState) {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	lc, ok := c.(*limitConn)
	if !ok {
		return
	}
	switch s {
	case http.StateActive:
		lc.state.CompareAndSwap(connWaiting, connBusy)
	case http.StateIdle:
		lc.since.Store(lc.l.now().UnixNano())
		lc.state.CompareAndSwap(connBusy, connWaiting)
	}
}

// ---------------------------------------------------------------- memory

// budget is a byte semaphore for in-flight request bodies.
type budget struct {
	mu        sync.Mutex
	used, max int64
}

func (b *budget) take(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.max-b.used {
		return false
	}
	b.used += n
	return true
}

func (b *budget) give(n int64) {
	b.mu.Lock()
	b.used -= n
	b.mu.Unlock()
}

// ---------------------------------------------------------------- rate limit

// limiter counts events per key in a 15 minute window. It holds at most
// maxKeys keys; when full, the least recently used key is evicted. Eviction
// never resets other keys (a flood of new addresses cannot wipe the
// counters of the addresses that matter), and every key keeps at most
// limit+1 timestamps.
type limiter struct {
	mu      sync.Mutex
	maxKeys int
	ll      *list.List
	m       map[string]*list.Element
}

type limEntry struct {
	key    string
	events []time.Time
}

const (
	failLimit     = 10
	limiterKeys   = 50000
	limiterWindow = 15 * time.Minute
)

func newLimiter() *limiter { return newLimiterN(limiterKeys) }

func newLimiterN(n int) *limiter {
	return &limiter{maxKeys: n, ll: list.New(), m: map[string]*list.Element{}}
}

func (l *limiter) entry(key string) *limEntry {
	if e, ok := l.m[key]; ok {
		l.ll.MoveToFront(e)
		return e.Value.(*limEntry)
	}
	for l.ll.Len() >= l.maxKeys {
		old := l.ll.Back()
		l.ll.Remove(old)
		delete(l.m, old.Value.(*limEntry).key)
	}
	en := &limEntry{key: key}
	l.m[key] = l.ll.PushFront(en)
	return en
}

func (en *limEntry) prune(now time.Time, keep int) {
	i := 0
	for i < len(en.events) && now.Sub(en.events[i]) >= limiterWindow {
		i++
	}
	en.events = en.events[i:]
	if len(en.events) > keep {
		en.events = en.events[len(en.events)-keep:]
	}
}

// allow reports whether key may go on. perWindow > 0 counts this call as an
// event (requests); perWindow 0 only checks recorded failures.
func (l *limiter) allow(key string, now time.Time, perWindow int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	en := l.entry(key)
	limit := failLimit
	if perWindow > 0 {
		limit = perWindow
	}
	if perWindow > 0 {
		en.prune(now, limit)
		en.events = append(en.events, now)
	} else {
		en.prune(now, limit+1)
	}
	return len(en.events) <= limit
}

// refund takes back the newest event of key (a request that was answered
// with 503 busy, or one that turned out to be an enrolled agent's).
func (l *limiter) refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.m[key]; ok {
		en := e.Value.(*limEntry)
		if n := len(en.events); n > 0 {
			en.events = en.events[:n-1]
		}
	}
}

func (l *limiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	en := l.entry(key)
	en.prune(now, failLimit)
	en.events = append(en.events, now)
}
