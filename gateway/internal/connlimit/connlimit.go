// Package connlimit bounds the open connections of the ingress (D46,
// contracts/body-limits.md section 2c). It wraps Caddy's listeners below TLS, so a
// refused connection costs an accept and a close, no handshake and no goroutine.
// The decision is bodylimit.AdmitConnection.
//
// A connection without a running request holds memory that no limit of the gate
// sees: open connections from one address ended a 2 GiB container, with
// schild_requests_waiting near 0. The counts here are per client key, per network
// and for the gateway.
//
// A full scope gives the place of its oldest idle connection to the new one, and
// refuses only when none is idle long enough. Without this a client behind one
// address would lock itself out with its own keep-alive connections, and many
// networks could fill the gateway with connections that do nothing. Only a request
// holds a place: bytes alone would let a PING every few seconds keep every place,
// and new visitors out. A request is what reached a handler (Served): the server
// reports a stream it refused at once as active and idle too.
package connlimit

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// Options of a limiter. Only Limits is needed.
type Options struct {
	Limits bodylimit.ConnLimits
	// Trusted reports a trusted proxy: such a peer is not the client, so only the
	// limit of the gateway applies to it.
	Trusted func(netip.Addr) bool
	// NetClass is the net class of a peer, for the factor of cgnat and mobile.
	NetClass func(netip.Addr) string
	// Open follows the number of open connections, Refused and Evicted count by
	// scope. Each may be nil.
	Open             func(delta float64)
	Refused, Evicted func(scope string)
	Log              *slog.Logger
	Now              func() time.Time
}

// evictTries bounds the scan for an idle connection at a full scope. What was not
// idle goes to the end of the list, so the next try starts further on.
const evictTries = 64

// Limiter counts the connections of every listener it wraps: the gateway limit
// covers ports 80 and 443 together.
type Limiter struct {
	o        Options
	minIdle  time.Duration
	warnings ratelog.Limiter

	mu       sync.Mutex
	all      ring // every connection, the least recently active first
	clients  map[netip.Prefix]*group
	networks map[netip.Prefix]*group
}

// group is one client key or one network.
type group struct {
	n    int
	ring ring
}

// New returns a limiter.
func New(o Options) *Limiter {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Limiter{o: o, minIdle: bodylimit.ConnEvictMinAgeS * time.Second, clients: map[netip.Prefix]*group{}, networks: map[netip.Prefix]*group{}}
}

// Open returns the open connections of the limiter.
func (l *Limiter) Open() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.all.n
}

// Listen wraps ln. proxied says that every peer of this listener is a proxy
// (proxy_protocol on the server): the address the kernel gives is the proxy's.
func (l *Limiter) Listen(ln net.Listener, proxied bool) net.Listener {
	return &listener{Listener: ln, l: l, proxied: proxied}
}

type listener struct {
	net.Listener
	l       *Limiter
	proxied bool
}

// Accept returns the next admitted connection. A refused one is closed at once.
func (ln *listener) Accept() (net.Conn, error) {
	for {
		c, err := ln.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if lc := ln.l.admit(c, ln.proxied); lc != nil {
			return lc, nil
		}
		_ = c.Close()
	}
}

func prefixOf(a netip.Addr, v4, v6 int) netip.Prefix {
	bits := v6
	if a.Is4() {
		bits = v4
	}
	p, _ := a.Prefix(bits)
	return p
}

// admit decides on c and counts it. nil: refused, the caller closes c.
func (l *Limiter) admit(c net.Conn, proxied bool) *Conn {
	peer, _ := clientip.Peer(c.RemoteAddr().String())
	known := peer.IsValid()
	proxy := proxied || (known && l.o.Trusted != nil && l.o.Trusted(peer))
	netClass := ""
	if known && !proxy && l.o.NetClass != nil {
		netClass = l.o.NetClass(peer)
	}
	now := l.o.Now()
	lc := &Conn{Conn: c, l: l}
	lc.active.Store(now.UnixNano())
	lc.addr = &peerAddr{Addr: c.RemoteAddr(), conn: lc}
	var clientKey, netKey netip.Prefix
	if known && !proxy {
		clientKey, netKey = prefixOf(peer, 32, 64), prefixOf(peer, 24, 48)
	}

	l.mu.Lock()
	cl, nw := l.clients[clientKey], l.networks[netKey]
	st := bodylimit.ConnState{Open: l.all.n}
	if cl != nil {
		st.Client = cl.n
	}
	if nw != nil {
		st.Network = nw.n
	}
	d := bodylimit.AdmitConnection(l.o.Limits, st, netClass, known, proxy)
	var victim *Conn
	if d.Refused != nil {
		scope := *d.Refused
		if victim = l.pick(scope, cl, nw, now); victim != nil {
			switch scope {
			case bodylimit.ScopeClient:
				st.ClientIdle = true
			case bodylimit.ScopeNetwork:
				st.NetworkIdle = true
			default:
				st.OpenIdle = true
			}
			d = bodylimit.AdmitConnection(l.o.Limits, st, netClass, known, proxy)
			l.remove(victim)
			cl, nw = l.clients[clientKey], l.networks[netKey] // the victim may have emptied them
		}
	}
	if !d.Admitted {
		l.mu.Unlock()
		if l.o.Refused != nil {
			l.o.Refused(*d.Refused)
		}
		if l.o.Log != nil {
			l.warnings.Warn(l.o.Log, "connection limit reached, connection closed; behind a proxy check ingress.trusted_proxies", "scope", *d.Refused)
		}
		return nil
	}
	if known && !proxy {
		if cl == nil {
			cl = &group{}
			l.clients[clientKey] = cl
		}
		if nw == nil {
			nw = &group{}
			l.networks[netKey] = nw
		}
		lc.client, lc.network = cl, nw
		lc.clientKey, lc.netKey = clientKey, netKey
		cl.n++
		nw.n++
		cl.ring.push(lc, ringClient)
		nw.ring.push(lc, ringNetwork)
	}
	l.all.push(lc, ringAll)
	l.mu.Unlock()
	if l.o.Open != nil {
		l.o.Open(1)
	}
	if victim != nil {
		_ = victim.Conn.Close()
		if l.o.Open != nil {
			l.o.Open(-1)
		}
		if l.o.Evicted != nil {
			l.o.Evicted(*d.Evict)
		}
	}
	return lc
}

// pick finds the oldest idle connection of a full scope and claims it, or returns
// nil. A connection that is busy or was active of late goes to the end of its list.
func (l *Limiter) pick(scope string, cl, nw *group, now time.Time) *Conn {
	r, which := &l.all, ringAll
	switch {
	case scope == bodylimit.ScopeClient && cl != nil:
		r, which = &cl.ring, ringClient
	case scope == bodylimit.ScopeNetwork && nw != nil:
		r, which = &nw.ring, ringNetwork
	}
	limit := now.Add(-l.minIdle).UnixNano()
	for i := 0; i < evictTries && r.n > 0; i++ {
		c := r.head
		if c.active.Load() <= limit && c.state.CompareAndSwap(stateIdle, stateGone) {
			return c
		}
		r.remove(c, which)
		r.push(c, which)
	}
	return nil
}

// remove takes c out of every count. Caller holds l.mu.
func (l *Limiter) remove(c *Conn) {
	if !c.released.CompareAndSwap(false, true) {
		return
	}
	l.all.remove(c, ringAll)
	if c.client != nil {
		c.client.ring.remove(c, ringClient)
		if c.client.n--; c.client.n == 0 {
			delete(l.clients, c.clientKey)
		}
		c.network.ring.remove(c, ringNetwork)
		if c.network.n--; c.network.n == 0 {
			delete(l.networks, c.netKey)
		}
	}
}

// release ends the count of a closed connection.
func (l *Limiter) release(c *Conn) {
	l.mu.Lock()
	gone := c.released.Load()
	l.remove(c)
	l.mu.Unlock()
	if !gone && l.o.Open != nil {
		l.o.Open(-1)
	}
}

const (
	stateIdle int32 = iota // accept, TLS handshake, headers, keep-alive
	stateBusy              // at least one request runs, or the connection was hijacked
	stateGone              // claimed for a new connection
)

// Conn is a counted connection.
type Conn struct {
	net.Conn
	l                 *Limiter
	addr              *peerAddr
	client, network   *group
	clientKey, netKey netip.Prefix
	links             [3]link
	state             atomic.Int32
	active            atomic.Int64 // unix nanoseconds of the opening or the end of the last request
	served            atomic.Bool  // a request reached a handler since the connection was last idle
	released          atomic.Bool
}

// Close closes the connection and gives its place back.
func (c *Conn) Close() error {
	err := c.Conn.Close()
	c.l.release(c)
	return err
}

// CloseWrite half-closes as a TCP connection does: net/http looks for this method
// before it waits for a client to read a refusal.
func (c *Conn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}

// RemoteAddr returns the peer's address, which also leads back to this connection.
func (c *Conn) RemoteAddr() net.Addr { return c.addr }

// peerAddr finds a Conn from outside: Caddy wraps connections in types of its own
// that cannot be unwrapped, and every such wrapper hands on RemoteAddr.
type peerAddr struct {
	net.Addr
	conn *Conn
}

// Track is the ConnState hook of a server: which connections run a request. The
// age starts again only when a request reached a handler in between: a HEADERS
// frame the server refuses, or a stream reset at once, makes the connection active
// and idle without one, and would keep the place for a few bytes.
//
// StateNew is left alone: the server reports it from its accept loop, where of
// must not run.
func Track(c net.Conn, s http.ConnState) {
	if s != http.StateActive && s != http.StateHijacked && s != http.StateIdle {
		return
	}
	lc := of(c)
	if lc == nil {
		return
	}
	switch s {
	case http.StateActive, http.StateHijacked:
		lc.state.CompareAndSwap(stateIdle, stateBusy)
	case http.StateIdle:
		if lc.served.Swap(false) {
			lc.active.Store(lc.l.o.Now().UnixNano())
		}
		lc.state.CompareAndSwap(stateBusy, stateIdle)
	}
}

// maxUnwrap bounds the walk of of through wrapped connections.
const maxUnwrap = 8

// of finds the counted connection under c, the connection a server hands its
// hooks: a *tls.Conn (NetConn), a proxy protocol connection (Raw), or a wrapper of
// Caddy's own that only hands on RemoteAddr. The address of a proxy protocol
// connection is the one of its header, so it never leads back here, and asking for
// it waits until the header is read: of runs only once the connection was read
// from, never in the accept loop (ConnContext, StateNew), where a client that
// sends nothing would hold up every new connection. Behind a wrapper of Caddy's
// own on top of the proxy protocol (h1 or h2 alone, without TLS) it finds nothing.
func of(c net.Conn) *Conn {
	for i := 0; i < maxUnwrap && c != nil; i++ {
		switch u := c.(type) {
		case *Conn:
			return u
		case interface{ NetConn() net.Conn }:
			c = u.NetConn()
		case interface{ Raw() net.Conn }:
			c = u.Raw()
		default:
			if a, ok := c.RemoteAddr().(*peerAddr); ok {
				return a.conn
			}
			return nil
		}
	}
	return nil
}

type ctxKey struct{}

// WithConn is the ConnContext hook of a server: it puts the connection into the
// context of its requests, for Served. It runs in the accept loop, so it only
// keeps c; Served looks up the counted connection.
func WithConn(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// Served marks the connection of a request that reached a handler.
func Served(ctx context.Context) {
	if c, ok := ctx.Value(ctxKey{}).(net.Conn); ok {
		if lc := of(c); lc != nil {
			lc.served.Store(true)
		}
	}
}

// Which of the three lists of a connection.
const (
	ringAll = iota
	ringClient
	ringNetwork
)

type link struct{ prev, next *Conn }

// ring is a doubly linked list through the connections, so a connection in three
// lists costs no allocation, and moving one costs no scan.
type ring struct {
	head, tail *Conn
	n          int
}

func (r *ring) push(c *Conn, w int) {
	c.links[w] = link{prev: r.tail}
	if r.tail != nil {
		r.tail.links[w].next = c
	} else {
		r.head = c
	}
	r.tail = c
	r.n++
}

func (r *ring) remove(c *Conn, w int) {
	l := c.links[w]
	if l.prev != nil {
		l.prev.links[w].next = l.next
	} else {
		r.head = l.next
	}
	if l.next != nil {
		l.next.links[w].prev = l.prev
	} else {
		r.tail = l.prev
	}
	c.links[w] = link{}
	r.n--
}
