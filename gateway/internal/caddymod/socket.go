package caddymod

import (
	"context"
	"errors"
	"net"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// One listening socket over every config load (D106).
//
// Caddy opens a second socket for the same address with SO_REUSEPORT when it
// loads a config, and closes the first one. The kernel resets what waits in
// the queue of a socket that closes, so under load every reload costs some
// visitors their connection: 1 to 5 of 4200 requests over 20 reloads.
//
// So the first socket of an address stays open for as long as any config
// listens there, and a program on the socket group (socket_linux.go) sends
// every connection to it. The sockets of later configs stay empty, and
// closing them resets nothing. The connections go to the config that runs.
//
// That leaves one gap, in net/http: a server that stops drops a connection it
// has accepted and whose first request it reads at that moment, without an
// answer. So before Caddy stops the config before it, a new config that has
// started takes the connections alone, and waits until the old one has read
// the first request of those it has (takeOver). The wait is a time and no
// proof: a goroutine that pauses for longer than quietFor at that point
// still loses its request.

// keepSocket returns ln on the socket of its address that stays open, or ln
// itself where that does not work (no TCP, not Linux, Multipath TCP, which
// schild turns off: cmd/schild/main.go).
func keepSocket(ln net.Listener, ka net.KeepAliveConfig, fresh *atomic.Int64) net.Listener {
	tl := tcpListenerOf(ln)
	if tl == nil {
		return ln
	}
	a := acceptorOf(tl)
	if a == nil {
		return ln
	}
	g := &generation{Listener: ln, a: a, ka: ka, fresh: fresh, deaf: make(chan struct{}), done: make(chan struct{})}
	acceptors.mu.Lock()
	a.gens = append(a.gens, g)
	acceptors.mu.Unlock()
	return g
}

// tcpListenerOf returns the TCP listener below Caddy's wrapper, which counts
// the users of an address and hides everything but net.Listener.
func tcpListenerOf(ln net.Listener) *net.TCPListener {
	for range 4 {
		if tl, ok := ln.(*net.TCPListener); ok {
			return tl
		}
		v := reflect.Indirect(reflect.ValueOf(ln))
		if v.Kind() != reflect.Struct {
			return nil
		}
		f := v.FieldByName("Listener")
		if !f.IsValid() || !f.CanInterface() {
			return nil
		}
		next, ok := f.Interface().(net.Listener)
		if !ok {
			return nil
		}
		ln = next
	}
	return nil
}

// acceptor takes the connections of one address and hands them to the
// configs that listen there.
type acceptor struct {
	key   string
	ln    net.Listener // the first socket, by a descriptor of its own
	users int
	gens  []*generation // oldest first
	conns chan net.Conn
	done  chan struct{} // no config listens here any more
}

var acceptors = struct {
	mu sync.Mutex
	m  map[string]*acceptor
}{m: map[string]*acceptor{}}

// acceptorOf returns the acceptor of the address of tl, one user more; nil
// when it cannot be kept open.
func acceptorOf(tl *net.TCPListener) *acceptor {
	key := tl.Addr().Network() + "/" + tl.Addr().String()
	acceptors.mu.Lock()
	defer acceptors.mu.Unlock()
	if a := acceptors.m[key]; a != nil {
		a.users++
		return a
	}
	if err := firstTakesAll(tl); err != nil {
		return nil
	}
	f, err := tl.File()
	if err != nil {
		return nil
	}
	defer f.Close()
	own, err := net.FileListener(f)
	if err != nil {
		return nil
	}
	a := &acceptor{key: key, ln: own, users: 1, conns: make(chan net.Conn), done: make(chan struct{})}
	acceptors.m[key] = a
	go a.run()
	return a
}

func (a *acceptor) run() {
	wait := time.Duration(0)
	for {
		c, err := a.ln.Accept()
		if err != nil {
			select {
			case <-a.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Out of descriptors and the like: as net/http does it.
			wait = min(max(2*wait, 5*time.Millisecond), time.Second)
			time.Sleep(wait)
			continue
		}
		wait = 0
		a.give(c)
	}
}

// give hands c to a config that accepts, or closes it when there is none.
func (a *acceptor) give(c net.Conn) {
	select {
	case a.conns <- c:
	case <-a.done:
		_ = c.Close()
	}
}

func (a *acceptor) release(g *generation) {
	acceptors.mu.Lock()
	defer acceptors.mu.Unlock()
	a.gens = slices.DeleteFunc(a.gens, func(x *generation) bool { return x == g })
	if a.users--; a.users > 0 {
		return
	}
	delete(acceptors.m, a.key)
	close(a.done)
	_ = a.ln.Close()
}

// generation is the listener of one config on an acceptor. Its own socket,
// the embedded Listener, is only there for Caddy's count of users.
type generation struct {
	net.Listener
	a  *acceptor
	ka net.KeepAliveConfig
	// fresh counts the connections of the server that have sent no request.
	fresh *atomic.Int64
	deaf  chan struct{} // closed: takes no more connections (takeOver)
	once  sync.Once
	done  chan struct{}
}

// Accept implements net.Listener.
func (g *generation) Accept() (net.Conn, error) {
	select {
	case <-g.done:
		return nil, g.closed()
	default:
	}
	conns := g.a.conns
	select {
	case <-g.deaf:
		conns = nil
	default:
	}
	select {
	case <-g.done:
		return nil, g.closed()
	case <-g.deaf:
		<-g.done
		return nil, g.closed()
	case c := <-conns:
		select {
		case <-g.done:
			// Closed meanwhile: it belongs to the next config.
			go g.a.give(c)
			return nil, g.closed()
		default:
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetKeepAliveConfig(g.ka)
		}
		return c, nil
	}
}

func (g *generation) closed() error {
	return &net.OpError{Op: "accept", Net: g.Addr().Network(), Addr: g.Addr(), Err: net.ErrClosed}
}

// Close implements net.Listener.
func (g *generation) Close() error {
	err := net.ErrClosed
	g.once.Do(func() {
		close(g.done)
		err = g.Listener.Close()
		g.a.release(g)
	})
	return err
}

// takeOverWait bounds how long a reload waits for connections that have sent
// nothing, for example those a browser opens ahead.
const takeOverWait = 2 * time.Second

// quietFor is how long the configs before the newest have to be without a
// fresh connection before Caddy may stop them. Every reload lasts at least
// this long.
const quietFor = 500 * time.Millisecond

// takeOver leaves the connections of every address to its newest config, and
// waits until the configs before it have read the first request of the
// connections they have. Called when the new config has started and before
// the old one stops.
func takeOver() {
	var old []*generation
	acceptors.mu.Lock()
	for _, a := range acceptors.m {
		for _, g := range a.gens[:max(len(a.gens)-1, 0)] {
			select {
			case <-g.deaf:
			default:
				close(g.deaf)
				old = append(old, g)
			}
		}
	}
	acceptors.mu.Unlock()
	if len(old) == 0 {
		return
	}
	// net/http marks a connection as read and only then looks whether its
	// server stops; a request read in between gets no answer. Nothing tells
	// when a goroutine is past that point, so the old configs have to be
	// without a fresh connection for quietFor in a row. On a busy machine
	// the goroutine waited longer than the 40 ms this was at first (found by
	// the race detector in CI: 1 of 1495 requests). The same time covers a
	// connection the old config has accepted and not yet counted.
	const step = 20 * time.Millisecond
	calm := time.Duration(0)
	for end := time.Now().Add(takeOverWait); time.Now().Before(end) && calm < quietFor; time.Sleep(step) {
		if slices.ContainsFunc(old, func(g *generation) bool { return g.fresh.Load() > 0 }) {
			calm = 0
		} else {
			calm += step
		}
	}
}

// onStarted runs takeOver when the config that provisions it has started.
type onStarted struct{}

// Handle implements caddyevents.Handler.
func (onStarted) Handle(context.Context, caddy.Event) error {
	takeOver()
	return nil
}
