package connlimit

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/bodylimit"
)

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// fakeConn is a connection from a chosen peer.
type fakeConn struct {
	net.Conn
	peer   string
	closed atomic.Bool
}

func (c *fakeConn) RemoteAddr() net.Addr { return fakeAddr(c.peer) }
func (c *fakeConn) Close() error         { c.closed.Store(true); return nil }

type fixture struct {
	l       *Limiter
	now     time.Time
	mu      sync.Mutex
	open    float64
	refused map[string]int
	evicted map[string]int
	nets    map[string]string
	trusted map[string]bool
	proxied bool
}

func newFixture(lim bodylimit.ConnLimits) *fixture {
	f := &fixture{now: time.Unix(1000, 0), refused: map[string]int{}, evicted: map[string]int{}, nets: map[string]string{}, trusted: map[string]bool{}}
	f.l = New(Options{Limits: lim, Now: func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now },
		Trusted:  func(a netip.Addr) bool { return f.trusted[a.String()] },
		NetClass: func(a netip.Addr) string { return f.nets[a.String()] },
		Open:     func(d float64) { f.mu.Lock(); f.open += d; f.mu.Unlock() },
		Refused:  func(s string) { f.mu.Lock(); f.refused[s]++; f.mu.Unlock() },
		Evicted:  func(s string) { f.mu.Lock(); f.evicted[s]++; f.mu.Unlock() }})
	return f
}

func (f *fixture) dial(peer string) (*Conn, *fakeConn) {
	fc := &fakeConn{peer: peer + ":1234"}
	if ip, err := netip.ParseAddr(peer); err == nil && ip.Is6() {
		fc.peer = "[" + peer + "]:1234"
	}
	c := f.l.admit(fc, f.proxied)
	return c, fc
}

func (f *fixture) tick(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

var small = bodylimit.ConnLimits{MaxPerClient: 2, MaxPerNetwork: 4, Max: 8}

func mustOpen(t *testing.T, f *fixture, peers ...string) []*Conn {
	t.Helper()
	var out []*Conn
	for _, p := range peers {
		c, _ := f.dial(p)
		if c == nil {
			t.Fatalf("%s refused", p)
		}
		out = append(out, c)
	}
	return out
}

func TestClientLimit(t *testing.T) {
	f := newFixture(small)
	mustOpen(t, f, "192.0.2.1", "192.0.2.1")
	if c, _ := f.dial("192.0.2.1"); c != nil {
		t.Fatal("third connection of a client admitted")
	}
	if f.refused[bodylimit.ScopeClient] != 1 || f.l.Open() != 2 {
		t.Fatalf("refused %v open %d", f.refused, f.l.Open())
	}
	mustOpen(t, f, "192.0.2.2")
}

func TestIPv6CountsPer64(t *testing.T) {
	f := newFixture(small)
	mustOpen(t, f, "2001:db8:0:1::1", "2001:db8:0:1::2")
	if c, _ := f.dial("2001:db8:0:1::3"); c != nil {
		t.Fatal("a third address of one /64 is the same client")
	}
	mustOpen(t, f, "2001:db8:0:2::1")
}

func TestMappedIPv4IsTheSameClient(t *testing.T) {
	f := newFixture(small)
	mustOpen(t, f, "192.0.2.1", "::ffff:192.0.2.1")
	if c, _ := f.dial("192.0.2.1"); c != nil {
		t.Fatal("an IPv4-mapped address must count with its IPv4 address")
	}
}

func TestNetworkLimit(t *testing.T) {
	f := newFixture(small)
	mustOpen(t, f, "192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.2")
	if c, _ := f.dial("192.0.2.3"); c != nil {
		t.Fatal("fifth connection of a /24 admitted")
	}
	if f.refused[bodylimit.ScopeNetwork] != 1 {
		t.Fatalf("refused %v", f.refused)
	}
	mustOpen(t, f, "192.0.3.1")
}

func TestSharedAddressFactor(t *testing.T) {
	f := newFixture(small)
	f.nets["192.0.2.1"] = "cgnat"
	f.nets["192.0.2.2"] = "tor"
	mustOpen(t, f, "192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.1")
	if c, _ := f.dial("192.0.2.1"); c != nil {
		t.Fatal("cgnat over four times the limit")
	}
	f = newFixture(small)
	f.nets["192.0.2.2"] = "tor"
	mustOpen(t, f, "192.0.2.2", "192.0.2.2")
	if c, _ := f.dial("192.0.2.2"); c != nil {
		t.Fatal("tor keeps the plain limit")
	}
}

func TestTrustedProxyIsNotAClient(t *testing.T) {
	f := newFixture(small)
	f.trusted["10.0.0.1"] = true
	for i := 0; i < 8; i++ {
		mustOpen(t, f, "10.0.0.1")
	}
	if c, _ := f.dial("10.0.0.1"); c != nil {
		t.Fatal("the gateway limit holds for a proxy too")
	}
	if f.refused[bodylimit.ScopeGateway] != 1 {
		t.Fatalf("refused %v", f.refused)
	}
}

func TestProxiedListener(t *testing.T) {
	f := newFixture(small)
	f.proxied = true
	mustOpen(t, f, "10.0.0.1", "10.0.0.1", "10.0.0.1")
}

func TestPeerWithoutAddress(t *testing.T) {
	f := newFixture(small)
	mustOpen(t, f, "@", "@", "@")
}

func TestGatewayLimitCountsEveryListener(t *testing.T) {
	f := newFixture(bodylimit.ConnLimits{MaxPerClient: 8, MaxPerNetwork: 8, Max: 2})
	mustOpen(t, f, "192.0.2.1", "192.0.3.1")
	if c, _ := f.dial("192.0.4.1"); c != nil {
		t.Fatal("over the gateway limit")
	}
}

func TestEvictsOldestIdleOfTheScope(t *testing.T) {
	f := newFixture(small)
	cs := mustOpen(t, f, "192.0.2.1", "192.0.2.1")
	first, second := cs[0].Conn.(*fakeConn), cs[1].Conn.(*fakeConn)
	f.tick(bodylimit.ConnEvictMinAgeS * time.Second)
	c, _ := f.dial("192.0.2.1")
	if c == nil {
		t.Fatal("no place taken from an idle connection")
	}
	if !first.closed.Load() || second.closed.Load() {
		t.Fatalf("closed first=%v second=%v, want the oldest", first.closed.Load(), second.closed.Load())
	}
	if f.evicted[bodylimit.ScopeClient] != 1 || f.l.Open() != 2 || f.open != 2 {
		t.Fatalf("evicted %v open %d gauge %v", f.evicted, f.l.Open(), f.open)
	}
	// The evicted connection closes later, on its own: it must not count twice.
	_ = cs[0].Close()
	if f.l.Open() != 2 || f.open != 2 {
		t.Fatalf("a second release: open %d gauge %v", f.l.Open(), f.open)
	}
}

func TestFreshIdleIsNotEvicted(t *testing.T) {
	f := newFixture(small)
	mustOpen(t, f, "192.0.2.1", "192.0.2.1")
	f.tick(bodylimit.ConnEvictMinAgeS*time.Second - time.Millisecond)
	if c, _ := f.dial("192.0.2.1"); c != nil {
		t.Fatal("a connection younger than the minimum age lost its place")
	}
}

func TestBusyIsNeverEvicted(t *testing.T) {
	f := newFixture(bodylimit.ConnLimits{MaxPerClient: 2, MaxPerNetwork: 2, Max: 2})
	cs := mustOpen(t, f, "192.0.2.1", "192.0.2.1")
	Track(cs[0], http.StateActive)
	Track(cs[1], http.StateActive)
	f.tick(time.Hour)
	if c, _ := f.dial("192.0.2.1"); c != nil {
		t.Fatal("a connection with a running request lost its place")
	}
	served(cs[0])
	Track(cs[0], http.StateIdle)
	if c, _ := f.dial("192.0.2.1"); c != nil {
		t.Fatal("idle for a moment only")
	}
	f.tick(time.Hour)
	if c, _ := f.dial("192.0.2.1"); c == nil {
		t.Fatal("idle again, the place should go")
	}
	if !cs[0].Conn.(*fakeConn).closed.Load() || cs[1].Conn.(*fakeConn).closed.Load() {
		t.Fatal("wrong victim")
	}
}

func TestHijackedStaysBusy(t *testing.T) {
	f := newFixture(small)
	cs := mustOpen(t, f, "192.0.2.1", "192.0.2.1")
	Track(cs[0], http.StateHijacked)
	Track(cs[1], http.StateHijacked)
	f.tick(time.Hour)
	if c, _ := f.dial("192.0.2.1"); c != nil {
		t.Fatal("a WebSocket lost its place")
	}
}

func TestEndOfRequestKeepsThePlace(t *testing.T) {
	f := newFixture(bodylimit.ConnLimits{MaxPerClient: 1, MaxPerNetwork: 1, Max: 1})
	cs := mustOpen(t, f, "192.0.2.1")
	f.tick(time.Hour)
	Track(cs[0], http.StateActive)
	served(cs[0])
	Track(cs[0], http.StateIdle)
	if c, _ := f.dial("192.0.2.1"); c != nil {
		t.Fatal("a connection that ended a request just now lost its place")
	}
}

// proxyConn is a proxy protocol connection on top of a counted one: its address is
// the one of the header, and asking for it waits for the header.
type proxyConn struct {
	net.Conn
	asked atomic.Int32
}

func (p *proxyConn) RemoteAddr() net.Addr { p.asked.Add(1); return fakeAddr("198.51.100.7:40000") }
func (p *proxyConn) Raw() net.Conn        { return p.Conn }

// tlsConn stands for *tls.Conn: it hands on RemoteAddr and unwraps with NetConn.
type tlsConn struct{ net.Conn }

func (c tlsConn) NetConn() net.Conn { return c.Conn }

// The hooks that run in the accept loop never ask a connection for its address, and
// a request finds its counted connection under the wrappers of TLS and the proxy
// protocol.
func TestHooksFindTheConnUnderWrappers(t *testing.T) {
	f := newFixture(bodylimit.ConnLimits{MaxPerClient: 1, MaxPerNetwork: 1, Max: 1})
	f.proxied = true
	cs := mustOpen(t, f, "10.0.0.1")
	pc := &proxyConn{Conn: cs[0]}
	outer := tlsConn{pc}
	Track(outer, http.StateNew)
	ctx := WithConn(context.Background(), outer)
	if n := pc.asked.Load(); n != 0 {
		t.Fatalf("the accept loop asked for the address %d times", n)
	}
	if of(outer) != cs[0] {
		t.Fatal("the counted connection is not found under TLS and the proxy protocol")
	}
	Track(outer, http.StateActive)
	f.tick(time.Hour)
	if c, _ := f.dial("10.0.0.1"); c != nil {
		t.Fatal("a connection with a running request lost its place")
	}
	Served(ctx)
	Track(outer, http.StateIdle)
	if c, _ := f.dial("10.0.0.1"); c != nil {
		t.Fatal("a connection that ended a request just now lost its place")
	}
	f.tick(time.Hour)
	if c, _ := f.dial("10.0.0.1"); c == nil {
		t.Fatal("idle again, the place should go")
	}
}

// served is what the first handler of a route does for a request on c.
func served(c *Conn) { Served(WithConn(context.Background(), c)) }

// A stream the server refuses before any handler, or one reset at once, makes the
// connection active and idle: that alone keeps no place.
func TestStreamWithoutRequestKeepsNoPlace(t *testing.T) {
	f := newFixture(bodylimit.ConnLimits{MaxPerClient: 1, MaxPerNetwork: 1, Max: 4})
	cs := mustOpen(t, f, "192.0.2.1")
	f.tick(time.Hour)
	for i := 0; i < 3; i++ {
		Track(cs[0], http.StateActive)
		Track(cs[0], http.StateIdle)
	}
	if c, _ := f.dial("192.0.2.1"); c == nil {
		t.Fatal("refused streams kept the place")
	}
	// Served counts once: the next idle without a request starts no new age.
	cs = mustOpen(t, f, "198.51.100.2")
	served(cs[0])
	Track(cs[0], http.StateActive)
	Track(cs[0], http.StateIdle)
	f.tick(time.Hour)
	Track(cs[0], http.StateActive)
	Track(cs[0], http.StateIdle)
	if c, _ := f.dial("198.51.100.2"); c == nil {
		t.Fatal("an old request kept the place through a refused stream")
	}
}

func TestEvictFromFullGatewayAcrossClients(t *testing.T) {
	f := newFixture(bodylimit.ConnLimits{MaxPerClient: 8, MaxPerNetwork: 8, Max: 2})
	cs := mustOpen(t, f, "192.0.2.1", "192.0.3.1")
	f.tick(time.Hour)
	if c, _ := f.dial("192.0.4.1"); c == nil {
		t.Fatal("a new visitor on a gateway full of idle connections")
	}
	if !cs[0].Conn.(*fakeConn).closed.Load() || f.evicted[bodylimit.ScopeGateway] != 1 {
		t.Fatalf("evicted %v", f.evicted)
	}
	// The group of the victim is gone with its last connection.
	f.l.mu.Lock()
	defer f.l.mu.Unlock()
	if len(f.l.clients) != 2 || len(f.l.networks) != 2 {
		t.Fatalf("clients %d networks %d", len(f.l.clients), len(f.l.networks))
	}
}

func TestEvictFromItsOwnEmptiedGroup(t *testing.T) {
	f := newFixture(bodylimit.ConnLimits{MaxPerClient: 1, MaxPerNetwork: 1, Max: 1})
	mustOpen(t, f, "192.0.2.1")
	f.tick(time.Hour)
	c, _ := f.dial("192.0.2.1")
	if c == nil {
		t.Fatal("refused")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if f.l.Open() != 0 {
		t.Fatalf("open %d", f.l.Open())
	}
	f.l.mu.Lock()
	defer f.l.mu.Unlock()
	if len(f.l.clients) != 0 || len(f.l.networks) != 0 {
		t.Fatal("groups stay behind")
	}
}

func TestCloseGivesThePlaceBack(t *testing.T) {
	f := newFixture(small)
	cs := mustOpen(t, f, "192.0.2.1", "192.0.2.1")
	_ = cs[0].Close()
	_ = cs[0].Close()
	if f.l.Open() != 1 || f.open != 1 {
		t.Fatalf("open %d gauge %v", f.l.Open(), f.open)
	}
	mustOpen(t, f, "192.0.2.1")
}

// TestNoStateLeftBehind runs a churn and looks at every count.
func TestNoStateLeftBehind(t *testing.T) {
	f := newFixture(bodylimit.ConnLimits{MaxPerClient: 4, MaxPerNetwork: 16, Max: 64})
	var cs []*Conn
	for i := 0; i < 2000; i++ {
		ip := netip.AddrFrom4([4]byte{192, 0, byte(2 + i%5), byte(i % 7)})
		if c, _ := f.dial(ip.String()); c != nil {
			cs = append(cs, c)
		}
		if i%3 == 0 {
			f.tick(10 * time.Second)
		}
	}
	for _, c := range cs {
		_ = c.Close()
	}
	if f.l.Open() != 0 || f.open != 0 {
		t.Fatalf("open %d gauge %v", f.l.Open(), f.open)
	}
	f.l.mu.Lock()
	defer f.l.mu.Unlock()
	if len(f.l.clients) != 0 || len(f.l.networks) != 0 || f.l.all.head != nil || f.l.all.tail != nil {
		t.Fatal("state left behind")
	}
}

// TestListenerClosesRefused goes through a real listener.
func TestListenerClosesRefused(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(bodylimit.ConnLimits{MaxPerClient: 1, MaxPerNetwork: 1, Max: 8})
	ln := f.l.Listen(inner, false)
	defer ln.Close()
	first, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	got, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	second, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	go func() {
		// The listener closes the second and waits for a third.
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	var b [1]byte
	_, err = second.Read(b[:])
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("a refused connection stayed open")
	}
	if err == nil {
		t.Fatal("data on a refused connection")
	}
	if a, ok := got.RemoteAddr().(*peerAddr); !ok || a.conn != got.(*Conn) {
		t.Fatal("RemoteAddr does not lead back to the connection")
	}
}

// BenchmarkAdmit shows the cost at a full limit of the accept loop.
func BenchmarkAdmit(b *testing.B) {
	f := newFixture(bodylimit.ConnLimits{MaxPerClient: 2048, MaxPerNetwork: 8192, Max: 16384})
	for i := 0; i < 2048; i++ {
		f.dial("192.0.2.1")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.dial("192.0.2.1")
	}
}
