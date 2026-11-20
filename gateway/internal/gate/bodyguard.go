package gate

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// Limits on request bodies (D41, contracts/body-limits.md). They protect the
// ingress, so they act in every mode. Reading a body costs a goroutine, a
// connection, memory and disk without taking an evaluation slot, so what runs
// at once is bounded here: per client, per network and for the whole gateway.

const (
	// drainWindow is the longest a refused request is read before its answer.
	drainWindow = 2 * time.Second
	// drainRepeat is how often the end of the window is applied again.
	drainRepeat = 50 * time.Millisecond
	// drainBytes is what is read of it, so that keep-alive connections survive
	// small refused uploads; larger ones are closed by the server.
	drainBytes = 64 << 10
	// goneWait: on HTTP/2 the error of a reset stream reaches the body just
	// before the request context ends.
	goneWait = 50 * time.Millisecond
)

// normBody fills unset body limits.
func normBody(l bodylimit.Limits) bodylimit.Limits {
	if l.MaxPerClient <= 0 {
		l.MaxPerClient = bodylimit.DefaultMaxPerClient
	}
	if l.MaxPerNetwork <= 0 {
		l.MaxPerNetwork = bodylimit.DefaultMaxPerNetwork
	}
	if l.MaxInFlight <= 0 {
		l.MaxInFlight = bodylimit.InFlightLimit(0, 0)
	}
	if l.MaxInFlightBytes <= 0 {
		l.MaxInFlightBytes = bodylimit.DefaultMaxInFlightBytes
	}
	if l.MaxWaitingBytesPerClient <= 0 {
		l.MaxWaitingBytesPerClient = bodylimit.DefaultMaxWaitingBytesPerClient
	}
	if l.MaxWaitingBytesPerNetwork <= 0 {
		l.MaxWaitingBytesPerNetwork = bodylimit.DefaultMaxWaitingBytesPerNetwork
	}
	if l.MaxWaitingBytes <= 0 {
		l.MaxWaitingBytes = bodylimit.WaitingLimit(0, 0)
	}
	if l.MaxLargeInFlight <= 0 {
		l.MaxLargeInFlight = bodylimit.LargeInFlightLimit(0, 0)
	}
	return l
}

// normRequests fills unset limits of waiting requests.
func normRequests(l bodylimit.RequestLimits) bodylimit.RequestLimits {
	if l.MaxPerClient <= 0 {
		l.MaxPerClient = bodylimit.DefaultMaxWaitingPerClient
	}
	if l.MaxPerNetwork <= 0 {
		l.MaxPerNetwork = bodylimit.DefaultMaxWaitingPerNetwork
	}
	if l.Max <= 0 {
		l.Max = bodylimit.RequestLimit(0, 0)
	}
	return l
}

// bodyLimiter counts the bodies being read, the held bytes of the gateway and
// the waiting bytes of bodies that wait for the backend (bodywait.go), and the
// requests that wait for it (requestwait.go).
type bodyLimiter struct {
	mu           sync.Mutex
	clients      map[string]int
	networks     map[string]int
	inFlight     int
	largeBodies  int
	held         atomic.Int64
	waitClients  map[string]int64
	waitNetworks map[string]int64
	waiting      int64
	reqClients   map[string]int
	reqNetworks  map[string]int
	requests     int
	pressure     atomic.Int32 // bodylimit.Pressure, from the memory watch of the app
}

// admission is one counted body. end is safe to call more than once.
type admission struct {
	l               *bodyLimiter
	client, network string
	large           bool
	m               *metrics.Metrics
	ended           atomic.Bool
}

// bodyNetKey is the IPv4 /24 or the IPv6 /48 of an address.
func bodyNetKey(ip netip.Addr) string {
	ip = ip.Unmap()
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits)
	return p.String()
}

// admit decides on one body and counts it when it is admitted.
func (l *bodyLimiter) admit(lim bodylimit.Limits, ip netip.Addr, netClass string, declared int64, draw uint32, m *metrics.Metrics) (*admission, bodylimit.Decision) {
	known := ip.IsValid()
	client, network := "", ""
	if known {
		client, network = clientKey(ip), bodyNetKey(ip)
	}
	large := bodylimit.Large(declared)
	l.mu.Lock()
	defer l.mu.Unlock()
	st := bodylimit.State{Large: large, LargeInFlight: l.largeBodies, Client: l.clients[client], Network: l.networks[network], InFlight: l.inFlight, InFlightBytes: l.held.Load(),
		ClientWaitingBytes: l.waitClients[client], NetWaitingBytes: l.waitNetworks[network], WaitingBytes: l.waiting, Pressure: int(l.pressure.Load())}
	d := bodylimit.Admit(lim, st, netClass, known, draw)
	if !d.Admitted {
		return nil, d
	}
	if l.clients == nil {
		l.clients, l.networks = map[string]int{}, map[string]int{}
	}
	if known {
		l.clients[client]++
		l.networks[network]++
	}
	l.inFlight++
	if large {
		l.largeBodies++
	}
	if m != nil {
		m.BodiesInFlight.Inc()
	}
	return &admission{l: l, client: client, network: network, large: large, m: m}, d
}

// end gives the place back: the body was read, failed, or was never read.
func (a *admission) end() {
	if a == nil || !a.ended.CompareAndSwap(false, true) {
		return
	}
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.client != "" {
		if l.clients[a.client]--; l.clients[a.client] <= 0 {
			delete(l.clients, a.client)
		}
		if l.networks[a.network]--; l.networks[a.network] <= 0 {
			delete(l.networks, a.network)
		}
	}
	l.inFlight--
	if a.large {
		l.largeBodies--
	}
	if a.m != nil {
		a.m.BodiesInFlight.Dec()
	}
}

// endRead ends the count of this request's body.
func (ri *reqInfo) endRead() { ri.admission.end() }

// admitBody takes the admission of a request with a body, or answers it and
// returns false. A request holds one admission however often it is evaluated
// (D33).
func (g *Gate) admitBody(w http.ResponseWriter, r *http.Request, ri *reqInfo, set *Settings) bool {
	if ri.recheck.bodyAdmitted() {
		return true
	}
	adm, d := g.bodies.admit(set.Body, ri.client.IP, ri.geo.NetClass, r.ContentLength, g.draw(), g.Metrics)
	if d.Admitted {
		ri.admission = adm
		ri.recheck.noteBodyAdmitted()
		return true
	}
	g.refuse(w, r, ri, d)
	return false
}

// countAbort counts a body that was refused or ended early.
func (g *Gate) countAbort(ri *reqInfo) {
	if g.Metrics == nil {
		return
	}
	reason := ""
	switch ri.limit {
	case waf.ErrBodyTooLarge, waf.ErrRawTooLarge:
		reason = bodylimit.AbortTooLarge
	case waf.ErrBodyShare, waf.ErrBodyShareBusy:
		reason = bodylimit.AbortShare
	case waf.ErrBodyWaitShare, waf.ErrBodyWaitShareBusy:
		reason = bodylimit.AbortWaiting
	case waf.ErrBodyBusy:
		reason = bodylimit.AbortBusy
	case waf.ErrClientGone:
		reason = bodylimit.AbortClientGone
	default:
		return
	}
	g.Metrics.BodiesAborted.WithLabelValues(reason).Inc()
}

// drain reads a little of an unread body before a refusal, for at most
// drainWindow. Without a read deadline nothing is read: a client must not be
// able to hold the answer open.
//
// A deadline set once is not enough: the body reader of Caddy (idle timeouts
// since 2.11.6) sets its own deadline on every read, which replaces this one.
// So a timer ends the read at the window, and repeats until the read returns,
// because a read that starts at that moment arms a new deadline.
func (g *Gate) drain(w http.ResponseWriter, r *http.Request, ri *reqInfo) {
	if r.Body == nil || r.Body == http.NoBody || ri.body.ended {
		return
	}
	// Under memory pressure the window is the problem: a flood of refused bodies
	// keeps thousands of sockets open and full for it (D45). No drain, and the
	// connection goes with the answer (finish).
	if g.bodies.pressure.Load() >= bodylimit.PressureBodies {
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
			ri.closeNow = true
		}
		return
	}
	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(time.Now().Add(drainWindow)) != nil {
		return
	}
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTimer(drainWindow)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				_ = rc.SetReadDeadline(time.Now())
				t.Reset(drainRepeat)
			}
		}
	}()
	_, _ = io.CopyN(io.Discard, r.Body, drainBytes)
	close(done)
	<-stopped // rc must not outlive the handler
}

// clientGone ends a request whose client left or stalled while its body was
// read: no incident, no event, no body_read_error, only the counter. The status
// goes out for a client that stalled or only closed its sending side, so that it
// never reads a 200 for a body nobody saw.
func (g *Gate) clientGone(w http.ResponseWriter, r *http.Request, ri *reqInfo) {
	ri.quiet = true
	g.countAbort(ri)
	ri.status = ri.limit.Status
	ri.decision = decide.Output{Outcome: decide.Blocked, Status: ri.status, Sources: []string{"limit:" + ri.limit.Code}}
	w.WriteHeader(ri.status)
	g.finish(r, ri)
}

// rateMeter measures a body in fixed windows from its start, the online form
// of bodylimit.Rate. Times are milliseconds after the start. Enforcing nothing
// (E2), it only reports: each complete window gives one sample, and the first
// window under the minimum counts the body once.
type rateMeter struct {
	mu     sync.Mutex
	window int64 // the window bytes are added to
	bytes  int64
	below  bool
	closed bool
	sample func(rate int64, firstBelow bool)
}

// roll closes every window that ended by ms. A stall closes windows of 0.
func (m *rateMeter) roll(ms int64) {
	windowMS := int64(bodylimit.RateWindowS) * 1000
	for m.window < ms/windowMS {
		rate := m.bytes / bodylimit.RateWindowS
		first := rate < bodylimit.RateMinBytesPerS && !m.below
		m.below = m.below || first
		m.bytes = 0
		m.window++
		if m.sample != nil {
			m.sample(rate, first)
		}
	}
}

// add records n bytes read at ms.
func (m *rateMeter) add(ms, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll(ms)
	m.bytes += n
}

// tick closes the windows that ended by ms, for a body that sends nothing. It
// reports whether the body is still open.
func (m *rateMeter) tick(ms int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	m.roll(ms)
	return true
}

// close ends the measurement at ms. The open window gives no sample.
func (m *rateMeter) close(ms int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roll(ms)
	m.closed = true
}

// bodyGuard is the reader between a request body and Coraza. It counts held
// bytes and the receive rate, and remembers why reading stopped. Read runs on
// the goroutine of the request; release may run on another one, after reading
// ended.
type bodyGuard struct {
	g       *Gate
	rc      io.ReadCloser
	class   string
	max     int64
	held    atomic.Int64
	busy    bool
	readErr error
	start   time.Time
	meter   *rateMeter // nil for a re-check: the body was read and measured
	timer   *time.Timer
}

func (g *Gate) newBodyGuard(r *http.Request, ri *reqInfo, set *Settings) *bodyGuard {
	b := &bodyGuard{g: g, rc: r.Body, class: waf.BodyClass(r), max: set.Body.MaxInFlightBytes, start: time.Now()}
	if ri.admission != nil {
		b.meter = &rateMeter{sample: g.bodySample}
		b.arm()
	}
	return b
}

// bodySample records one complete window of a body.
func (g *Gate) bodySample(rate int64, firstBelow bool) {
	if g.Metrics == nil {
		return
	}
	g.Metrics.BodyRate.Observe(float64(rate))
	if firstBelow {
		g.Metrics.BodiesBelowMinRate.Inc()
	}
}

// arm wakes the meter at the end of the running window, so a body that never
// sends another byte still shows up.
func (b *bodyGuard) arm() {
	windowMS := int64(bodylimit.RateWindowS) * 1000
	elapsed := time.Since(b.start).Milliseconds()
	next := time.Duration(windowMS-elapsed%windowMS) * time.Millisecond
	b.timer = time.AfterFunc(next, func() {
		if b.meter.tick(time.Since(b.start).Milliseconds()) {
			b.timer.Reset(time.Duration(windowMS) * time.Millisecond)
		}
	})
}

func (b *bodyGuard) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		if b.meter != nil {
			b.meter.add(time.Since(b.start).Milliseconds(), int64(n))
		}
		if b.hold(bodylimit.Held(b.class, int64(n))) > b.max {
			// Over max_in_flight_bytes: this body ends with the answer of a
			// full gateway, and its bytes go when its transaction closes.
			b.busy = true
			return n, waf.ErrBodyBusy
		}
	}
	if err != nil && err != io.EOF {
		b.readErr = err
	}
	return n, err
}

func (b *bodyGuard) Close() error { return b.rc.Close() }

// hold adds to the held bytes and returns those of the gateway.
func (b *bodyGuard) hold(n int64) int64 {
	b.held.Add(n)
	if m := b.g.Metrics; m != nil {
		m.BodyBytesInFlight.Add(float64(n))
	}
	return b.g.bodies.held.Add(n)
}

// finish ends the read: the histogram, and the end of the measurement.
func (b *bodyGuard) finish() {
	if b.meter == nil {
		return
	}
	b.timer.Stop()
	elapsed := time.Since(b.start)
	b.meter.close(elapsed.Milliseconds())
	if m := b.g.Metrics; m != nil {
		m.BodyReadSeconds.Observe(elapsed.Seconds())
	}
}

// settle sets the held bytes to the n bytes of a body that left its transaction:
// the second copy of a multipart body is gone. A nil guard has nothing held.
func (b *bodyGuard) settle(n int64) {
	if b == nil {
		return
	}
	d := n - b.held.Swap(n)
	b.g.bodies.held.Add(d)
	if m := b.g.Metrics; m != nil {
		m.BodyBytesInFlight.Add(float64(d))
	}
}

// release gives back the held bytes. It runs when the temp files are gone: the
// body's own at the end of the request, or the transaction's when it never got
// that far. A nil guard (no body) has nothing to give.
func (b *bodyGuard) release() {
	if b == nil {
		return
	}
	n := b.held.Swap(0)
	b.g.bodies.held.Add(-n)
	if m := b.g.Metrics; m != nil {
		m.BodyBytesInFlight.Add(-float64(n))
	}
}

// verdict maps the error of reading the body to its limit.
func (b *bodyGuard) verdict(r *http.Request, err error) *waf.LimitError {
	if b != nil && b.busy {
		return waf.ErrBodyBusy
	}
	if l, ok := waf.IsLimit(err); ok && l != waf.ErrBodyRead {
		return l
	}
	if b != nil && b.readErr != nil && bodylimit.ReadEndCode(readEnd(r, b.readErr)) == bodylimit.CodeClientGone {
		return waf.ErrClientGone
	}
	return waf.ErrBodyRead
}

// readEnd says how reading a body failed. A read timeout of the server
// (read_body, read_body_idle) leaves the client there, but says nothing against
// it: a tunnel or a radio gap looks the same (E10, D45).
func readEnd(r *http.Request, err error) string {
	var timeout net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return bodylimit.ReadEndTimeout
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return bodylimit.ReadEndClientLeft
	}
	t := time.NewTimer(goneWait)
	defer t.Stop()
	select {
	case <-r.Context().Done():
		return bodylimit.ReadEndClientLeft
	case <-t.C:
		return bodylimit.ReadEndError
	}
}
