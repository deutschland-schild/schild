package gate

import (
	mrand "math/rand/v2"
	"net/http"
	"net/netip"
	"sync/atomic"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/contract/waitingpage"
	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// Requests waiting for the backend (D45, contracts/body-limits.md section 2a).
// A running request costs about 100 KiB whether it has a body or not: four
// goroutines and the buffers of two connections. Every request counts from its
// admission until it ended, in every mode, also one the allowlist lets past the
// WAF: the limit protects the memory of the ingress, not a website. A WebSocket
// or an event stream counts for as long as it runs, because it costs the same.

// requestAdmission is one counted request. end is safe to call more than once.
type requestAdmission struct {
	l               *bodyLimiter
	client, network string
	m               *metrics.Metrics
	ended           atomic.Bool
}

// admitRequest decides on one request and counts it when it is admitted.
func (l *bodyLimiter) admitRequest(lim bodylimit.RequestLimits, ip netip.Addr, netClass string, draw uint32, m *metrics.Metrics) (*requestAdmission, bodylimit.Decision) {
	known := ip.IsValid()
	client, network := "", ""
	if known {
		client, network = clientKey(ip), bodyNetKey(ip)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	st := bodylimit.RequestState{Client: l.reqClients[client], Network: l.reqNetworks[network], Waiting: l.requests, Pressure: int(l.pressure.Load())}
	d := bodylimit.AdmitRequest(lim, st, netClass, known, draw)
	if !d.Admitted {
		return nil, d
	}
	if l.reqClients == nil {
		l.reqClients, l.reqNetworks = map[string]int{}, map[string]int{}
	}
	if known {
		l.reqClients[client]++
		l.reqNetworks[network]++
	}
	l.requests++
	if m != nil {
		m.RequestsWaiting.Inc()
	}
	return &requestAdmission{l: l, client: client, network: network, m: m}, d
}

// end gives the place back. A nil admission has none.
func (a *requestAdmission) end() {
	if a == nil || !a.ended.CompareAndSwap(false, true) {
		return
	}
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.client != "" {
		if l.reqClients[a.client]--; l.reqClients[a.client] <= 0 {
			delete(l.reqClients, a.client)
		}
		if l.reqNetworks[a.network]--; l.reqNetworks[a.network] <= 0 {
			delete(l.reqNetworks, a.network)
		}
	}
	l.requests--
	if a.m != nil {
		a.m.RequestsWaiting.Dec()
	}
}

// endRequest ends the count of this request. A schild further down the chain
// holds no admission of its own, so it never reaches this count.
func (ri *reqInfo) endRequest() {
	if ri.waitAdmission != nil {
		ri.recheck.noteRequest(false)
		ri.waitAdmission.end()
	}
}

// admitRequest takes the place of a request, or answers it and returns false.
// While an evaluation further up the chain holds the place, a nested one needs
// none: one request counts once (D33). An evaluation that follows the first one
// (handle_errors) takes a new place, the first one has given it back.
func (g *Gate) admitRequest(w http.ResponseWriter, r *http.Request, ri *reqInfo, set *Settings) bool {
	if ri.recheck.requestHeld() {
		return true
	}
	adm, d := g.bodies.admitRequest(set.Requests, ri.client.IP, ri.geo.NetClass, g.draw(), g.Metrics)
	if d.Admitted {
		ri.waitAdmission = adm
		ri.recheck.noteRequest(true)
		return true
	}
	g.refuse(w, r, ri, d)
	return false
}

// draw is the random value of a refusal.
func (g *Gate) draw() uint32 {
	if g.jitter != nil {
		return g.jitter()
	}
	return mrand.Uint32()
}

// refuse answers a request the admission of bodies or requests turned away: no
// incident, its event sampled like an unremarkable request.
func (g *Gate) refuse(w http.ResponseWriter, r *http.Request, ri *reqInfo, d bodylimit.Decision) {
	ri.quiet = true
	ri.limit = refusalOf(*d.Status, *d.Code)
	if *d.Status != http.StatusTooManyRequests {
		g.block(w, r, ri)
		return
	}
	g.countAbort(ri)
	ri.status = *d.Status
	ri.decision = decide.Output{Outcome: decide.Blocked, Status: ri.status, Sources: []string{"limit:" + ri.limit.Code}}
	if g.Metrics != nil {
		g.Metrics.HardLimits.WithLabelValues(ri.limit.Code).Inc()
	}
	g.drain(w, r, ri)
	blockpage.WriteBodyShare(w, r, waitingpage.Document(r.Method, decisionHeaders(r.Header)), ri.limit.Code, *d.RetryAfter, ri.start)
	g.finish(r, ri)
}

// refusalOf is the limit of a refused admission.
func refusalOf(status int, code string) *waf.LimitError {
	limited := status == http.StatusTooManyRequests
	pick := func(share, shared *waf.LimitError) *waf.LimitError {
		if limited {
			return share
		}
		return shared
	}
	switch code {
	case bodylimit.CodeClientShare:
		return pick(waf.ErrBodyShare, waf.ErrBodyShareBusy)
	case bodylimit.CodeWaitingShare:
		return pick(waf.ErrBodyWaitShare, waf.ErrBodyWaitShareBusy)
	case bodylimit.CodeRequestShare:
		return pick(waf.ErrRequestShare, waf.ErrRequestShareBusy)
	case bodylimit.CodeRequestBusy:
		return waf.ErrRequestBusy
	}
	return waf.ErrBodyBusy
}

// closeRefused sends the answer and closes the connection of a refused body at
// once. The server would half-close it and wait 500 ms for the client to read:
// a sender that goes on sending fills the receive buffer of a socket nobody reads,
// and at a thousand refusals per second these sockets took 450 MiB (D45). The
// client may lose the answer to a reset: under pressure that is the better deal.
func closeRefused(s *statusWriter) {
	rc := http.NewResponseController(s.ResponseWriter)
	_ = rc.Flush()
	if c, _, err := rc.Hijack(); err == nil {
		_ = c.Close()
	}
}

// SetMemoryPressure sets the level of bodylimit.Pressure for the admissions
// that follow.
func (g *Gate) SetMemoryPressure(level int) {
	g.bodies.pressure.Store(int32(level))
	if g.Metrics != nil {
		g.Metrics.MemoryPressure.Set(float64(level))
	}
}
