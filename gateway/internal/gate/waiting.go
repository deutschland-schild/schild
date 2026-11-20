package gate

import (
	mrand "math/rand/v2"
	"net/http"
	"strings"

	"github.com/deutschland-schild/schild/contract/waitingpage"
	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
	"github.com/deutschland-schild/schild/gateway/internal/waitpage"
)

// SetWaitingPage switches the waiting page (schild.yaml
// waiting_page.enabled, D37; on by default).
func (g *Gate) SetWaitingPage(on bool) { g.waitingOff.Store(!on) }

// WaitingPage reports whether the waiting page is on.
func (g *Gate) WaitingPage() bool { return !g.waitingOff.Load() }

// overloadReason is the fail-closed reason of a refused request that may
// get the waiting page (waf_busy, waf_timeout, body_busy, also for the request
// limits of D45), "" otherwise (not_ready,
// every other limit, a WAF block).
func overloadReason(ri *reqInfo) string {
	switch {
	case ri.limit == waf.ErrBusy:
		return waitingpage.ReasonWAFBusy
	case ri.limit == waf.ErrTimeout && !ri.notReady:
		return waitingpage.ReasonWAFTimeout
	case ri.limit == waf.ErrBodyBusy, ri.limit == waf.ErrBodyShareBusy, ri.limit == waf.ErrBodyWaitShareBusy,
		ri.limit == waf.ErrRequestBusy, ri.limit == waf.ErrRequestShareBusy:
		return waitingpage.ReasonBodyBusy
	}
	return ""
}

// overload answers a request refused because schild is overloaded while the
// waiting page is on (D37, contracts/waiting-page.md): the waiting page for
// a document navigation, 503 problem details for everything else, both with
// a jittered Retry-After. It reports false when the request is not such a
// case (the caller answers as before D37).
//
// This runs exactly when the gateway is overloaded, so it does no WAF work,
// no database write and no per-request lookup beyond the cached website of
// the host: the page is pre-rendered (waitpage), the jitter comes from the
// per-thread runtime generator (math/rand/v2, no global lock), and a waiting
// page creates no incident.
func (g *Gate) overload(w http.ResponseWriter, r *http.Request, ri *reqInfo) bool {
	reason := overloadReason(ri)
	if reason == "" || g.waitingOff.Load() {
		return false
	}
	draw := mrand.Uint32()
	if g.jitter != nil {
		draw = g.jitter()
	}
	d := waitingpage.Decide(waitingpage.Input{
		Reason: reason, Enabled: true, Method: r.Method, Headers: decisionHeaders(r.Header),
		Host: r.Host, Website: g.websiteOf(r.Host), JitterDraw: draw,
	})
	if d.Answer == waitingpage.AnswerUnchanged {
		return false
	}
	status := ri.limit.Status
	ri.status = status
	ri.decision = decide.Output{Outcome: decide.Blocked, Status: status, Sources: []string{"limit:" + ri.limit.Code}}
	if g.Metrics != nil {
		g.Metrics.HardLimits.WithLabelValues(ri.limit.Code).Inc()
	}
	g.drain(w, r, ri)
	markOwn(w)
	switch d.Answer {
	case waitingpage.AnswerWaitingPage:
		ri.waiting = true
		waitpage.Write(w, d, ri.start)
	default: // AnswerProblem
		if !ri.quiet {
			g.drawIncident(ri)
		}
		blockpage.WriteProblem(w, ri.incident, *d.RetryAfter, *d.Body)
	}
	g.finish(r, ri)
	return true
}

// stripMarker removes a Schild-Waiting header from a response the backend
// (the next handler) is sending, so an app cannot fake the waiting page
// marker (D37 amendment, contracts/waiting-page.md section 4). schild's own
// answers keep it: they are written before forwarding, or marked own by
// markOwn when a re-checking schild further down the chain writes them.
func (s *statusWriter) stripMarker() {
	if !s.forwarding || s.own {
		return
	}
	delete(s.ResponseWriter.Header(), waitingpage.MarkerHeader)
}

// markOwn marks every gate writer around w (the chain of Unwrap) as carrying
// schild's own answer: a schild that re-checks the request further down a
// Caddy route (D33) writes its waiting page through the writer of the
// first, which must not strip that marker.
func markOwn(w http.ResponseWriter) {
	for w != nil {
		if s, ok := w.(*statusWriter); ok {
			s.own = true
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}

// websiteOf is the D36 website id of a host ("" for none).
func (g *Gate) websiteOf(host string) string {
	if g.siteID != nil {
		return g.siteID(host)
	}
	if g.Sites == nil {
		return ""
	}
	return g.Sites.ID(host)
}

// decisionHeaders reads the request headers of the decision; a repeated
// header is its values joined with ", " (only then does this allocate).
func decisionHeaders(h http.Header) waitingpage.Headers {
	return waitingpage.Headers{
		Accept: joined(h["Accept"]), AcceptLanguage: joined(h["Accept-Language"]), SecFetchDest: joined(h["Sec-Fetch-Dest"]),
		SecFetchMode: joined(h["Sec-Fetch-Mode"]), XRequestedWith: joined(h["X-Requested-With"]),
	}
}

func joined(v []string) string {
	switch len(v) {
	case 0:
		return ""
	case 1:
		return v[0]
	}
	return strings.Join(v, ", ")
}
