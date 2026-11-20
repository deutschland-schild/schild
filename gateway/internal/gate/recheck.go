package gate

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/redact"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// Recheck is the state of one HTTP request that schild may evaluate more
// than once (D33 amendment 2026-10-29, contract monitoring.Recheck): the
// site's schild, then schild in handle_errors after a handle_path strip, or
// a schild after a rewrite that follows a schild handler. Such a request
// counts once in every counter, breakdown, top list, visitor estimate, the
// request ring and schild_requests_total, and writes at most one event,
// with the combined result and the inspected paths (checked_paths).
//
// The Caddy adapter keeps one Recheck per request (a Caddy request
// variable) and hands it to every evaluation (ServeChecked). Evaluations
// nest (a schild further down the chain of a schild) or follow each other
// (handle_errors runs after the route returned its error): the request is
// recorded when the outermost evaluation finishes and no error went back to
// Caddy, else when the next evaluation finishes, at the latest when Caddy
// is done with the request (its context ends).
type Recheck struct {
	mu    sync.Mutex
	depth int  // evaluations running
	seq   int  // evaluations started
	next  bool // an error went back to Caddy: handle_errors may evaluate again
	after bool // the end-of-request flush is registered
	body  bool // the body was admitted: one admission per request (D41)
	held  bool // an evaluation holds the place of this request (D45)
	evals []evalRec
}

type evalRec struct {
	seq int
	ri  *reqInfo
	r   *http.Request // the request as this evaluation inspected it
}

// NewRecheck returns the state of one request.
func NewRecheck() *Recheck { return &Recheck{} }

// MayFollow notes that an error goes back to Caddy (ingress mode), so
// handle_errors may run another schild for the same request.
func (st *Recheck) MayFollow() {
	if st == nil {
		return
	}
	st.mu.Lock()
	st.next = true
	st.mu.Unlock()
}

// bodyAdmitted reports whether an earlier evaluation admitted the body.
func (st *Recheck) bodyAdmitted() bool {
	if st == nil {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.body
}

// noteBodyAdmitted records that the body of this request holds its admission.
func (st *Recheck) noteBodyAdmitted() {
	if st != nil {
		st.mu.Lock()
		st.body = true
		st.mu.Unlock()
	}
}

// requestHeld reports whether a running evaluation holds the request's place.
func (st *Recheck) requestHeld() bool {
	if st == nil {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.held
}

// noteRequest records that an evaluation took or gave back the request's place.
func (st *Recheck) noteRequest(held bool) {
	if st != nil {
		st.mu.Lock()
		st.held = held
		st.mu.Unlock()
	}
}

// enter starts an evaluation.
func (st *Recheck) enter(ri *reqInfo) {
	st.mu.Lock()
	st.depth++
	st.seq++
	ri.seq = st.seq
	st.mu.Unlock()
}

// leave ends an evaluation (ri nil: it ended without a result, a panic or
// a health check) and returns the evaluations to record when the request
// is complete; register asks for the end-of-request flush.
func (st *Recheck) leave(ri *reqInfo, r *http.Request) (evals []evalRec, register bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.depth--
	if ri != nil {
		st.evals = append(st.evals, evalRec{seq: ri.seq, ri: ri, r: r})
	}
	if st.depth > 0 || len(st.evals) == 0 {
		return nil, false
	}
	if st.next {
		st.next = false
		register = !st.after
		st.after = true
		return nil, register
	}
	return st.take(), false
}

// take returns the finished evaluations in the order they started (mu held).
func (st *Recheck) take() []evalRec {
	evals := st.evals
	st.evals = nil
	sort.Slice(evals, func(i, j int) bool { return evals[i].seq < evals[j].seq })
	return evals
}

// flush records what is left when Caddy is done with the request.
func (st *Recheck) flush() []evalRec {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.depth > 0 || len(st.evals) == 0 {
		return nil
	}
	return st.take()
}

// ServeChecked is Serve for the Caddy adapter: st (nil: none) is the
// request's re-check state shared by every schild evaluation of it.
func (g *Gate) ServeChecked(w http.ResponseWriter, r *http.Request, next http.Handler, st *Recheck) {
	g.serve(w, r, next, st, "")
}

// ServeRouted is ServeChecked for a request Caddy routed to the site block
// of website (ingress mode, D69): the access lock and crawler control decide
// by that website, not by a second reading of the Host header. An empty
// website reads the Host as ServeChecked does.
func (g *Gate) ServeRouted(w http.ResponseWriter, r *http.Request, next http.Handler, st *Recheck, website string) {
	g.serve(w, r, next, st, website)
}

// finishChecked hands a finished evaluation to its request's state and
// records the request once it is complete (finish).
func (g *Gate) finishChecked(ri *reqInfo, r *http.Request) {
	st := ri.recheck
	ri.left = true
	evals, register := st.leave(ri, ri.req)
	if register {
		context.AfterFunc(r.Context(), func() { g.completeAll(st.flush()) })
	}
	g.completeAll(evals)
}

// leaveUnfinished ends an evaluation that produced no result (deferred in
// serve: a panic below it or a health check).
func (g *Gate) leaveUnfinished(ri *reqInfo, r *http.Request) {
	if ri.left {
		return
	}
	ri.left = true
	evals, register := ri.recheck.leave(nil, r)
	if register {
		st := ri.recheck
		context.AfterFunc(r.Context(), func() { g.completeAll(st.flush()) })
	}
	g.completeAll(evals)
}

func (g *Gate) completeAll(evals []evalRec) {
	if len(evals) == 0 {
		return
	}
	ri, r := combine(evals)
	g.complete(r, ri)
}

// ringOutcomeOf is the request ring outcome of one evaluation
// (monitoring.Recheck input).
func ringOutcomeOf(ri *reqInfo) string {
	switch classOf(ri) {
	case monitoring.Forwarded:
		if ri.decision.Outcome == decide.WouldBlock {
			return cm.OutcomeWouldBlock
		}
		return cm.OutcomePassed
	case monitoring.BlockedWAF:
		return cm.OutcomeBlockedWAF
	case monitoring.BlockedBehaviour, monitoring.Challenged:
		return cm.OutcomeBlockedBehaviour
	case monitoring.RateLimited:
		return cm.OutcomeRateLimited
	case monitoring.RejectedLimit:
		return cm.OutcomeRejectedLimit
	case monitoring.BlockedCrawler:
		return cm.OutcomeBlockedCrawler
	}
	return cm.OutcomeFailClosed
}

// combine merges the evaluations of one request (in the order they ran)
// into the request info that is recorded (contract monitoring.Recheck):
// the last evaluation's stop, else would_block when any evaluation was
// would_block, else passed; matched rules merged, the highest score; the
// event path is what the last evaluation inspected.
func combine(evals []evalRec) (*reqInfo, *http.Request) {
	last := evals[len(evals)-1]
	if len(evals) == 1 {
		return last.ri, last.r
	}
	in := make([]cm.Evaluation, len(evals))
	for i, e := range evals {
		in[i] = cm.Evaluation{Path: redact.Path(e.r.URL.EscapedPath()), Outcome: ringOutcomeOf(e.ri),
			Detection: classOf(e.ri) == monitoring.BlockedWAF || e.ri.decision.Outcome == decide.WouldBlock && !e.ri.crawlerOnly}
		if a := e.ri.analysis; a != nil {
			in[i].Score = a.Score
		}
	}
	res, err := cm.Recheck(in)
	if err != nil {
		// Only the last evaluation can stop a request; should an earlier
		// one have stopped it, the last one is recorded alone.
		return last.ri, last.r
	}
	c := *last.ri
	c.rechecked, c.checkedPaths = true, res.CheckedPaths
	c.start = evals[0].ri.start
	c.wafTime = 0
	for _, e := range evals {
		x := e.ri
		c.wafTime += x.wafTime
		c.evaluated = c.evaluated || x.evaluated
		c.body.n = max(c.body.n, x.body.n)
		c.sw.bytes = max(c.sw.bytes, x.sw.bytes)
		if c.sw.upstream == 0 {
			c.sw.upstream = x.sw.upstream
		}
		if c.upstreamDur == 0 {
			c.upstreamDur = x.upstreamDur
		}
		c.wouldRL = c.wouldRL || x.wouldRL
		if c.crawler == crawlerNone && x.crawler != crawlerNone {
			c.crawler, c.crawlerRule, c.crawlerReason = x.crawler, x.crawlerRule, x.crawlerReason
		}
	}
	if res.Outcome == cm.OutcomeWouldBlock && c.decision.Outcome != decide.WouldBlock {
		// An earlier evaluation would have blocked: the request is
		// would_block with that evaluation's reason.
		for i := len(evals) - 2; i >= 0; i-- {
			if evals[i].ri.decision.Outcome == decide.WouldBlock {
				c.decision = evals[i].ri.decision
				c.crawlerOnly = evals[i].ri.crawlerOnly
				break
			}
		}
	}
	c.analysis = mergeAnalyses(evals)
	return &c, last.r
}

// mergeAnalyses returns the WAF analysis of the request: the last
// evaluation's with the matches of every evaluation (first occurrence
// first, at most cm.MaxRecheckRules distinct ids), the highest score and
// the union of the matched ids. nil when no evaluation was analysed.
func mergeAnalyses(evals []evalRec) *waf.Analysis {
	var base *waf.Analysis
	n := 0
	for _, e := range evals {
		if e.ri.analysis != nil {
			base = e.ri.analysis
			n++
		}
	}
	if n <= 1 {
		return base
	}
	out := *base
	out.Matches, out.MatchedIDs, out.Score = nil, nil, 0
	seen := map[string]bool{}
	ids := map[int]bool{}
	for _, e := range evals {
		a := e.ri.analysis
		if a == nil {
			continue
		}
		out.Score = max(out.Score, a.Score)
		for _, m := range a.Matches {
			key := m.Key()
			if !seen[key] && len(seen) < cm.MaxRecheckRules {
				seen[key] = true
				out.Matches = append(out.Matches, m)
			}
		}
		for _, id := range a.MatchedIDs {
			ids[id] = true
		}
	}
	for id := range ids {
		out.MatchedIDs = append(out.MatchedIDs, id)
	}
	sort.Ints(out.MatchedIDs)
	return &out
}

// inspected returns a copy of r as schild inspects it now (method, host,
// URL), so a later rewrite does not change the recorded path.
func inspected(r *http.Request) *http.Request {
	cp := *r
	u := *r.URL
	cp.URL = &u
	return &cp
}

// timedOf: latency counts for everything but upgrades and event streams.
func timedOf(ri *reqInfo) bool {
	return ri.status != http.StatusSwitchingProtocols && !strings.HasPrefix(ri.sw.Header().Get("Content-Type"), "text/event-stream")
}
