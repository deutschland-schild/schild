package gate

import (
	"io"
	"net/http"

	"github.com/deutschland-schild/schild/gateway/internal/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
)

// Crawler control (D57, MVP-29): the crawler policy of the request's
// website. A request whose User-Agent names a crawler the policy blocks is
// answered 403 before behaviour, admission and the WAF; in observe mode, or
// from an allowlisted address, it goes on and is recorded as would_block.
// No incident: its event is sampled like a rate limit.

// States of reqInfo.crawler.
const (
	crawlerNone uint8 = iota
	crawlerWould
	crawlerBlocked
)

// crawlerSources name the rule in the sources of a decision (fixed slices,
// so a hit does not allocate).
var crawlerSources = [...][]string{
	crawlers.RuleBot:          {"crawler:bot"},
	crawlers.RuleCategory:     {"crawler:category"},
	crawlers.RuleImpersonator: {"crawler:impersonator"},
}

// crawlerBody is the answer to a blocked crawler: short, plain, for a
// machine.
const crawlerBody = "This website does not allow this crawler.\n"

// crawlerStop applies the crawler policy of the request's website and
// reports whether it answered the request. Without a policy that blocks
// something it costs one map lookup.
func (g *Gate) crawlerStop(w http.ResponseWriter, r *http.Request, ri *reqInfo) bool {
	t := g.Crawlers.Lookup(g.reqSite(r, ri))
	if t == nil {
		return false
	}
	id := g.crawlerBotID(r.UserAgent())
	rule := t.Rule(id, ri.client.IP)
	if rule == crawlers.RuleNone {
		return false
	}
	ri.crawlerRule = rule
	switch {
	case ri.mode == decide.ModeObserve:
		ri.crawler, ri.crawlerReason = crawlerWould, decide.ReasonGatewayObserve
	case ri.allow != "":
		ri.crawler, ri.crawlerReason = crawlerWould, decide.ReasonAllowlist
	default:
		ri.crawler = crawlerBlocked
	}
	if ri.crawler == crawlerWould {
		t.Add(id, crawlers.OutWouldBlock)
		return false
	}
	t.Add(id, crawlers.OutBlocked)
	ri.stopped = true
	g.drain(w, r, ri)
	ri.status = http.StatusForbidden
	ri.decision = decide.Output{Outcome: decide.Blocked, Status: ri.status, Sources: crawlerSources[rule]}
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(ri.status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, crawlerBody)
	}
	g.finish(r, ri)
	return true
}

// crawlerBotID is the catalogue entry a User-Agent names: from the
// monitor's UA cache when monitoring is on (the record then hits the same
// slot), else from the cache of crawler control.
func (g *Gate) crawlerBotID(ua string) uint16 {
	if g.Monitor != nil {
		return g.Monitor.BotID(ua)
	}
	return g.Crawlers.BotID(ua)
}

// reqSite is the website of the request, looked up once for the access
// lock and crawler control (in ingress mode the website of the Caddy route,
// D69).
func (g *Gate) reqSite(r *http.Request, ri *reqInfo) string {
	if !ri.siteKnown {
		ri.site, ri.siteKnown = g.websiteOf(r.Host), true
	}
	return ri.site
}

// crawlerOutcome turns a request a crawler rule would have blocked into
// would_block when nothing else decided more (D57). It reports whether the
// outcome is the crawler rule's alone: such a request is no WAF detection,
// pins no context and is sampled like an unremarkable one.
func crawlerOutcome(ri *reqInfo) bool {
	if ri.crawler != crawlerWould || ri.decision.Outcome != decide.Passed {
		return false
	}
	ri.decision.Outcome = decide.WouldBlock
	ri.decision.WouldBlockReason = ri.crawlerReason
	ri.decision.Sources = crawlerSources[ri.crawlerRule]
	return true
}
