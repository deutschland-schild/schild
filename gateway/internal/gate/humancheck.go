package gate

import (
	"net/http"

	hc "github.com/deutschland-schild/schild/contract/humancheck"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/humancheck"
)

const humanCheckSource = "human_check"

// humanCheckEndpoint handles POST {prefix}verify and POST {prefix}continue
// before behaviour/WAF so browsers submitting a PoW solution always reach it.
func (g *Gate) humanCheckEndpoint(w http.ResponseWriter, r *http.Request, ri *reqInfo) bool {
	action, ok := g.HumanCheck.IsEndpoint(r.URL.Path)
	if !ok {
		return false
	}
	website := g.reqSite(r, ri)
	ri.stopped = true
	ri.status = g.HumanCheck.HandleEndpoint(w, r, website, ri.client.IP, action, ri.start)
	ri.decision = decide.Output{Outcome: decide.Passed, Status: ri.status, Sources: []string{humanCheckSource + ":" + action}}
	g.finish(r, ri)
	return true
}

// humanCheckStop evaluates the website's browser verification / Under Attack
// policy (MVP-12 v1_cut) and serves the "Kurze Prüfung" interstitial when needed.
// Any internal error fails open so visitors are never locked out.
func (g *Gate) humanCheckStop(w http.ResponseWriter, r *http.Request, ri *reqInfo, bv behaviour.Verdict) bool {
	website := g.reqSite(r, ri)
	sharedClass := ri.geo.NetClass == "cgnat" || ri.geo.NetClass == "mobile" || ri.geo.NetClass == "tor"
	sig := humancheck.RequestSignals{
		Allowlisted:        ri.allow != "",
		SharedScenarioHit:  sharedClass && (bv.WouldRateLimit || bv.Scenario != ""),
		AggressiveCrawlHit: bv.Scenario == "aggressive_crawl",
		DistributedWave:    bv.WaveID != "",
	}
	v, active := g.HumanCheck.Check(r, website, ri.client.IP, sig, ri.start)
	if !active {
		return false
	}
	if v.Result.Answer == hc.AnswerPass {
		if v.HadCookie {
			humancheck.StripCookie(r)
		}
		return false
	}
	if !g.HumanCheck.ServeInterstitial(w, r, v, website, ri.start) {
		return false // fail-open on internal error
	}
	ri.stopped = true
	g.drain(w, r, ri)
	ri.status = v.Result.Status
	ri.decision = decide.Output{Outcome: decide.Blocked, Status: v.Result.Status, Sources: []string{humanCheckSource + ":" + v.Result.Reason}}
	g.finish(r, ri)
	return true
}
