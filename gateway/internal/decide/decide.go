// Package decide turns the matched rules of one request into an outcome. It
// is a pure function so that every combination is unit-tested.
//
// Each rule repository that would act on the request (CRS by anomaly score,
// local rules, every matched crowdsec rule) comes in as one Hit with the
// action contract/rules gave it for the gateway mode, the repository state,
// the rule's status, the allowlist and the client's exceptions (D73). The
// decision only merges them: one block blocks, else one would_block logs
// what would be blocked, else the request passes.
//
// Hard limits (body size, parse limits, WAF timeout) are rejected in every
// mode: a request that could not be inspected never reaches the backend (M1).
package decide

import (
	"sort"

	"github.com/deutschland-schild/schild/contract/rules"
)

// The two values of Settings.Mode (D89: no protection mode to set): observe is
// the dry run of the test profile, autoblock every other gateway.
const (
	ModeObserve   = "observe"
	ModeAutoblock = "autoblock"
)

// Outcomes (events.schema.json; challenged only in events before D92, schild
// has no browser check).
const (
	Passed     = "passed"
	Logged     = "logged"
	Blocked    = "blocked"
	WouldBlock = "would_block"
)

// Why a would_block request was passed (events.WouldBlockReasons, v0.5 D36
// open items), in precedence order: when several apply the first wins.
const (
	ReasonGatewayObserve  = "gateway_observe"
	ReasonSiteObserve     = "site_observe"
	ReasonLearning        = "learning"
	ReasonScenarioObserve = "scenario_observe"
	ReasonSourceDetect    = "source_detect" // D90: the rule source is on detect
	ReasonSettling        = "settling"      // D90: a CrowdSec update still settles
	ReasonAllowlist       = "allowlist"
	ReasonSharedAddress   = "shared_address"
)

var reasonRank = map[string]int{ReasonGatewayObserve: 1, ReasonSiteObserve: 2, ReasonLearning: 3, ReasonScenarioObserve: 4,
	ReasonSourceDetect: 5, ReasonSettling: 6, ReasonAllowlist: 7, ReasonSharedAddress: 8}

// FirstReason returns the reason that wins by precedence ("" for none;
// unknown reasons never win over known ones).
func FirstReason(reasons ...string) string {
	best, br := "", 0
	for _, r := range reasons {
		k := reasonRank[r]
		if k > 0 && (br == 0 || k < br) {
			best, br = r, k
		}
	}
	return best
}

// Allowlist levels.
const (
	AllowNone      = ""
	AllowNoBlock   = "no_block"
	AllowBypassWAF = "bypass_waf"
)

// Hit is one repository or rule that matched, with its action on this
// request (rules.Apply). A hit with action none is not handed in.
type Hit struct {
	// Source is the decision source: crs, local or crowdsec:<base id>.
	Source           string
	Action           string // rules.Action*
	WouldBlockReason string
}

// Input of one decision.
type Input struct {
	Allow      string
	HardStatus int // > 0: hard limit violation with this status
	Hits       []Hit
	AnyMatch   bool
}

// Output of one decision.
type Output struct {
	Outcome  string
	Status   int      // HTTP status when Outcome is blocked
	Sources  []string // blocking (or would-block) sources: crs, local, crowdsec:<base id>, limit
	Excepted []string // sources that would have blocked but are excepted
	// WouldBlockReason: why a would_block request was passed (only with
	// outcome would_block), the first of the hits by precedence.
	WouldBlockReason string
}

// Decide computes the outcome.
func Decide(in Input) Output {
	if in.Allow == AllowBypassWAF {
		return Output{Outcome: Passed}
	}
	if in.HardStatus > 0 {
		return Output{Outcome: Blocked, Status: in.HardStatus, Sources: []string{"limit"}}
	}
	var block, would, excepted, reasons []string
	for _, h := range in.Hits {
		switch h.Action {
		case rules.ActionBlock:
			block = append(block, h.Source)
		case rules.ActionWouldBlock:
			would = append(would, h.Source)
			reasons = append(reasons, h.WouldBlockReason)
		case rules.ActionExcepted:
			excepted = append(excepted, h.Source)
		}
	}
	sort.Strings(block)
	sort.Strings(would)
	out := Output{Excepted: excepted}
	switch {
	case len(block) > 0:
		out.Outcome, out.Status, out.Sources = Blocked, 403, block
	case len(would) > 0:
		out.Outcome, out.Sources = WouldBlock, would
		out.WouldBlockReason = FirstReason(reasons...)
	case in.AnyMatch || len(excepted) > 0:
		out.Outcome = Logged
	default:
		out.Outcome = Passed
	}
	return out
}
