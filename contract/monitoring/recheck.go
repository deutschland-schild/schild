package monitoring

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Re-checked requests (initiator decision 2026-10-29, DECISIONS D33
// amendment; MVP-19 fix round 3 bound the "already checked" marker to what
// schild inspected): schild may evaluate one HTTP request more than once,
// e.g. in a site block and again in handle_errors after a handle_path
// stripped the prefix, or again after a rewrite that follows a schild
// handler. Such a request still counts once everywhere: once in requests
// and in exactly one outcome class of TrafficCounters, once in the
// breakdowns, top lists and visitor estimates, once in the request ring,
// once in Prometheus schild_requests_total, and it writes at most one
// request event. The event and the counters describe the combined result
// (Recheck); the event lists the paths schild inspected (checked_paths).

// RecheckSchema is the vector input schema (request-recheck.schema.json).
const RecheckSchema = "request-recheck"

// MaxCheckedPaths bounds events.schema.json checked_paths.
const MaxCheckedPaths = 4

// MaxRecheckRules bounds the merged rule ids (events rules maxItems).
const MaxRecheckRules = 128

// Evaluation is one schild evaluation of a request, in the order they ran.
type Evaluation struct {
	// Path as this evaluation inspected it (redacted as the event path).
	Path string
	// Outcome as the request ring names it (OutcomePassed ... ).
	Outcome string
	// Detection: the WAF reached its blocking decision in this evaluation
	// (enforced or observed).
	Detection bool
	// Rules are the matched rule ids of this evaluation.
	Rules []string
	Score int
}

// Request ring outcomes (RequestRecord.outcome).
const (
	OutcomePassed           = "passed"
	OutcomeWouldBlock       = "would_block"
	OutcomeBlockedWAF       = "blocked_waf"
	OutcomeBlockedBehaviour = "blocked_behaviour"
	OutcomeRateLimited      = "rate_limited"
	OutcomeRejectedLimit    = "rejected_limit"
	OutcomeFailClosed       = "fail_closed"
	OutcomeBlockedCrawler   = "blocked_crawler" // D57
)

// Stop reports whether an outcome ends the request (it is not forwarded).
func Stop(outcome string) bool { return outcome != OutcomePassed && outcome != OutcomeWouldBlock }

// Rechecked is the combined record of one request.
type Rechecked struct {
	// Requests is always 1: the request counts once.
	Requests int `json:"requests"`
	// Rechecked: schild evaluated it more than once
	// (TrafficCounters.rechecked).
	Rechecked bool `json:"rechecked"`
	// Outcome: the last evaluation's when it stopped the request (only the
	// last can: a stop ends the request), else would_block when any
	// evaluation was would_block, else passed.
	Outcome string `json:"outcome"`
	// Detection: any evaluation detected (TrafficCounters.detections + 1
	// once).
	Detection bool `json:"detection"`
	// Path of the event: what the last evaluation inspected, never a later
	// rewrite.
	Path string `json:"path"`
	// CheckedPaths of the event: null for one evaluation; else the paths
	// of every evaluation in order, above MaxCheckedPaths the first three
	// and the last.
	CheckedPaths []string `json:"checked_paths"`
	// Rules: the matched rule ids of all evaluations, first occurrence
	// first, duplicates dropped, at most MaxRecheckRules.
	Rules []string `json:"rules"`
	// Score: the highest anomaly score of the evaluations.
	Score int `json:"score"`
}

// Recheck combines the evaluations of one request (at least one; only the
// last may stop it).
func Recheck(evs []Evaluation) (Rechecked, error) {
	if len(evs) == 0 {
		return Rechecked{}, contract.Errf(contract.CodeSchema, "no evaluation")
	}
	for i, e := range evs[:len(evs)-1] {
		if Stop(e.Outcome) {
			return Rechecked{}, contract.Errf(contract.CodeSchema, "evaluation %d stopped the request but is not the last", i)
		}
	}
	last := evs[len(evs)-1]
	r := Rechecked{Requests: 1, Rechecked: len(evs) > 1, Outcome: OutcomePassed, Path: last.Path, Rules: []string{}}
	seen := map[string]bool{}
	for _, e := range evs {
		if e.Outcome == OutcomeWouldBlock {
			r.Outcome = OutcomeWouldBlock
		}
		r.Detection = r.Detection || e.Detection
		r.Score = max(r.Score, e.Score)
		for _, id := range e.Rules {
			if !seen[id] && len(r.Rules) < MaxRecheckRules {
				seen[id] = true
				r.Rules = append(r.Rules, id)
			}
		}
	}
	if Stop(last.Outcome) {
		r.Outcome = last.Outcome
	}
	if len(evs) > 1 {
		for i, e := range evs {
			if len(evs) <= MaxCheckedPaths || i < MaxCheckedPaths-1 || i == len(evs)-1 {
				r.CheckedPaths = append(r.CheckedPaths, e.Path)
			}
		}
	}
	return r, nil
}

// RunRecheckVector checks one request-recheck vector input:
// {"evaluations": [{path, outcome, detection, rules, score}, ...]}.
func RunRecheckVector(raw []byte) (Rechecked, error) {
	if len(raw) > 64<<10 {
		return Rechecked{}, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), 64<<10)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return Rechecked{}, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(RecheckSchema, v); err != nil {
		return Rechecked{}, err
	}
	var evs []Evaluation
	for _, x := range v["evaluations"].([]any) {
		m := x.(map[string]any)
		e := Evaluation{Path: m["path"].(string), Outcome: m["outcome"].(string), Detection: m["detection"].(bool)}
		for _, id := range m["rules"].([]any) {
			e.Rules = append(e.Rules, id.(string))
		}
		n, err := m["score"].(interface{ Int64() (int64, error) }).Int64()
		if err != nil {
			return Rechecked{}, contract.Errf(contract.CodeSchema, "score: %v", err)
		}
		e.Score = int(n)
		evs = append(evs, e)
	}
	return Recheck(evs)
}
