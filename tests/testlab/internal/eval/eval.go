// Package eval joins the schild client's local events with the test lab's
// ground truth and turns the join into the metrics of results.schema.json:
// precision/recall per class, false-positive rate, latency percentiles with
// and without schild, the bypass count, the canary findings and the number of
// legitimate requests that were blocked.
//
// The evaluator is the measurement; it is built by a different agent than the
// client it measures (conventions §1). Its own correctness is guarded by the
// planted-fault self-test in selftest.go: on a clean synthetic run every kill
// criterion must stay unhit, and each injected fault (a canary leak, a bypass,
// a false block, an unlabelled request) must be caught.
package eval

import (
	"bufio"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/deutschland-schild/schild/testlab/internal/egress"
	"github.com/deutschland-schild/schild/testlab/internal/groundtruth"
	"github.com/deutschland-schild/schild/testlab/internal/label"
)

// EventRecord is the subset of a schild.request.{evaluated,blocked}.v1 event
// the evaluator needs. It is parsed loosely so an extra field in the event
// does not break the join.
type EventRecord struct {
	Type string `json:"type"`
	Data struct {
		RequestID  string  `json:"request_id"`
		Status     int     `json:"status"`
		Outcome    string  `json:"outcome"` // passed|logged|challenged|blocked|would_block
		Mode       string  `json:"mode"`
		Score      int     `json:"score"`
		DurationMS float64 `json:"duration_ms"`
		WAFMS      float64 `json:"waf_ms"`
		Rules      []struct {
			ID     int    `json:"id"`
			Source string `json:"source"`
		} `json:"rules"`
	} `json:"data"`
}

// flagged reports whether the WAF reacted to the request at all.
func (e EventRecord) flagged() bool {
	return e.Data.Outcome != "passed" || len(e.Data.Rules) > 0 || e.Data.Score > 0
}

// blocked reports whether the request was effectively stopped (blocked or
// challenged). "would_block" is a shadow decision and does not stop traffic.
func (e EventRecord) blocked() bool {
	return e.Data.Outcome == "blocked" || e.Data.Outcome == "challenged"
}

// ParseEvents reads NDJSON events and returns only request events, keyed by
// request id. If a request id appears twice, the blocked event wins (a block
// event is the authoritative outcome).
func ParseEvents(r io.Reader) (map[string]EventRecord, error) {
	out := map[string]EventRecord{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		b := strings.TrimSpace(sc.Text())
		if b == "" {
			continue
		}
		var ev EventRecord
		if err := json.Unmarshal([]byte(b), &ev); err != nil {
			continue
		}
		if ev.Type != "schild.request.evaluated.v1" && ev.Type != "schild.request.blocked.v1" {
			continue
		}
		if ev.Data.RequestID == "" {
			continue
		}
		prev, ok := out[ev.Data.RequestID]
		if !ok || (ev.Type == "schild.request.blocked.v1" && prev.Type != "schild.request.blocked.v1") {
			out[ev.Data.RequestID] = ev
		}
	}
	return out, sc.Err()
}

// ClassStats are the per-class counts.
type ClassStats struct {
	Total     int     `json:"total"`
	Matched   int     `json:"matched"` // joined to an event
	Flagged   int     `json:"flagged"`
	Blocked   int     `json:"blocked"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
}

// Report is the full evaluation.
type Report struct {
	// Per-class stats keyed by class name.
	Classes map[label.Class]*ClassStats `json:"classes"`
	// Overall attack detection.
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	// FalsePositiveRate is flagged legit / total legit.
	FalsePositiveRate float64 `json:"false_positive_rate"`
	// LegitBlocks is the number of legitimate requests that were blocked.
	LegitBlocks int `json:"legit_blocks"`
	// BypassCount is attacks that were not blocked (reached the origin).
	BypassCount int `json:"bypass_count"`
	// Unlabelled is the number of requests that reached a site without a
	// valid ground-truth label (a generator bug or injection).
	Unlabelled int `json:"unlabelled"`
	// Unmatched is ground-truth records with no matching event (lost events).
	Unmatched int `json:"unmatched"`
	// CanaryFindings comes from the egress check.
	CanaryFindings int `json:"canary_findings"`
	// EgressIPFindings and EgressFieldFindings come from the egress check too:
	// an address or a field outside the positive list in an outgoing signal (M2).
	EgressIPFindings    int `json:"egress_ip_findings"`
	EgressFieldFindings int `json:"egress_field_findings"`
	// ObservedAttacks are attacks in observe mode: flagged or not, observe
	// never blocks, so they are not bypasses.
	ObservedAttacks int `json:"observed_attacks"`
	// Latency percentiles over duration_ms, with schild and (optionally) a
	// baseline run without schild.
	LatencyWith    Percentiles  `json:"latency_with"`
	LatencyWithout *Percentiles `json:"latency_without,omitempty"`
	Total          int          `json:"total"`
}

// Percentiles over a sample.
type Percentiles struct {
	P50     float64 `json:"p50"`
	P95     float64 `json:"p95"`
	P99     float64 `json:"p99"`
	Samples int     `json:"samples"`
}

// Inputs bundle everything the evaluator joins.
type Inputs struct {
	Truth    []groundtruth.Record
	Events   map[string]EventRecord // schild run, keyed by request id
	Baseline map[string]EventRecord // optional run without schild, keyed by id
	Egress   *egress.Report         // optional egress check result
}

// Evaluate joins truth and events and computes the report.
func Evaluate(in Inputs) Report {
	rep := Report{Classes: map[label.Class]*ClassStats{}}
	for _, c := range label.Classes {
		rep.Classes[c] = &ClassStats{}
	}
	var withLat []float64

	var flaggedAttacks, flaggedLegit, totalAttacks, totalLegit int

	for _, t := range in.Truth {
		rep.Total++
		if !t.Labelled {
			rep.Unlabelled++
		}
		cs := rep.Classes[t.Class]
		if cs == nil {
			cs = &ClassStats{}
			rep.Classes[t.Class] = cs
		}
		cs.Total++

		ev, ok := in.Events[t.RequestID]
		if !ok {
			rep.Unmatched++
			continue
		}
		cs.Matched++
		if ev.Data.DurationMS > 0 {
			withLat = append(withLat, ev.Data.DurationMS)
		}
		isAttack := t.Class == label.Malicious || t.Class == label.Bypass
		if ev.flagged() {
			cs.Flagged++
		}
		if ev.blocked() {
			cs.Blocked++
		}
		if isAttack {
			totalAttacks++
			if ev.flagged() {
				flaggedAttacks++
			}
			// A bypass is an attack that a blocking mode let through; in
			// observe mode nothing is blocked by design.
			if !ev.blocked() {
				if ev.Data.Mode == "observe" {
					rep.ObservedAttacks++
				} else {
					rep.BypassCount++
				}
			}
		} else {
			totalLegit++
			if ev.flagged() {
				flaggedLegit++
			}
			if ev.blocked() {
				rep.LegitBlocks++
			}
		}
	}

	// Per-class precision/recall. For an attack class, recall is "flagged of
	// this class"; precision is this class's flags over all flags. For a
	// legit class, "recall" of being left alone is 1-flag-rate, but we report
	// the standard detection precision/recall only for attack classes and
	// leave legit classes' precision/recall at 0 (their fpr is separate).
	for c, cs := range rep.Classes {
		if cs.Total == 0 {
			continue
		}
		if c == label.Malicious || c == label.Bypass {
			cs.Recall = ratio(cs.Flagged, cs.Total)
			cs.Precision = ratio(cs.Flagged, cs.Flagged+flaggedLegit)
		}
	}

	rep.Recall = ratio(flaggedAttacks, totalAttacks)
	rep.Precision = ratio(flaggedAttacks, flaggedAttacks+flaggedLegit)
	rep.FalsePositiveRate = ratio(flaggedLegit, totalLegit)
	rep.LatencyWith = percentiles(withLat)

	if in.Baseline != nil {
		var base []float64
		for _, ev := range in.Baseline {
			if ev.Data.DurationMS > 0 {
				base = append(base, ev.Data.DurationMS)
			}
		}
		p := percentiles(base)
		rep.LatencyWithout = &p
	}
	if in.Egress != nil {
		rep.CanaryFindings = in.Egress.CanaryFindings
		rep.EgressIPFindings = in.Egress.IPFindings
		rep.EgressFieldFindings = in.Egress.FieldFindings
	}
	return rep
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

// percentiles computes p50/p95/p99 with linear interpolation (nearest-rank
// variant on a sorted copy).
func percentiles(xs []float64) Percentiles {
	n := len(xs)
	if n == 0 {
		return Percentiles{}
	}
	s := make([]float64, n)
	copy(s, xs)
	sort.Float64s(s)
	return Percentiles{
		P50:     pct(s, 0.50),
		P95:     pct(s, 0.95),
		P99:     pct(s, 0.99),
		Samples: n,
	}
}

func pct(sorted []float64, q float64) float64 {
	n := len(sorted)
	if n == 1 {
		return sorted[0]
	}
	rank := q * float64(n-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo] + frac*(sorted[hi]-sorted[lo])
}
