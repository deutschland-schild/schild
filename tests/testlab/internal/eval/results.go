package eval

import (
	"fmt"

	"github.com/deutschland-schild/schild/contract/results"
	"github.com/deutschland-schild/schild/testlab/internal/label"
)

// KillCriteria is the fixed list of conditions the evaluator reports. Humans
// decide what a hit means (conventions §8); the evaluator only observes.
func (rep Report) killCriteria() []results.KillCriteria {
	return []results.KillCriteria{
		{
			Expr:     "an attack reaches the origin unblocked (bypass_count > 0 in a blocking mode)",
			Hit:      rep.BypassCount > 0,
			Observed: fmt.Sprintf("bypass_count=%d", rep.BypassCount),
		},
		{
			Expr:     "a canary value leaves the server in a signal (canary_findings > 0)",
			Hit:      rep.CanaryFindings > 0,
			Observed: fmt.Sprintf("canary_findings=%d", rep.CanaryFindings),
		},
		{
			Expr:     "an address or a field outside the positive list leaves the server in a signal (egress_ip_findings + egress_field_findings > 0)",
			Hit:      rep.EgressIPFindings+rep.EgressFieldFindings > 0,
			Observed: fmt.Sprintf("egress_ip_findings=%d egress_field_findings=%d", rep.EgressIPFindings, rep.EgressFieldFindings),
		},
		{
			Expr:     "legitimate traffic is blocked (legit_blocks > 0)",
			Hit:      rep.LegitBlocks > 0,
			Observed: fmt.Sprintf("legit_blocks=%d", rep.LegitBlocks),
		},
		{
			Expr:     "a request reaches a site without a valid ground-truth label (unlabelled > 0)",
			Hit:      rep.Unlabelled > 0,
			Observed: fmt.Sprintf("unlabelled=%d", rep.Unlabelled),
		},
	}
}

// Metrics renders the report as the metric list of results.schema.json.
func (rep Report) Metrics() []results.Metric {
	m := []results.Metric{
		{Name: "precision", Value: round(rep.Precision), Unit: "ratio", Samples: rep.Total},
		{Name: "recall", Value: round(rep.Recall), Unit: "ratio", Samples: rep.Total},
		{Name: "false_positive_rate", Value: round(rep.FalsePositiveRate), Unit: "ratio", Samples: rep.Total},
		{Name: "legit_blocks", Value: float64(rep.LegitBlocks), Unit: "count"},
		{Name: "bypass_count", Value: float64(rep.BypassCount), Unit: "count"},
		{Name: "canary_findings", Value: float64(rep.CanaryFindings), Unit: "count"},
		{Name: "egress_ip_findings", Value: float64(rep.EgressIPFindings), Unit: "count"},
		{Name: "egress_field_findings", Value: float64(rep.EgressFieldFindings), Unit: "count"},
		{Name: "observed_attacks", Value: float64(rep.ObservedAttacks), Unit: "count"},
		{Name: "unlabelled_requests", Value: float64(rep.Unlabelled), Unit: "count"},
		{Name: "unmatched_truth", Value: float64(rep.Unmatched), Unit: "count"},
		{Name: "latency_p50", Value: round(rep.LatencyWith.P50), Unit: "ms", Samples: rep.LatencyWith.Samples, Labels: map[string]string{"variant": "with_schild"}},
		{Name: "latency_p95", Value: round(rep.LatencyWith.P95), Unit: "ms", Samples: rep.LatencyWith.Samples, Labels: map[string]string{"variant": "with_schild"}},
		{Name: "latency_p99", Value: round(rep.LatencyWith.P99), Unit: "ms", Samples: rep.LatencyWith.Samples, Labels: map[string]string{"variant": "with_schild"}},
	}
	if rep.LatencyWithout != nil {
		m = append(m,
			results.Metric{Name: "latency_p50", Value: round(rep.LatencyWithout.P50), Unit: "ms", Samples: rep.LatencyWithout.Samples, Labels: map[string]string{"variant": "without_schild"}},
			results.Metric{Name: "latency_p95", Value: round(rep.LatencyWithout.P95), Unit: "ms", Samples: rep.LatencyWithout.Samples, Labels: map[string]string{"variant": "without_schild"}},
			results.Metric{Name: "latency_p99", Value: round(rep.LatencyWithout.P99), Unit: "ms", Samples: rep.LatencyWithout.Samples, Labels: map[string]string{"variant": "without_schild"}},
		)
	}
	// Per-class recall for attack classes.
	for _, c := range label.Classes {
		cs := rep.Classes[c]
		if cs == nil || cs.Total == 0 {
			continue
		}
		if c == label.Malicious || c == label.Bypass {
			m = append(m, results.Metric{
				Name: "class_recall", Value: round(cs.Recall), Unit: "ratio",
				Samples: cs.Total, Labels: map[string]string{"class": string(c)},
			})
		}
	}
	return m
}

// ToResult builds a complete, schema-valid result. The caller fills run_id,
// timestamps, images and host. verdict is pass when no kill criterion is hit
// and every ground-truth record matched an event; otherwise fail.
func (rep Report) ToResult(spec, runID, started, finished string, seed uint64, profile string) *results.Result {
	kc := rep.killCriteria()
	verdict := "pass"
	for _, k := range kc {
		if k.Hit {
			verdict = "fail"
		}
	}
	if rep.Total == 0 {
		verdict = "inconclusive"
	} else if rep.Unmatched > 0 && verdict == "pass" {
		verdict = "inconclusive"
	}
	return &results.Result{
		ResultsVersion: 0, Spec: spec, RunID: runID,
		StartedAt: started, FinishedAt: finished, Seed: seed, Profile: profile,
		Metrics: rep.Metrics(), KillCriteria: kc, Verdict: verdict,
		Notes: fmt.Sprintf("joined %d events to %d ground-truth records (%d unmatched)",
			rep.Total-rep.Unmatched, rep.Total, rep.Unmatched),
	}
}

func round(f float64) float64 {
	return float64(int64(f*1e6+0.5)) / 1e6
}
