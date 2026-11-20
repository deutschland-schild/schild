package eval

import "testing"

// TestSelfTestCleanRun is the baseline: a clean synthetic run must not hit any
// kill criterion.
func TestSelfTestCleanRun(t *testing.T) {
	rep := BuildSynthetic(42, 50, FaultNone).Report()
	res := rep.ToResult("MVP-05", "selftest-clean", "2026-10-26T12:00:00Z", "2026-10-26T12:00:01Z", 42, "unit")
	if res.Verdict != "pass" {
		t.Fatalf("clean run verdict = %q, want pass (%+v)", res.Verdict, rep)
	}
	for _, k := range res.KillCriteria {
		if k.Hit {
			t.Errorf("clean run hit kill criterion: %s (%s)", k.Expr, k.Observed)
		}
	}
	if rep.Recall != 1 {
		t.Errorf("clean recall = %v, want 1", rep.Recall)
	}
	if rep.FalsePositiveRate != 0 {
		t.Errorf("clean fpr = %v, want 0", rep.FalsePositiveRate)
	}
}

// TestSelfTestDetectsFaults is the MVP-05 kill criterion: the evaluator must
// detect every planted fault. Missing one fails the whole measurement.
func TestSelfTestDetectsFaults(t *testing.T) {
	cases := []struct {
		fault   Fault
		checkFn func(Report) bool
		what    string
	}{
		{FaultBypass, func(r Report) bool { return r.BypassCount > 0 }, "bypass_count > 0"},
		{FaultFalseBlock, func(r Report) bool { return r.LegitBlocks > 0 }, "legit_blocks > 0"},
		{FaultCanaryLeak, func(r Report) bool { return r.CanaryFindings > 0 }, "canary_findings > 0"},
		{FaultUnlabelled, func(r Report) bool { return r.Unlabelled > 0 }, "unlabelled > 0"},
	}
	for _, tc := range cases {
		t.Run(string(tc.fault), func(t *testing.T) {
			rep := BuildSynthetic(42, 50, tc.fault).Report()
			if !tc.checkFn(rep) {
				t.Fatalf("fault %q NOT detected (expected %s); report=%+v", tc.fault, tc.what, rep)
			}
			res := rep.ToResult("MVP-05", "selftest", "2026-10-26T12:00:00Z", "2026-10-26T12:00:01Z", 42, "unit")
			if res.Verdict == "pass" {
				t.Fatalf("fault %q gave verdict pass; a planted fault must fail", tc.fault)
			}
			// The result must be schema-valid.
			if _, err := res.Marshal(); err != nil {
				t.Fatalf("result for fault %q not schema-valid: %v", tc.fault, err)
			}
		})
	}
}

// TestSelfTestDeterministic checks the synthetic run is reproducible for a
// fixed seed (MVP-06 reproducibility spirit, applied to the evaluator input).
func TestSelfTestDeterministic(t *testing.T) {
	a := BuildSynthetic(7, 40, FaultNone)
	b := BuildSynthetic(7, 40, FaultNone)
	if len(a.Truth) != len(b.Truth) {
		t.Fatalf("truth length differs: %d vs %d", len(a.Truth), len(b.Truth))
	}
	for i := range a.Truth {
		if a.Truth[i] != b.Truth[i] {
			t.Fatalf("truth[%d] differs: %+v vs %+v", i, a.Truth[i], b.Truth[i])
		}
	}
	if a.Events[a.Truth[1].RequestID].Data.DurationMS != b.Events[b.Truth[1].RequestID].Data.DurationMS {
		t.Fatal("event durations differ for same seed")
	}
}
