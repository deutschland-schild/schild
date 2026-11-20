package results

import (
	"os"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract"
)

func TestWrite(t *testing.T) {
	r := &Result{
		ResultsVersion: 0, Spec: "MVP-01", RunID: "unit-1", StartedAt: "2026-10-26T12:00:00Z", FinishedAt: "2026-10-26T12:00:01Z",
		Seed: 42, Profile: "unit", Metrics: []Metric{{Name: "vectors_disagreeing", Value: 0, Unit: "count"}},
		KillCriteria: []KillCriteria{{Expr: "a vector validates differently in the two implementations", Hit: false}}, Verdict: "pass",
	}
	p, err := r.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p, "MVP-01.json") {
		t.Fatal(p)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"verdict":"pass"`) {
		t.Fatal(string(b))
	}
	r.Verdict = "ok"
	if _, err := r.Marshal(); contract.CodeOf(err) != contract.CodeSchema {
		t.Fatalf("invalid verdict accepted: %v", err)
	}
	r.Verdict = "pass"
	r.FinishedAt = "2026-10-26T11:00:00Z"
	if _, err := r.Marshal(); err == nil {
		t.Fatal("finished before started accepted")
	}
}
