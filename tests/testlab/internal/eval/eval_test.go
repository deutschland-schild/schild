package eval

import (
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/testlab/internal/groundtruth"
	"github.com/deutschland-schild/schild/testlab/internal/label"
)

func TestParseEventsBlockedWins(t *testing.T) {
	log := `{"type":"schild.request.evaluated.v1","data":{"request_id":"r1","outcome":"passed","duration_ms":3}}
{"type":"schild.request.blocked.v1","data":{"request_id":"r1","outcome":"blocked","duration_ms":4,"rules":[{"id":1,"source":"crs"}]}}
not json
{"type":"schild.rule.adopted.v1","data":{"request_id":"ignored"}}`
	ev, err := ParseEvents(strings.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 {
		t.Fatalf("want 1 event, got %d", len(ev))
	}
	if ev["r1"].Type != "schild.request.blocked.v1" {
		t.Fatalf("blocked event should win: %+v", ev["r1"])
	}
}

func TestEvaluateMetrics(t *testing.T) {
	truth := []groundtruth.Record{
		{RequestID: "a", Class: label.Malicious, ExpectBlock: true, Labelled: true},
		{RequestID: "b", Class: label.Benign, Labelled: true},
		{RequestID: "c", Class: label.Benign, Labelled: true},
		{RequestID: "d", Class: label.Bypass, ExpectBlock: true, Labelled: true},
	}
	events := map[string]EventRecord{}
	mk := func(id, outcome string, dur float64, rules int) EventRecord {
		var e EventRecord
		e.Type = "schild.request.evaluated.v1"
		e.Data.RequestID = id
		e.Data.Outcome = outcome
		e.Data.DurationMS = dur
		for i := 0; i < rules; i++ {
			e.Data.Rules = append(e.Data.Rules, struct {
				ID     int    `json:"id"`
				Source string `json:"source"`
			}{ID: 1, Source: "crs"})
		}
		return e
	}
	events["a"] = mk("a", "blocked", 5, 1) // attack blocked
	events["b"] = mk("b", "passed", 2, 0)  // benign ok
	events["c"] = mk("c", "blocked", 3, 1) // benign WRONGLY blocked
	events["d"] = mk("d", "passed", 10, 0) // bypass slipped through

	rep := Evaluate(Inputs{Truth: truth, Events: events})
	if rep.LegitBlocks != 1 {
		t.Errorf("legit_blocks = %d, want 1", rep.LegitBlocks)
	}
	if rep.BypassCount != 1 {
		t.Errorf("bypass_count = %d, want 1", rep.BypassCount)
	}
	if rep.FalsePositiveRate != 0.5 {
		t.Errorf("fpr = %v, want 0.5", rep.FalsePositiveRate)
	}
	// Attacks: a flagged, d not flagged => recall 0.5.
	if rep.Recall != 0.5 {
		t.Errorf("recall = %v, want 0.5", rep.Recall)
	}
	if rep.LatencyWith.Samples != 4 {
		t.Errorf("latency samples = %d, want 4", rep.LatencyWith.Samples)
	}
}

func TestEvaluateUnmatched(t *testing.T) {
	truth := []groundtruth.Record{{RequestID: "x", Class: label.Benign, Labelled: true}}
	rep := Evaluate(Inputs{Truth: truth, Events: map[string]EventRecord{}})
	if rep.Unmatched != 1 {
		t.Fatalf("unmatched = %d, want 1", rep.Unmatched)
	}
}

func TestPercentiles(t *testing.T) {
	p := percentiles([]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	if p.P50 < 5 || p.P50 > 6 {
		t.Errorf("p50 = %v, want ~5.5", p.P50)
	}
	if p.P99 < 9.8 {
		t.Errorf("p99 = %v, want ~9.9", p.P99)
	}
}
