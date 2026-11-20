package eval

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/deutschland-schild/schild/testlab/internal/egress"
	"github.com/deutschland-schild/schild/testlab/internal/groundtruth"
	"github.com/deutschland-schild/schild/testlab/internal/label"
)

// Fault names a deliberately injected defect for the self-test.
type Fault string

const (
	// FaultNone is a clean run: every attack blocked, no legit blocked, no
	// canary leak, every request labelled. All kill criteria must stay unhit.
	FaultNone Fault = "none"
	// FaultBypass lets one attack through to the origin unblocked.
	FaultBypass Fault = "bypass"
	// FaultFalseBlock blocks one benign request.
	FaultFalseBlock Fault = "false_block"
	// FaultCanaryLeak leaks one canary value in an outgoing signal.
	FaultCanaryLeak Fault = "canary_leak"
	// FaultUnlabelled sends one request to a site without a valid label.
	FaultUnlabelled Fault = "unlabelled"
)

// Faults lists every fault the self-test covers.
var Faults = []Fault{FaultNone, FaultBypass, FaultFalseBlock, FaultCanaryLeak, FaultUnlabelled}

// Synthetic is a self-contained synthetic run: ground truth, matching events,
// a transparency log and the canary list, with an optional planted fault.
type Synthetic struct {
	Truth    []groundtruth.Record
	Events   map[string]EventRecord
	Canaries []string
	Log      string // NDJSON transparency log for the egress checker
}

// BuildSynthetic produces a deterministic run of n records (n is rounded up to
// a multiple of the class count). With fault == FaultNone the run is clean.
func BuildSynthetic(seed int64, n int, fault Fault) Synthetic {
	rng := rand.New(rand.NewSource(seed))
	classes := []label.Class{label.Benign, label.Malicious, label.Bypass, label.Canary, label.GoodBot}
	if n < len(classes) {
		n = len(classes)
	}
	var s Synthetic
	s.Events = map[string]EventRecord{}
	var logLines []string

	for i := 0; i < n; i++ {
		c := classes[i%len(classes)]
		id := fmt.Sprintf("req-%08d", i)
		isAttack := c == label.Malicious || c == label.Bypass

		rec := groundtruth.Record{
			RequestID: id, Class: c, Scenario: "T01", Source: "selftest",
			ExpectBlock: label.ExpectedOutcome(c), Seq: i, Labelled: true,
			Host: "a.example", Method: "GET", Path: "/",
		}

		outcome := "passed"
		rules := 0
		if isAttack {
			outcome = "blocked"
			rules = 1
		}
		dur := 2.0 + rng.Float64()*8.0 // 2..10 ms, deterministic given seed

		// Plant a canary in canary records.
		if c == label.Canary {
			canary := fmt.Sprintf("CANARY-%08X", rng.Uint32())
			rec.Canary = canary
			s.Canaries = append(s.Canaries, canary)
		}

		s.Truth = append(s.Truth, rec)
		ev := EventRecord{Type: "schild.request.evaluated.v1"}
		ev.Data.RequestID = id
		ev.Data.Outcome = outcome
		ev.Data.Mode = "block"
		ev.Data.DurationMS = dur
		ev.Data.WAFMS = dur / 3
		if rules > 0 {
			ev.Data.Rules = make([]struct {
				ID     int    `json:"id"`
				Source string `json:"source"`
			}, rules)
			ev.Data.Rules[0].ID = 942100
			ev.Data.Rules[0].Source = "crs"
			ev.Data.Score = 5
			ev.Type = "schild.request.blocked.v1"
		}
		s.Events[id] = ev
	}

	// A clean transparency log: one well-formed signal with only positive-list
	// fields and no canary, no IP.
	logLines = append(logLines, cleanSignalLine("a.example"))

	// Apply the planted fault.
	switch fault {
	case FaultBypass:
		id := firstOfClass(s.Truth, label.Malicious)
		ev := s.Events[id]
		ev.Type = "schild.request.evaluated.v1"
		ev.Data.Outcome = "passed"
		ev.Data.Rules = nil
		ev.Data.Score = 0
		s.Events[id] = ev
	case FaultFalseBlock:
		id := firstOfClass(s.Truth, label.Benign)
		ev := s.Events[id]
		ev.Type = "schild.request.blocked.v1"
		ev.Data.Outcome = "blocked"
		ev.Data.Score = 5
		ev.Data.Rules = []struct {
			ID     int    `json:"id"`
			Source string `json:"source"`
		}{{ID: 942100, Source: "crs"}}
		s.Events[id] = ev
	case FaultCanaryLeak:
		if len(s.Canaries) > 0 {
			logLines = append(logLines, leakySignalLine(s.Canaries[0]))
		}
	case FaultUnlabelled:
		s.Truth = append(s.Truth, groundtruth.Record{
			RequestID: "req-unlabelled", Class: label.Benign, Labelled: false,
			Host: "a.example", Method: "GET", Path: "/leak", Seq: n,
		})
		ev := EventRecord{Type: "schild.request.evaluated.v1"}
		ev.Data.RequestID = "req-unlabelled"
		ev.Data.Outcome = "passed"
		ev.Data.DurationMS = 3
		s.Events["req-unlabelled"] = ev
	}

	s.Log = ""
	for _, l := range logLines {
		s.Log += l + "\n"
	}
	return s
}

// Report runs the evaluator over the synthetic run, including the egress check.
func (s Synthetic) Report() Report {
	ck := egress.New(s.Canaries, nil)
	rep, _ := ck.CheckLog(strings.NewReader(s.Log))
	return Evaluate(Inputs{Truth: s.Truth, Events: s.Events, Egress: &rep})
}

func firstOfClass(recs []groundtruth.Record, c label.Class) string {
	for _, r := range recs {
		if r.Class == c {
			return r.RequestID
		}
	}
	return ""
}

func cleanSignalLine(site string) string {
	// A schild.signal/0.3 payload: positive list only, no site, no address.
	_ = site
	return `{"specversion":"1.0","id":"11111111-1111-4111-8111-111111111111",` +
		`"source":"schild://a.example","type":"schild.signal.sent.v1",` +
		`"time":"2026-10-26T12:00:00.000Z","datacontenttype":"application/json",` +
		`"data":{"kind":"signal","lab":"lab-a","envelope_sha256":"` +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		`","result":"accepted","payload":{"schema":"schild.signal/0.3","id":"0f8f3c3e-6c1e-4d55-9d38-1c2b8f2a7a10",` +
		`"kind":"tip","time_bucket":"2026-10-26T12:00:00Z","action_sig":"sqli/api","waf_rules":[942100],"score":45,"category":"sqli",` +
		`"origin":{"country":"NL","asn":64500,"net_class":"hosting","attribution":"trusted_proxy"},"agent":{"family":"python-requests","major":2,"bot":true}}}}`
}

func leakySignalLine(canary string) string {
	return `{"specversion":"1.0","id":"22222222-2222-4222-8222-222222222222",` +
		`"source":"schild://a.example","type":"schild.signal.sent.v1",` +
		`"time":"2026-10-26T12:00:01.000Z","datacontenttype":"application/json",` +
		`"data":{"kind":"signal","lab":"lab-a","envelope_sha256":"` +
		"1111111111111111111111111111111111111111111111111111111111111111" +
		`","result":"accepted","payload":{"schema":"schild.signal/1",` +
		`"category":"sqli","note":"` + canary + `"}}}`
}
