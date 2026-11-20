// Command adversary is the MVP-07 red-team scenario runner. It runs one or
// all of the scenarios (T06, T07, T08, T10, T11, T24, K6) against the real
// acceptance code of the schild network and writes a measurement result per
// contracts/results.schema.json.
//
//	make adversary SCENARIO=T08              # one scenario
//	make adversary SCENARIO=all              # every scenario, aggregated
//
// The run is deterministic (fixed base clock and seed). A scenario is a pass
// only if the honest side accepted zero adversarial artifacts; the MVP-07
// kill criterion is that any harm measure is greater than zero. Humans decide
// what a hit means.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/adversaries/internal/scenario"
	"github.com/deutschland-schild/schild/contract/results"
)

func main() {
	scn := flag.String("scenario", "all", "scenario id (T06|T07|T08|T10|T11|T24|K6) or all")
	profile := flag.String("profile", "t1", "profile recorded in the result (t0|t1|live|unit)")
	seed := flag.Uint64("seed", 42, "seed recorded in the result")
	outDir := flag.String("out", "results", "directory for the result JSON")
	images := flag.String("images", "", "comma-separated name=sha256:... image digests")
	flag.Parse()

	ids := scenario.All
	if s := strings.ToUpper(*scn); s != "ALL" {
		ids = []string{s}
	}

	start := time.Now().UTC()
	var (
		metrics    []results.Metric
		kills      []results.KillCriteria
		scenSet    = map[string]bool{}
		hypSet     = map[string]bool{}
		totalAcc   int
		totalTries int
		lines      []string
		verdict    = "pass"
	)
	for _, id := range ids {
		o, err := scenario.Run(id)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, s := range o.Scenarios {
			scenSet[s] = true
		}
		for _, h := range o.Hypotheses {
			hypSet[h] = true
		}
		for k, v := range o.Metrics {
			metrics = append(metrics, results.Metric{Name: k, Value: v, Unit: unitFor(k), Labels: map[string]string{"scenario": id}})
		}
		metrics = append(metrics, results.Metric{Name: "attempts", Value: float64(o.Attempts), Unit: "count", Labels: map[string]string{"scenario": id}})
		metrics = append(metrics, results.Metric{Name: "accepted", Value: float64(o.Accepted), Unit: "count", Labels: map[string]string{"scenario": id}})
		hit := o.Accepted > 0
		if hit {
			verdict = "fail"
		}
		kills = append(kills, results.KillCriteria{
			Expr:     id + ": " + o.KillExpr,
			Hit:      hit,
			Observed: o.KillObserved,
		})
		totalAcc += o.Accepted
		totalTries += o.Attempts
		lines = append(lines, fmt.Sprintf("== %s (%s) attempts=%d accepted=%d", id, strings.Join(o.Hypotheses, ","), o.Attempts, o.Accepted))
		for _, d := range o.Detail {
			lines = append(lines, "   - "+d)
		}
	}

	res := &results.Result{
		ResultsVersion: 0,
		Spec:           "MVP-07",
		RunID:          runID(*scn, start),
		StartedAt:      formatTS(start),
		FinishedAt:     formatTS(time.Now().UTC()),
		Seed:           *seed,
		Profile:        *profile,
		Images:         parseImages(*images),
		Scenarios:      sortedKeys(scenSet),
		Hypotheses:     sortedKeys(hypSet),
		Metrics:        metrics,
		KillCriteria:   kills,
		Verdict:        verdict,
		Notes:          notes(totalTries, totalAcc, lines),
	}

	name := "MVP-07.json"
	if len(ids) == 1 {
		name = "MVP-07-" + ids[0] + ".json"
	}
	b, err := res.Marshal()
	if err != nil {
		fmt.Fprintln(os.Stderr, "result:", err)
		os.Exit(2)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "result:", err)
		os.Exit(2)
	}
	path := filepath.Join(*outDir, name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "result:", err)
		os.Exit(2)
	}
	fmt.Printf("adversary: scenario=%s profile=%s attempts=%d accepted=%d verdict=%s -> %s\n",
		*scn, *profile, totalTries, totalAcc, verdict, path)
	if verdict != "pass" {
		os.Exit(1)
	}
}

func unitFor(name string) string {
	switch {
	case strings.HasSuffix(name, "_s"):
		return "s"
	case name == "freeze_detected":
		return "bool"
	default:
		return "count"
	}
}

func runID(scn string, t time.Time) string {
	return "adv-" + strings.ToLower(scn) + "-" + t.Format("20060102T150405Z")
}

func formatTS(t time.Time) string { return t.Truncate(time.Second).Format("2006-01-02T15:04:05Z") }

func parseImages(s string) []results.Image {
	var out []results.Image
	for _, it := range strings.Split(s, ",") {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		name, digest, ok := strings.Cut(it, "=")
		if ok {
			out = append(out, results.Image{Name: name, Digest: digest})
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	// small sets; simple insertion sort keeps it dependency-free and stable
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func notes(tries, acc int, lines []string) string {
	head := fmt.Sprintf("MVP-07 red team, in-process against the real acceptance code (contract/verify, contract/seclang, contract/stream, contract/peerauth). Total adversarial attempts=%d, accepted by the honest side=%d.\n", tries, acc)
	body := head + strings.Join(lines, "\n")
	if len(body) > 8000 {
		body = body[:8000] + "\n...(truncated)"
	}
	return body
}
