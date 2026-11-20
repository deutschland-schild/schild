// Command evaluator joins schild client events with the test-lab ground truth
// and writes results/<spec>.json per contracts/results.schema.json. It also
// hosts the planted-fault self-test (--selftest), which is the MVP-05 kill
// criterion: the evaluator must detect every injected fault.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/results"
	"github.com/deutschland-schild/schild/testlab/internal/egress"
	"github.com/deutschland-schild/schild/testlab/internal/eval"
	"github.com/deutschland-schild/schild/testlab/internal/groundtruth"
)

func main() {
	var (
		selftest   = flag.Bool("selftest", false, "run the planted-fault self-test and exit")
		synthetic  = flag.Bool("synthetic", false, "evaluate a clean synthetic run and write results/<spec>.json (no live stack needed)")
		gtPath     = flag.String("ground-truth", "/var/lib/testlab/ground-truth.sqlite", "ground-truth SQLite path")
		eventsPath = flag.String("events", "", "NDJSON of schild client events (with schild); comma-separated for several sites")
		basePath   = flag.String("baseline", "", "NDJSON of events without schild (optional)")
		signalPath = flag.String("signals", "", "NDJSON transparency log for the egress check (optional; comma-separated for several sites)")
		canaryList = flag.String("canaries", "", "comma-separated canary values to scan for")
		forbidIP   = flag.String("forbidden-ips", "", "comma-separated source IPs that must never leave")
		spec       = flag.String("spec", "MVP-05", "spec id for results/<spec>.json")
		profile    = flag.String("profile", "t0", "t0|t1|live|unit")
		seed       = flag.Uint64("seed", 42, "run seed")
		runID      = flag.String("run-id", "", "run id (default: spec-<unix>)")
		outDir     = flag.String("out", "/results", "results directory")
		imagesCSV  = flag.String("images", "", "comma-separated name@sha256:... image pins")
	)
	flag.Parse()

	if *selftest {
		os.Exit(runSelftest())
	}

	if *synthetic {
		os.Exit(emitSynthetic(*spec, *outDir, *profile, *seed))
	}

	if *eventsPath == "" {
		fmt.Fprintln(os.Stderr, "evaluator: -events is required (or use -selftest)")
		os.Exit(2)
	}

	store, err := groundtruth.Open(*gtPath)
	if err != nil {
		fatal("open ground truth: %v", err)
	}
	defer store.Close()
	truth, err := store.All()
	if err != nil {
		fatal("read ground truth: %v", err)
	}

	events, err := parseEventsFile(*eventsPath)
	if err != nil {
		fatal("parse events: %v", err)
	}
	in := eval.Inputs{Truth: truth, Events: events}
	if *basePath != "" {
		base, err := parseEventsFile(*basePath)
		if err != nil {
			fatal("parse baseline: %v", err)
		}
		in.Baseline = base
	}
	if *signalPath != "" {
		rep, err := checkEgress(*signalPath, split(*canaryList), split(*forbidIP))
		if err != nil {
			fatal("egress check: %v", err)
		}
		in.Egress = rep
	}

	rep := eval.Evaluate(in)
	now := time.Now().UTC()
	rid := *runID
	if rid == "" {
		rid = fmt.Sprintf("%s-%d", *spec, now.Unix())
	}
	res := rep.ToResult(*spec, rid, now.Format(time.RFC3339), now.Format(time.RFC3339), *seed, *profile)
	res.Host = &results.Host{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU()}
	res.Images = parseImages(*imagesCSV)
	if in.Egress != nil && !in.Egress.OK() {
		res.Notes += fmt.Sprintf("; egress findings: %d", len(in.Egress.Findings))
	}

	path, err := res.Write(*outDir)
	if err != nil {
		fatal("write result: %v", err)
	}
	fmt.Printf("evaluator: wrote %s verdict=%s bypass=%d legit_blocks=%d canary=%d unlabelled=%d\n",
		path, res.Verdict, rep.BypassCount, rep.LegitBlocks, rep.CanaryFindings, rep.Unlabelled)
	if res.Verdict == "fail" || res.Verdict == "error" {
		os.Exit(1)
	}
}

// parseEventsFile reads one or several (comma-separated) NDJSON event files.
func parseEventsFile(paths string) (map[string]eval.EventRecord, error) {
	out := map[string]eval.EventRecord{}
	for _, path := range split(paths) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		evs, err := eval.ParseEvents(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		for id, ev := range evs {
			out[id] = ev
		}
	}
	return out, nil
}

// checkEgress scans one or several (comma-separated) transparency logs.
func checkEgress(paths string, canaries, ips []string) (*egress.Report, error) {
	var readers []io.Reader
	for _, path := range split(paths) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		readers = append(readers, f, strings.NewReader("\n"))
	}
	ck := egress.New(canaries, ips)
	rep, err := ck.CheckLog(io.MultiReader(readers...))
	return &rep, err
}

func parseImages(csv string) []results.Image {
	var out []results.Image
	for _, s := range split(csv) {
		at := strings.LastIndex(s, "@")
		if at <= 0 {
			continue
		}
		out = append(out, results.Image{Name: s[:at], Digest: s[at+1:]})
	}
	return out
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "evaluator: "+format+"\n", a...)
	os.Exit(1)
}
