package main

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sort"
	"time"

	"github.com/deutschland-schild/schild/contract/results"
	"github.com/deutschland-schild/schild/testlab/internal/label"
	"github.com/deutschland-schild/schild/testlab/traffic/internal/plan"
)

// emitResults builds the plan twice for the same seed and writes a
// results/<spec>.json whose single kill criterion is the MVP-06 one: two runs
// with the same seed must produce the same labelled request counts.
func emitResults(spec, outDir, scenario string, seed int64, profile string, sites []string, opt plan.Options) int {
	a, err := plan.Build(scenario, seed, sites, opt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "traffic: %v\n", err)
		return 1
	}
	b, _ := plan.Build(scenario, seed, sites, opt)
	differ := !reflect.DeepEqual(a.Counts(), b.Counts())

	ca, cb := a.Counts(), b.Counts()
	now := time.Now().UTC()
	res := &results.Result{
		ResultsVersion: 0, Spec: spec,
		RunID:     fmt.Sprintf("%s-%s-%d", spec, scenario, now.Unix()),
		StartedAt: now.Format(time.RFC3339), FinishedAt: now.Format(time.RFC3339),
		Seed: uint64(seed), Profile: profile,
		Host:      &results.Host{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU()},
		Scenarios: []string{scenario},
		Metrics:   countMetrics(ca),
		KillCriteria: []results.KillCriteria{{
			Expr:     "two runs with the same seed differ in labelled request counts",
			Hit:      differ,
			Observed: fmt.Sprintf("run1=%v run2=%v", ca, cb),
		}},
	}
	res.Metrics = append(res.Metrics, results.Metric{Name: "requests_total", Value: float64(len(a.Requests)), Unit: "count"})
	if differ {
		res.Verdict = "fail"
	} else {
		res.Verdict = "pass"
	}
	path, err := res.Write(outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "traffic: write result: %v\n", err)
		return 1
	}
	fmt.Printf("traffic: wrote %s verdict=%s counts=%s\n", path, res.Verdict, a.CountsString())
	if differ {
		return 1
	}
	return 0
}

func countMetrics(c map[label.Class]int) []results.Metric {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	var m []results.Metric
	for _, k := range keys {
		m = append(m, results.Metric{
			Name: "labelled_requests", Value: float64(c[label.Class(k)]),
			Unit: "count", Labels: map[string]string{"class": k},
		})
	}
	return m
}
