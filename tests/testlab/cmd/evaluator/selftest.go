package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/deutschland-schild/schild/contract/results"
	"github.com/deutschland-schild/schild/testlab/internal/eval"
)

// emitSynthetic evaluates a clean synthetic run and writes results/<spec>.json.
// It lets `make eval SPEC=MVP-05` produce a valid, reproducible artifact
// without a live stack; a real run passes -events/-ground-truth instead.
func emitSynthetic(spec, outDir, profile string, seed uint64) int {
	rep := eval.BuildSynthetic(int64(seed), 60, eval.FaultNone).Report()
	now := time.Now().UTC()
	res := rep.ToResult(spec, fmt.Sprintf("%s-synthetic-%d", spec, now.Unix()),
		now.Format(time.RFC3339), now.Format(time.RFC3339), seed, profile)
	res.Host = &results.Host{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU()}
	res.Notes += "; synthetic clean run (no live stack)"
	path, err := res.Write(outDir)
	if err != nil {
		fmt.Printf("emit-synthetic: FAIL %v\n", err)
		return 1
	}
	fmt.Printf("evaluator: wrote %s verdict=%s (synthetic clean run)\n", path, res.Verdict)
	return 0
}

// runSelftest runs the planted-fault self-test. It returns a non-zero exit
// code if the clean run hits a kill criterion or if any planted fault is
// missed. This is the MVP-05 kill criterion ("evaluator misses a planted
// fault").
func runSelftest() int {
	const seed, n = 42, 60
	fail := 0

	// Clean run: nothing must be flagged.
	clean := eval.BuildSynthetic(seed, n, eval.FaultNone).Report()
	res := clean.ToResult("MVP-05", "selftest-clean", "2026-10-26T12:00:00Z", "2026-10-26T12:00:01Z", seed, "unit")
	if res.Verdict != "pass" {
		fmt.Printf("SELFTEST clean: FAIL verdict=%s (expected pass)\n", res.Verdict)
		fail++
	} else {
		fmt.Println("SELFTEST clean: OK (no kill criterion hit)")
	}

	// Each planted fault must be detected.
	checks := []struct {
		fault eval.Fault
		ok    func(eval.Report) bool
		what  string
	}{
		{eval.FaultBypass, func(r eval.Report) bool { return r.BypassCount > 0 }, "bypass detected"},
		{eval.FaultFalseBlock, func(r eval.Report) bool { return r.LegitBlocks > 0 }, "false block detected"},
		{eval.FaultCanaryLeak, func(r eval.Report) bool { return r.CanaryFindings > 0 }, "canary leak detected"},
		{eval.FaultUnlabelled, func(r eval.Report) bool { return r.Unlabelled > 0 }, "unlabelled request detected"},
	}
	for _, c := range checks {
		rep := eval.BuildSynthetic(seed, n, c.fault).Report()
		if !c.ok(rep) {
			fmt.Printf("SELFTEST %s: FAIL (%s NOT observed)\n", c.fault, c.what)
			fail++
			continue
		}
		r := rep.ToResult("MVP-05", "selftest-"+string(c.fault), "2026-10-26T12:00:00Z", "2026-10-26T12:00:01Z", seed, "unit")
		if r.Verdict == "pass" {
			fmt.Printf("SELFTEST %s: FAIL (verdict pass despite planted fault)\n", c.fault)
			fail++
			continue
		}
		fmt.Printf("SELFTEST %s: OK (%s, verdict=%s)\n", c.fault, c.what, r.Verdict)
	}

	if fail > 0 {
		fmt.Printf("SELFTEST: %d check(s) failed\n", fail)
		return 1
	}
	fmt.Println("SELFTEST: OK (clean run clean; every planted fault detected)")
	return 0
}
