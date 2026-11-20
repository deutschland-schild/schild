// Command seclang-fuzzer generates SecLang rule texts from a grammar of the
// allowed subset plus forbidden constructs, runs each through the reference
// validator (contract/seclang) and the independent third checker
// (internal/seclang3), and reports every rule that is forbidden by the
// independent checker but accepted by the reference. Such a rule is a
// validator bypass: a network rule that could disable protection, exfiltrate
// data or target one site would reach clients (M4, SEC-01, K7).
//
// It is deterministic: seed and index reproduce every rule. Output is a JSON
// summary plus, with -v, one line per generated rule.
//
//	go run ./cmd/seclang-fuzzer -seed 42 -n 200000 -out report.json
//
// Exit status is non-zero if any bypass is found.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/deutschland-schild/schild/adversaries/internal/grammar"
	"github.com/deutschland-schild/schild/adversaries/internal/seclang3"
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/seclang"
)

type bypass struct {
	Index     int    `json:"index"`
	Seed      uint64 `json:"seed"`
	Text      string `json:"text"`
	MaxAction string `json:"max_action"`
	Forbidden string `json:"forbidden_class"`
	Detail    string `json:"detail"`
}

type report struct {
	Seed       uint64   `json:"seed"`
	N          int      `json:"n"`
	Accepted   int      `json:"accepted"`
	Rejected   int      `json:"rejected"`
	Flagged    int      `json:"flagged_by_seclang3"`
	Bypasses   []bypass `json:"bypasses"`
	NBypasses  int      `json:"n_bypasses"`
	MissedByS3 int      `json:"rejected_but_not_flagged"` // informational: reference stricter than seclang3
}

func main() {
	seed := flag.Uint64("seed", 42, "deterministic seed")
	n := flag.Int("n", 200000, "number of rules to generate")
	out := flag.String("out", "", "write the JSON report to this file")
	verbose := flag.Bool("v", false, "print one line per rule")
	flag.Parse()

	g := grammar.New(*seed)
	rep := report{Seed: *seed, N: *n}
	for i := 0; i < *n; i++ {
		rule := g.Next()
		_, err := seclang.Validate(rule.Text, seclang.Options{MaxAction: rule.MaxAction})
		accepted := err == nil
		findings := seclang3.Check(rule.Text)
		if accepted {
			rep.Accepted++
		} else {
			rep.Rejected++
			if len(findings) == 0 {
				rep.MissedByS3++
			}
		}
		if len(findings) > 0 {
			rep.Flagged++
			if accepted {
				// seclang3 says forbidden, reference accepted: a real bypass.
				rep.Bypasses = append(rep.Bypasses, bypass{
					Index: i, Seed: *seed, Text: rule.Text, MaxAction: rule.MaxAction,
					Forbidden: findings[0].Class, Detail: findings[0].Detail,
				})
			}
		}
		if *verbose {
			code := "valid"
			if err != nil {
				code = string(contract.CodeOf(err))
			}
			fmt.Printf("%d\t%s\t%s\t%q\n", i, code, s3classes(findings), rule.Text)
		}
	}
	rep.NBypasses = len(rep.Bypasses)

	b, _ := json.MarshalIndent(rep, "", "  ")
	if *out != "" {
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	fmt.Printf("seclang-fuzzer: seed=%d n=%d accepted=%d rejected=%d flagged=%d bypasses=%d\n",
		*seed, *n, rep.Accepted, rep.Rejected, rep.Flagged, rep.NBypasses)
	if rep.NBypasses > 0 {
		for _, bp := range rep.Bypasses {
			fmt.Fprintf(os.Stderr, "BYPASS i=%d class=%s %s: %q\n", bp.Index, bp.Forbidden, bp.Detail, bp.Text)
		}
		os.Exit(1)
	}
}

func s3classes(fs []seclang3.Finding) string {
	if len(fs) == 0 {
		return "-"
	}
	return fs[0].Class
}
