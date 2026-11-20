// Package ftwcorpus prepares the go-ftw CRS regression subset in
// traffic/compose/ftw for a run in the test lab: it writes a copy in which
// every request carries the signed ground-truth label, so the label stripper
// records go-ftw traffic like any other generator's (an unlabelled request is
// an evaluator finding, and an unlabelled blocked request would count as a
// blocked legitimate request).
package ftwcorpus

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/deutschland-schild/schild/testlab/internal/label"
)

// NegativeRuleID is the rule id of the negative tests (tests/negative.yaml):
// the inbound anomaly score block 949110 must not fire on them.
const NegativeRuleID = 949110

// Render copies srcDir (ftw.yaml and tests/*.yaml) to dstDir and adds the
// signed label header to every stage: class benign for the negative tests,
// malicious (technique crs-<rule_id>) for every other file. It returns the
// number of labelled stages.
func Render(srcDir, dstDir string, secret []byte, scenario string) (int, error) {
	if len(secret) == 0 {
		return 0, fmt.Errorf("ftwcorpus: missing %s", label.EnvSecret)
	}
	if err := os.MkdirAll(filepath.Join(dstDir, "tests"), 0o755); err != nil {
		return 0, err
	}
	cfg, err := os.ReadFile(filepath.Join(srcDir, "ftw.yaml"))
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(dstDir, "ftw.yaml"), cfg, 0o644); err != nil {
		return 0, err
	}
	files, err := filepath.Glob(filepath.Join(srcDir, "tests", "*.yaml"))
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		return 0, fmt.Errorf("ftwcorpus: no tests in %s", srcDir)
	}
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return n, err
		}
		var doc map[string]any
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return n, fmt.Errorf("%s: %w", f, err)
		}
		rule, _ := doc["rule_id"].(int)
		if rule <= 0 {
			return n, fmt.Errorf("%s: rule_id missing", f)
		}
		l := label.Label{Class: label.Malicious, Scenario: scenario, Source: "go-ftw", Technique: "crs-" + strconv.Itoa(rule)}
		if rule == NegativeRuleID {
			l = label.Label{Class: label.Benign, Scenario: scenario, Source: "go-ftw", Technique: "crs-negative"}
		}
		l.ExpectBlock = label.ExpectedOutcome(l.Class)
		hdr, err := label.Sign(secret, l)
		if err != nil {
			return n, err
		}
		tests, _ := doc["tests"].([]any)
		for _, t := range tests {
			tm, _ := t.(map[string]any)
			stages, _ := tm["stages"].([]any)
			for _, s := range stages {
				in, _ := s.(map[string]any)["input"].(map[string]any)
				if in == nil {
					return n, fmt.Errorf("%s: stage without input", f)
				}
				h, _ := in["headers"].(map[string]any)
				if h == nil {
					h = map[string]any{}
					in["headers"] = h
				}
				h[label.HeaderName] = hdr
				n++
			}
		}
		out, err := yaml.Marshal(doc)
		if err != nil {
			return n, err
		}
		name := filepath.Base(f)
		if err := os.WriteFile(filepath.Join(dstDir, "tests", name), append([]byte("---\n# Rendered with signed labels by `traffic -ftw-render` (TEST ONLY secret); do not edit.\n"), out...), 0o644); err != nil {
			return n, err
		}
	}
	return n, nil
}

// IsNegative reports whether a corpus file holds the negative tests.
func IsNegative(path string) bool {
	return strings.TrimSuffix(filepath.Base(path), ".yaml") == "negative"
}
