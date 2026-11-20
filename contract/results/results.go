// Package results writes measurement results in the common format of
// contracts/results.schema.json to results/<spec>.json.
package results

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/verify"
)

// Result is one measurement run.
type Result struct {
	ResultsVersion int            `json:"results_version"`
	Spec           string         `json:"spec"`
	RunID          string         `json:"run_id"`
	StartedAt      string         `json:"started_at"`
	FinishedAt     string         `json:"finished_at"`
	Seed           uint64         `json:"seed"`
	Profile        string         `json:"profile"` // t0 | t1 | live | unit
	GitRev         string         `json:"git_rev,omitempty"`
	Host           *Host          `json:"host,omitempty"`
	Images         []Image        `json:"images"`
	Scenarios      []string       `json:"scenarios,omitempty"`
	Hypotheses     []string       `json:"hypotheses,omitempty"`
	Metrics        []Metric       `json:"metrics"`
	KillCriteria   []KillCriteria `json:"kill_criteria"`
	Verdict        string         `json:"verdict"` // pass | fail | inconclusive | error
	Notes          string         `json:"notes,omitempty"`
	Artifacts      []string       `json:"artifacts,omitempty"`
}

// Host describes the machine of the run.
type Host struct {
	OS    string `json:"os,omitempty"`
	Arch  string `json:"arch,omitempty"`
	CPUs  int    `json:"cpus,omitempty"`
	MemMB int    `json:"mem_mb,omitempty"`
}

// Image is a pinned image.
type Image struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// Metric is one measured value.
type Metric struct {
	Name    string            `json:"name"`
	Value   float64           `json:"value"`
	Unit    string            `json:"unit"`
	Labels  map[string]string `json:"labels,omitempty"`
	Samples int               `json:"samples,omitempty"`
}

// KillCriteria records whether a kill criterion was hit. Humans decide what follows.
type KillCriteria struct {
	Expr     string `json:"expr"`
	Hit      bool   `json:"hit"`
	Observed string `json:"observed,omitempty"`
}

// Marshal validates and renders the result.
func (r *Result) Marshal() ([]byte, error) {
	if r.Images == nil {
		r.Images = []Image{}
	}
	if r.Metrics == nil {
		r.Metrics = []Metric{}
	}
	if r.KillCriteria == nil {
		r.KillCriteria = []KillCriteria{}
	}
	b, err := jsonx.Marshal(r)
	if err != nil {
		return nil, err
	}
	if _, err := verify.Document(verify.DocResults, b, &verify.Context{}); err != nil {
		return nil, err
	}
	return b, nil
}

// Write validates r and writes <dir>/<spec>.json.
func (r *Result) Write(dir string) (string, error) {
	b, err := r.Marshal()
	if err != nil {
		return "", fmt.Errorf("results: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, r.Spec+".json")
	return p, os.WriteFile(p, append(b, '\n'), 0o644)
}
