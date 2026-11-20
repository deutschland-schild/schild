// Package ftwcorpus checks the go-ftw CRS regression subset in
// traffic/compose/ftw (finding: the directory held only a README, so the
// attack-ftw service ran zero tests).
package ftwcorpus

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/deutschland-schild/schild/testlab/internal/label"
)

const dir = "../../compose/ftw"

type ftwFile struct {
	RuleID int `yaml:"rule_id"`
	Tests  []struct {
		TestID int    `yaml:"test_id"`
		Desc   string `yaml:"desc"`
		Stages []struct {
			Input struct {
				Method  string            `yaml:"method"`
				URI     string            `yaml:"uri"`
				Headers map[string]string `yaml:"headers"`
			} `yaml:"input"`
			Output struct {
				Status *int `yaml:"status"`
			} `yaml:"output"`
		} `yaml:"stages"`
	} `yaml:"tests"`
}

func TestCorpusNotEmptyAndWellFormed(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(dir, "tests", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var attacks, negatives int
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var c ftwFile
		if err := yaml.Unmarshal(b, &c); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		base := strings.TrimSuffix(filepath.Base(f), ".yaml")
		// go-ftw skips a file without a rule id (0 counts as missing).
		if c.RuleID <= 0 || base != "negative" && base != strconv.Itoa(c.RuleID) {
			t.Errorf("%s: rule_id %d missing or not matching the file name", f, c.RuleID)
		}
		if len(c.Tests) == 0 {
			t.Errorf("%s: no tests", f)
		}
		for _, tc := range c.Tests {
			if tc.TestID <= 0 || tc.Desc == "" || len(tc.Stages) == 0 {
				t.Errorf("%s: test %d incomplete", f, tc.TestID)
			}
			for _, st := range tc.Stages {
				if st.Output.Status == nil {
					t.Errorf("%s/%d: no status assertion (cloud mode judges by status only)", f, tc.TestID)
					continue
				}
				if st.Input.Headers["Host"] == "" || st.Input.Method == "" || !strings.HasPrefix(st.Input.URI, "/") {
					t.Errorf("%s/%d: input needs Host, method and an absolute uri", f, tc.TestID)
				}
				switch {
				case base == "negative" && *st.Output.Status < 400:
					negatives++
				case base != "negative" && *st.Output.Status == 403:
					attacks++
				default:
					t.Errorf("%s/%d: status %d (attacks expect 403, negatives 2xx)", f, tc.TestID, *st.Output.Status)
				}
			}
		}
	}
	if attacks < 10 || negatives < 3 {
		t.Fatalf("corpus too small: %d attack stages, %d negative stages", attacks, negatives)
	}
}

func TestComposeRunsTheCorpus(t *testing.T) {
	b, err := os.ReadFile("../../compose/docker-compose.traffic.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Services map[string]struct {
			Image   string   `yaml:"image"`
			Command []string `yaml:"command"`
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	s := c.Services["attack-ftw"]
	cmd := strings.Join(s.Command, " ")
	if !strings.Contains(cmd, "--dir /corpus/tests") || !strings.Contains(cmd, "--config /corpus/ftw.yaml") || !strings.Contains(cmd, "--cloud") {
		t.Errorf("attack-ftw command %q: want the corpus dir, the config and cloud mode", cmd)
	}
	// Not /ftw: that path is the go-ftw binary inside the image.
	if len(s.Volumes) != 1 || !strings.HasPrefix(s.Volumes[0], "${FTW_CORPUS:-../traffic/compose/ftw}:/corpus") {
		t.Errorf("attack-ftw volumes %v", s.Volumes)
	}
	if !strings.Contains(s.Image, "@sha256:") {
		t.Errorf("attack-ftw image %q is not pinned by digest", s.Image)
	}
	var cfg struct {
		TestOverride struct {
			Input struct {
				DestAddr string `yaml:"dest_addr"`
				Port     int    `yaml:"port"`
			} `yaml:"input"`
		} `yaml:"testoverride"`
	}
	cb, err := os.ReadFile(filepath.Join(dir, "ftw.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(cb, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.TestOverride.Input.DestAddr != "stripper-shop" || cfg.TestOverride.Input.Port != 8080 {
		t.Errorf("ftw.yaml must target the lab's own stripper-shop:8080, got %+v", cfg.TestOverride.Input)
	}
}

// The rendered copy labels every stage (benign for the negatives, malicious
// for attacks) with a label the stripper accepts.
func TestRenderLabelsEveryStage(t *testing.T) {
	secret := []byte("test-secret")
	dst := t.TempDir()
	n, err := Render(dir, dst, secret, "T03")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dst, "tests", "*.yaml"))
	stages := 0
	for _, f := range files {
		b, _ := os.ReadFile(f)
		var c ftwFile
		if err := yaml.Unmarshal(b, &c); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, tc := range c.Tests {
			for _, st := range tc.Stages {
				stages++
				l, err := label.Parse(secret, st.Input.Headers[label.HeaderName])
				if err != nil {
					t.Fatalf("%s/%d: label: %v", f, tc.TestID, err)
				}
				want := label.Malicious
				if IsNegative(f) {
					want = label.Benign
				}
				if l.Class != want || l.Source != "go-ftw" || l.ExpectBlock != (want == label.Malicious) {
					t.Errorf("%s/%d: label %+v", f, tc.TestID, l)
				}
			}
		}
	}
	if stages == 0 || stages != n {
		t.Fatalf("labelled %d stages, found %d", n, stages)
	}
	if _, err := os.Stat(filepath.Join(dst, "ftw.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := Render(dir, t.TempDir(), nil, "T03"); err == nil {
		t.Fatal("rendered without a secret")
	}
}
