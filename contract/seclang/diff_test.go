package seclang

import (
	"encoding/json"
	"os"
	"testing"
)

// TestDifferential compares this validator with the Python cross-check on a
// generated corpus (make contracts-fuzz). Skipped unless SCHILD_SECLANG_DIFF
// names the corpus file written by contracts/tools/seclang_fuzz.py.
func TestDifferential(t *testing.T) {
	path := os.Getenv("SCHILD_SECLANG_DIFF")
	if path == "" {
		t.Skip("SCHILD_SECLANG_DIFF not set (run make contracts-fuzz)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var in []struct {
		Text      string `json:"text"`
		MaxAction string `json:"max_action"`
		Py        string `json:"py"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range in {
		got := "valid"
		if _, err := Validate(c.Text, Options{MaxAction: c.MaxAction}); err != nil {
			got = "seclang"
		}
		if got != c.Py {
			n++
			if n <= 20 {
				t.Errorf("go=%s python=%s: %q", got, c.Py, c.Text)
			}
		}
	}
	t.Logf("%d disagreements in %d rules", n, len(in))
}
