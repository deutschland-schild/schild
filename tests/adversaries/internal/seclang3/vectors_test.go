package seclang3

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The independent checker runs over every rule the contract calls valid (D40,
// decision 6): it runs here, not in the client, because a false alarm should
// cost a look by a person, not a lost bundle. This test is what make test,
// the CI gate of this repository, runs.
func TestContractValidRulesPassSeclang3(t *testing.T) {
	files, err := filepath.Glob("../../../../contracts/vectors/seclang/valid/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("vectors: %v (%d)", err, len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			InputRaw string `json:"input_raw"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		if fs := Check(v.InputRaw); len(fs) > 0 {
			t.Errorf("%s: %v", filepath.Base(f), fs)
		}
	}
}
