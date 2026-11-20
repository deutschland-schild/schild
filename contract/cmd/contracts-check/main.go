// Command contracts-check runs every golden vector with the Go reference
// implementation, prints mismatches against the expected verdicts and writes
// the verdicts as JSON (for the Go/Python comparison).
//
//	go run ./cmd/contracts-check -contracts ../contracts -out ../contracts/.check/go.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

import "github.com/deutschland-schild/schild/contract/vectors"

func main() {
	dir := flag.String("contracts", "../contracts", "contracts directory")
	out := flag.String("out", "", "write verdicts JSON here")
	flag.Parse()
	r, err := vectors.NewRunner(filepath.Join(*dir, "testkeys", "keys.json"))
	if err != nil {
		fail(err)
	}
	verdicts, vecs, err := r.RunAll(filepath.Join(*dir, "vectors"))
	if err != nil {
		fail(err)
	}
	bad := 0
	for i, v := range verdicts {
		if !v.Matches(vecs[i].Expect) {
			bad++
			fmt.Printf("MISMATCH %s: expected valid=%v error=%q result=%s, got valid=%v error=%q result=%s (%s)\n",
				v.File, vecs[i].Expect.Valid, vecs[i].Expect.Error, vecs[i].Expect.Result, v.Valid, v.Error, v.Result, v.Detail)
		}
	}
	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			fail(err)
		}
		type row struct {
			File   string          `json:"file"`
			Valid  bool            `json:"valid"`
			Error  string          `json:"error"`
			Result json.RawMessage `json:"result,omitempty"` // v0.5: bot-match, geo-map
		}
		rows := make([]row, len(verdicts))
		for i, v := range verdicts {
			rows[i] = row{v.File, v.Valid, v.Error, v.Result}
		}
		b, _ := json.MarshalIndent(rows, "", "  ")
		if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
			fail(err)
		}
	}
	fmt.Printf("go: %d vectors, %d mismatches against expectations\n", len(verdicts), bad)
	if bad > 0 {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "contracts-check:", err)
	os.Exit(2)
}
