package schema

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
)

func TestCompileAll(t *testing.T) {
	if err := Check(); err != nil {
		t.Fatal(err)
	}
	want := []string{Ack, ConfigLab, ConfigSite, Checkpoint, commonName, Envelope, Events, Feedback, Results, RuleBundle, Signal, Stream, Submission, Withdrawal}
	got := strings.Join(Names(), ",")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("schema %s missing (have %s)", w, got)
		}
	}
}

// The embedded copies must equal contracts (run make contracts-sync).
func TestEmbeddedInSync(t *testing.T) {
	root := "../../contracts"
	if _, err := os.Stat(root); os.IsNotExist(err) {
		t.Skip("contracts/ not present")
	}
	seen := map[string]bool{}
	for rel, b := range Files() {
		seen[rel] = true
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("%s: %v (run make contracts-sync)", rel, err)
			continue
		}
		if !bytes.Equal(src, b) {
			t.Errorf("%s differs from contracts/ (run make contracts-sync)", rel)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(root, "*.schema.json"))
	more, _ := filepath.Glob(filepath.Join(root, "config", "*.schema.json"))
	for _, m := range append(matches, more...) {
		rel, _ := filepath.Rel(root, m)
		if !seen[filepath.ToSlash(rel)] {
			t.Errorf("%s not embedded (run make contracts-sync)", rel)
		}
	}
}

// Patterns must stay inside the portable regex subset (ECMA-262 and RE2 and
// Python re agree): no \d \w \s, no lookaround, no backreferences.
func TestPortablePatterns(t *testing.T) {
	bad := regexp.MustCompile(`\\\\[dDwWsSbBpPQEzZ1-9k]|\(\?[=!<>]`)
	for rel, b := range Files() {
		v, err := jsonx.Parse(b)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		walkPatterns(v, func(p string) {
			if bad.MatchString(strings.ReplaceAll(p, `\`, `\\`)) {
				t.Errorf("%s: non-portable pattern %q", rel, p)
			}
		})
	}
}

func walkPatterns(v any, f func(string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if k == "pattern" {
				if s, ok := x.(string); ok {
					f(s)
				}
			}
			walkPatterns(x, f)
		}
	case []any:
		for _, x := range t {
			walkPatterns(x, f)
		}
	}
}

func TestValidateCodes(t *testing.T) {
	v, _ := jsonx.Parse([]byte(`{"payloadType":"x","payload":"","signatures":[]}`))
	err := Validate(Envelope, v)
	if contract.CodeOf(err) != contract.CodeSchema {
		t.Fatalf("want schema error, got %v", err)
	}
	if err := Validate("nope", v); err == nil || contract.CodeOf(err) != "" {
		t.Fatalf("unknown schema: %v", err)
	}
}
