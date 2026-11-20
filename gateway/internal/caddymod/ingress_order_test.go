package caddymod

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/ingress"
)

// TestIngressOrderVectorsAdapt: the `servers` of every valid ingress-order
// vector (contracts/ingress-order.md) is what the embedded Caddy's stock
// Caddyfile adapter makes of the vector's `caddyfile`, so the contract rule
// reads the same JSON the gateway's validator reads. file_server hides the
// adapted Caddyfile itself; that path differs between the contracts agent's
// run and this test, so hide entries ending in .caddy or naming the test's
// file are dropped on both sides. CheckConfig reports the vector's expected
// findings as ingress.Message errors.
func TestIngressOrderVectorsAdapt(t *testing.T) {
	files, err := filepath.Glob("../../../contracts/vectors/ingress-order/valid/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("vectors: %d files, %v", len(files), err)
	}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var vec struct {
				InputRaw string `json:"input_raw"`
				Expect   struct {
					Result ingress.Result `json:"result"`
				} `json:"expect"`
			}
			if err := json.Unmarshal(b, &vec); err != nil {
				t.Fatal(err)
			}
			var in struct {
				Caddyfile *string `json:"caddyfile"`
				Servers   any     `json:"servers"`
			}
			if err := json.Unmarshal([]byte(vec.InputRaw), &in); err != nil {
				t.Fatal(err)
			}
			if in.Caddyfile == nil {
				t.Skip("vector without caddyfile")
			}
			p := writeFile(t, t.TempDir(), "Caddyfile", *in.Caddyfile)
			raw, _, err := ReadCaddyfile(p)
			if err != nil {
				t.Fatal(err)
			}
			var cfg struct {
				Apps struct {
					HTTP struct {
						Servers any `json:"servers"`
					} `json:"http"`
				} `json:"apps"`
			}
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			got, want := dropHiddenCaddyfile(cfg.Apps.HTTP.Servers, p), dropHiddenCaddyfile(in.Servers, p)
			if m, _ := want.(map[string]any); len(m) == 0 {
				t.Fatal("vector without servers")
			}
			if !reflect.DeepEqual(got, want) {
				g, _ := json.Marshal(got)
				w, _ := json.Marshal(want)
				t.Fatalf("adapted servers differ\n got %s\nwant %s", g, w)
			}
			// The validator reports each expected finding as its message.
			c, err := CheckConfig(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, fd := range vec.Expect.Result.Findings {
				if !slices.Contains(c.Errors, ingress.Message(fd)) {
					t.Fatalf("missing %q in %v", ingress.Message(fd), c.Errors)
				}
			}
			n := 0
			for _, e := range c.Errors {
				if strings.HasPrefix(e, ingress.CodeRewriteBeforeSchild+": ") || strings.HasPrefix(e, ingress.CodeHeaderHiddenFromSchild+": ") {
					n++
				}
			}
			if n != len(vec.Expect.Result.Findings) {
				t.Fatalf("%d order errors, want %d: %v", n, len(vec.Expect.Result.Findings), c.Errors)
			}
		})
	}
}

// dropHiddenCaddyfile removes the Caddyfile path the adapter adds to
// file_server's hide list (an empty list goes with it).
func dropHiddenCaddyfile(v any, path string) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, c := range t {
			if hide, ok := c.([]any); ok && k == "hide" && t["handler"] == "file_server" {
				kept := []any{}
				for _, h := range hide {
					if s, _ := h.(string); s == path || strings.HasSuffix(s, ".caddy") {
						continue
					}
					kept = append(kept, h)
				}
				if len(kept) > 0 {
					out[k] = kept
				}
				continue
			}
			out[k] = dropHiddenCaddyfile(c, path)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, c := range t {
			out[i] = dropHiddenCaddyfile(c, path)
		}
		return out
	}
	return v
}
