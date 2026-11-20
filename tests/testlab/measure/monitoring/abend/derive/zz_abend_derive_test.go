//go:build d36measure

// D36 evening re-measurement (TEST ONLY, copy of d36n/scratch/zz_d36_derive_test.go
// plus "expect_drop": block indices the gateway must drop as broken (D36 fix
// round 2, sites.deriveWithoutBroken); then the expected websites are
// websites.Derive of the remaining blocks and the gateway must report an error).
// Original header:
// D36 measurement (TEST ONLY): the gateway's website derivation for real
// Caddyfiles, run in a scratch copy of client/internal/app (never in the
// product tree):
//
//	cp zz_d36_derive_test.go <scratch>/gateway/internal/app/
//	cd <scratch>/gateway && D36_CASES=<dir> D36_OUT=<file> \
//	  go test -tags d36measure -run TestAbendDerive ./internal/app/
//
// Every case directory holds a Caddyfile and case.json
// {"unprotected_sites": [...], "resolve": [...], "blocks": [...]}, where
// blocks is the measurer's own reading of the Caddyfile (addresses, schild,
// proxies; input of contract/websites.Derive). The test writes, per case,
// what the gateway derives (the same calls as App.websitesView: PrepareIngress,
// caddymod.SiteBlocks, sites.NewView), how it resolves the listed hosts, and
// what contract/websites.Derive gives for the measurer's blocks.
package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/caddymod"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

type abCase struct {
	UnprotectedSites []string         `json:"unprotected_sites"`
	Resolve          []string         `json:"resolve"`
	Blocks           []websites.Block `json:"blocks"`
	ExpectDrop       []int            `json:"expect_drop"`
}

type abOut struct {
	Case            string               `json:"case"`
	PrepareErr      string               `json:"prepare_err,omitempty"`
	SiteChecks      []caddymod.SiteCheck `json:"site_checks,omitempty"`
	GatewayBlocks   []websites.Block     `json:"gateway_blocks"`
	GatewayErr      string               `json:"gateway_err,omitempty"`
	Gateway         []websites.Website   `json:"gateway_websites"`
	GatewayResolve  []string             `json:"gateway_resolve,omitempty"`
	Expected        []websites.Website   `json:"expected_websites"`
	ExpectedErr     string               `json:"expected_err,omitempty"`
	ExpectedResolve []string             `json:"expected_resolve,omitempty"`
	Match           bool                 `json:"match"`
}

func TestAbendDerive(t *testing.T) {
	dir := os.Getenv("D36_CASES")
	if dir == "" {
		t.Skip("D36_CASES not set")
	}
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var outs []abOut
	for _, n := range names {
		cd := filepath.Join(dir, n)
		var c abCase
		raw, err := os.ReadFile(filepath.Join(cd, "case.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(n, err)
		}
		o := abOut{Case: n}
		cf := filepath.Join(cd, "Caddyfile")
		ing, err := caddymod.PrepareIngress(caddymod.IngressOptions{Caddyfile: cf, Storage: t.TempDir(), Unprotected: c.UnprotectedSites})
		if err != nil {
			o.PrepareErr = err.Error()
		}
		in := websites.Input{Mode: websites.ModeIngress, UnprotectedSites: c.UnprotectedSites}
		if ing != nil {
			o.SiteChecks = ing.Check.Sites
			in.Blocks, err = caddymod.SiteBlocks(cf, ing.Check)
			if err != nil {
				o.GatewayErr = err.Error()
			}
		}
		o.GatewayBlocks = in.Blocks
		v := sites.NewView(in)
		if v.Err != nil {
			o.GatewayErr = v.Err.Error()
		}
		o.Gateway = v.Websites()
		for _, h := range c.Resolve {
			o.GatewayResolve = append(o.GatewayResolve, v.ID(h))
		}
		want := c.Blocks
		if len(c.ExpectDrop) > 0 {
			drop := map[int]bool{}
			for _, i := range c.ExpectDrop {
				drop[i] = true
			}
			want = nil
			for i, b := range c.Blocks {
				if !drop[i] {
					want = append(want, b)
				}
			}
		}
		set, err := websites.Derive(websites.Input{Mode: websites.ModeIngress, Blocks: want, UnprotectedSites: c.UnprotectedSites})
		if err != nil {
			o.ExpectedErr = err.Error()
		} else {
			o.Expected = set.Websites
			for _, h := range c.Resolve {
				o.ExpectedResolve = append(o.ExpectedResolve, set.Resolve(h))
			}
		}
		a, _ := json.Marshal([]any{o.Gateway, o.GatewayResolve})
		b, _ := json.Marshal([]any{o.Expected, o.ExpectedResolve})
		o.Match = string(a) == string(b) && (o.ExpectedErr == "") == (o.GatewayErr == "" && o.PrepareErr == "")
		if o.ExpectedErr != "" {
			o.Match = o.PrepareErr != "" || o.GatewayErr != ""
		}
		if len(c.ExpectDrop) > 0 {
			o.Match = string(a) == string(b) && o.ExpectedErr == "" && o.GatewayErr != ""
		}
		outs = append(outs, o)
	}
	b, _ := json.MarshalIndent(outs, "", " ")
	if err := os.WriteFile(os.Getenv("D36_OUT"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}
