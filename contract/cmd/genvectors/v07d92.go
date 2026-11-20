//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D92 (2026-11-19): no browser check. schild.yaml may still set a scenario to
// challenge; the gateway reads it as observe and warns.
func genSiteConfigD92(g *gen) {
	const c = "config/schild"
	x := siteConfig()
	x["behaviour"] = map[string]any{"scenarios": map[string]any{"path_probing": map[string]any{"mode": "challenge"}}}
	g.add(c, "behaviour-legacy-challenge", true, "", "D92: the old mode challenge still loads; the gateway reads it as observe and warns.", vectors.Context{}, mustJSON(x), x)
}
