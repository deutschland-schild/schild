//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D89 (2026-11-18): no protection mode. schild.yaml may still carry mode, the
// gateway ignores it; the test profile observes on its own.
func genSiteConfigD89(g *gen) {
	const c = "config/schild"
	add := func(name, desc string, edit func(m map[string]any)) {
		x := siteConfig()
		edit(x)
		g.add(c, name, true, "", desc, vectors.Context{}, mustJSON(x), x)
	}
	add("no-mode", "D89: without mode: the repository states decide.", func(x map[string]any) { delete(x, "mode") })
	add("test-profile-no-mode", "D89: the test profile needs no mode, it observes on its own.", func(x map[string]any) {
		delete(x, "mode")
		x["profile"] = "test"
	})
	add("test-profile-autoblock", "D89: an old mode next to the test profile is ignored; the test profile still observes.", func(x map[string]any) {
		x["profile"] = "test"
		x["mode"] = "autoblock"
	})
}
