//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D52 (2026-11-01): the built-in Livewire exception can be switched off. The
// generator appends, so no earlier vector changes.
func genSiteConfigD52(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, v any) {
		x := siteConfig()
		x["rules"] = m{"crs": m{"livewire_exception": v}}
		g.add(c, name, valid, code, desc, ctx, mustJSON(x), x)
	}
	add(true, "", "waf-livewire-exception-off", "D52: the exception can be switched off.", false)
	add(false, contract.CodeSchema, "waf-livewire-exception-not-bool", "D52: on or off, nothing else.", "off")
}
