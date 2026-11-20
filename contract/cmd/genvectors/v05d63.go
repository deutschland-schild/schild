//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D63 (2026-11-04): every record keeps the real (redacted) path; the switch
// monitoring.requests.raw_paths is gone. The generator appends.
func genSiteConfigD63(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	x := siteConfig()
	x["monitoring"] = m{"requests": m{"raw_paths": false}}
	g.add(c, "requests-raw-paths-false", false, contract.CodeSchema, "D63: no switch back to path templates.", ctx, mustJSON(x), x)
}
