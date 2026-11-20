//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// genSiteConfigD95: preset limits are switched one by one
// (behaviour.preset_limit_modes); preset_limits left open means the
// recommendation of every limit.
func genSiteConfigD95(g *gen) {
	const c = "config/schild"
	add := func(name string, valid bool, code contract.Code, desc string, beh map[string]any) {
		x := siteConfig()
		x["behaviour"] = beh
		g.add(c, name, valid, code, desc, vectors.Context{}, mustJSON(x), x)
	}
	add("behaviour-preset-limit-modes", true, "", "D95: a mode per preset limit, next to the one mode for the rest.",
		map[string]any{"preset_limits": "observe", "preset_limit_modes": map[string]any{"preset-wordpress-login": "block", "preset-generic-api-write": "off"}})
	add("behaviour-preset-limit-modes-unknown-id", true, "", "D95: an id this version does not ship is ignored, not refused.",
		map[string]any{"preset_limit_modes": map[string]any{"preset-magento-login": "block"}})
	add("behaviour-preset-limit-modes-own-limit", false, contract.CodeSchema, "D95: only ids of preset limits; an own limit carries its mode itself.",
		map[string]any{"preset_limit_modes": map[string]any{"contact-form": "block"}})
	add("behaviour-preset-limit-modes-challenge", false, contract.CodeSchema, "D95: preset limits are off, observe or block.",
		map[string]any{"preset_limit_modes": map[string]any{"preset-wordpress-login": "challenge"}})
}
