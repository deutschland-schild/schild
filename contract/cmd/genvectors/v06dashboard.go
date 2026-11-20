//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// genSiteConfigD76 writes the config vectors of dashboard.allowed_hosts
// (D76): the host names the dashboard answers besides localhost, IP
// addresses and the host of listen.dashboard.
func genSiteConfigD76(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, name, desc string, hosts any) {
		x := siteConfig()
		x["dashboard"] = map[string]any{"allowed_hosts": hosts}
		var code contract.Code
		if !valid {
			code = contract.CodeSchema
		}
		g.add(c, name, valid, code, desc, ctx, mustJSON(x), x)
	}
	add(true, "dashboard-allowed-hosts", "D76: a VPN name and a single-label name.", []any{"gateway.vpn.example", "schild-host"})
	add(true, "dashboard-allowed-hosts-empty", "D76: an empty list is the default: localhost, IP addresses and the host of listen.dashboard.", []any{})
	add(false, "dashboard-allowed-hosts-port", "D76: a host name, no port.", []any{"gateway.vpn.example:8788"})
	add(false, "dashboard-allowed-hosts-url", "D76: a host name, no URL.", []any{"https://gateway.vpn.example"})
	add(false, "dashboard-allowed-hosts-wildcard", "D76: no wildcards: every name is listed.", []any{"*.vpn.example"})
	add(false, "dashboard-allowed-hosts-duplicate", "D76: no duplicates.", []any{"gateway.vpn.example", "gateway.vpn.example"})
	add(false, "dashboard-allowed-hosts-string", "D76: a list, not one name.", "gateway.vpn.example")
}
