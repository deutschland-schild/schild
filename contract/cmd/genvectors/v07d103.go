//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract/vectors"
)

// genSiteConfigD103: agent_api.listen also takes every interface, for a
// container whose port is published on the loopback of its host.
func genSiteConfigD103(g *gen) {
	add := func(name, desc, listen string) {
		x := standaloneConfig()
		x["agent_api"] = map[string]any{"listen": listen}
		g.add("config/schild", name, true, "", desc, vectors.Context{}, mustJSON(x), x)
	}
	add("agent-api-all-interfaces", "D103: every IPv4 interface, for a container that publishes the port on 127.0.0.1 of its host.", "0.0.0.0:8789")
	add("agent-api-ipv6-any", "D103: every interface, IPv6 form.", "[::]:8789")
}
