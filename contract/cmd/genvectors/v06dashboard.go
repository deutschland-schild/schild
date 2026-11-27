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

// genSiteConfigAudit writes the config vectors of the audit log (MVP-36,
// D108): audit.keep_days and audit.stream.
func genSiteConfigAudit(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, name, desc string, audit any) {
		x := siteConfig()
		x["audit"] = audit
		var code contract.Code
		if !valid {
			code = contract.CodeSchema
		}
		g.add(c, name, valid, code, desc, ctx, mustJSON(x), x)
	}
	add(true, "audit-keep-days", "D108: entries of changes are kept 14 days.", map[string]any{"keep_days": 14})
	add(true, "audit-keep-unlimited", "D108: the word unlimited, not 0: 0 days reads like nothing is kept.", map[string]any{"keep_days": "unlimited"})
	add(true, "audit-keep-longest", "D108: 36500 days is the longest.", map[string]any{"keep_days": 36500})
	add(true, "audit-stream-stdout", "D108: a copy of every entry as JSON lines on stdout.", map[string]any{"stream": "stdout"})
	add(true, "audit-stream-file", "D108: a copy into a file.", map[string]any{"keep_days": 365, "stream": "/var/log/schild/audit.jsonl"})
	add(false, "audit-keep-zero", "D108: 0 is no number of days; unlimited is a word.", map[string]any{"keep_days": 0})
	add(false, "audit-keep-too-long", "D108: more than 36500 days.", map[string]any{"keep_days": 36501})
	add(false, "audit-keep-word", "D108: unlimited is the only word.", map[string]any{"keep_days": "forever"})
	add(false, "audit-stream-relative", "D108: stdout or an absolute path.", map[string]any{"stream": "audit.jsonl"})
	add(false, "audit-unknown-key", "D108: no other key.", map[string]any{"forget": true})
}
