//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D88 (2026-11-18): an address blocked by hand in the dashboard.
func genEventsD88(g *gen) {
	client := m{"ip": "203.0.113.7", "attribution": "tcp_peer", "allowlisted": false, "geo": m{"country": "DE", "asn": 64496, "net_class": "hosting"}}
	data := func(set m, drop ...string) m {
		x := m{"actor": "dashboard", "effect": "block", "client": client, "key_bits": 32, "duration_s": 86400, "until": "2026-11-19T10:00:00Z", "incident": "K7QM-4XWD",
			"target_kind": "address", "reason": "scanner from the access log"}
		for k, v := range set {
			x[k] = v
		}
		for _, k := range drop {
			delete(x, k)
		}
		return x
	}
	add := func(valid bool, name, desc string, d m) {
		var code contract.Code
		if !valid {
			code = contract.CodeSchema
		}
		x := cloudEvent("schild.block.set.v1", name, d)
		g.add("events", name, valid, code, desc, vectors.Context{}, mustJSON(x), x)
	}
	add(true, "block-set-dashboard", "D88: the operator blocked an address in the dashboard: no token, no evidence event.", data(nil))
	add(true, "block-set-dashboard-week", "D88: 7 days, kept in schild.db.", data(m{"duration_s": 604800, "persisted": true}))
	add(true, "block-set-agent-actor", "D88: an agent names itself as actor, with its token and evidence.", data(m{"actor": "agent", "target_kind": "event",
		"evidence_event_id": "6f1c2b7e-1d4a-4c8e-9b2f-6a5d4e3c2b16", "token_id": "tok_000000000001", "token_label": "Local agent"}))
	add(false, "block-set-dashboard-token", "D88: the dashboard names no token.", data(m{"token_id": "tok_000000000001", "token_label": "Local agent"}))
	add(false, "block-set-dashboard-event-target", "D88: the dashboard blocks a typed address.", data(m{"target_kind": "event"}))
	add(false, "block-set-agent-address-target", "D88: an agent never names an address.", data(m{"actor": "agent", "evidence_event_id": "6f1c2b7e-1d4a-4c8e-9b2f-6a5d4e3c2b16",
		"token_id": "tok_000000000001", "token_label": "Local agent"}))
	add(false, "block-set-dashboard-no-reason", "D88: a reason is required.", data(nil, "reason"))
	add(false, "block-set-dashboard-over-week", "D88: at most 7 days.", data(m{"duration_s": 604801}))
}
