//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D84 (2026-11-12): rule exceptions set and removed in the dashboard.
func genEventsD84(g *gen) {
	data := func(set m, drop ...string) m {
		x := m{"id": 1900000, "website": "app.example.org", "path": "/livewire/update", "target": "ARGS:json.components.*.updates.body", "repository": "crs", "rules": []string{"933180"},
			"actor": "dashboard", "reason": "math text is blocked"}
		for k, v := range set {
			x[k] = v
		}
		for _, k := range drop {
			delete(x, k)
		}
		return x
	}
	add := func(valid bool, name, desc, typ string, d m) {
		var code contract.Code
		if !valid {
			code = contract.CodeSchema
		}
		x := cloudEvent(typ, name, d)
		g.add("events", name, valid, code, desc, vectors.Context{}, mustJSON(x), x)
	}
	add(true, "rule-exception-set-dashboard", "D84: the operator set an exception in the dashboard, no token.", "schild.rule.exception_set.v1", data(nil))
	add(true, "rule-exception-removed-dashboard", "D84: removed in the dashboard, the reason may be empty.", "schild.rule.exception_removed.v1", data(m{"reason": ""}))
	add(true, "rule-exception-set-agent-actor", "D84: an agent names itself as actor, with its token.", "schild.rule.exception_set.v1",
		data(m{"actor": "agent", "token_id": "tok_000000000001", "token_label": "Local agent"}))
	add(false, "rule-exception-dashboard-token", "D84: the dashboard names no token.", "schild.rule.exception_set.v1",
		data(m{"token_id": "tok_000000000001", "token_label": "Local agent"}))
	add(false, "rule-exception-agent-no-token", "D84: an agent as actor names its token.", "schild.rule.exception_set.v1", data(m{"actor": "agent"}))
	add(false, "rule-exception-agent-empty-reason", "D84: an agent gives a reason.", "schild.rule.exception_removed.v1",
		data(m{"reason": "", "token_id": "tok_000000000001", "token_label": "Local agent"}, "actor"))
	add(false, "rule-exception-dashboard-no-reason", "D84: the reason field is always there.", "schild.rule.exception_removed.v1", data(nil, "reason"))
}
