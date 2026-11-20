//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D54 (2026-11-01): rule exceptions through the agent API.
func genEventsD54(g *gen) {
	data := func(drop ...string) m {
		x := m{"id": 1900000, "website": "app.example.org", "path": "/livewire/update", "target": "ARGS:json.components.*.updates.body", "repository": "crs", "rules": []string{"933180"},
			"token_id": "tok_000000000001", "token_label": "Local agent", "reason": "math text is blocked"}
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
	add(true, "rule-exception-set", "D54: an agent set an exception.", "schild.rule.exception_set.v1", data())
	add(true, "rule-exception-removed", "D54: an agent removed one.", "schild.rule.exception_removed.v1", data())
	add(false, "rule-exception-no-reason", "D54: a reason is required.", "schild.rule.exception_set.v1", data("reason"))
	add(false, "rule-exception-no-token", "D54: every write names its token.", "schild.rule.exception_removed.v1", data("token_id"))
	add(false, "rule-exception-outside-range", "D54: the ids have their range.", "schild.rule.exception_set.v1", func() m { x := data(); x["id"] = 1000301; return x }())
}
