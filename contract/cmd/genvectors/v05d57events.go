//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D57 (2026-11-02, MVP-29): the event of a crawler policy change.
func genEventsD57(g *gen) {
	add := func(valid bool, name, desc string, d m) {
		var code contract.Code
		if !valid {
			code = contract.CodeSchema
		}
		x := cloudEvent("schild.crawler.policy_set.v1", name, d)
		g.add("events", name, valid, code, desc, vectors.Context{}, mustJSON(x), x)
	}
	dash := func(k string, v any) m {
		x := m{"website": "musterverein.example", "categories": m{"ai_training": "block"}, "bots": m{"gptbot": "allow"}, "impersonators": "block",
			"actor": "dashboard", "user": "admin"}
		if v == nil {
			delete(x, k)
		} else if k != "" {
			x[k] = v
		}
		return x
	}
	agent := func(k string, v any) m {
		x := m{"website": "musterverein.example", "categories": m{"ai_training": "block"}, "bots": m{}, "impersonators": "allow", "preset": "block_ai_training",
			"actor": "agent", "token_id": "tok_000000000002", "token_label": "site agent", "reason": "The operator asked to keep AI training crawlers out."}
		if v == nil {
			delete(x, k)
		} else if k != "" {
			x[k] = v
		}
		return x
	}
	add(true, "crawler-policy-set-dashboard", "D57: the crawler policy of a website changed in the dashboard.", dash("", nil))
	add(true, "crawler-policy-set-agent-preset", "D57: an agent applied the preset block_ai_training, with token and reason.", agent("", nil))
	add(true, "crawler-policy-set-empty", "D57: everything allowed again: empty categories and bots.", dash("categories", m{}))
	add(false, "crawler-policy-set-agent-no-reason", "D57: a change through the agent API carries the agent's reason.", agent("reason", nil))
	add(false, "crawler-policy-set-agent-no-token", "D57: a change through the agent API names the token.", agent("token_id", nil))
	add(false, "crawler-policy-set-unknown-category", "D57: only catalogue categories.", dash("categories", m{"likely_browser": "block"}))
	add(false, "crawler-policy-set-charge", "D57: allow or block, nothing is charged.", dash("categories", m{"ai_training": "charge"}))
	add(false, "crawler-policy-set-cli", "D57: the policy changes from the dashboard or the agent API.", dash("actor", "cli"))
	add(false, "crawler-policy-set-no-impersonators", "D57: the event holds the whole policy.", dash("impersonators", nil))
}
