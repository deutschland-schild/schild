//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// v0.4 addendum (initiator, 2026-10-28): schild.yaml keys for the bounded WAF
// evaluation and the behaviour reason `learning`. Appended last so every
// earlier vector keeps its number.

func genV04Addendum(g *gen) {
	ctx := vectors.Context{}
	cfg := func(valid bool, code contract.Code, name, desc string, waf map[string]any) {
		m := siteConfig()
		m["waf"] = waf
		g.add("config/schild", name, valid, code, desc, ctx, mustJSON(m), m)
	}
	cfg(true, "", "waf-eval-limits", "v0.4 addendum: 8 evaluation slots and 250 ms queue wait in schild.yaml.", map[string]any{"eval_timeout_ms": 1000, "max_concurrent_evals": 8, "queue_wait_ms": 250})
	cfg(true, "", "waf-queue-wait-only", "v0.4 addendum: queue wait alone; the slots stay derived from GOMAXPROCS.", map[string]any{"queue_wait_ms": 50})
	for _, f := range []struct {
		name string
		waf  map[string]any
		desc string
	}{
		{"waf-one-eval-slot", map[string]any{"max_concurrent_evals": 1}, "v0.4 addendum: at least 2 evaluation slots (heavy bodies get half)."},
		{"waf-too-many-eval-slots", map[string]any{"max_concurrent_evals": 1025}, "v0.4 addendum: at most 1024 evaluation slots."},
		{"waf-queue-wait-zero", map[string]any{"queue_wait_ms": 0}, "v0.4 addendum: queue wait at least 1 ms."},
		{"waf-queue-wait-too-long", map[string]any{"queue_wait_ms": 10001}, "v0.4 addendum: queue wait at most 10 s."},
		{"waf-eval-slots-string", map[string]any{"max_concurrent_evals": "auto"}, "v0.4 addendum: leave the key out for the derived default."},
	} {
		cfg(false, contract.CodeSchema, f.name, f.desc, f.waf)
	}

	ev := func(valid bool, code contract.Code, name, desc string, e map[string]any) {
		g.add("events", name, valid, code, desc, ctx, mustJSON(e), e)
	}
	cl := func() map[string]any { return reqData("x")["client"].(map[string]any) }
	ev(true, "", "behaviour-learning", "v0.4 addendum: a scenario in block observes during the learning period, reason learning.", cloudEvent("schild.behaviour.triggered.v1", "beh-learning",
		map[string]any{"scenario": "path_probing", "scope": "client", "client": cl(), "key_bits": 32, "host": "verein.example", "route": "/", "count": 24, "threshold": 20, "window_s": 60,
			"mode": "block", "action": "observe", "would_action": "block", "reason": "learning"}))
	ev(false, contract.CodeSchema, "ratelimit-learning", "v0.4 addendum: rate limits act from day 0, never reason learning.", cloudEvent("schild.ratelimit.exceeded.v1", "rl-learning",
		map[string]any{"limit_id": "preset-wordpress-login", "source": "preset", "route": "/wp-login.php", "methods": []string{"POST"}, "host": "verein.example", "path": "/wp-login.php",
			"client": cl(), "key_bits": 32, "limit": 10, "per_s": 60, "burst": 10, "count": 14, "mode": "block", "action": "observe", "reason": "learning"}))
}
