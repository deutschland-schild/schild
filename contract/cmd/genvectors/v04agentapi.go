//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// v0.4 (MVP-21, D33): agent_api, the read-only agent API on its own loopback
// listener. Appended after the 2026-10-28 addendum.

func genSiteConfigV04AgentAPI(g *gen) {
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add("config/schild", name, valid, code, desc, ctx, mustJSON(m), m)
	}
	with := func(a map[string]any) map[string]any {
		m := standaloneConfig()
		m["agent_api"] = a
		return m
	}
	add(true, "", "agent-api-defaults", "v0.4 MVP-21: agent API on with the defaults (127.0.0.1:8789, 120 requests per minute, 2 in flight).", with(map[string]any{"enabled": true}))
	add(true, "", "agent-api-full", "v0.4 MVP-21: every agent_api key.", with(map[string]any{"enabled": true, "listen": "127.0.0.1:9790", "requests_per_minute": 30, "max_concurrent": 1, "log_days": 90}))
	add(true, "", "agent-api-ipv6-loopback", "v0.4 MVP-21: IPv6 loopback listener.", with(map[string]any{"enabled": true, "listen": "[::1]:8789"}))
	add(true, "", "agent-api-off", "v0.4 MVP-21: section present, API off (default).", with(map[string]any{"enabled": false, "listen": "localhost:8789"}))
	m := with(map[string]any{"enabled": true, "listen": "127.0.0.1:8788"})
	m["listen"] = map[string]any{"dashboard": "127.0.0.1:8790"}
	add(true, "", "agent-api-moved-dashboard", "v0.4 MVP-21: the default dashboard port is free when the dashboard moved.", m)

	for _, f := range []struct {
		name string
		code contract.Code
		a    map[string]any
		desc string
	}{
		{"agent-api-all-interfaces", contract.CodeSchema, map[string]any{"enabled": true, "listen": "0.0.0.0:8789"}, "v0.4 MVP-21: loopback only; reach it through an SSH tunnel."},
		{"agent-api-port-only", contract.CodeSchema, map[string]any{"enabled": true, "listen": ":8789"}, "v0.4 MVP-21: a bare port listens on every interface."},
		{"agent-api-private-address", contract.CodeSchema, map[string]any{"enabled": true, "listen": "10.0.0.1:8789"}, "v0.4 MVP-21: not even a private network address in v0.4."},
		{"agent-api-ipv6-any", contract.CodeSchema, map[string]any{"enabled": true, "listen": "[::]:8789"}, "v0.4 MVP-21: IPv6 any address."},
		{"agent-api-token-in-yaml", contract.CodeSchema, map[string]any{"enabled": true, "tokens": []string{"sat1_AAAA"}}, "v0.4 MVP-21: tokens never live in schild.yaml (host CLI, stored hashed)."},
		{"agent-api-enabled-string", contract.CodeSchema, map[string]any{"enabled": "true"}, "v0.4 MVP-21: enabled is a boolean."},
		{"agent-api-rpm-zero", contract.CodeSchema, map[string]any{"requests_per_minute": 0}, "v0.4 MVP-21: at least one request per minute."},
		{"agent-api-rpm-too-high", contract.CodeSchema, map[string]any{"requests_per_minute": 601}, "v0.4 MVP-21: at most 600 requests per minute per token."},
		{"agent-api-concurrency-too-high", contract.CodeSchema, map[string]any{"max_concurrent": 9}, "v0.4 MVP-21: at most 8 requests in flight per token."},
		{"agent-api-log-days-too-long", contract.CodeSchema, map[string]any{"log_days": 91}, "v0.4 MVP-21: call log at most 90 days."},
		{"agent-api-on-dashboard-port", contract.CodeConfig, map[string]any{"enabled": true, "listen": "127.0.0.1:8788"}, "v0.4 MVP-21: the default dashboard listener is not shared (semantic check)."},
		{"agent-api-on-metrics-port", contract.CodeConfig, map[string]any{"listen": "127.0.0.1:9101"}, "v0.4 MVP-21: the default metrics listener is not shared, also while the API is off."},
	} {
		add(false, f.code, f.name, f.desc, with(f.a))
	}
}
