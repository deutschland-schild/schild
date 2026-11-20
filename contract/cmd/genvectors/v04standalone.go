//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// v0.4 (MVP-19, D31): gateway without the network and schild as ingress with
// the operator's Caddyfile. Appended after the MVP-18 vectors so every
// earlier vector keeps its number.

// standaloneConfig is a production gateway: autoblock, no keys, plain proxy
// to upstream. D72: there is no network section any more.
func standaloneConfig() map[string]any {
	return map[string]any{
		"config_version": 0,
		"profile":        "production",
		"mode":           "autoblock",
		"node_name":      "web-1",
		"upstream":       map[string]any{"url": "http://app:80"},
	}
}

// caddyIngress replaces the plain proxy by the operator's Caddyfile.
func caddyIngress(m map[string]any) map[string]any {
	delete(m, "upstream")
	m["ingress"] = map[string]any{"caddyfile": "/etc/caddy/Caddyfile", "storage": "/data/caddy"}
	return m
}

func genSiteConfigV04Standalone(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}

	add(true, "", "standalone-autoblock", "v0.4 MVP-19: production without the network, autoblock with local decisions, no keys.", standaloneConfig())
	m := caddyIngress(standaloneConfig())
	m["ingress"].(map[string]any)["unprotected_sites"] = []string{"static.verein.example", "*.preview.verein.example"}
	m["listen"] = map[string]any{"dashboard": "127.0.0.1:8788", "metrics": "127.0.0.1:9101"}
	m["behaviour"] = map[string]any{"distributed": map[string]any{"learning_days": 14}}
	add(true, "", "standalone-ingress", "v0.4 MVP-19: without the network, the operator's Caddyfile and Caddy storage, two sites deliberately without schild.", m)
	g.retire(c, true) // ingress-networked (D72: no network)
	g.retire(c, true) // network-enabled-explicit (D72: no network)
	m = siteConfig()
	m["ingress"] = map[string]any{"trusted_proxies": []string{"10.0.0.0/8"}, "client_ip_headers": []string{"X-Forwarded-For"}}
	add(true, "", "legacy-ingress-without-caddyfile", "v0.4 MVP-19: ingress without caddyfile keeps the plain proxy to upstream.", m)
	m = standaloneConfig()
	m["profile"] = "test"
	m["mode"] = "observe"
	add(true, "", "standalone-test-profile-observe", "v0.4 MVP-19: profile test, observe only.", m)

	for _, f := range []struct {
		name string
		code contract.Code
		base func() map[string]any
		mut  func(map[string]any)
		desc string
	}{
		{"standalone-labs", contract.CodeSchema, standaloneConfig, func(m map[string]any) {
			m["labs"] = []any{labEntry("lab-a", "https://lab-a.schild.test:7443")}
		}, "D72: labs is an unknown key, rejected, not ignored."},
		{"standalone-relays", contract.CodeSchema, standaloneConfig, func(m map[string]any) {
			m["relays"] = []any{map[string]any{"url": "https://relay-1.schild.test:7480"}, map[string]any{"url": "https://relay-2.schild.test:7480"}}
		}, "D72: relays is an unknown key."},
		{"standalone-channel", contract.CodeSchema, standaloneConfig, func(m map[string]any) { m["channel"] = channel }, "D72: channel is an unknown key."},
		{"standalone-site-key", contract.CodeSchema, standaloneConfig, func(m map[string]any) {
			m["site_key"] = map[string]any{"keyid": "test-site-a", "private_key_file": "/etc/schild/keys/site.key"}
		}, "D72: site_key is an unknown key (nothing is signed or sent)."},
		{"standalone-min-operators", contract.CodeSchema, standaloneConfig, func(m map[string]any) { m["min_independent_operators"] = 3 }, "D72: min_independent_operators is an unknown key."},
		{"standalone-test-profile-section", contract.CodeSchema, standaloneConfig, func(m map[string]any) {
			m["profile"] = "test"
			m["mode"] = "observe"
			m["test_profile"] = map[string]any{"simulated_operators": []any{map[string]any{"lab": "lab-a", "operator": "sim-1"}}}
		}, "D72: test_profile is an unknown key."},
		{"standalone-signals", contract.CodeSchema, standaloneConfig, func(m map[string]any) { m["signals"] = map[string]any{"enabled": false} }, "D72: signals is an unknown key, also when disabled."},
		{"standalone-remote-rules", contract.CodeSchema, standaloneConfig, func(m map[string]any) { m["remote_rules"] = map[string]any{"enabled": true} }, "D72: remote_rules is an unknown key."},
		{"standalone-test-profile-autoblock", "", standaloneConfig, nil, "D89: the mode is ignored, the test profile observes on its own; a valid vector of genD89."},
		{"standalone-no-backend", contract.CodeSchema, standaloneConfig, func(m map[string]any) { delete(m, "upstream") }, "v0.4 MVP-19: neither upstream nor ingress.caddyfile."},
		{"network-on-without-labs", contract.CodeSchema, siteConfig, func(m map[string]any) {
			m["network"] = map[string]any{"enabled": true}
		}, "D72: network is an unknown key, also enabled."},
		{"network-on-without-site-key", contract.CodeSchema, siteConfig, func(m map[string]any) { m["network"] = map[string]any{} }, "D72: network is an unknown key, also empty."},
		{"network-enabled-string", contract.CodeSchema, standaloneConfig, func(m map[string]any) { m["network"] = map[string]any{"enabled": "no"} }, "D72: network is an unknown key."},
		{"network-unknown-key", contract.CodeSchema, standaloneConfig, func(m map[string]any) { m["network"] = map[string]any{"enabled": false} }, "D72: network is an unknown key, also disabled."},
		{"ingress-with-upstream", contract.CodeSchema, standaloneConfig, func(m map[string]any) {
			m["ingress"] = map[string]any{"caddyfile": "/etc/caddy/Caddyfile"}
		}, "v0.4 MVP-19: ingress.caddyfile and upstream exclude each other."},
		{"ingress-with-listen-proxy", contract.CodeSchema, func() map[string]any { return caddyIngress(standaloneConfig()) }, func(m map[string]any) {
			m["listen"] = map[string]any{"proxy": ":8080"}
		}, "v0.4 MVP-19: ingress.caddyfile and listen.proxy exclude each other."},
		{"ingress-storage-without-caddyfile", contract.CodeSchema, standaloneConfig, func(m map[string]any) {
			m["ingress"] = map[string]any{"storage": "/data/caddy"}
		}, "v0.4 MVP-19: ingress.storage needs ingress.caddyfile."},
		{"ingress-unprotected-without-caddyfile", contract.CodeSchema, standaloneConfig, func(m map[string]any) {
			m["ingress"] = map[string]any{"unprotected_sites": []string{"static.verein.example"}}
		}, "v0.4 MVP-19: ingress.unprotected_sites needs ingress.caddyfile."},
		{"ingress-caddyfile-relative", contract.CodeSchema, func() map[string]any { return caddyIngress(standaloneConfig()) }, func(m map[string]any) {
			m["ingress"].(map[string]any)["caddyfile"] = "Caddyfile"
		}, "v0.4 MVP-19: the Caddyfile path is absolute."},
		{"ingress-unprotected-url", contract.CodeSchema, func() map[string]any { return caddyIngress(standaloneConfig()) }, func(m map[string]any) {
			m["ingress"].(map[string]any)["unprotected_sites"] = []string{"https://static.verein.example"}
		}, "v0.4 MVP-19: unprotected_sites are host names, not URLs."},
		{"ingress-unprotected-duplicate", contract.CodeSchema, func() map[string]any { return caddyIngress(standaloneConfig()) }, func(m map[string]any) {
			m["ingress"].(map[string]any)["unprotected_sites"] = []string{"static.verein.example", "static.verein.example"}
		}, "v0.4 MVP-19: each unprotected site once."},
	} {
		if f.mut == nil {
			g.retire(c, false)
			continue
		}
		m := f.base()
		f.mut(m)
		add(false, f.code, f.name, f.desc, m)
	}
}
