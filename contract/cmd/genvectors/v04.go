//go:build !release

package main

import (
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// v0.4 (MVP-17): behaviour across requests and rate limits. Appended after
// the v0.3 vectors so that every earlier vector keeps its number.

func genSiteConfigV04(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	login := map[string]any{"id": "wp-login", "label": "WordPress Anmeldung", "route": "/wp-login.php", "methods": []string{"POST"}, "limit": 10, "per": "1m", "burst": 10, "mode": "block"}
	full := func() map[string]any {
		return map[string]any{
			"presets":       []string{"wordpress", "generic"},
			"preset_limits": "observe",
			"scenarios": map[string]any{
				"login_bruteforce":    map[string]any{"mode": "block", "thresholds": map[string]any{"count": 5, "window_s": 60, "slow_count": 30, "slow_window_s": 3600}},
				"credential_stuffing": map[string]any{"mode": "observe", "thresholds": map[string]any{"count": 10, "window_s": 600}},
				"path_probing":        map[string]any{"mode": "challenge", "thresholds": map[string]any{"count": 20, "window_s": 60}},
				"aggressive_crawl":    map[string]any{"mode": "observe", "thresholds": map[string]any{"count": 120, "window_s": 60, "baseline_factor": 10}},
				"waf_repeat":          map[string]any{"mode": "off"},
			},
			"rate_limits": []any{login,
				map[string]any{"route": "/wp-json/contact-form-7/v1/contact-forms/*/feedback", "methods": []string{"POST"}, "limit": 3, "per": "10m", "site": "verein.example"},
				map[string]any{"route": "/api/**", "methods": []string{"POST", "PUT", "PATCH", "DELETE"}, "limit": 60, "per": "1m", "burst": 120, "mode": "observe"},
			},
		}
	}
	m := siteConfig()
	m["behaviour"] = map[string]any{}
	add(true, "", "behaviour-defaults", "v0.4: empty behaviour section, every scenario and preset limit on its default.", m)
	m = siteConfig()
	m["behaviour"] = full()
	add(true, "", "behaviour-full", "v0.4: scenarios with modes and thresholds, own rate limits with wildcards and a site.", m)
	m = siteConfig()
	m["behaviour"] = map[string]any{"rate_limits": []any{map[string]any{"route": "/**", "limit": 600, "per": "1m", "confirm_site_wide": true}}}
	add(true, "", "behaviour-site-wide-confirmed", "v0.4: a limit on the whole site with the explicit confirm flag.", m)
	m = siteConfig()
	m["behaviour"] = map[string]any{"rate_limits": []any{map[string]any{"route": "/", "limit": 30, "per": "1s"}, map[string]any{"route": "/search", "methods": []string{"GET"}, "limit": 20, "per": "24h"}}}
	add(true, "", "behaviour-root-and-day", "v0.4: the start page alone is not the whole site; 24h is the longest period.", m)
	m = siteConfig()
	m["behaviour"] = map[string]any{"scenarios": map[string]any{"login_bruteforce": map[string]any{"mode": "block"}}}
	add(true, "", "behaviour-one-scenario", "v0.4: switch on one scenario, defaults for the rest.", m)

	for _, f := range []struct {
		name string
		code contract.Code
		beh  map[string]any
		desc string
	}{
		{"behaviour-site-wide-unconfirmed", contract.CodeSchema, map[string]any{"rate_limits": []any{map[string]any{"route": "/**", "limit": 600, "per": "1m"}}}, "v0.4: a limit on the whole site needs confirm_site_wide."},
		{"behaviour-site-wide-false", contract.CodeSchema, map[string]any{"rate_limits": []any{map[string]any{"route": "/*/**", "limit": 600, "per": "1m", "confirm_site_wide": false}}}, "v0.4: confirm_site_wide false is no confirmation."},
		{"behaviour-duplicate-limit-id", contract.CodeConfig, map[string]any{"rate_limits": []any{login, login}}, "v0.4: rate limit ids are unique."},
		{"behaviour-unknown-scenario", contract.CodeSchema, map[string]any{"scenarios": map[string]any{"ssh_bruteforce": map[string]any{"mode": "block"}}}, "v0.4: fixed scenarios only (network-level SSH is MVP-15)."},
		{"behaviour-unknown-mode", contract.CodeSchema, map[string]any{"scenarios": map[string]any{"path_probing": map[string]any{"mode": "ban"}}}, "v0.4: modes off, observe, challenge, block."},
		{"behaviour-threshold-one", contract.CodeSchema, map[string]any{"scenarios": map[string]any{"login_bruteforce": map[string]any{"thresholds": map[string]any{"count": 1}}}}, "v0.4: a single failed login never triggers."},
		{"behaviour-per-too-long", contract.CodeSchema, map[string]any{"rate_limits": []any{map[string]any{"route": "/login", "limit": 5, "per": "25h"}}}, "v0.4: at most 24 h per period."},
		{"behaviour-route-relative", contract.CodeSchema, map[string]any{"rate_limits": []any{map[string]any{"route": "wp-login.php", "limit": 5, "per": "1m"}}}, "v0.4: routes start with a slash."},
		{"behaviour-unknown-preset", contract.CodeSchema, map[string]any{"presets": []string{"magento"}}, "v0.4: known presets only."},
		{"behaviour-limit-challenge", contract.CodeSchema, map[string]any{"rate_limits": []any{map[string]any{"route": "/login", "limit": 5, "per": "1m", "mode": "challenge"}}}, "v0.4: rate limits observe or block (429), no challenge."},
		{"behaviour-crawl-slow-window", contract.CodeSchema, map[string]any{"scenarios": map[string]any{"aggressive_crawl": map[string]any{"thresholds": map[string]any{"slow_count": 1000}}}}, "v0.4: aggressive_crawl has its own thresholds."},
		{"behaviour-unknown-key", contract.CodeSchema, map[string]any{"share_with_labs": true}, "v0.4: no option sends behaviour data anywhere."},
	} {
		m := siteConfig()
		m["behaviour"] = f.beh
		add(false, f.code, f.name, f.desc, m)
	}
}

func genEventsV04(g *gen) {
	const c = "events"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, e map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(e), e)
	}
	cl := func() map[string]any { return reqData("x")["client"].(map[string]any) }
	blockData := func() map[string]any {
		return map[string]any{"scenario": "login_bruteforce", "scope": "client", "client": cl(), "key_bits": 32, "host": "verein.example", "route": "/wp-login.php", "preset": "wordpress",
			"count": 6, "threshold": 5, "window_s": 60, "mode": "block", "action": "block", "would_action": "block", "level": 1, "duration_s": 900, "until": ts(15 * time.Minute), "incident": "K7QM-4XWD"}
	}
	add(true, "", "behaviour-block", "v0.4: login brute force blocked for 15 minutes (first step of the ladder).", cloudEvent("schild.behaviour.triggered.v1", "beh-block", blockData()))
	d := blockData()
	d["client"].(map[string]any)["ip"] = "2001:db8:1:2::17"
	d["key_bits"] = 64
	d["mode"], d["action"], d["would_action"], d["reason"] = "observe", "observe", "challenge", "net_class"
	d["client"].(map[string]any)["geo"].(map[string]any)["net_class"] = "mobile"
	delete(d, "level")
	delete(d, "duration_s")
	delete(d, "until")
	delete(d, "incident")
	add(true, "", "behaviour-observe-mobile", "v0.4: mobile address, IPv6 /64 key: at most challenge, here observed.", cloudEvent("schild.behaviour.triggered.v1", "beh-mobile", d))
	add(true, "", "behaviour-site-scope", "v0.4: credential stuffing across the whole site from a pool of addresses, no client.", cloudEvent("schild.behaviour.triggered.v1", "beh-site",
		map[string]any{"scenario": "credential_stuffing", "scope": "site", "host": "verein.example", "route": "/wp-login.php", "count": 412, "threshold": 50, "window_s": 600, "mode": "block", "action": "observe", "reason": "site_scope"}))
	rl := func() map[string]any {
		return map[string]any{"limit_id": "preset-wordpress-login", "source": "preset", "route": "/wp-login.php", "methods": []string{"POST"}, "host": "verein.example", "path": "/wp-login.php",
			"client": cl(), "key_bits": 32, "limit": 10, "per_s": 60, "burst": 10, "count": 14, "mode": "block", "action": "block", "retry_after_s": 6}
	}
	add(true, "", "ratelimit-block", "v0.4: requests over a preset limit answered with 429.", cloudEvent("schild.ratelimit.exceeded.v1", "rl-block", rl()))
	r := rl()
	r["mode"], r["action"], r["source"], r["limit_id"] = "observe", "observe", "dashboard", "contact-form"
	delete(r, "retry_after_s")
	add(true, "", "ratelimit-observe", "v0.4: own limit in observe (\"hätte begrenzt\").", cloudEvent("schild.ratelimit.exceeded.v1", "rl-observe", r))

	d = blockData()
	delete(d, "until")
	add(false, contract.CodeSchema, "behaviour-block-without-until", "v0.4: every block expires by itself.", cloudEvent("schild.behaviour.triggered.v1", "beh-nountil", d))
	d = blockData()
	d["duration_s"] = 172800
	add(false, contract.CodeSchema, "behaviour-block-over-cap", "v0.4: blocks are capped at 24 h.", cloudEvent("schild.behaviour.triggered.v1", "beh-cap", d))
	d = blockData()
	d["user_name"] = "admin"
	add(false, contract.CodeSchema, "behaviour-user-name", "v0.4: user names are never stored (not even hashed).", cloudEvent("schild.behaviour.triggered.v1", "beh-user", d))
	d = blockData()
	d["scope"] = "site"
	add(false, contract.CodeSchema, "behaviour-site-with-client", "v0.4: a site-wide hit names no client.", cloudEvent("schild.behaviour.triggered.v1", "beh-siteclient", d))
	d = blockData()
	d["scenario"] = "ssh_bruteforce"
	add(false, contract.CodeSchema, "behaviour-unknown-scenario", "v0.4: fixed scenarios only.", cloudEvent("schild.behaviour.triggered.v1", "beh-unknown", d))
	d = blockData()
	d["key_bits"] = 16
	add(false, contract.CodeSchema, "behaviour-key-too-coarse", "v0.4: client keys are never coarser than /24.", cloudEvent("schild.behaviour.triggered.v1", "beh-bits", d))
	r = rl()
	r["body"] = "log=admin&pwd=secret"
	add(false, contract.CodeSchema, "ratelimit-body", "v0.4: no request body in a rate limit record.", cloudEvent("schild.ratelimit.exceeded.v1", "rl-body", r))
	r = rl()
	r["action"] = "challenge"
	add(false, contract.CodeSchema, "ratelimit-challenge", "v0.4: rate limits observe or block.", cloudEvent("schild.ratelimit.exceeded.v1", "rl-challenge", r))
	r = rl()
	delete(r, "client")
	add(false, contract.CodeSchema, "ratelimit-without-client", "v0.4: a limit is always per client key.", cloudEvent("schild.ratelimit.exceeded.v1", "rl-noclient", r))
	r = rl()
	r["count"] = 0
	add(false, contract.CodeSchema, "ratelimit-count-zero", "v0.4: only written when a request went over the limit.", cloudEvent("schild.ratelimit.exceeded.v1", "rl-zero", r))
}
