//go:build !release

package main

import (
	"fmt"
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// v0.5 (D36): the website model of the dashboards - website derivation from
// the Caddyfile site blocks or the proxy configuration, host resolution, and
// the status rules. Appended after the MVP-22 vectors. Host names use the
// reserved names of RFC 2606 / RFC 6761 (example.org, .example) and the
// documentation addresses of RFC 5737 / RFC 3849.

func blk(schild, proxies bool, addrs ...string) map[string]any {
	return map[string]any{"addresses": addrs, "schild": schild, "proxies": proxies}
}

func site(id, label string, prot string, tracked bool, hosts ...string) map[string]any {
	if hosts == nil {
		hosts = []string{}
	}
	return map[string]any{"id": id, "label": label, "hosts": hosts, "protection": prot, "tracked": tracked}
}

// genSiteConfigV05Websites: upstream.site_hosts (proxy mode).
func genSiteConfigV05Websites(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, hosts any) {
		m := siteConfig()
		m["upstream"].(map[string]any)["site_hosts"] = hosts
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	add(true, "", "site-hosts", "D36: proxy mode names its one website after the first of upstream.site_hosts.", []string{"verein.example", "www.verein.example"})
	add(true, "", "site-hosts-wildcard", "D36: a wildcard host is allowed.", []string{"*.verein.example"})
	add(false, contract.CodeSchema, "site-hosts-empty", "D36: at least one host when the key is given.", []string{})
	add(false, contract.CodeSchema, "site-hosts-url", "D36: host names, not URLs.", []string{"https://verein.example"})
	add(false, contract.CodeSchema, "site-hosts-port", "D36: no port.", []string{"verein.example:443"})
	add(false, contract.CodeSchema, "site-hosts-duplicate", "D36: each host once.", []string{"verein.example", "verein.example"})
	m := caddyIngress(standaloneConfig())
	m["upstream"] = map[string]any{"url": "http://app:80", "site_hosts": []string{"verein.example"}}
	g.add(c, "site-hosts-ingress", false, contract.CodeSchema, "D36: with ingress.caddyfile the Caddyfile names the websites; upstream (and site_hosts) must be absent.", ctx, mustJSON(m), m)
}

func genWebsiteDerive(g *gen) {
	const c = "website-derive"
	ctx := vectors.Context{}
	ing := func(blocks ...map[string]any) map[string]any {
		bs := make([]any, len(blocks))
		for i, b := range blocks {
			bs[i] = b
		}
		return map[string]any{"mode": "ingress", "blocks": bs}
	}
	ok := func(name, desc string, in map[string]any, sites []map[string]any, resolved ...any) {
		r := map[string]any{"websites": sites}
		if resolved != nil {
			r["resolved"] = resolved
		}
		g.addResult(c, name, true, "", desc, ctx, mustJSON(in), in, r)
	}
	const P, PA, U = "protected", "partial", "unprotected"

	ok("one-block", "D36: one site block with two names is one website; the id is the first host.",
		ing(blk(true, true, "example.org", "www.example.org")),
		[]map[string]any{site("example.org", "example.org", P, true, "example.org", "www.example.org")})
	ok("schemes-ports-paths", "D36: scheme, port and path do not matter; http and https addresses of one host are one host.",
		ing(blk(true, true, "http://example.org", "https://example.org:443", "example.org:8443/api/*")),
		[]map[string]any{site("example.org", "example.org", P, true, "example.org")})
	in := ing(blk(false, false, "http://shop.example.org"), blk(true, true, "Shop.Example.ORG."), blk(true, true, "shop.example.org:8443"))
	in["resolve"] = []string{"shop.example.org", "SHOP.example.org:8443", "shop.example.org.", "other.example.org"}
	ok("duplicate-host-across-blocks", "D36: blocks that share a host (case, trailing dot and port ignored) are one website; a redirect block without schild and without a backend is no website; an unknown host resolves to none.",
		in, []map[string]any{site("shop.example.org", "shop.example.org", P, true, "shop.example.org")},
		"shop.example.org", "shop.example.org", "shop.example.org", nil)
	ok("transitive-merge", "D36: A{a} and B{b} are joined by C{a, b}; the earliest block names the website, hosts in order of appearance.",
		ing(blk(true, true, "a.example.org"), blk(true, true, "b.example.org"), blk(true, true, "b.example.org", "a.example.org", "c.example.org")),
		[]map[string]any{site("a.example.org", "a.example.org", P, true, "a.example.org", "b.example.org", "c.example.org")})
	ok("earliest-block-names", "D36: the first host of the earliest block is the id, even when a later block lists another host first.",
		ing(blk(true, true, "www.example.org"), blk(true, true, "example.org", "www.example.org")),
		[]map[string]any{site("www.example.org", "www.example.org", P, true, "www.example.org", "example.org")})
	in = ing(blk(true, true, "*.kunden.example.org"), blk(true, true, "a.kunden.example.org"), blk(true, true, "*.*.example.org"))
	in["resolve"] = []string{"a.kunden.example.org", "b.kunden.example.org", "x.y.kunden.example.org", "kunden.example.org", "b.c.example.org", "*.kunden.example.org"}
	ok("wildcards", "D36: a wildcard label becomes _ in the id; an exact host beats a wildcard, fewer wildcard labels beat more; a wildcard covers exactly one label. D69: a request host with a * label matches a wildcard host like any other label, as in Caddy.",
		in, []map[string]any{
			site("_.kunden.example.org", "*.kunden.example.org", P, true, "*.kunden.example.org"),
			site("a.kunden.example.org", "a.kunden.example.org", P, true, "a.kunden.example.org"),
			site("_._.example.org", "*.*.example.org", P, true, "*.*.example.org")},
		"a.kunden.example.org", "_.kunden.example.org", nil, nil, "_._.example.org", "_.kunden.example.org")
	in = ing(blk(true, true, "bücher.example", "www.bücher.example"), blk(true, true, "xn--bcher-kva.example:8443"), blk(true, true, "münchen-verein.example"))
	in["resolve"] = []string{"xn--bcher-kva.example", "www.xn--bcher-kva.example", "xn--mnchen-verein-wob.example"}
	ok("idn", "D36: Unicode labels become punycode A-labels (RFC 3492); the Unicode and the punycode spelling are one host; the label shows Unicode.",
		in, []map[string]any{
			site("xn--bcher-kva.example", "bücher.example", P, true, "xn--bcher-kva.example", "www.xn--bcher-kva.example"),
			site("xn--mnchen-verein-wob.example", "münchen-verein.example", P, true, "xn--mnchen-verein-wob.example")},
		"xn--bcher-kva.example", "xn--bcher-kva.example", "xn--mnchen-verein-wob.example")
	in = ing(blk(true, true, "example.org"), blk(false, true, "legacy.example.org"), blk(false, false, "static.example.org"), blk(true, true, "verein.example"))
	in["unprotected_sites"] = []string{"legacy.example.org"}
	in["resolve"] = []string{"legacy.example.org", "static.example.org"}
	ok("unprotected", "D36: a block listed in ingress.unprotected_sites is an unprotected website (listed, never tracked: schild sees none of its requests); a static block without schild is no website.",
		in, []map[string]any{
			site("example.org", "example.org", P, true, "example.org"),
			site("legacy.example.org", "legacy.example.org", U, false, "legacy.example.org"),
			site("verein.example", "verein.example", P, true, "verein.example")},
		"legacy.example.org", nil)
	in = ing(blk(true, true, "app.example.org"), blk(false, true, "http://app.example.org:8080"))
	in["unprotected_sites"] = []string{"*.example.org"}
	ok("partial", "D36: one host in a schild block and in a listed block without schild: one website, protection partial.",
		in, []map[string]any{site("app.example.org", "app.example.org", PA, true, "app.example.org")})
	in = ing(blk(true, true, "example.org"), blk(true, true, ":8080", "http://"))
	in["resolve"] = []string{"Example.ORG:443", "unknown.example.net", "[2001:db8::7]:80", "", "bad host"}
	ok("catch-all", "D36: blocks without a host are the website _any; every host no other block names resolves to it, also a missing or malformed Host.",
		in, []map[string]any{site("example.org", "example.org", P, true, "example.org"), site("_any", "_any", P, true)},
		"example.org", "_any", "_any", "_any", "_any")
	in = ing(blk(true, true, "192.0.2.10:8080"), blk(true, true, "[2001:db8::1]", "https://[2001:0db8:0:0::1]:8443"))
	in["resolve"] = []string{"192.0.2.10", "[2001:db8::1]:443", "2001:db8::1"}
	ok("ip-literals", "D36: IPv4 literal as id; IPv6 literal in canonical form (RFC 5952) as ipv6-<form with - for :>, label in brackets. D69: an unbracketed IPv6 Host resolves like a bracketed one, as in Caddy.",
		in, []map[string]any{site("192.0.2.10", "192.0.2.10", P, true, "192.0.2.10"), site("ipv6-2001-db8--1", "[2001:db8::1]", P, true, "2001:db8::1")},
		"192.0.2.10", "ipv6-2001-db8--1", "ipv6-2001-db8--1")
	var many []map[string]any
	var exp []map[string]any
	for i := 1; i <= 34; i++ {
		h := fmt.Sprintf("s%02d.example.org", i)
		if i == 5 {
			many = append(many, blk(false, true, h))
			exp = append(exp, site(h, h, U, false, h))
			continue
		}
		many = append(many, blk(true, true, h))
		exp = append(exp, site(h, h, P, i <= 33, h))
	}
	in = ing(many...)
	in["unprotected_sites"] = []string{"s05.example.org"}
	ok("cap-32", "D36: the first 32 websites schild sees are tracked (own series); later ones are summed as _other; an unprotected website does not use a place.",
		in, exp)
	in = map[string]any{"mode": "proxy", "site_hosts": []string{"Verein.example", "www.verein.example", "verein.example"}, "resolve": []string{"anything.example.net", "verein.example"}}
	ok("proxy-site-hosts", "D36: proxy mode: one website named after the first of upstream.site_hosts (normalised, duplicates dropped); every request belongs to it.",
		in, []map[string]any{site("verein.example", "verein.example", P, true, "verein.example", "www.verein.example")}, "verein.example", "verein.example")
	ok("proxy-default", "D36: proxy mode without upstream.site_hosts: the one website default (local to this gateway, never merged across gateways).",
		map[string]any{"mode": "proxy", "resolve": []string{"example.org"}}, []map[string]any{site("default", "default", P, true)}, "default")
	ok("proxy-wildcard", "D36: proxy mode with a wildcard first host.",
		map[string]any{"mode": "proxy", "site_hosts": []string{"*.example.org"}}, []map[string]any{site("_.example.org", "*.example.org", P, true, "*.example.org")})

	bad := func(name string, code contract.Code, desc string, in map[string]any) {
		g.add(c, name, false, code, desc, ctx, mustJSON(in), in)
	}
	bad("proxies-without-schild", contract.CodeConfig, "D36: a block that reaches a backend without schild and is not listed is refused (MVP-19 validator).",
		ing(blk(true, true, "example.org"), blk(false, true, "admin.example.org")))
	in = ing(blk(false, true, "admin.example.org", "example.org"))
	in["unprotected_sites"] = []string{"admin.example.org"}
	bad("listed-partly", contract.CodeConfig, "D36: a block counts as listed only when every host of it is listed.", in)
	bad("scheme", contract.CodeSchema, "D36: only http and https.", ing(blk(true, true, "ftp://example.org")))
	bad("placeholder", contract.CodeSchema, "D36: addresses are derived after environment substitution; a placeholder is refused.", ing(blk(true, true, "{$DOMAIN}")))
	bad("port-zero", contract.CodeSchema, "D36: port 1..65535.", ing(blk(true, true, "example.org:0")))
	bad("port-too-large", contract.CodeSchema, "D36: port 1..65535.", ing(blk(true, true, "example.org:65536")))
	bad("partial-wildcard", contract.CodeSchema, "D36: a wildcard is a whole label.", ing(blk(true, true, "a*.example.org")))
	bad("upper-case-unicode", contract.CodeSchema, "D36: non-ASCII letters must be lower case (no further IDNA mapping).", ing(blk(true, true, "BÜCHER.example")))
	bad("label-too-long", contract.CodeSchema, "D36: a label has at most 63 characters.", ing(blk(true, true, strings.Repeat("a", 64)+".example.org")))
	bad("underscore", contract.CodeSchema, "D36: labels are letters, digits and hyphens.", ing(blk(true, true, "_dmarc.example.org")))
	bad("empty-label", contract.CodeSchema, "D36: no empty label.", ing(blk(true, true, ".example.org")))
	bad("only-dot", contract.CodeSchema, "D36: a host of one dot is no name.", ing(blk(true, true, ".")))
	bad("ipv6-zone", contract.CodeSchema, "D36: no IPv6 zone.", ing(blk(true, true, "[fe80::1%eth0]")))
	bad("ipv4-mapped", contract.CodeSchema, "D36: IPv4-mapped IPv6 literals are written as IPv4.", ing(blk(true, true, "[::ffff:192.0.2.1]")))
	bad("space", contract.CodeSchema, "D36: no space inside an address.", ing(blk(true, true, "example.org other.example.org")))
	bad("ingress-site-hosts", contract.CodeSchema, "D36: upstream.site_hosts belongs to proxy mode.", map[string]any{"mode": "ingress", "blocks": []any{blk(true, true, "example.org")}, "site_hosts": []string{"example.org"}})
	bad("proxy-blocks", contract.CodeSchema, "D36: proxy mode has no site blocks.", map[string]any{"mode": "proxy", "blocks": []any{blk(true, true, "example.org")}})
	bad("no-addresses", contract.CodeSchema, "D36: a block has at least one address.", ing(map[string]any{"addresses": []string{}, "schild": true, "proxies": true}))
	bad("unknown-field", contract.CodeSchema, "D36: no other fields (no site id chosen by hand here; that is MVP-16).", map[string]any{"mode": "proxy", "id": "verein"})
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "D36: duplicate keys are malformed JSON.", ctx, []byte(`{"mode":"proxy","mode":"ingress"}`), nil)
}

func genWebsiteStatus(g *gen) {
	const c = "website-status"
	ctx := vectors.Context{}
	traffic := func(req, fwd, fc, ue, ut, s5 int) map[string]any {
		return map[string]any{"requests": req, "forwarded": fwd, "fail_closed": fc, "upstream_errors": ue, "upstream_timeouts": ut, "status_5xx": s5}
	}
	srv := func(node, state, gs string, hints ...map[string]any) map[string]any {
		if hints == nil {
			hints = []map[string]any{}
		}
		return map[string]any{"node": node, "state": state, "baseline_protection": gs, "hints": hints}
	}
	hint := func(code, level, object string) map[string]any {
		h := map[string]any{"code": code, "level": level}
		if object != "" {
			h["object"] = object
		}
		return h
	}
	in := func(t map[string]any, servers ...map[string]any) map[string]any {
		m := map[string]any{"protection": "protected", "tracked": true, "monitoring": true, "servers": servers}
		if servers == nil {
			m["servers"] = []any{}
		}
		if t != nil {
			m["traffic"] = t
		}
		return m
	}
	reason := func(code, node, h, object string) map[string]any {
		r := map[string]any{"code": code}
		if node != "" {
			r["node"] = node
		}
		if h != "" {
			r["hint"] = h
		}
		if object != "" {
			r["object"] = object
		}
		return r
	}
	res := func(status string, reasons ...map[string]any) map[string]any {
		if reasons == nil {
			reasons = []map[string]any{}
		}
		return map[string]any{"status": status, "reasons": reasons}
	}
	ok := func(name, desc string, m, r map[string]any) {
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, r)
	}
	web1 := func(hints ...map[string]any) map[string]any { return srv("web-1", "ok", "active", hints...) }
	normal := traffic(12000, 11900, 0, 3, 0, 4)

	ok("ok", "D36: normal traffic, no hints: ok (\"läuft\").", in(normal, web1()), res("ok"))
	ok("idle", "D36: no requests in 5 minutes: still ok (a quiet website is no problem).", in(traffic(0, 0, 0, 0, 0, 0), web1()), res("ok"))
	ok("server-hint", "D36: a hint of the server it runs on: attention (\"bitte ansehen\"), shown as \"web-1: Platte fast voll\".",
		in(normal, web1(hint("disk_full_soon", "notice", "/var/lib/docker"))), res("attention", reason("server_hint", "web-1", "disk_full_soon", "/var/lib/docker")))
	ok("info-hint", "D36: any hint counts, also level info (initiator 2026-10-29: \"jeder Hinweis\").",
		in(normal, web1(hint("swap_active", "info", ""))), res("attention", reason("server_hint", "web-1", "swap_active", "")))
	m := in(normal, web1())
	m["site_hints"] = []any{hint("upstream_slow", "notice", "")}
	ok("site-hint", "D36: a hint of the website itself: attention.", m, res("attention", reason("site_hint", "", "upstream_slow", "")))
	ok("not-ready", "D36: the only gateway is not ready (schild answers 503): disrupted (\"gestört\").",
		in(normal, srv("web-1", "not_ready", "active")), res("disrupted", reason("not_ready", "web-1", "", "")))
	ok("baseline-off", "D36: baseline protection off on the only gateway: it fails closed, disrupted.",
		in(normal, srv("web-1", "ok", "off")), res("disrupted", reason("baseline_off", "web-1", "", "")))
	ok("baseline-degraded", "D36: baseline protection degraded: attention.",
		in(normal, srv("web-1", "ok", "degraded")), res("attention", reason("baseline_degraded", "web-1", "", "")))
	ok("fail-closed-5-percent", "D36: 10 of 200 requests answered 503 by schild (exactly 5 %): disrupted.",
		in(traffic(200, 190, 10, 0, 0, 10), web1()), res("disrupted", reason("fail_closed", "", "", "")))
	ok("fail-closed-below", "D36: 10 of 201 (below 5 %): not disrupted by this rule.",
		in(traffic(201, 191, 10, 0, 0, 10), web1()), res("ok"))
	ok("fail-closed-min-count", "D36: 9 of 20 (45 %) but fewer than 10 requests: not disrupted (no flapping on tiny traffic).",
		in(traffic(20, 11, 9, 0, 0, 9), web1()), res("ok"))
	ok("upstream-and-5xx", "D36: 15 errors and 5 timeouts of 100 forwarded (20 %) and 20 of 100 answers 5xx: disrupted with both reasons.",
		in(traffic(100, 100, 0, 15, 5, 20), web1()), res("disrupted", reason("upstream_unreachable", "", "", ""), reason("errors_5xx", "", "", "")))
	ok("app-5xx", "D36: the app itself answers 5xx to 30 of 100 requests: disrupted (errors_5xx only).",
		in(traffic(100, 100, 0, 0, 0, 30), web1()), res("disrupted", reason("errors_5xx", "", "", "")))
	m = in(traffic(400, 380, 20, 0, 0, 20), web1(hint("waf_saturated", "warning", "")))
	m["site_hints"] = []any{hint("fail_closed", "warning", "")}
	ok("disrupted-with-hints", "D36: the deciding reasons come first, then the attention reasons (site hints before server hints).",
		m, res("disrupted", reason("fail_closed", "", "", ""), reason("site_hint", "", "fail_closed", ""), reason("server_hint", "web-1", "waf_saturated", "")))
	ok("one-of-two-down", "D36 (MVP-20): the website runs on two gateways, one is not ready: attention, not disrupted.",
		in(normal, srv("web-1", "ok", "active"), srv("web-2", "not_ready", "active")), res("attention", reason("not_ready", "web-2", "", "")))
	ok("all-unreachable", "D36 (MVP-20): no gateway of the website answers the central dashboard: disrupted.",
		in(nil, srv("web-1", "unreachable", "active"), srv("web-2", "unreachable", "active")),
		res("disrupted", reason("unreachable", "web-1", "", ""), reason("unreachable", "web-2", "", "")))
	m = in(nil, web1())
	m["protection"] = "unprotected"
	ok("unprotected", "D36: unprotected website: unknown (schild sees none of its requests).", m, res("unknown", reason("unprotected", "", "", "")))
	m = in(nil, web1())
	m["tracked"] = false
	ok("untracked", "D36: beyond the first 32 websites, no hint: unknown (its numbers are in _other).", m, res("unknown", reason("untracked", "", "", "")))
	m = in(nil, web1(hint("memory_low", "warning", "")))
	m["tracked"] = false
	ok("untracked-hint", "D36: untracked, but its server has a hint: attention.", m, res("attention", reason("server_hint", "web-1", "memory_low", "")))
	m = in(normal, web1())
	m["monitoring"] = false
	ok("monitoring-off", "D36: monitoring off: counters are ignored, unknown.", m, res("unknown", reason("monitoring_off", "", "", "")))
	ok("no-data", "D36: monitoring on, tracked, but no counters yet (first seconds after start): unknown.", in(nil, web1()), res("unknown", reason("no_data", "", "", "")))
	ok("no-server", "D36: no gateway serves it (central dashboard, after a config change): unknown.", in(normal), res("unknown", reason("no_server", "", "", "")))

	bad := func(name, desc string, m map[string]any) {
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(m), m)
	}
	bad("duplicate-node", "D36: each gateway once.", in(normal, web1(), web1()))
	m = in(normal, web1())
	m["site_hints"] = []any{hint("disk_full_soon", "notice", "/")}
	bad("site-hint-host-code", "D36: host codes are server hints, never website hints.", m)
	bad("server-hint-site-code", "D36: website codes are never server hints.", in(normal, web1(hint("upstream_errors", "notice", ""))))
	bad("level-critical", "D36: calm levels only (info, notice, warning).", in(normal, web1(hint("cpu_high", "critical", ""))))
	bad("negative-count", "D36: counts are not negative.", in(traffic(10, 10, -1, 0, 0, 0), web1()))
	bad("state-down", "D36: state ok, not_ready or unreachable.", in(normal, srv("web-1", "down", "active")))
	bad("traffic-missing-field", "D36: all six counters.", in(map[string]any{"requests": 1}, web1()))
	m = in(normal, web1())
	delete(m, "servers")
	bad("servers-missing", "D36: servers is required (empty for none).", m)
	m = in(normal, web1())
	m["ip"] = "192.0.2.1"
	bad("unknown-field", "D36: no other fields (no addresses).", m)
	bad("object-space", "D36: objects are local names.", in(normal, web1(hint("disk_full_soon", "notice", "/var/lib docker"))))
	bad("node-upper-case", "D36: node names are ids.", in(normal, srv("Web-1", "ok", "active")))
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "D36: duplicate keys are malformed JSON.", ctx,
		[]byte(`{"protection":"protected","protection":"unprotected","tracked":true,"monitoring":true,"servers":[]}`), nil)
}
