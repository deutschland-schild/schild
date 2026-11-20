//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D36 amendment (initiator, 2026-10-29): "Besucher" are people, not bots
// (website-visitor), and a Referer from any website of the gateway is
// _intern (website-derive own_hosts). Appended after the D29 ladder vectors
// so every earlier vector keeps its number.

func genWebsiteVisitor(g *gen) {
	const c = "website-visitor"
	ctx := vectors.Context{}
	in := func(ua, cat, out string) map[string]any {
		return map[string]any{"ua_class": ua, "bot_category": cat, "outcome": out}
	}
	ok := func(name, desc string, m map[string]any, visitor, bot bool) {
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, map[string]any{"visitor": visitor, "bot_client": bot})
	}
	ok("browser-passed", "D36 amendment: a browser user agent whose request schild forwarded is a visitor.", in("browser", "likely_browser", "passed"), true, false)
	ok("browser-would-block", "D36 amendment: forwarded in observe mode (hätte gesperrt) still counts: the request reached the website.", in("browser", "likely_browser", "would_block"), true, false)
	ok("browser-blocked-waf", "D36 amendment: a request the WAF stopped makes no visitor, even with a browser user agent, and no bot client either.", in("browser", "likely_browser", "blocked_waf"), false, false)
	ok("browser-blocked-behaviour", "D36 amendment: a behaviour block makes no visitor.", in("browser", "likely_browser", "blocked_behaviour"), false, false)
	ok("browser-rate-limited", "D36 amendment: a rate-limited request makes no visitor.", in("browser", "likely_browser", "rate_limited"), false, false)
	ok("browser-rejected-limit", "D36 amendment: a request refused by a hard limit makes no visitor.", in("browser", "likely_browser", "rejected_limit"), false, false)
	ok("browser-fail-closed", "D36 amendment: a fail-closed 503 makes no visitor (the request never reached the website).", in("browser", "likely_browser", "fail_closed"), false, false)
	ok("bot-verified", "D36 amendment: a verified search engine is a bot client, never a visitor.", in("bot_verified", "search_engine", "passed"), false, true)
	ok("bot-unverified-ai", "D36 amendment: an AI crawler that is not verified is a bot client.", in("bot_unverified", "ai_training", "passed"), false, true)
	ok("bot-unverified-generic", "D36 amendment: a generic bot token without catalogue entry (likely_automated) is a bot client.", in("bot_unverified", "likely_automated", "would_block"), false, true)
	ok("tool", "D36 amendment: HTTP libraries and command line tools are bot clients.", in("tool", "tool_library", "passed"), false, true)
	ok("scanner-blocked", "D36 amendment: a security scanner stopped by the WAF is still a bot client (the bot estimate counts every outcome).", in("tool", "security_scanner", "blocked_waf"), false, true)
	ok("no-user-agent", "D36 amendment: a request without User-Agent is a bot client.", in("none", "likely_automated", "passed"), false, true)
	ok("other", "D36 amendment: a user agent that is neither browser, bot nor tool (likely automated) is a bot client.", in("other", "likely_automated", "passed"), false, true)
	ok("preview-fail-closed", "D36 amendment: a link preview fetcher is a bot client whatever schild did.", in("bot_unverified", "preview_social", "fail_closed"), false, true)

	bad := func(name, desc string, m map[string]any) {
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(m), m)
	}
	bad("browser-with-bot-category", "D36 amendment: ua_class browser comes with bot category likely_browser only.", in("browser", "likely_automated", "passed"))
	bad("browser-with-catalogue-category", "D36 amendment: a catalogue category is never a browser.", in("browser", "ai_assistant", "passed"))
	bad("likely-browser-as-bot", "D36 amendment: likely_browser comes with ua_class browser only.", in("bot_unverified", "likely_browser", "passed"))
	bad("likely-browser-as-tool", "D36 amendment: likely_browser comes with ua_class browser only.", in("tool", "likely_browser", "passed"))
	bad("no-user-agent-as-browser", "D36 amendment: a request without User-Agent is likely_automated.", in("none", "likely_browser", "passed"))
	bad("no-user-agent-with-catalogue-category", "D36 amendment: a request without User-Agent matches no catalogue entry.", in("none", "search_engine", "passed"))
	bad("unknown-ua-class", "D36 amendment: ua_class is one of the six UAClass values.", in("human", "likely_browser", "passed"))
	bad("unknown-category", "D36 amendment: bot_category is one of the 13 BotCategory values.", in("bot_unverified", "crawler", "passed"))
	bad("unknown-outcome", "D36 amendment: outcome is a RequestOutcome (challenged is no request ring outcome).", in("browser", "likely_browser", "challenged"))
	bad("missing-outcome", "D36 amendment: all three fields are required.", map[string]any{"ua_class": "browser", "bot_category": "likely_browser"})
	bad("extra-field", "D36 amendment: no other fields (no address, no user agent).", map[string]any{"ua_class": "browser", "bot_category": "likely_browser", "outcome": "passed", "user_agent": "Mozilla/5.0"})
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "D36 amendment: duplicate keys are malformed JSON.", ctx,
		[]byte(`{"ua_class":"browser","bot_category":"likely_browser","outcome":"passed","outcome":"blocked_waf"}`), nil)
}

// genWebsiteDeriveOwnHosts: Set.OwnHost, the hosts whose Referer is _intern.
func genWebsiteDeriveOwnHosts(g *gen) {
	const c = "website-derive"
	ctx := vectors.Context{}
	ok := func(name, desc string, in map[string]any, sites []map[string]any, own ...bool) {
		r := map[string]any{"websites": sites, "own": own}
		g.addResult(c, name, true, "", desc, ctx, mustJSON(in), in, r)
	}
	const P, U = "protected", "unprotected"
	in := map[string]any{"mode": "ingress", "blocks": []any{
		blk(true, true, "shop.example.org", "www.shop.example.org"),
		blk(true, true, "*.kunden.example.org"),
		blk(false, true, "legacy.example.org"),
		blk(true, true, "verein.example"),
		blk(true, true, ":8080"),
	}, "unprotected_sites": []string{"legacy.example.org"}}
	in["own_hosts"] = []string{"verein.example", "WWW.Shop.Example.ORG.", "shop.example.org:8443", "a.kunden.example.org", "kunden.example.org",
		"legacy.example.org", "example.org", "blog.verein.example", "", "*.kunden.example.org", "bad host"}
	ok("own-hosts-ingress", "D36 amendment: a Referer host of any website of the gateway is _intern - exact hosts (case, trailing dot and port ignored), wildcard hosts (one label), unprotected websites too; the parent domain, other subdomains, the host-less catch-all, an empty, wildcard or malformed host are not own.",
		in, []map[string]any{
			site("shop.example.org", "shop.example.org", P, true, "shop.example.org", "www.shop.example.org"),
			site("_.kunden.example.org", "*.kunden.example.org", P, true, "*.kunden.example.org"),
			site("legacy.example.org", "legacy.example.org", U, false, "legacy.example.org"),
			site("verein.example", "verein.example", P, true, "verein.example"),
			site("_any", "_any", P, true)},
		true, true, true, true, false, true, false, false, false, false, false)
	in = map[string]any{"mode": "ingress", "blocks": []any{blk(true, true, "192.0.2.10"), blk(true, true, "[2001:db8::1]")},
		"own_hosts": []string{"192.0.2.10:443", "[2001:0db8::1]", "192.0.2.11", "2001:db8::1"}}
	ok("own-hosts-ip-literals", "D36 amendment: IP literal websites own their literal (IPv6 in brackets, canonical form); an unbracketed IPv6 host is not parsed.",
		in, []map[string]any{site("192.0.2.10", "192.0.2.10", P, true, "192.0.2.10"), site("ipv6-2001-db8--1", "[2001:db8::1]", P, true, "2001:db8::1")},
		true, true, false, false)
	in = map[string]any{"mode": "proxy", "site_hosts": []string{"verein.example", "*.verein.example"},
		"own_hosts": []string{"verein.example", "www.verein.example", "a.b.verein.example", "other.example"}}
	ok("own-hosts-proxy", "D36 amendment: proxy mode owns upstream.site_hosts (wildcards one label deep), nothing else.",
		in, []map[string]any{site("verein.example", "verein.example", P, true, "verein.example", "*.verein.example")},
		true, true, false, false)
	ok("own-hosts-proxy-default", "D36 amendment: proxy mode without upstream.site_hosts owns no host; only the request's own host and its registrable domain are _intern.",
		map[string]any{"mode": "proxy", "own_hosts": []string{"example.org"}}, []map[string]any{site("default", "default", P, true)}, false)

	bad := func(name, desc string, in map[string]any) {
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(in), in)
	}
	bad("own-hosts-empty", "D36 amendment: own_hosts has at least one entry when given.", map[string]any{"mode": "proxy", "own_hosts": []string{}})
	bad("own-hosts-not-string", "D36 amendment: own_hosts are strings.", map[string]any{"mode": "proxy", "own_hosts": []any{1}})
	many := make([]string, 51)
	for i := range many {
		many[i] = "example.org"
	}
	bad("own-hosts-too-many", "D36 amendment: at most 50 own_hosts per vector.", map[string]any{"mode": "proxy", "own_hosts": many})
}
