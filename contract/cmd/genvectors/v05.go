//go:build !release

package main

import (
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// v0.5 (MVP-22, D35): request ring, bots and geo in schild.yaml; the bot
// catalogue, bot matching and verification, and the geo field mapping.
// Appended after every v0.4 vector so earlier vectors keep their numbers.
// Addresses are documentation ranges (RFC 5737, RFC 3849) only; the
// catalogue below is TEST ONLY data, not the shipped catalogue.

func genSiteConfigV05(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	with := func(base func() map[string]any, key string, v any) map[string]any {
		m := base()
		m[key] = v
		return m
	}
	req := func(r map[string]any) map[string]any { return map[string]any{"requests": r} }

	add(true, "", "requests-defaults", "v0.5 MVP-22: empty request ring section: on with monitoring, kept as long as retention.raw_ip_days (D66), 512 MB.", with(siteConfig, "monitoring", req(map[string]any{})))
	add(true, "", "requests-full", "v0.5 MVP-22: 24 h, 1 GB (D63: raw_paths removed, real paths always).", with(standaloneConfig, "monitoring", req(map[string]any{
		"enabled": true, "keep_hours": 24, "max_size_mb": 1024})))
	add(true, "", "requests-off", "v0.5 MVP-22: monitoring on, request ring off.", with(siteConfig, "monitoring", req(map[string]any{"enabled": false})))
	add(true, "", "requests-monitoring-off", "v0.5 MVP-22: monitoring off turns the ring off; its other keys may stay.", with(standaloneConfig, "monitoring", map[string]any{
		"enabled": false, "requests": map[string]any{"keep_hours": 12}}))
	add(true, "", "bots-defaults", "v0.5 MVP-22: empty bots section: ranges checked, no FCrDNS, daily direct range fetch (D67).", with(siteConfig, "bots", map[string]any{}))
	add(true, "", "bots-full", "v0.5 MVP-22: FCrDNS and the direct range fetch switched on by the operator.", with(standaloneConfig, "bots", map[string]any{
		"verify": map[string]any{"ranges": true, "fcrdns": true}, "ranges_fetch": true}))
	add(true, "", "geo-ipinfo", "v0.5 MVP-22: IPinfo with the operator's own token from a file; IPinfo Lite, daily.", with(siteConfig, "geo", map[string]any{
		"provider": "ipinfo", "token_file": "/etc/schild/ipinfo.token"}))
	add(true, "", "geo-ipinfo-env", "v0.5 MVP-22: IPinfo with the token from SCHILD_GEO_TOKEN, every 12 h, gateway without the network.", with(standaloneConfig, "geo", map[string]any{
		"provider": "ipinfo", "refresh_hours": 12}))
	add(true, "", "geo-maxmind-paid", "v0.5 MVP-22: MaxMind paid databases incl. anonymous IP, every 3 days.", with(siteConfig, "geo", map[string]any{
		"provider": "maxmind", "token_file": "/etc/schild/maxmind.token", "database": []string{"GeoIP2-Country", "GeoIP2-ISP", "GeoIP2-Anonymous-IP"}, "refresh_hours": 72}))
	add(true, "", "geo-dbip-explicit", "v0.5 MVP-22: the bundled DB-IP Lite named explicitly (the default).", with(siteConfig, "geo", map[string]any{
		"provider": "dbip", "db_path": "/var/lib/schild/geo/geo.mmdb"}))

	for _, f := range []struct {
		name string
		code contract.Code
		key  string
		v    any
		desc string
	}{
		{"requests-keep-too-long", contract.CodeSchema, "monitoring", req(map[string]any{"keep_hours": 721}), "D66: single requests are kept at most 720 h (30 days)."},
		{"requests-keep-zero", contract.CodeSchema, "monitoring", req(map[string]any{"keep_hours": 0}), "v0.5 MVP-22: keep_hours at least 1."},
		{"requests-size-too-small", contract.CodeSchema, "monitoring", req(map[string]any{"max_size_mb": 15}), "v0.5 MVP-22: max_size_mb at least 16."},
		{"requests-size-too-large", contract.CodeSchema, "monitoring", req(map[string]any{"max_size_mb": 4097}), "v0.5 MVP-22: max_size_mb at most 4096."},
		{"requests-raw-paths-duplicate", contract.CodeSchema, "monitoring", req(map[string]any{"raw_paths": []string{"verein.example", "verein.example"}}), "D63: raw_paths is gone, every record keeps the real path."},
		{"requests-raw-paths-path", contract.CodeSchema, "monitoring", req(map[string]any{"raw_paths": []string{"/blog"}}), "D63: raw_paths is gone, also with a path in it."},
		{"requests-store-ip", contract.CodeSchema, "monitoring", req(map[string]any{"store_ip": true}), "v0.5 MVP-22: no switch stores addresses in the ring."},
		{"requests-query-strings", contract.CodeSchema, "monitoring", req(map[string]any{"query_strings": true}), "v0.5 MVP-22: query strings are never stored."},
		{"requests-without-monitoring", contract.CodeConfig, "monitoring", map[string]any{"enabled": false, "requests": map[string]any{"enabled": true}}, "v0.5 MVP-22: the ring needs the monitoring counters (semantic check)."},
		{"bots-fcrdns-string", contract.CodeSchema, "bots", map[string]any{"verify": map[string]any{"fcrdns": "on"}}, "v0.5 MVP-22: fcrdns is a boolean."},
		{"bots-block-ai", contract.CodeSchema, "bots", map[string]any{"block_ai_crawlers": true}, "v0.5 MVP-22: no blocking or charging of AI crawlers (decided 2026-10-29: not now)."},
		{"bots-robots-enforce", contract.CodeSchema, "bots", map[string]any{"robots_txt": map[string]any{"enforce": true}}, "v0.5 MVP-22: robots.txt is observed, never enforced."},
		{"bots-verify-unknown", contract.CodeSchema, "bots", map[string]any{"verify": map[string]any{"whois": true}}, "v0.5 MVP-22: only ranges and FCrDNS; no lookups at third parties."},
		{"geo-token-inline", contract.CodeSchema, "geo", map[string]any{"provider": "ipinfo", "token": "TEST-ONLY-NOT-A-TOKEN"}, "v0.5 MVP-22: the token never lives in schild.yaml (token_file or SCHILD_GEO_TOKEN)."},
		{"geo-license-key-inline", contract.CodeSchema, "geo", map[string]any{"provider": "maxmind", "license_key": "TEST-ONLY-NOT-A-KEY"}, "v0.5 MVP-22: no licence key in schild.yaml either."},
		{"geo-unknown-provider", contract.CodeSchema, "geo", map[string]any{"provider": "ip2location"}, "v0.5 MVP-22: dbip, ipinfo or maxmind."},
		{"geo-live-api", contract.CodeSchema, "geo", map[string]any{"provider": "ipinfo", "lookup": "api"}, "v0.5 MVP-22: no live lookups per request (they would send visitor addresses out)."},
		{"geo-token-file-relative", contract.CodeSchema, "geo", map[string]any{"provider": "ipinfo", "token_file": "ipinfo.token"}, "v0.5 MVP-22: token_file is an absolute path."},
		{"geo-token-file-dbip", contract.CodeSchema, "geo", map[string]any{"provider": "dbip", "token_file": "/etc/schild/ipinfo.token"}, "v0.5 MVP-22: the bundled database needs no token."},
		{"geo-token-file-default-provider", contract.CodeSchema, "geo", map[string]any{"token_file": "/etc/schild/ipinfo.token"}, "v0.5 MVP-22: without provider (dbip) no token_file."},
		{"geo-database-dbip", contract.CodeSchema, "geo", map[string]any{"provider": "dbip", "database": []string{"dbip-city-lite"}}, "v0.5 MVP-22: the bundled database is not chosen by name."},
		{"geo-refresh-dbip", contract.CodeSchema, "geo", map[string]any{"refresh_hours": 24}, "v0.5 MVP-22: nothing is downloaded for dbip."},
		{"geo-refresh-zero", contract.CodeSchema, "geo", map[string]any{"provider": "maxmind", "refresh_hours": 0}, "v0.5 MVP-22: refresh_hours at least 1."},
		{"geo-refresh-too-long", contract.CodeSchema, "geo", map[string]any{"provider": "maxmind", "refresh_hours": 169}, "v0.5 MVP-22: refresh_hours at most 168."},
		{"geo-database-duplicate", contract.CodeSchema, "geo", map[string]any{"provider": "maxmind", "database": []string{"GeoLite2-ASN", "GeoLite2-ASN"}}, "v0.5 MVP-22: each database once."},
		{"geo-database-path", contract.CodeSchema, "geo", map[string]any{"provider": "maxmind", "database": []string{"../GeoLite2-ASN"}}, "v0.5 MVP-22: database ids, never paths."},
	} {
		add(false, f.code, f.name, f.desc, with(siteConfig, f.key, f.v))
	}
}

// testCatalogue is the TEST ONLY catalogue of the bot vectors (not the
// shipped one): three range sets with documentation prefixes, one stale
// (55 days) and one exactly 30 days old at the vector clock.
func testCatalogue() map[string]any {
	google := map[string]any{"ranges": "googlebot", "rdns_suffixes": []string{"googlebot.com", "google.com"}}
	return map[string]any{
		"schema":            "schild.bot_catalogue/0.1",
		"version":           "2026-10-26.1",
		"generated_at":      "2026-10-20T12:00:00Z",
		"sources":           []any{map[string]any{"id": "ai-robots-txt", "license": "MIT", "url": "https://github.com/ai-robots-txt/ai.robots.txt"}},
		"automation_tokens": []string{"bot", "crawl", "spider", "scrape", "headless", "python", "curl"},
		"bots": []any{
			map[string]any{"id": "googlebot-image", "name": "Googlebot-Image", "operator": "Google", "category": "search_engine", "robots_token": "Googlebot-Image", "ua_match": []string{"Googlebot-Image"}, "verify": google},
			map[string]any{"id": "googlebot", "name": "Googlebot", "operator": "Google", "category": "search_engine", "robots_token": "Googlebot", "ua_match": []string{"Googlebot"}, "verify": google},
			map[string]any{"id": "gptbot", "name": "GPTBot", "operator": "OpenAI", "category": "ai_training", "robots_token": "GPTBot", "ua_match": []string{"GPTBot"}, "verify": map[string]any{"ranges": "gptbot"}, "source": "ai-robots-txt"},
			map[string]any{"id": "chatgpt-user", "name": "ChatGPT-User", "operator": "OpenAI", "category": "ai_assistant", "robots_token": "ChatGPT-User", "ua_match": []string{"ChatGPT-User"}, "verify": map[string]any{}, "source": "ai-robots-txt"},
			map[string]any{"id": "bingbot", "name": "Bingbot", "operator": "Microsoft", "category": "search_engine", "robots_token": "bingbot", "ua_match": []string{"bingbot"}, "verify": map[string]any{"ranges": "bingbot"}},
			map[string]any{"id": "examplebot", "name": "ExampleBot", "operator": "Example Search", "category": "seo_tool", "ua_match": []string{"ExampleBot"}, "verify": map[string]any{"rdns_suffixes": []string{"crawl.example.net"}}},
			map[string]any{"id": "curl", "name": "curl", "operator": "curl project", "category": "tool_library", "ua_match": []string{"curl/"}, "verify": map[string]any{}},
		},
		"ranges": []any{
			map[string]any{"id": "googlebot", "operator": "Google", "url": "https://developers.google.com/static/search/apis/ipranges/googlebot.json", "fetched_at": "2026-10-20T00:00:00Z", "prefixes": []string{"192.0.2.0/27", "2001:db8:4860::/48"}},
			map[string]any{"id": "gptbot", "operator": "OpenAI", "url": "https://openai.com/gptbot.json", "fetched_at": "2026-09-01T00:00:00Z", "prefixes": []string{"198.51.100.0/28"}},
			map[string]any{"id": "bingbot", "operator": "Microsoft", "url": "https://www.bing.com/toolbox/bingbot.json", "fetched_at": "2026-09-26T12:00:00Z", "prefixes": []string{"203.0.113.0/26"}},
		},
	}
}

func catBot(m map[string]any, i int) map[string]any   { return m["bots"].([]any)[i].(map[string]any) }
func catRange(m map[string]any, i int) map[string]any { return m["ranges"].([]any)[i].(map[string]any) }

func genBotCatalogue(g *gen) {
	const c = "bot-catalogue"
	ctx := vectors.Context{}
	add := func(valid bool, name, desc string, m map[string]any) {
		code := contract.Code("")
		if !valid {
			code = contract.CodeSchema
		}
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	add(true, "test-catalogue", "v0.5 MVP-22: the TEST ONLY catalogue of the bot-match vectors.", testCatalogue())
	add(true, "minimal", "v0.5 MVP-22: one bot the operator publishes nothing for, no range sets.", map[string]any{
		"schema": "schild.bot_catalogue/0.1", "version": "2026-10-26.2", "generated_at": "2026-10-26T00:00:00Z",
		"sources":           []any{map[string]any{"id": "schild", "license": "Apache-2.0", "url": "https://schild.example/bots"}},
		"automation_tokens": []string{"bot"},
		"bots":              []any{map[string]any{"id": "feedfetcher", "name": "Example Feed", "operator": "Example", "category": "feed_reader", "ua_match": []string{"ExampleFeed"}, "verify": map[string]any{}}},
		"ranges":            []any{}})
	m := testCatalogue()
	catRange(m, 0)["prefixes"] = []string{"2001:db8:4860::/48", "2001:db8:4861::/48"}
	add(true, "ipv6-only-ranges", "v0.5 MVP-22: a range set with IPv6 prefixes only.", m)
	m = testCatalogue()
	catRange(m, 2)["prefixes"] = []string{"0.0.0.0/0"}
	add(true, "default-route", "v0.5 MVP-22: /0 is canonical (a catalogue review catches it, the schema does not).", m)
	m = testCatalogue()
	delete(catBot(m, 2), "source")
	delete(catBot(m, 3), "source")
	m["sources"] = []any{map[string]any{"id": "own", "license": "Apache-2.0", "url": "https://schild.example/bots"}}
	add(true, "own-entries", "v0.5 MVP-22: own entries without a source attribution.", m)

	bad := func(name, desc string, f func(m map[string]any)) {
		m := testCatalogue()
		f(m)
		add(false, name, desc, m)
	}
	bad("schema-version", "v0.5 MVP-22: unknown catalogue format.", func(m map[string]any) { m["schema"] = "schild.bot_catalogue/0.2" })
	bad("duplicate-bot", "v0.5 MVP-22: bot ids are unique.", func(m map[string]any) { catBot(m, 1)["id"] = "googlebot-image" })
	bad("duplicate-range-set", "v0.5 MVP-22: range set ids are unique.", func(m map[string]any) { catRange(m, 1)["id"] = "googlebot" })
	bad("unknown-range-set", "v0.5 MVP-22: verify.ranges names a range set of the catalogue.", func(m map[string]any) {
		catBot(m, 4)["verify"] = map[string]any{"ranges": "bingbot-v2"}
	})
	bad("unknown-source", "v0.5 MVP-22: a bot's source is listed in sources.", func(m map[string]any) { catBot(m, 2)["source"] = "darkvisitors" })
	bad("prefix-host-bits", "v0.5 MVP-22: prefixes are canonical (no host bits).", func(m map[string]any) { catRange(m, 0)["prefixes"] = []string{"192.0.2.1/27"} })
	bad("prefix-bits-leading-zero", "v0.5 MVP-22: prefix length without leading zeros.", func(m map[string]any) { catRange(m, 0)["prefixes"] = []string{"192.0.2.0/027"} })
	bad("prefix-ipv4-mapped", "v0.5 MVP-22: no IPv4-mapped IPv6 prefixes (IPv4 ranges are written as IPv4).", func(m map[string]any) {
		catRange(m, 0)["prefixes"] = []string{"::ffff:192.0.2.0/120"}
	})
	bad("prefix-too-long", "v0.5 MVP-22: an IPv4 prefix has at most 32 bits.", func(m map[string]any) { catRange(m, 1)["prefixes"] = []string{"198.51.100.0/33"} })
	bad("token-twice-case", "v0.5 MVP-22: ua_match tokens are unique ASCII case-insensitively across bots.", func(m map[string]any) {
		catBot(m, 4)["ua_match"] = []string{"GoogleBot"}
	})
	bad("token-is-automation-token", "v0.5 MVP-22: a bot token may not repeat an automation token.", func(m map[string]any) { catBot(m, 6)["ua_match"] = []string{"Curl"} })
	bad("unknown-category", "v0.5 MVP-22: fixed categories only.", func(m map[string]any) { catBot(m, 2)["category"] = "ai_crawler" })
	bad("category-likely", "v0.5 MVP-22: likely_* describe unmatched user agents, never a catalogue entry.", func(m map[string]any) { catBot(m, 2)["category"] = "likely_automated" })
	bad("ua-match-empty", "v0.5 MVP-22: every bot has a token.", func(m map[string]any) { catBot(m, 0)["ua_match"] = []string{} })
	bad("token-leading-space", "v0.5 MVP-22: tokens have no leading or trailing space.", func(m map[string]any) { catBot(m, 0)["ua_match"] = []string{" Googlebot-Image"} })
	bad("token-control", "v0.5 MVP-22: tokens are printable ASCII.", func(m map[string]any) { catBot(m, 0)["ua_match"] = []string{"Googlebot\tImage"} })
	bad("fetched-at-impossible", "v0.5 MVP-22: fetched_at is a real date.", func(m map[string]any) { catRange(m, 0)["fetched_at"] = "2026-02-30T00:00:00Z" })
	bad("block-field", "v0.5 MVP-22: the catalogue observes; no blocking field.", func(m map[string]any) { catBot(m, 2)["block"] = true })
	bad("http-url", "v0.5 MVP-22: range sources are fetched over HTTPS only.", func(m map[string]any) { catRange(m, 2)["url"] = "http://www.bing.com/toolbox/bingbot.json" })
	bad("rdns-suffix-ip", "v0.5 MVP-22: rDNS suffixes are domains.", func(m map[string]any) {
		catBot(m, 5)["verify"] = map[string]any{"rdns_suffixes": []string{"203.0.113.9"}}
	})
}

const (
	uaGooglebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	uaGPTBot    = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"
	uaChrome    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

func genBotMatch(g *gen) {
	const c = "bot-match"
	ctx := vectors.Context{}
	in := func(ua, ip string, extra map[string]any, opt map[string]any) map[string]any {
		r := map[string]any{"user_agent": ua, "ip": ip}
		for k, v := range extra {
			r[k] = v
		}
		m := map[string]any{"catalogue": testCatalogue(), "request": r}
		if opt != nil {
			m["options"] = opt
		}
		return m
	}
	res := func(bot, cat, ver string) map[string]any {
		out := map[string]any{"bot": nil, "category": cat, "verification": nil}
		if bot != "" {
			out["bot"], out["verification"] = bot, ver
		}
		return out
	}
	ok := func(name, desc string, m map[string]any, r map[string]any) {
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), map[string]any{"request": m["request"], "options": m["options"]}, r)
	}
	fc := map[string]any{"fcrdns": true}

	ok("googlebot-verified", "v0.5 MVP-22: Googlebot from its published range: verified.", in(uaGooglebot, "192.0.2.10", nil, nil), res("googlebot", "search_engine", "verified"))
	ok("googlebot-spoofed", "v0.5 MVP-22: Googlebot user agent from an address outside Google's fresh ranges: mismatch (\"gibt sich als Googlebot aus\"), never verified.", in(uaGooglebot, "198.51.100.200", nil, nil), res("googlebot", "search_engine", "mismatch"))
	ok("googlebot-image-longest-token", "v0.5 MVP-22: the longest matching token wins (Googlebot-Image over Googlebot).", in("Googlebot-Image/1.0", "192.0.2.11", nil, nil), res("googlebot-image", "search_engine", "verified"))
	ok("googlebot-ipv6", "v0.5 MVP-22: IPv6 address in the published IPv6 range.", in(uaGooglebot, "2001:db8:4860:4801::1", nil, nil), res("googlebot", "search_engine", "verified"))
	ok("googlebot-ipv4-mapped", "v0.5 MVP-22: an IPv4-mapped IPv6 client address is unmapped before the check.", in(uaGooglebot, "::ffff:192.0.2.12", nil, nil), res("googlebot", "search_engine", "verified"))
	ok("googlebot-ranges-off", "v0.5 MVP-22: bots.verify.ranges false: a matched bot is only claimed.", in(uaGooglebot, "198.51.100.200", nil, map[string]any{"ranges": false}), res("googlebot", "search_engine", "claimed"))
	ok("googlebot-fcrdns-outside-ranges", "v0.5 MVP-22: with FCrDNS on, a confirmed googlebot.com name verifies even outside the snapshot.", in(uaGooglebot, "198.51.100.201", map[string]any{"fcrdns_name": "crawl-198-51-100-201.googlebot.com"}, fc), res("googlebot", "search_engine", "verified"))
	ok("gptbot-stale-in-range", "v0.5 MVP-22: the GPTBot snapshot is 55 days old: unknown_stale, even for an address inside it.", in(uaGPTBot, "198.51.100.5", nil, nil), res("gptbot", "ai_training", "unknown_stale"))
	ok("gptbot-stale-outside", "v0.5 MVP-22: stale snapshot, address outside: still unknown_stale, not mismatch.", in(uaGPTBot, "203.0.113.99", nil, nil), res("gptbot", "ai_training", "unknown_stale"))
	ok("gptbot-case-insensitive", "v0.5 MVP-22: tokens match ASCII case-insensitively.", in("mozilla/5.0 (compatible; gptbot/1.0)", "198.51.100.6", nil, nil), res("gptbot", "ai_training", "unknown_stale"))
	ok("bingbot-30-days", "v0.5 MVP-22: a snapshot exactly 30 days old is still fresh.", in("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "203.0.113.5", nil, nil), res("bingbot", "search_engine", "verified"))
	ok("chatgpt-user-claimed", "v0.5 MVP-22: the operator publishes no check for this bot in the test catalogue: claimed.", in("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", "203.0.113.70", nil, nil), res("chatgpt-user", "ai_assistant", "claimed"))
	ok("fcrdns-match", "v0.5 MVP-22: FCrDNS on, confirmed name under the documented suffix (trailing dot): verified.", in("ExampleBot/3.1", "203.0.113.80", map[string]any{"fcrdns_name": "Crawl-7.CRAWL.example.net."}, fc), res("examplebot", "seo_tool", "verified"))
	ok("fcrdns-other-suffix", "v0.5 MVP-22: FCrDNS on, the confirmed name only contains the suffix: mismatch.", in("ExampleBot/3.1", "203.0.113.81", map[string]any{"fcrdns_name": "crawl.example.net.attacker.example"}, fc), res("examplebot", "seo_tool", "mismatch"))
	ok("fcrdns-off", "v0.5 MVP-22: FCrDNS off (default): a name is ignored, the bot is claimed.", in("ExampleBot/3.1", "203.0.113.82", map[string]any{"fcrdns_name": "crawl-7.crawl.example.net"}, nil), res("examplebot", "seo_tool", "claimed"))
	ok("fcrdns-no-name", "v0.5 MVP-22: FCrDNS on but the lookup confirmed nothing: claimed.", in("ExampleBot/3.1", "203.0.113.83", nil, fc), res("examplebot", "seo_tool", "claimed"))
	ok("curl-tool", "v0.5 MVP-22: curl is a catalogue entry (Werkzeug/Bibliothek), claimed.", in("curl/8.5.0", "203.0.113.90", nil, nil), res("curl", "tool_library", "claimed"))
	ok("browser", "v0.5 MVP-22: an ordinary browser: likely_browser, no bot, no verification.", in(uaChrome, "203.0.113.91", nil, nil), res("", "likely_browser", ""))
	ok("empty-user-agent", "v0.5 MVP-22: no User-Agent: likely_automated.", in("", "203.0.113.92", nil, nil), res("", "likely_automated", ""))
	ok("library-without-mozilla", "v0.5 MVP-22: a user agent that does not start with Mozilla/: likely_automated.", in("Go-http-client/2.0", "203.0.113.93", nil, nil), res("", "likely_automated", ""))
	ok("headless-browser", "v0.5 MVP-22: Mozilla/ with an automation token (HeadlessChrome): likely_automated.", in(strings.Replace(uaChrome, "Chrome/", "HeadlessChrome/", 1), "203.0.113.94", nil, nil), res("", "likely_automated", ""))
	ok("token-after-512-bytes", "v0.5 MVP-22: only the first 512 bytes are matched; a token after them is not seen.", in("Mozilla/5.0 "+strings.Repeat("a", 520)+" GPTBot/1.2", "198.51.100.7", nil, nil), res("", "likely_browser", ""))
	ok("multibyte-cut", "v0.5 MVP-22: the 512-byte cut may split a UTF-8 character; matching is on bytes.", in("Mozilla/5.0 x"+strings.Repeat("ä", 260)+" bingbot", "203.0.113.6", nil, nil), res("", "likely_browser", ""))

	bad := func(name string, code contract.Code, desc string, m map[string]any) {
		g.add(c, name, false, code, desc, ctx, mustJSON(m), nil)
	}
	m := in(uaGooglebot, "192.0.2.300", nil, nil)
	bad("ip-not-address", contract.CodeSchema, "v0.5 MVP-22: the client address must parse.", m)
	m = in(uaGooglebot, "192.0.2.010", nil, nil)
	bad("ip-leading-zero", contract.CodeSchema, "v0.5 MVP-22: IPv4 with leading zeros is ambiguous and rejected.", m)
	m = in(uaGooglebot, "192.0.2.10", nil, nil)
	delete(m["request"].(map[string]any), "user_agent")
	bad("user-agent-missing", contract.CodeSchema, "v0.5 MVP-22: user_agent is required (empty when the request had none).", m)
	bad("user-agent-too-long", contract.CodeSchema, "v0.5 MVP-22: at most 8192 characters.", in(strings.Repeat("a", 8193), "192.0.2.10", nil, nil))
	bad("options-unknown", contract.CodeSchema, "v0.5 MVP-22: only ranges and fcrdns.", in(uaGooglebot, "192.0.2.10", nil, map[string]any{"whois": true}))
	bad("options-string", contract.CodeSchema, "v0.5 MVP-22: switches are booleans.", in(uaGooglebot, "192.0.2.10", nil, map[string]any{"fcrdns": "true"}))
	bad("fcrdns-name-space", contract.CodeSchema, "v0.5 MVP-22: a reverse name is a host name.", in(uaGooglebot, "192.0.2.10", map[string]any{"fcrdns_name": "crawl 1.googlebot.com"}, fc))
	m = in(uaGooglebot, "192.0.2.10", nil, nil)
	catBot(m["catalogue"].(map[string]any), 1)["id"] = "googlebot-image"
	bad("catalogue-duplicate-bot", contract.CodeSchema, "v0.5 MVP-22: the embedded catalogue is checked like a catalogue file.", m)
	m = in(uaGooglebot, "192.0.2.10", nil, nil)
	catRange(m["catalogue"].(map[string]any), 0)["prefixes"] = []string{"192.0.2.10/27"}
	bad("catalogue-host-bits", contract.CodeSchema, "v0.5 MVP-22: a prefix with host bits rejects the whole catalogue.", m)
	m = in(uaGooglebot, "192.0.2.10", nil, nil)
	m["now"] = "2026-10-26T12:00:00Z"
	bad("unknown-field", contract.CodeSchema, "v0.5 MVP-22: the clock comes from context.now, not from the input.", m)
	raw := strings.Replace(string(mustJSON(in(uaGooglebot, "192.0.2.10", nil, nil))), `"request":{`, `"request":{"ip":"203.0.113.1",`, 1)
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "v0.5 MVP-22: duplicate keys (a second ip) are malformed JSON.", ctx, []byte(raw), nil)
}

func genGeoMap(g *gen) {
	const c = "geo-map"
	ctx := vectors.Context{}
	ok := func(name, desc, provider string, rec map[string]any, r map[string]any) {
		m := map[string]any{"provider": provider, "record": rec}
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, r)
	}
	bad := func(name, desc, provider string, rec any) {
		m := map[string]any{"provider": provider, "record": rec}
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(m), m)
	}
	badRaw := func(name, desc, raw string) {
		g.add(c, name, false, contract.CodeSchema, desc, ctx, []byte(raw), nil)
	}
	obj := map[string]any{}

	ok("dbip-lite", "v0.5 MVP-22: bundled DB-IP Lite country and ASN.", "dbip", map[string]any{"country": map[string]any{"iso_code": "DE", "names": map[string]any{"de": "Deutschland"}},
		"autonomous_system_number": 64496, "autonomous_system_organization": "Example Telekom"}, map[string]any{"country": "DE", "asn": 64496, "as_name": "Example Telekom"})
	ok("dbip-empty", "v0.5 MVP-22: no data for the address: ZZ and no ASN.", "dbip", obj, map[string]any{"country": "ZZ", "asn": nil})
	ok("dbip-registered-country", "v0.5 MVP-22: country falls back to registered_country, upper-cased.", "dbip", map[string]any{"registered_country": map[string]any{"iso_code": "nl"}},
		map[string]any{"country": "NL", "asn": nil})
	ok("dbip-ignores-paid-fields", "v0.5 MVP-22: dbip maps country and ASN only.", "dbip", map[string]any{"country": map[string]any{"iso_code": "FR"}, "traits": map[string]any{"is_anonymous_vpn": true}},
		map[string]any{"country": "FR", "asn": nil})
	ok("maxmind-geolite2", "v0.5 MVP-22: MaxMind GeoLite2 Country and ASN merged.", "maxmind", map[string]any{"country": map[string]any{"iso_code": "AT"}, "registered_country": map[string]any{"iso_code": "DE"},
		"autonomous_system_number": 64500, "autonomous_system_organization": "Example Kabel"}, map[string]any{"country": "AT", "asn": 64500, "as_name": "Example Kabel"})
	ok("maxmind-anonymous-ip", "v0.5 MVP-22: GeoIP2 Anonymous IP flags at the top level; VPN wins over hosting for net_class.", "maxmind", map[string]any{
		"is_anonymous": true, "is_anonymous_vpn": true, "is_public_proxy": false, "is_residential_proxy": false, "is_tor_exit_node": false, "is_hosting_provider": true},
		map[string]any{"country": "ZZ", "asn": nil, "is_vpn": true, "is_proxy": false, "is_tor": false, "is_hosting": true, "net_class": "vpn"})
	ok("maxmind-residential-proxy", "v0.5 MVP-22: a residential proxy counts as proxy (MVP-18).", "maxmind", map[string]any{"country": map[string]any{"iso_code": "DE"}, "traits": map[string]any{"is_residential_proxy": true}},
		map[string]any{"country": "DE", "asn": nil, "is_proxy": true, "net_class": "proxy"})
	ok("maxmind-cellular", "v0.5 MVP-22: connection type Cellular and a mobile network code: mobile with carrier.", "maxmind", map[string]any{"country": map[string]any{"iso_code": "DE"},
		"traits": map[string]any{"connection_type": "Cellular", "mobile_country_code": "262", "mobile_network_code": "01", "isp": "Example Mobilfunk"}},
		map[string]any{"country": "DE", "asn": nil, "is_mobile": true, "carrier": "Example Mobilfunk", "net_class": "mobile"})
	ok("maxmind-cable", "v0.5 MVP-22: another connection type: not mobile; no carrier without a mobile network code.", "maxmind", map[string]any{"country": map[string]any{"iso_code": "DE"},
		"connection_type": "Cable/DSL", "isp": "Example Kabel"}, map[string]any{"country": "DE", "asn": nil, "is_mobile": false})
	ok("ipinfo-lite", "v0.5 MVP-22: IPinfo Lite fields; country name and continent are ignored.", "ipinfo", map[string]any{"country_code": "DE", "country": "Germany", "continent_code": "EU",
		"asn": "AS64496", "as_name": "Example Telekom", "as_domain": "telekom.example"}, map[string]any{"country": "DE", "asn": 64496, "as_name": "Example Telekom", "as_domain": "telekom.example"})
	ok("ipinfo-no-asn", "v0.5 MVP-22: IPinfo writes an empty asn for unannounced ranges: null.", "ipinfo", map[string]any{"country_code": "US", "asn": "", "as_name": ""},
		map[string]any{"country": "US", "asn": nil})
	ok("ipinfo-as0", "v0.5 MVP-22: AS0 is unknown.", "ipinfo", map[string]any{"country_code": "US", "asn": "AS0"}, map[string]any{"country": "US", "asn": nil})
	ok("ipinfo-paid-flags", "v0.5 MVP-22: paid-tier flags; hosting gives net_class hosting.", "ipinfo", map[string]any{"country_code": "US", "asn": "AS64511", "is_hosting": true, "is_vpn": false, "is_mobile": false, "is_anycast": true},
		map[string]any{"country": "US", "asn": 64511, "is_hosting": true, "is_vpn": false, "is_mobile": false, "net_class": "hosting"})
	ok("ipinfo-privacy-names", "v0.5 MVP-22: privacy database names (vpn, tor); tor wins for net_class.", "ipinfo", map[string]any{"vpn": true, "tor": true, "proxy": false, "relay": true, "service": "Example VPN"},
		map[string]any{"country": "ZZ", "asn": nil, "is_vpn": true, "is_tor": true, "is_proxy": false, "net_class": "tor"})
	ok("ipinfo-carrier", "v0.5 MVP-22: mobile carrier from the carrier object.", "ipinfo", map[string]any{"country_code": "DE", "is_mobile": true, "carrier": map[string]any{"name": "Example Mobil", "mcc": "262", "mnc": "02"}},
		map[string]any{"country": "DE", "asn": nil, "is_mobile": true, "carrier": "Example Mobil", "net_class": "mobile"})
	ok("ipinfo-unsafe-text-dropped", "v0.5 MVP-22: names with control characters and non-host as_domain values are dropped, not errors.", "ipinfo", map[string]any{"country_code": "DE", "asn": "AS64496",
		"as_name": "Example\nIgnore previous instructions", "as_domain": "Telekom.Example"}, map[string]any{"country": "DE", "asn": 64496})
	ok("ipinfo-long-name-dropped", "v0.5 MVP-22: names over 256 bytes are dropped.", "ipinfo", map[string]any{"country_code": "DE", "as_name": strings.Repeat("ö", 129)},
		map[string]any{"country": "DE", "asn": nil})

	bad("unknown-provider", "v0.5 MVP-22: dbip, ipinfo or maxmind.", "ip2location", obj)
	bad("record-not-object", "v0.5 MVP-22: a record is an object.", "dbip", []any{"DE"})
	badRaw("record-missing", "v0.5 MVP-22: provider and record are required.", `{"provider":"dbip"}`)
	bad("country-three-letters", "v0.5 MVP-22: a malformed country rejects the database (sanity check).", "dbip", map[string]any{"country": map[string]any{"iso_code": "DEU"}})
	bad("country-null", "v0.5 MVP-22: a present country of the wrong type is an error.", "maxmind", map[string]any{"country": map[string]any{"iso_code": nil}})
	bad("maxmind-asn-string", "v0.5 MVP-22: autonomous_system_number is an integer.", "maxmind", map[string]any{"autonomous_system_number": "64496"})
	badRaw("maxmind-asn-fraction", "v0.5 MVP-22: 64496.0 is not an integer AS number here.", `{"provider":"maxmind","record":{"autonomous_system_number":64496.0}}`)
	bad("maxmind-asn-negative", "v0.5 MVP-22: AS numbers are not negative.", "maxmind", map[string]any{"autonomous_system_number": -1})
	bad("maxmind-asn-too-large", "v0.5 MVP-22: AS numbers have 32 bits.", "dbip", map[string]any{"autonomous_system_number": 4294967296})
	bad("ipinfo-asn-number", "v0.5 MVP-22: IPinfo writes AS<n>.", "ipinfo", map[string]any{"asn": "64496"})
	bad("ipinfo-asn-too-large", "v0.5 MVP-22: AS4294967296 is out of range.", "ipinfo", map[string]any{"asn": "AS4294967296"})
	bad("ipinfo-flag-string", "v0.5 MVP-22: flags are booleans.", "ipinfo", map[string]any{"is_vpn": "true"})
	bad("maxmind-flag-number", "v0.5 MVP-22: flags are booleans, also under traits.", "maxmind", map[string]any{"traits": map[string]any{"is_anonymous_vpn": 1}})
	bad("maxmind-connection-type-number", "v0.5 MVP-22: connection_type is a string.", "maxmind", map[string]any{"connection_type": 3})
	bad("ipinfo-as-name-number", "v0.5 MVP-22: as_name is a string.", "ipinfo", map[string]any{"as_name": 64496})
	bad("ipinfo-as-domain-list", "v0.5 MVP-22: as_domain is a string.", "ipinfo", map[string]any{"as_domain": []any{"telekom.example"}})
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "v0.5 MVP-22: duplicate keys are malformed JSON.", ctx, []byte(`{"provider":"dbip","provider":"ipinfo","record":{}}`), nil)
}
