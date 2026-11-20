//go:build !release

package main

import (
	"log"
	"reflect"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D57 (initiator, 2026-11-02; MVP-29): crawler control. Which request a
// website's crawler policy blocks, which rule decided, and what the gateway
// mode and the allowlist make of it. The test catalogue of the bot-match
// vectors: Googlebot ranges fresh, GPTBot ranges stale (55 days), Bingbot
// fresh. The expected results are written out by hand; the generator stops
// when the Go implementation disagrees.
func genCrawlerPolicy(g *gen) {
	const c = "crawler-policy"
	ctx := vectors.Context{}
	type M = map[string]any
	in := func(policy M, ua, ip, mode string, extra M) M {
		m := M{"catalogue": testCatalogue(), "policy": policy, "request": M{"user_agent": ua, "ip": ip}, "mode": mode}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	res := func(bot, cat, ver, rule, outcome, reason string, status int) M {
		out := M{"bot": nil, "category": cat, "verification": nil, "rule": rule, "outcome": outcome, "reason": reason, "status": status}
		if bot != "" {
			out["bot"], out["verification"] = bot, ver
		}
		return out
	}
	blocked := func(bot, cat, ver, rule string) M { return res(bot, cat, ver, rule, "blocked_crawler", "", 403) }
	passed := func(bot, cat, ver string) M { return res(bot, cat, ver, "none", "passed", "", 0) }
	decoded := func(m M) M {
		d := M{"policy": m["policy"], "request": m["request"], "mode": m["mode"]}
		for _, k := range []string{"preset", "allowlisted"} {
			if v, ok := m[k]; ok {
				d[k] = v
			}
		}
		return d
	}
	ok := func(name, desc string, m, want M) {
		got, err := crawlers.RunVector(mustJSON(m), Now)
		if err != nil {
			log.Fatalf("crawler-policy %s: %v", name, err)
		}
		gotM := M{"bot": nil, "category": got.Category, "verification": nil, "rule": got.Rule, "outcome": got.Outcome, "reason": got.Reason, "status": got.Status}
		if got.Bot != nil {
			gotM["bot"] = *got.Bot
		}
		if got.Verification != nil {
			gotM["verification"] = *got.Verification
		}
		if !reflect.DeepEqual(gotM, want) {
			log.Fatalf("crawler-policy %s: got %v, want %v", name, gotM, want)
		}
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), decoded(m), want)
	}
	bad := func(name, desc string, m M) {
		if _, err := crawlers.RunVector(mustJSON(m), Now); err == nil {
			log.Fatalf("crawler-policy %s: accepted", name)
		}
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(m), decoded(m))
	}

	blockTraining := M{"categories": M{"ai_training": "block"}}
	const (
		gptUA   = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"
		chatUA  = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"
		bingUA  = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
		curlUA  = "curl/8.5.0"
		fakeBot = "Mozilla/5.0 (compatible; UnknownCrawler/1.0)"
	)

	// The empty policy changes nothing.
	ok("empty-policy-passes", "D57: an empty policy (the default of every website) passes a known AI crawler.",
		in(M{}, gptUA, "198.51.100.5", "autoblock", nil), passed("gptbot", "ai_training", "unknown_stale"))
	ok("all-allow-passes", "D57: rules that only allow change nothing.",
		in(M{"categories": M{"ai_training": "allow", "search_engine": "allow"}, "impersonators": "allow"}, uaGooglebot, "198.51.100.200", "autoblock", nil),
		passed("googlebot", "search_engine", "mismatch"))

	// A category rule.
	ok("category-block", "D57: ai_training blocked: GPTBot gets 403 in autoblock.",
		in(blockTraining, gptUA, "198.51.100.5", "autoblock", nil), blocked("gptbot", "ai_training", "unknown_stale", "category"))
	g.retire(c, true) // category-block-review (D89: mode review is gone; an invalid vector of genD89)
	ok("category-block-unverified", "D57: a block applies to every request that names the crawler, verified or not: it identified itself.",
		in(blockTraining, gptUA, "203.0.113.99", "autoblock", nil), blocked("gptbot", "ai_training", "unknown_stale", "category"))
	ok("category-other-passes", "D57: another category is not touched by an ai_training block.",
		in(blockTraining, chatUA, "203.0.113.70", "autoblock", nil), passed("chatgpt-user", "ai_assistant", "claimed"))
	ok("category-search-block-verified", "D57: a blocked category also blocks the verified crawler.",
		in(M{"categories": M{"search_engine": "block"}}, uaGooglebot, "192.0.2.10", "autoblock", nil), blocked("googlebot", "search_engine", "verified", "category"))
	ok("category-tool-library", "D57: tool_library is a category like the others: curl blocked when the website says so.",
		in(M{"categories": M{"tool_library": "block"}}, curlUA, "203.0.113.90", "autoblock", nil), blocked("curl", "tool_library", "claimed", "category"))

	// A bot rule overrides its category.
	ok("bot-allow-overrides-category", "D57: GPTBot allowed while ai_training is blocked: the bot rule wins.",
		in(M{"categories": M{"ai_training": "block"}, "bots": M{"gptbot": "allow"}}, gptUA, "198.51.100.5", "autoblock", nil),
		passed("gptbot", "ai_training", "unknown_stale"))
	ok("bot-block-overrides-category", "D57: Bingbot blocked while search_engine allows: the bot rule wins.",
		in(M{"categories": M{"search_engine": "allow"}, "bots": M{"bingbot": "block"}}, bingUA, "203.0.113.5", "autoblock", nil),
		blocked("bingbot", "search_engine", "verified", "bot"))
	ok("bot-block-only-that-bot", "D57: a bot rule touches only that bot, Googlebot passes.",
		in(M{"bots": M{"bingbot": "block"}}, uaGooglebot, "192.0.2.10", "autoblock", nil), passed("googlebot", "search_engine", "verified"))
	ok("bot-block-longest-token", "D57: the match decides the bot: Googlebot-Image is its own entry, a rule for googlebot does not touch it.",
		in(M{"bots": M{"googlebot": "block"}}, "Googlebot-Image/1.0", "192.0.2.11", "autoblock", nil), passed("googlebot-image", "search_engine", "verified"))

	// Impersonators.
	ok("impersonator-block", "D57: impersonators blocked: Googlebot from outside Google's fresh ranges gets 403.",
		in(M{"impersonators": "block"}, uaGooglebot, "198.51.100.200", "autoblock", nil), blocked("googlebot", "search_engine", "mismatch", "impersonator"))
	ok("impersonator-real-passes", "D57: impersonators blocked: the real Googlebot passes.",
		in(M{"impersonators": "block"}, uaGooglebot, "192.0.2.10", "autoblock", nil), passed("googlebot", "search_engine", "verified"))
	ok("impersonator-over-bot-allow", "D57: an allow for Googlebot is for the real one: an impersonator is still blocked.",
		in(M{"bots": M{"googlebot": "allow"}, "impersonators": "block"}, uaGooglebot, "198.51.100.200", "autoblock", nil),
		blocked("googlebot", "search_engine", "mismatch", "impersonator"))
	ok("impersonator-stale-ranges", "D57: stale ranges prove nothing: unknown_stale is no impersonator.",
		in(M{"impersonators": "block"}, gptUA, "203.0.113.99", "autoblock", nil), passed("gptbot", "ai_training", "unknown_stale"))
	ok("impersonator-no-ranges", "D57: a crawler whose operator publishes no ranges is only claimed, never an impersonator.",
		in(M{"impersonators": "block"}, chatUA, "203.0.113.70", "autoblock", nil), passed("chatgpt-user", "ai_assistant", "claimed"))
	ok("impersonator-allow", "D57: impersonators allow (default): the impersonator passes.",
		in(M{}, uaGooglebot, "198.51.100.200", "autoblock", nil), passed("googlebot", "search_engine", "mismatch"))

	// Requests that name no crawler are never blocked.
	ok("browser-never", "D57: an ordinary browser is no crawler, whatever the policy.",
		in(M{"categories": M{"ai_training": "block", "search_engine": "block", "tool_library": "block"}, "impersonators": "block"}, uaChrome, "203.0.113.91", "autoblock", nil),
		passed("", "likely_browser", ""))
	ok("likely-automated-never", "D57: a user agent the catalogue does not know (likely_automated) is never blocked here.",
		in(M{"categories": M{"ai_training": "block", "tool_library": "block"}, "impersonators": "block"}, fakeBot, "203.0.113.92", "autoblock", nil),
		passed("", "likely_automated", ""))
	ok("empty-ua-never", "D57: no user agent is no crawler.",
		in(M{"categories": M{"tool_library": "block"}}, "", "203.0.113.93", "autoblock", nil), passed("", "likely_automated", ""))

	// Mode and allowlist.
	ok("observe-would-block", "D57: the gateway in observe: a blocked crawler is only recorded as would_block.",
		in(blockTraining, gptUA, "198.51.100.5", "observe", nil), res("gptbot", "ai_training", "unknown_stale", "category", "would_block", "gateway_observe", 0))
	ok("observe-impersonator", "D57: observe also covers impersonators.",
		in(M{"impersonators": "block"}, uaGooglebot, "198.51.100.200", "observe", nil), res("googlebot", "search_engine", "mismatch", "impersonator", "would_block", "gateway_observe", 0))
	ok("allowlisted-would-block", "D57: an allowlisted address is never blocked by a crawler rule, it is recorded as would_block.",
		in(blockTraining, gptUA, "198.51.100.5", "autoblock", M{"allowlisted": true}), res("gptbot", "ai_training", "unknown_stale", "category", "would_block", "allowlist", 0))
	ok("observe-wins-over-allowlist", "D57: observe and allowlist: the reason is gateway_observe (precedence of WouldBlockReasons).",
		in(blockTraining, gptUA, "198.51.100.5", "observe", M{"allowlisted": true}), res("gptbot", "ai_training", "unknown_stale", "category", "would_block", "gateway_observe", 0))
	ok("allowlisted-pass-stays-pass", "D57: an allowlisted request no rule hits stays passed.",
		in(blockTraining, chatUA, "203.0.113.70", "autoblock", M{"allowlisted": true}), passed("chatgpt-user", "ai_assistant", "claimed"))

	// The preset.
	ok("preset-block-ai-training", "D57: preset block_ai_training on an empty policy blocks GPTBot.",
		in(M{}, gptUA, "198.51.100.5", "autoblock", M{"preset": "block_ai_training"}), blocked("gptbot", "ai_training", "unknown_stale", "category"))
	ok("preset-allows-the-rest", "D57: preset block_ai_training allows every other category: a search_engine block before is gone.",
		in(M{"categories": M{"search_engine": "block"}}, uaGooglebot, "192.0.2.10", "autoblock", M{"preset": "block_ai_training"}), passed("googlebot", "search_engine", "verified"))
	ok("preset-drops-bot-rules", "D57: the preset drops bot rules: an allow for GPTBot before no longer holds.",
		in(M{"bots": M{"gptbot": "allow"}}, gptUA, "198.51.100.5", "autoblock", M{"preset": "block_ai_training"}), blocked("gptbot", "ai_training", "unknown_stale", "category"))
	ok("preset-keeps-impersonators", "D57: the preset keeps the impersonator rule.",
		in(M{"impersonators": "block"}, uaGooglebot, "198.51.100.200", "autoblock", M{"preset": "block_ai_training"}), blocked("googlebot", "search_engine", "mismatch", "impersonator"))

	// Refused shapes.
	bad("unknown-bot", "D57: a bot id the catalogue does not know is refused.",
		in(M{"bots": M{"nosuchbot": "block"}}, gptUA, "198.51.100.5", "autoblock", nil))
	bad("unknown-category", "D57: a category the catalogue does not have is refused.",
		in(M{"categories": M{"ai_scraper": "block"}}, gptUA, "198.51.100.5", "autoblock", nil))
	bad("likely-automated-category", "D57: likely_automated is no crawler category and cannot be named.",
		in(M{"categories": M{"likely_automated": "block"}}, gptUA, "198.51.100.5", "autoblock", nil))
	bad("likely-browser-category", "D57: likely_browser cannot be named.",
		in(M{"categories": M{"likely_browser": "block"}}, gptUA, "198.51.100.5", "autoblock", nil))
	bad("action-charge", "D57: allow or block only; nothing is charged.",
		in(M{"categories": M{"ai_training": "charge"}}, gptUA, "198.51.100.5", "autoblock", nil))
	bad("bot-action-upper", "D57: actions are lower case.",
		in(M{"bots": M{"gptbot": "Block"}}, gptUA, "198.51.100.5", "autoblock", nil))
	bad("impersonators-value", "D57: impersonators is allow or block.",
		in(M{"impersonators": "true"}, gptUA, "198.51.100.5", "autoblock", nil))
	bad("unknown-key", "D57: a policy has categories, bots and impersonators, nothing else.",
		in(M{"robots_txt": "enforce"}, gptUA, "198.51.100.5", "autoblock", nil))
	bad("unknown-preset", "D57: only the named presets exist.",
		in(M{}, gptUA, "198.51.100.5", "autoblock", M{"preset": "block_everything"}))
	bad("bad-mode", "D57: the gateway modes only.",
		in(blockTraining, gptUA, "198.51.100.5", "enforce", nil))
	bad("bot-id-pattern", "D57: a bot id has the catalogue id form.",
		in(M{"bots": M{"GPTBot": "block"}}, gptUA, "198.51.100.5", "autoblock", nil))
	bad("no-policy", "D57: the policy is required (empty is fine).",
		M{"catalogue": testCatalogue(), "request": M{"user_agent": gptUA, "ip": "198.51.100.5"}, "mode": "autoblock"})
	bad("mode-review", "D89: mode review is gone; observe is the test profile, autoblock every other gateway.",
		in(blockTraining, gptUA, "198.51.100.5", "review", nil))
}
