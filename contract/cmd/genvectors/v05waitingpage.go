//go:build !release

package main

import (
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D37 (initiator, 2026-10-29; MVP-23 step 1, an MVP-19 addendum): the
// waiting page. Which fail-closed 503 gets it, the Retry-After range, the
// language from Accept-Language and the website name shown. Appended after
// the D36 amendment vectors; schild.yaml waiting_page in genSiteConfigV05WaitingPage.

// Header sets as current browsers send them (Chrome, Firefox).
const (
	chromeAccept  = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	firefoxAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
)

func genWaitingPage(g *gen) {
	const c = "waiting-page"
	ctx := vectors.Context{}
	type H = map[string]any
	nav := func(al string) H {
		h := H{"accept": chromeAccept, "sec_fetch_dest": "document", "sec_fetch_mode": "navigate"}
		if al != "" {
			h["accept_language"] = al
		}
		return h
	}
	in := func(reason string, method string, h H, draw int64) map[string]any {
		return map[string]any{"fail_closed": reason, "enabled": true, "method": method, "headers": h,
			"host": "musterverein.example", "website": "musterverein.example", "jitter_draw": draw}
	}
	retry := func(draw int64) int { return 5 + int(draw%4) }
	page := func(m map[string]any, lang string, site any) map[string]any {
		r := retry(m["jitter_draw"].(int64))
		res := map[string]any{"answer": "waiting_page", "variant": "reload", "language": lang, "retry_after": r, "refresh": r,
			"body": m["method"] != "HEAD", "site_name": site, "marker": true, "problem_code": nil}
		if m["method"] == "POST" {
			res["variant"], res["refresh"] = "form", nil
		}
		return res
	}
	problem := func(m map[string]any) map[string]any {
		return map[string]any{"answer": "problem", "variant": nil, "language": nil, "retry_after": retry(m["jitter_draw"].(int64)),
			"refresh": nil, "body": m["method"] != "HEAD", "site_name": nil, "marker": true, "problem_code": "waiting"}
	}
	unchanged := map[string]any{"answer": "unchanged", "variant": nil, "language": nil, "retry_after": nil, "refresh": nil, "body": nil, "site_name": nil, "marker": false, "problem_code": nil}
	ok := func(name, desc string, m, res map[string]any) {
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, res)
	}
	const site = "musterverein.example"

	// Document navigations.
	m := in("waf_busy", "GET", nav("de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"), 0)
	ok("chrome-navigation-busy", "D37: a browser navigation (Sec-Fetch-Dest document, Sec-Fetch-Mode navigate) answered waf_busy gets the waiting page: German, Retry-After 5 + draw mod 4, meta refresh equal to it, the website name.", m, page(m, "de", site))
	m = in("waf_timeout", "GET", H{"accept": firefoxAccept, "accept_language": "en-US,en;q=0.5", "sec_fetch_dest": "document", "sec_fetch_mode": "navigate"}, 7)
	ok("firefox-navigation-timeout-en", "D37: waf_timeout (evaluation over its budget) gets the waiting page too; English by Accept-Language; draw 7 gives the upper bound 8 s.", m, page(m, "en", site))
	m = in("waf_busy", "HEAD", nav(""), 1)
	ok("head-navigation", "D37: HEAD follows GET; the headers of the waiting page (503, Retry-After 6, Content-Language de) without a body.", m, page(m, "de", site))
	m = in("waf_busy", "POST", H{"accept": chromeAccept, "accept_language": "de", "sec_fetch_dest": "document", "sec_fetch_mode": "navigate"}, 2)
	ok("post-form-navigation", "D37: a form submit (POST navigation) gets the waiting page in the form variant: no meta refresh (it would load the URL with GET and drop the form), the copy asks to go back and send it again.", m, page(m, "de", site))
	m = in("waf_timeout", "POST", H{"accept": "text/html,application/xhtml+xml,*/*;q=0.8"}, 3)
	ok("post-form-without-fetch-metadata", "D37: a form submit of a browser without Fetch Metadata (Accept naming text/html) gets the form variant too.", m, page(m, "de", site))
	m = in("waf_busy", "GET", H{"accept": "text/html, */*"}, 4)
	ok("old-browser-accept-html", "D37: without Sec-Fetch-Dest an Accept naming text/html is a document; draw 4 wraps to 5 s.", m, page(m, "de", site))
	m = in("waf_busy", "GET", H{"accept": "text/html", "sec_fetch_mode": "navigate"}, 0)
	ok("navigate-without-dest", "D37: Sec-Fetch-Mode navigate without Sec-Fetch-Dest falls back to Accept.", m, page(m, "de", site))
	m = in("waf_busy", "GET", H{"sec_fetch_dest": "document"}, 0)
	ok("dest-document-without-mode-or-accept", "D37: Sec-Fetch-Dest document decides even without Sec-Fetch-Mode and Accept.", m, page(m, "de", site))
	m = in("waf_busy", "GET", H{"sec_fetch_dest": " Document\t", "sec_fetch_mode": "NAVIGATE"}, 0)
	ok("fetch-metadata-case-and-space", "D37: Fetch Metadata values are trimmed of spaces and tabs and compared ASCII case-insensitively.", m, page(m, "de", site))
	m = in("waf_busy", "GET", H{"accept": "application/json;q=0.5, text/html"}, 0)
	ok("accept-html-over-json", "D37: text/html with a higher q than every JSON type is a document.", m, page(m, "de", site))
	m = in("waf_busy", "GET", H{"accept": "application/xhtml+xml"}, 0)
	ok("accept-xhtml", "D37: application/xhtml+xml counts as HTML.", m, page(m, "de", site))
	m = in("waf_busy", "GET", nav(""), 4294967295)
	ok("draw-max", "D37: the largest draw gives 5 + 4294967295 mod 4 = 8 s (never above the bound).", m, page(m, "de", site))

	// Everything else keeps 503 + problem details.
	m = in("waf_busy", "GET", H{"accept": "application/json", "sec_fetch_dest": "empty", "sec_fetch_mode": "cors"}, 0)
	ok("fetch-cors-json", "D37: fetch()/XHR (Sec-Fetch-Mode cors) keeps 503 + problem details with the same jittered Retry-After.", m, problem(m))
	m = in("waf_busy", "GET", H{"accept": "text/html", "sec_fetch_dest": "empty", "sec_fetch_mode": "cors"}, 1)
	ok("fetch-cors-asking-html", "D37: Fetch Metadata wins over Accept: a fetch() asking for HTML (htmx, Turbo, Livewire) gets the problem, not a page swapped into the document.", m, problem(m))
	m = in("waf_busy", "GET", H{"accept": "text/html, */*; q=0.01", "x_requested_with": "XMLHttpRequest"}, 2)
	ok("xhr-requested-with", "D37: X-Requested-With present (jQuery and other XHR libraries) is never a document.", m, problem(m))
	m = in("waf_busy", "GET", H{"accept": chromeAccept, "sec_fetch_dest": "iframe", "sec_fetch_mode": "navigate"}, 0)
	ok("iframe-navigation", "D37: only the top-level document gets the page (frame-ancestors 'none' would hide it in a frame); iframe gets the problem.", m, problem(m))
	m = in("waf_busy", "GET", H{"accept": "image/avif,image/webp,*/*;q=0.8", "sec_fetch_dest": "image", "sec_fetch_mode": "no-cors"}, 0)
	ok("image", "D37: assets (image, script, style, font) get the problem.", m, problem(m))
	m = in("waf_busy", "GET", H{"sec_fetch_dest": "websocket", "sec_fetch_mode": "websocket"}, 0)
	ok("websocket", "D37: a WebSocket upgrade gets the problem.", m, problem(m))
	m = in("waf_busy", "GET", H{"accept": "*/*"}, 3)
	ok("curl", "D37: */* (curl, most HTTP libraries and bots without a browser Accept) gets the problem.", m, problem(m))
	m = in("waf_timeout", "GET", H{}, 0)
	ok("no-headers", "D37: no Accept and no Fetch Metadata: problem.", m, problem(m))
	m = in("waf_busy", "POST", H{"accept": "application/json", "accept_language": "en"}, 0)
	ok("api-post-json", "D37: an API call gets the problem; the problem body keeps the block page's (code timeout).", m, problem(m))
	m = in("waf_busy", "GET", H{"accept": "application/json, text/html"}, 0)
	ok("accept-json-html-tie", "D37: a tie between text/html and a JSON type goes to the problem.", m, problem(m))
	m = in("waf_busy", "GET", H{"accept": "application/vnd.api+json, text/html;q=0.9"}, 0)
	ok("accept-json-suffix", "D37: a +json media type is a JSON type.", m, problem(m))
	m = in("waf_busy", "GET", H{"accept": "text/html;q=0, */*"}, 0)
	ok("accept-html-q0", "D37: text/html with q=0 is refused, so no document.", m, problem(m))
	m = in("waf_busy", "PUT", nav(""), 0)
	ok("put-navigation-headers", "D37: methods other than GET, HEAD and POST never get the page, whatever the headers say.", m, problem(m))
	m = in("waf_busy", "HEAD", H{"accept": "*/*"}, 0)
	ok("head-not-document", "D37: HEAD of a non-document gets the problem headers without a body.", m, problem(m))

	// Unchanged answers.
	m = in("not_ready", "GET", nav(""), 0)
	ok("not-ready-unchanged", "D37: not_ready (gate starting) is no overload; its answer is unchanged.", m, unchanged)
	m = in("panic", "GET", nav(""), 0)
	ok("panic-unchanged", "D37: a recovered panic keeps its answer (with incident number for the operator).", m, unchanged)
	m = in("waf_busy", "GET", nav(""), 0)
	m["enabled"] = false
	ok("disabled-unchanged", "D37: waiting_page.enabled false: the answer before D37 (block page or problem by Accept, Retry-After 5).", m, unchanged)

	// Accept-Language -> language.
	lang := func(name, desc, al, want string) {
		m := in("waf_busy", "GET", nav(al), 0)
		ok(name, desc, m, page(m, want, site))
	}
	lang("lang-en-first", "D37: en-US with the highest q gives English.", "en-US,en;q=0.9,de;q=0.8", "en")
	lang("lang-de-ch", "D37: a regional German range (de-CH) gives German.", "de-CH", "de")
	lang("lang-fr-then-en", "D37: unsupported languages are skipped; English listed after French gives English.", "fr-FR,fr;q=0.9,en;q=0.8", "en")
	lang("lang-fr-only", "D37: neither de nor en: German (default).", "fr", "de")
	lang("lang-star", "D37: * picks no language: German.", "*", "de")
	lang("lang-en-q0", "D37: en;q=0 refuses English: German.", "en;q=0, fr", "de")
	lang("lang-tie-first-listed", "D37: equal q: the first listed wins.", "en;q=0.8, de;q=0.8", "en")
	lang("lang-q-order", "D37: the highest q wins, not the position.", "de;q=0.5, en;q=0.9", "en")
	lang("lang-upper-case", "D37: ranges are compared ASCII case-insensitively.", "EN-gb", "en")
	lang("lang-invalid-q-skipped", "D37: an element with an invalid q (2) is skipped.", "en;q=2, de;q=0.1", "de")
	lang("lang-q-three-decimals", "D37: q has at most three decimals (0.001 counts, 0.0001 is invalid and skipped).", "de;q=0.0001, en;q=0.001", "en")
	lang("lang-beyond-32", "D37: only the first 32 elements are read.", strings.Repeat("fr,", 32)+"en", "de")

	// Website name.
	name := func(nm, desc, host string, website any, want any) {
		m := in("waf_busy", "GET", nav(""), 0)
		m["host"] = host
		if website == nil {
			delete(m, "website")
		} else {
			m["website"] = website
		}
		ok(nm, desc, m, page(m, "de", want))
	}
	name("name-normalised", "D37: the request host without port and trailing dot, lower case.", "Musterverein.Example.:8443", "musterverein.example", "musterverein.example")
	name("name-any", "D37: the catch-all website _any takes any host: no name, generic wording.", "irgendwas.example", "_any", nil)
	name("name-default", "D37: proxy mode without upstream.site_hosts (website default): no name.", "musterverein.example", "default", nil)
	name("name-no-website", "D37: no website resolved: no name.", "musterverein.example", nil, nil)
	name("name-ipv4", "D37: an IPv4 literal website shows the address.", "192.0.2.10:8080", "192.0.2.10", "192.0.2.10")
	name("name-ipv6", "D37: an IPv6 literal is not shown.", "[2001:db8::1]:443", "ipv6-2001-db8--1", nil)
	name("name-punycode", "D37: A-labels are shown as they are.", "xn--mnchen-3ya.example", "xn--mnchen-3ya.example", "xn--mnchen-3ya.example")
	name("name-wildcard", "D37: a host matched by a wildcard website shows the host.", "a.kunden.example.org", "_.kunden.example.org", "a.kunden.example.org")
	name("name-underscore", "D37: a host that is no DNS name (underscore) is not shown.", "bad_host.kunden.example.org", "_.kunden.example.org", nil)
	name("name-markup", "D37: markup in the Host is never shown.", "<b>x</b>.example", "_.example", nil)
	name("name-bad-port", "D37: a port that is not 1-5 digits makes the host unusable.", "musterverein.example:http", "musterverein.example", nil)

	bad := func(name, desc string, m map[string]any) {
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(m), m)
	}
	m = in("memory_budget", "GET", nav(""), 0)
	bad("reason-memory-budget", "D37: the memory budget of expensive evaluations is waf_busy, not a reason of its own.", m)
	bad("reason-eval-timeout", "D37: the evaluation timeout is waf_timeout.", in("eval_timeout", "GET", nav(""), 0))
	bad("method-lower-case", "D37: methods are upper case tokens.", in("waf_busy", "get", nav(""), 0))
	bad("header-too-long", "D37: header values up to 1024 characters.", in("waf_busy", "GET", H{"accept": strings.Repeat("a", 1025)}, 0))
	bad("header-control-character", "D37: header values carry no control characters other than tab.", in("waf_busy", "GET", H{"accept": "text/html\n"}, 0))
	bad("header-non-ascii", "D37: header values are visible ASCII.", in("waf_busy", "GET", H{"accept_language": "de-ä"}, 0))
	bad("header-unknown", "D37: only the five headers the decision reads (no cookie, no user agent).", in("waf_busy", "GET", H{"cookie": "a=b"}, 0))
	m = in("waf_busy", "GET", nav(""), 0)
	delete(m, "jitter_draw")
	bad("missing-jitter-draw", "D37: the jitter draw is required.", m)
	bad("jitter-draw-negative", "D37: the draw is an unsigned 32-bit value.", in("waf_busy", "GET", nav(""), -1))
	bad("jitter-draw-too-large", "D37: the draw is an unsigned 32-bit value.", in("waf_busy", "GET", nav(""), 4294967296))
	m = in("waf_busy", "GET", nav(""), 0)
	m["enabled"] = "yes"
	bad("enabled-not-boolean", "D37: enabled is a boolean.", m)
	m = in("waf_busy", "GET", nav(""), 0)
	m["website"] = "Musterverein.example"
	bad("website-upper-case", "D37: website is a D36 website id (lower case).", m)
	m = in("waf_busy", "GET", nav(""), 0)
	m["host"] = "muster verein.example"
	bad("host-space", "D37: Host is visible ASCII.", m)
	m = in("waf_busy", "GET", nav(""), 0)
	m["client_ip"] = "192.0.2.1"
	bad("extra-field", "D37: no other fields (no address).", m)
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "D37: duplicate keys are malformed JSON.", ctx,
		[]byte(`{"fail_closed":"waf_busy","enabled":true,"enabled":false,"method":"GET","headers":{},"host":"musterverein.example","jitter_draw":0}`), nil)
}

// genSiteConfigV05WaitingPage: schild.yaml waiting_page (D37).
func genSiteConfigV05WaitingPage(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, wp any) {
		m := siteConfig()
		m["waiting_page"] = wp
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	add(true, "", "waiting-page-off", "D37: the waiting page can be switched off (default on).", map[string]any{"enabled": false})
	add(true, "", "waiting-page-empty", "D37: an empty waiting_page keeps the default (on).", map[string]any{})
	add(false, contract.CodeSchema, "waiting-page-enabled-string", "D37: enabled is a boolean.", map[string]any{"enabled": "yes"})
	add(false, contract.CodeSchema, "waiting-page-text-override", "D37: per-website text and image overrides are not part of step 1.", map[string]any{"enabled": true, "text": "Bitte warten"})
	add(false, contract.CodeSchema, "waiting-page-not-object", "D37: waiting_page is an object.", true)
}
