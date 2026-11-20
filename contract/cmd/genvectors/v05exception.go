//go:build !release

package main

import (
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// genWebsiteException: the exception snippet of a possible false positive is
// scoped to its website (initiator addendum 2026-10-29: several apps on one
// gateway; an exception for one app never relaxes the others).
func genWebsiteException(g *gen) {
	const c = "website-exception"
	ctx := vectors.Context{}
	in := func(id string, hosts []string, rule, path, target string) map[string]any {
		if hosts == nil {
			hosts = []string{}
		}
		m := map[string]any{"website": map[string]any{"id": id, "hosts": hosts}, "rule_id": rule, "path": path, "id": 1000001}
		if target != "" {
			m["target"] = target
		}
		return m
	}
	ok := func(name, desc string, m map[string]any, scope string, lines ...string) {
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, map[string]any{"scope": scope, "snippet": strings.Join(lines, "\n") + "\n"})
	}
	ok("website-field", "D36: one rule, one page, one field, limited to the hosts of one website by a Host condition heading the chain.",
		in("verein.example", []string{"verein.example", "www.verein.example"}, "942100", "/kontakt/", "ARGS:nachricht"), "website",
		`# schild: exception for rule 942100 on /kontakt/, website verein.example only`,
		`SecRule REQUEST_HEADERS:Host "@rx ^(?:verein\.example|www\.verein\.example)(?::[0-9]{1,5})?$" "id:1000001,phase:1,pass,nolog,t:none,t:lowercase,chain"`,
		`    SecRule REQUEST_FILENAME "@streq /kontakt/" "t:none,ctl:ruleRemoveTargetById=942100;ARGS:nachricht"`)
	ok("website-template", "D36: a path template becomes @rx with [^/]+ per {name} segment; literal parts escaped; without a field the whole rule is removed for that page.",
		in("shop.example.org", []string{"shop.example.org"}, "932100", "/api/v1/orders/{n}/notes.json", ""), "website",
		`# schild: exception for rule 932100 on /api/v1/orders/{n}/notes.json, website shop.example.org only`,
		`SecRule REQUEST_HEADERS:Host "@rx ^(?:shop\.example\.org)(?::[0-9]{1,5})?$" "id:1000001,phase:1,pass,nolog,t:none,t:lowercase,chain"`,
		`    SecRule REQUEST_FILENAME "@rx ^/api/v1/orders/[^/]+/notes\.json$" "t:none,ctl:ruleRemoveById=932100"`)
	ok("website-wildcard-idn", "D36: a wildcard host matches one label; IDN hosts in their A-label (the Host header carries punycode).",
		in("_.kunden.example.org", []string{"*.kunden.example.org", "xn--bcher-kva.example"}, "941100", "/", "ARGS_NAMES"), "website",
		`# schild: exception for rule 941100 on /, website _.kunden.example.org only`,
		`SecRule REQUEST_HEADERS:Host "@rx ^(?:[a-z0-9-]+\.kunden\.example\.org|xn--bcher-kva\.example)(?::[0-9]{1,5})?$" "id:1000001,phase:1,pass,nolog,t:none,t:lowercase,chain"`,
		`    SecRule REQUEST_FILENAME "@streq /" "t:none,ctl:ruleRemoveTargetById=941100;ARGS_NAMES"`)
	ok("website-ip-literals", "D36: IPv4 and bracketed IPv6 hosts.",
		in("192.0.2.10", []string{"192.0.2.10", "2001:db8::1"}, "920350", "/status", ""), "website",
		`# schild: exception for rule 920350 on /status, website 192.0.2.10 only`,
		`SecRule REQUEST_HEADERS:Host "@rx ^(?:192\.0\.2\.10|\[2001:db8::1\])(?::[0-9]{1,5})?$" "id:1000001,phase:1,pass,nolog,t:none,t:lowercase,chain"`,
		`    SecRule REQUEST_FILENAME "@streq /status" "t:none,ctl:ruleRemoveById=920350"`)
	ok("gateway-default", "D36: the proxy-mode website default has no hosts: the snippet applies to the whole gateway and says so (scope gateway).",
		in("default", nil, "942100", "/kontakt/", "ARGS:nachricht"), "gateway",
		`# schild: exception for rule 942100 on /kontakt/, every website of this gateway`,
		`SecRule REQUEST_FILENAME "@streq /kontakt/" "id:1000001,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:nachricht"`)
	ok("path-metacharacters", "D36: regex metacharacters of a template path are escaped.",
		in("verein.example", []string{"verein.example"}, "942100", "/wiki/(alt)/{slug}+x$", ""), "website",
		`# schild: exception for rule 942100 on /wiki/(alt)/{slug}+x$, website verein.example only`,
		`SecRule REQUEST_HEADERS:Host "@rx ^(?:verein\.example)(?::[0-9]{1,5})?$" "id:1000001,phase:1,pass,nolog,t:none,t:lowercase,chain"`,
		`    SecRule REQUEST_FILENAME "@rx ^/wiki/\(alt\)/[^/]+\+x\$$" "t:none,ctl:ruleRemoveById=942100"`)

	bad := func(name, desc string, m map[string]any) {
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(m), m)
	}
	h := []string{"verein.example"}
	bad("path-quote", "D36: a quote would end the operator string.", in("verein.example", h, "942100", `/a"b`, ""))
	bad("path-space", "D36: no space in the path.", in("verein.example", h, "942100", "/a b", ""))
	bad("path-backslash", "D36: no backslash in the path.", in("verein.example", h, "942100", `/a\b`, ""))
	bad("path-relative", "D36: the path starts with /.", in("verein.example", h, "942100", "kontakt", ""))
	bad("path-open-brace", "D36: braces only as {name} segments.", in("verein.example", h, "942100", "/a/{n", ""))
	bad("path-macro", "D36: no %{...} macro (SecLang would expand it).", in("verein.example", h, "942100", "/a/%{REMOTE_ADDR}", ""))
	bad("target-comma", "D36: a comma would start another action.", in("verein.example", h, "942100", "/", "ARGS:a,ctl:ruleEngine=Off"))
	bad("target-lowercase-collection", "D36: collections are upper case.", in("verein.example", h, "942100", "/", "args:a"))
	bad("rule-id-zero", "D36: rule ids start at 1.", in("verein.example", h, "0", "/", ""))
	bad("host-upper-case", "D36: hosts are normalised (lower case).", in("verein.example", []string{"Verein.example"}, "942100", "/", ""))
	bad("host-regex", "D36: hosts are names, never patterns.", in("verein.example", []string{"verein.example|.*"}, "942100", "/", ""))
	m := in("verein.example", h, "942100", "/", "")
	m["id"] = 0
	bad("id-zero", "D36: a fresh local id >= 1.", m)
	m = in("verein.example", h, "942100", "/", "")
	m["website"].(map[string]any)["id"] = "Verein"
	bad("site-id", "D36: a WebsiteId.", m)
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "D36: duplicate keys are malformed JSON.", ctx,
		[]byte(`{"website":{"id":"a.example","hosts":[]},"rule_id":"1","rule_id":"2","path":"/","id":1}`), nil)
}
