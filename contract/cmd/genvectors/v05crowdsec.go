//go:build !release

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D39 (initiator, 2026-10-30, MVP-26): the CrowdSec Hub source. The rule
// shapes below were rewritten by hand from rules of the public hub
// (https://github.com/crowdsecurity/hub, MIT, see vectors/crowdsec-hub/NOTICE).
// Appended after every earlier vector.

const hubT0 = "2026-10-26T12:00:00Z"

// hubYAML writes one rule with the given rules: block.
func hubYAML(name, rules string) string {
	return "name: " + name + "\ndescription: 'Rewritten test rule.'\nrules:\n" + rules +
		"labels:\n  type: exploit\n  confidence: 3\n  spoofable: 0\n  label: Example - RCE\n  classification:\n    - cve.CVE-2026-1207\n    - attack.T1190\n    - cwe.CWE-89\n"
}

const leafURI = "      - zones:\n          - URI\n        transform:\n          - lowercase\n        match:\n          type: contains\n          value: /wp-json/example/v1/\n"

func hubAnd(leaves ...string) string { return "  - and:\n" + strings.Join(leaves, "") }

// hubIndex builds a small .index.json. Members of the collection are the
// names unless a name ends in "!" (present in the index, not in the
// collection).
func hubIndex(items map[string]string, extra map[string]map[string]any) string {
	rules := map[string]any{}
	members := []any{}
	for name, content := range items {
		n := strings.TrimSuffix(name, "!")
		sum := sha256.Sum256([]byte(content))
		d := hex.EncodeToString(sum[:])
		it := map[string]any{"path": "appsec-rules/" + n + ".yaml", "version": "0.2", "author": "crowdsecurity",
			"content":  base64.StdEncoding.EncodeToString([]byte(content)),
			"versions": map[string]any{"0.1": map[string]any{"deprecated": false, "digest": strings.Repeat("0", 64)}, "0.2": map[string]any{"deprecated": false, "digest": d}}}
		for k, v := range extra[n] {
			it[k] = v
		}
		rules[n] = it
		if !strings.HasSuffix(name, "!") {
			members = append(members, n)
		}
	}
	for i := 1; i < len(members); i++ { // stable input: sorted members
		for j := i; j > 0 && members[j-1].(string) > members[j].(string); j-- {
			members[j-1], members[j] = members[j], members[j-1]
		}
	}
	return string(mustJSON(map[string]any{
		"appsec-rules": rules,
		"collections":  map[string]any{crowdsec.Collection: map[string]any{"appsec-rules": members}},
		"scenarios":    map[string]any{"crowdsecurity/http-probing": map[string]any{"path": "scenarios/x.yaml"}},
	}))
}

func genCrowdsecHub(g *gen) {
	const c = "crowdsec-hub"
	ctx := vectors.Context{}
	ok := func(name, desc string, m map[string]any) {
		res, err := crowdsec.RunVector(mustJSON(m))
		if err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, res)
	}
	bad := func(name, desc string, code contract.Code, raw []byte, decoded any) {
		g.add(c, name, false, code, desc, ctx, raw, decoded)
	}
	const name = "crowdsecurity/vpatch-CVE-2026-1207"
	conv := func(vec, desc, rules string) {
		ok("convert-"+vec, desc, map[string]any{"op": "convert", "name": name, "version": "0.2", "content": hubYAML(name, rules)})
	}
	leaf := func(zone, ty, value string, extra ...string) string {
		s := "      - zones:\n          - " + zone + "\n"
		for _, e := range extra {
			s += e
		}
		return s + "        match:\n          type: " + ty + "\n          value: " + value + "\n"
	}
	vars := func(v ...string) string {
		s := "        variables:\n"
		for _, x := range v {
			s += "          - '" + x + "'\n"
		}
		return s
	}
	tr := func(v ...string) string {
		s := "        transform:\n"
		for _, x := range v {
			s += "          - " + x + "\n"
		}
		return s
	}

	// ---- Mappings
	conv("and-uri-args", "Mapping: the common shape, URI AND a named query argument. ARGS is ARGS_GET and URI is REQUEST_FILENAME, as in CrowdSec's compiler; t:none first; the head carries id, phase 2, pass, severity, msg and tag; the chained line only t: and chain.",
		hubAnd(leafURI, leaf("ARGS", "contains", "\"../\"", vars("file"), tr("urldecode", "lowercase"))))
	conv("single-leaf", "Mapping: a rule without and, one line.", "  - zones:\n      - URI\n    transform:\n      - lowercase\n    match:\n      type: endsWith\n      value: /_profiler/phpinfo\n")
	conv("zones-all", "Mapping: BODY_ARGS is ARGS_POST, BODY_ARGS_NAMES ARGS_POST_NAMES, ARGS_NAMES ARGS_GET_NAMES, COOKIES REQUEST_COOKIES, FILENAMES FILES (the file name), FILES_NAMES FILES_NAMES, HEADERS_NAMES REQUEST_HEADERS_NAMES, URI_FULL REQUEST_URI, METHOD REQUEST_METHOD, PROTOCOL REQUEST_PROTOCOL.",
		hubAnd(leaf("URI_FULL", "contains", "/api/v2/import"), leaf("METHOD", "equals", "POST"), leaf("PROTOCOL", "startsWith", "HTTP/1"), leaf("BODY_ARGS", "contains", "x", vars("cmd")),
			leaf("ARGS_NAMES", "regex", "^tsml_(info|geocodes)$"), leaf("COOKIES", "contains", "'%2e'", vars("sid")), leaf("HEADERS_NAMES", "contains", "x-middleware-subrequest"), leaf("FILES_NAMES", "contains", "shell")))
	conv("zones-filenames", "Mapping: FILENAMES is FILES, BODY_ARGS_NAMES ARGS_POST_NAMES.", hubAnd(leafURI, leaf("FILENAMES", "endsWith", ".phar", tr("lowercase")), leaf("BODY_ARGS_NAMES", "contains", "upload_dir")))
	conv("two-zones-two-variables", "Mapping: the cross product of zones and variables, in that order, as in the compiler.", hubAnd(leafURI, "      - zones:\n          - BODY_ARGS\n          - ARGS\n"+vars("a", "b")+"        match:\n          type: contains\n          value: php://\n"))
	conv("or-top", "Mapping: or at the top: two groups, two SecRules, ids base and base+1. CrowdSec uses skip:N, the subset has no skip; each group stands alone, and one hub rule counts once.",
		"  - or:\n"+strings.ReplaceAll(leaf("URI", "contains", "/;/web-inf/", tr("lowercase"))+leaf("URI", "contains", "/;/meta-inf/", tr("lowercase")), "      - zones", "      - zones"))
	conv("or-in-and", "Mapping: or inside and is distributed (disjunctive normal form), as flattenToDNF does: URI AND (A OR B) gives two chains.",
		hubAnd(leafURI, "      - or:\n"+strings.ReplaceAll(leaf("ARGS_NAMES", "contains", "\"||\"")+leaf("ARGS_NAMES", "contains", "\"`\""), "      ", "          ")))
	conv("and-in-or", "Mapping: or of and groups.",
		"  - or:\n      - and:\n"+strings.ReplaceAll(leafURI+leaf("ARGS_NAMES", "regex", "^file\\.(path|size)$"), "      ", "          ")+"      - and:\n"+strings.ReplaceAll(leafURI+leaf("BODY_ARGS_NAMES", "regex", "^file\\.(path|size)$"), "      ", "          "))
	conv("rules-list-two", "Mapping: several entries in rules: are alternatives; the group index runs on across them.",
		"  - zones:\n      - URI\n    match:\n      type: endsWith\n      value: /_profiler/phpinfo\n  - zones:\n      - URI\n    match:\n      type: endsWith\n      value: /_profiler/open\n")
	conv("transform-b64", "Mapping: b64decode is t:base64Decode, before lowercase; order is kept.", hubAnd(leafURI, leaf("BODY_ARGS", "contains", "<!ENTITY", vars("SAMLRequest"), tr("b64decode", "lowercase"))))
	conv("transform-others", "Mapping: normalizepath, trim, uppercase (hub profile only).", hubAnd(leafURI, leaf("ARGS", "equals", "ADMIN", vars("role"), tr("urldecode", "uppercase", "trim", "normalizepath"))))
	conv("match-startswith", "Mapping: startsWith is @beginsWith.", hubAnd(leafURI, leaf("ARGS", "startsWith", "file://", vars("url"))))
	conv("match-libinjection", "Mapping: libinjectionSQL and libinjectionXSS take no value.", hubAnd(leafURI, "      - zones:\n          - ARGS\n        variables:\n          - id\n        match:\n          type: libinjectionSQL\n", "      - zones:\n          - BODY_ARGS\n        match:\n          type: libinjectionXSS\n"))
	conv("match-gte-length", "Mapping: gte is @ge; length is t:length. A numeric line goes last: AND is commutative and the subset wants a string head.", hubAnd(leaf("ARGS", "gte", "100", vars("target"), tr("length")), leafURI))
	conv("match-count-gte", "Mapping: count is the & prefix on every variable, and no t:. Rewritten from a rule that counts a repeated argument.", hubAnd(leaf("BODY_ARGS", "gte", "2", vars("user[email][]"), tr("count")), leafURI))
	conv("match-count-equals", "Mapping: count with equals is @eq (the compiler writes @streq on the digits, which means the same).", hubAnd(leafURI, leaf("HEADERS", "equals", "\"0\"", vars("User-Agent"), tr("count"))))
	conv("match-not", "Mapping: not is ! and goes last; a negated line is never the head.", hubAnd("      - zones:\n          - ARGS\n        variables:\n          - id\n        match:\n          type: regex\n          value: '[^0-9]'\n          not: true\n", leafURI))
	conv("scalar-text-bool", "Mapping: a scalar stays the text it was written as: value: false is the string false, as yaml.v3 decodes it into CrowdSec's string field.", hubAnd(leafURI, leaf("HEADERS", "equals", "false", vars("x-pan-authcheck"), tr("lowercase"))))
	conv("scalar-text-int", "Mapping: value: 1 is the string 1.", hubAnd(leafURI, leaf("ARGS", "equals", "1", vars("error"), tr("lowercase"))))
	conv("selector-bracket", "Mapping: the hub profile takes brackets in selectors (PHP array names).", hubAnd(leafURI, leaf("ARGS", "contains", "../", vars("parameters[template_name]"))))
	conv("selector-json-long", "Mapping: the hub profile takes selectors up to 128 bytes (json.a.b.c keys of Coraza's JSON processor); the subset stops at 64.", hubAnd(leafURI, leaf("BODY_ARGS", "regex", ".+", vars("json.address.totalsCollector.collectorList.totalCollector.sourceData.data"))))
	conv("selector-regex", "Mapping: a /regex/ selector passes the @rx subset.", hubAnd(leafURI, leaf("BODY_ARGS", "contains", "exec", vars("/.+filename$/"))))
	conv("raw-body", "Mapping and note: RAW_BODY is REQUEST_BODY|TX:json_request_body with the note raw_body_partial. RAW_REQUEST_BODY exists only in CrowdSec's Coraza fork; upstream fills REQUEST_BODY for urlencoded bodies and the TX variable for JSON, so XML, multipart and plain text bodies stay invisible to such a rule.",
		hubAnd(leafURI, leaf("RAW_BODY", "regex", "\\x22path\\x22\\s*:\\s*\\x22[^/\\x22]", tr("lowercase"))))
	conv("leaf-name-ignored", "Mapping: name on a leaf is not a variable: the compiler ignores it, so the whole zone is inspected.", hubAnd(leafURI, "      - zones:\n          - ARGS\n        name: lang\n        transform:\n          - lowercase\n        match:\n          type: contains\n          value: ../\n"))
	conv("eight-lines", "Bound: 8 lines of one chain is the hub maximum of 2026-10-30 and the limit of the hub profile (the subset allows 4).",
		hubAnd(leafURI, leaf("METHOD", "equals", "POST"), leaf("ARGS", "contains", "a", vars("a")), leaf("ARGS", "contains", "b", vars("b")), leaf("ARGS", "contains", "c", vars("c")), leaf("ARGS", "contains", "d", vars("d")), leaf("ARGS", "contains", "e", vars("e")), leaf("ARGS", "contains", "f", vars("f"))))
	ok("convert-description-fallback", "Metadata: without a description in the YAML the one of the index is used. Labels stay text, cut and cleaned; hub text never reaches the SecRule.",
		map[string]any{"op": "convert", "name": name, "version": "0.2", "description": "From the index. \u0007 Control characters go.", "content": "name: " + name + "\nrules:\n" + hubAnd(leafURI, leaf("ARGS", "contains", "x", vars("a"))) + "labels:\n  label: \"Example\\t- ',msg:'x\"\n  classification:\n    - cve.CVE-2024-0012\n    - cve.CVE-2024-0012\n    - CWE.CWE-79\n    - other.thing\n"})

	// ---- Refusals of one rule (valid input, verdict skipped)
	skipRaw := func(vec, desc, content string) {
		ok("skip-"+vec, desc, map[string]any{"op": "convert", "name": name, "version": "0.2", "content": content})
	}
	skipR := func(vec, desc, rules string) { skipRaw(vec, desc, hubYAML(name, rules)) }
	skipRaw("raw-seclang", "Refusal raw_seclang: an item with seclang_rules is refused whole, also when its rules: part converts. Its lines use TX, setvar and foreign ids, which no line of the subset may; nothing loads partly.",
		hubYAML(name, hubAnd(leafURI, leaf("ARGS", "contains", "x", vars("a"))))+"seclang_rules:\n  - SecRule TX:x \"@gt 50\" \"id:2026109617,phase:2,deny\"\n")
	skipRaw("external-data", "Refusal external_data: rules that need downloaded files.", hubYAML(name, hubAnd(leafURI))+"data:\n  - source_url: https://hub-data.crowdsec.net/x\n    dest_file: x\n    type: regexp\n")
	skipRaw("unknown-top-key", "Refusal unknown_key: an unknown construct is refused, not ignored.", hubYAML(name, hubAnd(leafURI))+"hooks:\n  - on_match: x\n")
	skipRaw("name-mismatch", "Refusal name_mismatch: the YAML names another rule.", hubYAML("crowdsecurity/vpatch-CVE-2026-9999", hubAnd(leafURI)))
	skipRaw("no-rules", "Refusal no_rules.", "name: "+name+"\nlabels:\n  type: exploit\n")
	skipRaw("yaml-broken", "Refusal yaml: does not parse.", "name: [unclosed\n")
	skipRaw("yaml-anchor", "Refusal yaml: anchors and aliases are refused (the same parser rules as schild.yaml).", "name: "+name+"\nrules:\n  - &a\n    zones:\n      - URI\n    match:\n      type: contains\n      value: /x/y/z\n  - *a\n")
	skipRaw("yaml-tag", "Refusal yaml: explicit tags are refused.", "name: "+name+"\nrules:\n  - zones:\n      - URI\n    match:\n      type: contains\n      value: !!binary eHg=\n")
	skipRaw("yaml-duplicate-key", "Refusal yaml: duplicate keys are refused.", "name: "+name+"\nname: "+name+"\nrules: []\n")
	skipRaw("yaml-two-documents", "Refusal yaml: one document.", "name: "+name+"\n---\nname: x\n")
	skipRaw("yaml-merge-key", "Refusal yaml: merge keys are refused.", "name: "+name+"\n<<: {x: 1}\nrules: []\n")
	ok("skip-bad-name", "Refusal bad_name: the name goes into msg, so its characters are fixed.", map[string]any{"op": "convert", "name": "crowdsecurity/vpatch-CVE,ctl:x", "version": "0.2", "content": "name: x\n"})
	ok("skip-rule-too-long", "Refusal rule_too_long: above 64 KiB of YAML.", map[string]any{"op": "convert", "name": name, "version": "0.2", "content": hubYAML(name, hubAnd(leafURI)) + "# " + strings.Repeat("x", 70000) + "\n"})
	skipR("zone-unknown", "Refusal unsupported_zone: an unknown zone.", hubAnd(leafURI, leaf("RESPONSE_BODY", "contains", "x")))
	skipR("zone-files-total", "Refusal unsupported_zone: FILES_TOTAL_SIZE exists in the compiler, but not in the subset, and no hub rule uses it.", hubAnd(leafURI, leaf("FILES_TOTAL_SIZE", "gt", "1000")))
	skipR("transform-unknown", "Refusal unsupported_transform.", hubAnd(leafURI, leaf("ARGS", "contains", "x", vars("a"), tr("rot13"))))
	skipR("transform-b64encode", "Refusal unsupported_transform: b64encode is in the compiler but not in the subset, and no hub rule uses it.", hubAnd(leafURI, leaf("ARGS", "contains", "x", vars("a"), tr("b64encode"))))
	skipR("match-unknown", "Refusal unsupported_match.", hubAnd(leafURI, leaf("ARGS", "fuzzy", "x", vars("a"))))
	skipR("match-from-file", "Refusal unsupported_match: fromFile needs external data.", hubAnd(leafURI, leaf("ARGS", "fromFile", "bad.txt", vars("a"))))
	skipR("missing-value", "Refusal missing_value.", hubAnd(leafURI, "      - zones:\n          - ARGS\n        variables:\n          - a\n        match:\n          type: contains\n"))
	skipR("empty-value", "Refusal missing_value: an empty string would match everything.", hubAnd(leafURI, leaf("ARGS", "contains", "\"\"", vars("a"))))
	skipR("value-nul", "Refusal value_chars: a NUL byte cannot be written in SecLang text. Rewritten from a real rule; CrowdSec puts the raw byte into the rule.", hubAnd(leafURI, leaf("BODY_ARGS", "contains", "\"\\x00\"", vars("auth"))))
	skipR("value-quote", "Refusal value_chars: a double quote would end the argument.", hubAnd(leafURI, leaf("ARGS", "contains", "'a\"b'", vars("a"))))
	skipR("value-macro", "Refusal value_chars: %{ expands macros in Coraza.", hubAnd(leafURI, leaf("ARGS", "contains", "'%{REMOTE_ADDR}'", vars("a"))))
	skipR("value-edge-space", "Refusal value_chars: Coraza trims the argument.", hubAnd(leafURI, leaf("ARGS", "contains", "' x'", vars("a"))))
	skipR("value-trailing-backslash", "Refusal value_chars: would escape the closing quote.", hubAnd(leafURI, leaf("ARGS", "contains", "'x\\'", vars("a"))))
	skipR("not-numeric", "Refusal not_numeric.", hubAnd(leafURI, leaf("ARGS", "gte", "many", vars("a"), tr("length"))))
	skipR("count-without-variable", "Refusal count_without_variable: the compiler silently drops count here, which would change the meaning.", hubAnd(leafURI, leaf("ARGS", "gte", "2", tr("count"))))
	skipR("selector-on-scalar", "Refusal selector: METHOD is one value.", hubAnd(leafURI, leaf("METHOD", "equals", "POST", vars("x"))))
	skipR("selector-chars", "Refusal selector: a space or quote would break the rule text.", hubAnd(leafURI, leaf("ARGS", "contains", "x", vars("a b"))))
	skipR("selector-regex-bad", "Refusal selector: the /regex/ pattern fails the @rx subset.", hubAnd(leafURI, leaf("ARGS", "contains", "x", vars("/(?=a)/"))))
	skipR("selector-regex-on-header", "Refusal selector: REQUEST_HEADERS needs a literal name for the forbidden lists.", hubAnd(leafURI, leaf("HEADERS", "contains", "x", vars("/.*/"))))
	skipR("headers-without-name", "Refusal headers_without_name: all headers include Host.", hubAnd(leafURI, leaf("HEADERS", "contains", "x")))
	skipR("forbidden-header-host", "Refusal forbidden_header: same list as the subset: no targeting of a site or a client.", hubAnd(leafURI, leaf("HEADERS", "contains", "x", vars("Host"))))
	skipR("forbidden-header-xff", "Refusal forbidden_header: X-Forwarded-For. Rewritten from a real rule.", hubAnd(leafURI, leaf("HEADERS", "contains", "127.0.0.1", vars("x-forwarded-for"), tr("lowercase"))))
	skipR("forbidden-header-origin", "Refusal forbidden_header: Origin only with a detection operator. Rewritten from a real rule.", hubAnd(leafURI, leaf("HEADERS", "contains", "https://", vars("origin"), tr("lowercase"))))
	skipR("regex-lookahead", "Refusal regex: outside the @rx subset.", hubAnd(leafURI, leaf("ARGS", "regex", "'(?=a)b'", vars("a"))))
	skipR("regex-nested", "Refusal regex: nested quantifier, as in the subset. Rewritten from the rules: part of the php2shell rule.", hubAnd(leafURI, leaf("BODY_ARGS_NAMES", "regex", "'(?:\\[[^\\]]*\\]){12}'")))
	skipR("catch-all", "Refusal catch_all: every line matches a value of the benign corpus. Rewritten from a real rule.", hubAnd(leaf("URI", "contains", "/", tr("lowercase")), leaf("BODY_ARGS", "contains", "\"1\"", vars("x"))))
	skipR("catch-all-numeric", "Refusal catch_all: a group of numeric or negated lines has no head and is never specific.", hubAnd(leaf("ARGS", "gte", "1", vars("a"), tr("count"))))
	skipR("node-both", "Refusal node_shape: and with zones at the same node: the compiler treats it as an implicit AND, no hub rule uses it.", "  - zones:\n      - URI\n    match:\n      type: contains\n      value: /x/y/z\n    and:\n"+strings.ReplaceAll(leafURI, "      ", "      "))
	skipR("node-empty-and", "Refusal node_shape: an empty and.", "  - and: []\n")
	skipR("node-no-match", "Refusal node_shape: a leaf without match.", hubAnd("      - zones:\n          - URI\n"))
	skipR("unknown-leaf-key", "Refusal unknown_key: body_type would need ctl:, which the subset refuses; severity is not used by any hub rule.", hubAnd(leafURI, "      - zones:\n          - ARGS\n        body_type: json\n        match:\n          type: contains\n          value: x\n"))
	skipR("unknown-match-key", "Refusal unknown_key in match.", hubAnd(leafURI, "      - zones:\n          - ARGS\n        match:\n          type: contains\n          value: x\n          flags: i\n"))
	var many strings.Builder
	many.WriteString("  - or:\n")
	for i := 0; i < 9; i++ {
		fmt.Fprintf(&many, "      - zones:\n          - URI\n        match:\n          type: contains\n          value: /example/path-%d\n", i)
	}
	skipR("too-many-groups", "Refusal too_many_groups: 9 alternatives; 8 ids per rule (the hub maximum is 4; the compiler allows 50).", many.String())
	skipR("too-many-lines", "Refusal too_many_lines: 9 lines of one chain.",
		hubAnd(leafURI, leaf("METHOD", "equals", "POST"), leaf("ARGS", "contains", "a", vars("a")), leaf("ARGS", "contains", "b", vars("b")), leaf("ARGS", "contains", "c", vars("c")), leaf("ARGS", "contains", "d", vars("d")), leaf("ARGS", "contains", "e", vars("e")), leaf("ARGS", "contains", "f", vars("f")), leaf("ARGS", "contains", "g", vars("g"))))
	skipR("too-many-variables", "Refusal too_many_variables: more than 16 after the cross product.", hubAnd(leafURI, "      - zones:\n          - ARGS\n          - BODY_ARGS\n        variables: [a, b, c, d, e, f, g, h, i]\n        match:\n          type: contains\n          value: x\n"))

	// ---- Update of a set
	a, b, x := "crowdsecurity/vpatch-CVE-2026-1207", "crowdsecurity/vpatch-CVE-2025-29927", "crowdsecurity/vpatch-CVE-2024-27956"
	ya := hubYAML(a, hubAnd(leafURI, leaf("ARGS", "contains", "x", vars("a"))))
	yb := hubYAML(b, "  - zones:\n      - HEADERS_NAMES\n    transform:\n      - lowercase\n    match:\n      type: regex\n      value: x-middleware-(subrequest|rewrite)\n")
	yx := hubYAML(x, hubAnd(leafURI, leaf("BODY_ARGS", "contains", "\"\\x00\"", vars("auth"))))
	dig := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	idx := hubIndex(map[string]string{a: ya, b: yb, x: yx, "crowdsecurity/vpatch-CVE-2026-111497!": ya,
		"crowdsecurity/base-config": "name: crowdsecurity/base-config\nseclang_rules: []\n"}, nil)
	up := func(vec, desc string, m map[string]any) {
		m["op"], m["now"] = "update", hubT0
		ok("update-"+vec, desc, m)
	}
	const earlier = "2026-10-01T00:00:00Z"
	up("first-set", "Update: a first set. Skipped rules are normal; an item outside the collection is counted, not listed, also when its name is vpatch-. Every rule is added, first_seen and changed_at are now.", map[string]any{"index": idx})
	prev := map[string]any{a: map[string]any{"digest": dig(ya), "first_seen": earlier, "changed_at": earlier},
		b: map[string]any{"digest": strings.Repeat("a", 64), "first_seen": earlier, "changed_at": earlier}, "crowdsecurity/vpatch-CVE-2020-0001": map[string]any{"digest": strings.Repeat("b", 64), "first_seen": earlier, "changed_at": earlier}}
	up("changed-and-removed", "Update: an unchanged rule keeps first_seen and changed_at; a changed digest restarts the settling time but keeps first_seen; a rule that left the set is listed as removed.", map[string]any{"index": idx, "previous": prev})
	up("digest-mismatch", "Update: a rule whose content does not match the digest of its version is skipped; the rest loads.", map[string]any{"index": hubIndex(map[string]string{a: ya, b: yb}, map[string]map[string]any{b: {"versions": map[string]any{"0.2": map[string]any{"deprecated": false, "digest": strings.Repeat("c", 64)}}}})})
	up("version-not-listed", "Update: the version is not in versions: digest_mismatch.", map[string]any{"index": hubIndex(map[string]string{a: ya, b: yb}, map[string]map[string]any{b: {"version": "0.9"}})})
	up("deprecated", "Update: a deprecated current version is skipped.", map[string]any{"index": hubIndex(map[string]string{a: ya, b: yb}, map[string]map[string]any{b: {"versions": map[string]any{"0.2": map[string]any{"deprecated": true, "digest": dig(yb)}}}})})
	up("path-mismatch", "Update: the path must fit the name.", map[string]any{"index": hubIndex(map[string]string{a: ya, b: yb}, map[string]map[string]any{b: {"path": "appsec-rules/crowdsecurity/other.yaml"}})})
	up("refuse-oversize", "Update refused index_oversize: above the bound (lowered here). The running set stays.", map[string]any{"index": idx, "limits": map[string]any{"index_bytes": 100}})
	up("refuse-not-json", "Update refused index_malformed: truncated download.", map[string]any{"index": idx[:200]})
	up("refuse-no-section", "Update refused index_malformed: no appsec-rules.", map[string]any{"index": `{"collections":{}}`})
	up("refuse-no-collection", "Update refused index_malformed: without the collection nothing says which rules belong to the source.", map[string]any{"index": `{"appsec-rules":{},"collections":{}}`})
	up("refuse-item-not-object", "Update refused index_malformed: a broken item is a broken index, not a skipped rule.", map[string]any{"index": `{"appsec-rules":{"` + a + `":1},"collections":{"` + crowdsec.Collection + `":{"appsec-rules":["` + a + `"]}}}`})
	up("refuse-item-no-content", "Update refused index_malformed: an item without content.", map[string]any{"index": `{"appsec-rules":{"` + a + `":{"path":"x","version":"0.1","versions":{}}},"collections":{"` + crowdsec.Collection + `":{"appsec-rules":["` + a + `"]}}}`})
	up("refuse-bad-base64", "Update refused index_malformed: content is not base64.", map[string]any{"index": `{"appsec-rules":{"` + a + `":{"path":"x","version":"0.1","content":"!!!","versions":{}}},"collections":{"` + crowdsec.Collection + `":{"appsec-rules":["` + a + `"]}}}`})
	up("refuse-too-many", "Update refused too_many_rules (bound lowered here).", map[string]any{"index": idx, "limits": map[string]any{"rules": 2}})
	up("refuse-set-too-large", "Update refused set_too_large (bound lowered here).", map[string]any{"index": idx, "limits": map[string]any{"set_bytes": 100}})
	up("refuse-empty", "Update refused set_empty: nothing would load.", map[string]any{"index": hubIndex(map[string]string{x: yx}, nil)})
	prevMany := map[string]any{}
	for i := 0; i < 7; i++ {
		prevMany[fmt.Sprintf("crowdsecurity/vpatch-CVE-2020-000%d", i)] = map[string]any{"digest": strings.Repeat("d", 64), "first_seen": earlier, "changed_at": earlier}
	}
	up("refuse-shrink", "Update refused shrink: 2 rules against 7 running: a hollow index looks valid.", map[string]any{"index": idx, "previous": prevMany})
	delete(prevMany, "crowdsecurity/vpatch-CVE-2020-0006")
	delete(prevMany, "crowdsecurity/vpatch-CVE-2020-0005")
	delete(prevMany, "crowdsecurity/vpatch-CVE-2020-0004")
	up("shrink-half-accepted", "Update: exactly half of the running set is accepted.", map[string]any{"index": idx, "previous": prevMany})

	// ---- Effect
	g.retire(c, true) // detect-autoblock (rule-effect, D73)
	g.retire(c, true) // detect-observe (rule-effect, D73)
	g.retire(c, true) // detect-review (rule-effect, D73)
	g.retire(c, true) // off (rule-effect, D73)
	g.retire(c, true) // disabled (rule-effect, D73)
	g.retire(c, true) // bypass (rule-effect, D73)
	g.retire(c, true) // block-autoblock (rule-effect, D73)
	g.retire(c, true) // block-review (rule-effect, D73)
	g.retire(c, true) // block-gateway-observe (rule-effect, D73)
	g.retire(c, true) // block-site-observe (rule-effect, D73)
	g.retire(c, true) // block-no-block-entry (rule-effect, D73)
	g.retire(c, true) // block-excepted (rule-effect, D73)
	g.retire(c, true) // effect-block-settling (rule-effect, D73)
	g.retire(c, true) // effect-block-settled (rule-effect, D73)
	g.retire(c, true) // effect-block-settling-observe (rule-effect, D73)
	g.retire(c, true) // effect-block-no-settling (rule-effect, D73)

	// ---- Which set loads at start
	sel := func(vec, desc string, m map[string]any) {
		m["op"], m["now"] = "select", hubT0
		ok("select-"+vec, desc, m)
	}
	const c1, c2 = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	cand := func(present, valid bool, commit string) map[string]any {
		m := map[string]any{"present": present, "valid": valid}
		if commit != "" {
			m["commit"] = commit
		}
		return m
	}
	at := func(c map[string]any, t string) map[string]any { c["time"] = t; return c }
	const older, newerT = "2026-10-20T00:00:00Z", "2026-10-25T00:00:00Z"
	sel("stored-first", "Start: the stored set is newer than the image snapshot, so it runs.", map[string]any{"state": "detect", "stored": at(cand(true, true, ""), newerT), "image": at(cand(true, true, c2), older)})
	sel("stored-broken", "Start: a stored set that fails to load falls back to the image snapshot, also an older one.", map[string]any{"state": "detect", "stored": at(cand(true, false, ""), newerT), "image": at(cand(true, true, c2), older)})
	sel("no-stored", "Start: the first start with no stored set uses the image snapshot, also without network.", map[string]any{"state": "detect", "stored": cand(false, false, ""), "image": cand(true, true, c2)})
	sel("nothing", "Start: nothing valid: no rules, and the gateway starts anyway; this source never stops a start.", map[string]any{"state": "block", "stored": cand(true, false, ""), "image": cand(false, false, "")})
	sel("off", "Start: off loads nothing.", map[string]any{"state": "off", "stored": cand(true, true, ""), "image": cand(true, true, c2)})
	sel("pin-stored", "Start: a pin wants the stored set of that commit.", map[string]any{"state": "detect", "pin": c1, "stored": cand(true, true, c1), "image": cand(true, true, c2)})
	sel("pin-other-stored", "Start: a pin neither set matches: the newer set runs and pin_pending stays until the fetch worked.", map[string]any{"state": "detect", "pin": c1, "stored": at(cand(true, true, c2), older), "image": at(cand(true, true, c2), newerT)})
	sel("pin-image", "Start: the image snapshot may be the pinned commit.", map[string]any{"state": "detect", "pin": c2, "stored": cand(false, false, ""), "image": cand(true, true, c2)})
	sel("pin-only-stored", "Start: with a broken image a stored set of another commit is still better than none.", map[string]any{"state": "detect", "pin": c1, "stored": cand(true, true, c2), "image": cand(true, false, "")})

	// ---- The switch
	g.retire(c, true) // default (rule-effect, D73)
	g.retire(c, true) // config (rule-effect, D73)
	g.retire(c, true) // overlay-wins (rule-effect, D73)
	g.retire(c, true) // overlay-equal (rule-effect, D73)
	g.retire(c, true) // off-to-detect (rule-effect, D73)
	g.retire(c, true) // detect-to-off (rule-effect, D73)
	g.retire(c, true) // detect-to-block (rule-effect, D73)
	g.retire(c, true) // block-to-detect (rule-effect, D73)
	g.retire(c, true) // no-change (rule-effect, D73)
	g.retire(c, true) // reset (rule-effect, D73)
	g.retire(c, true) // reset-nothing (rule-effect, D73)

	// ---- D39 amendment: the switch through the agent API, no password
	g.retire(c, true) // agent-sets (rule-effect, D73)
	g.retire(c, true) // agent-value-stays (rule-effect, D73)
	g.retire(c, true) // agent-to-off (rule-effect, D73)
	g.retire(c, true) // dashboard-over-agent (rule-effect, D73)
	g.retire(c, true) // agent-over-dashboard (rule-effect, D73)
	g.retire(c, true) // agent-reset (rule-effect, D73)
	g.retire(c, true) // read-token (rule-effect, D73)
	g.retire(c, true) // export-token (rule-effect, D73)
	g.retire(c, true) // write-token (rule-effect, D73)
	g.retire(c, true) // unknown-scope (rule-effect, D73)

	// ---- D39 amendment: the newer set wins
	sel("newer-image", "D39 amendment: a newer image snapshot wins over the stored set, whatever auto_update says (it is not an input).", map[string]any{"state": "detect", "stored": at(cand(true, true, ""), older), "image": at(cand(true, true, c2), newerT)})
	sel("tie", "D39 amendment: on a tie the stored set stays: it holds this gateway's history of the rules.", map[string]any{"state": "detect", "stored": at(cand(true, true, ""), newerT), "image": at(cand(true, true, c2), newerT)})
	sel("stored-no-date", "D39 amendment: a date beats no date: a pinned stored set without a commit time may be old.", map[string]any{"state": "detect", "stored": cand(true, true, c1), "image": at(cand(true, true, c2), older)})
	sel("image-no-date", "D39 amendment: the same the other way round.", map[string]any{"state": "detect", "stored": at(cand(true, true, ""), older), "image": cand(true, true, c2)})
	sel("no-dates", "D39 amendment: neither has a date: the stored set stays.", map[string]any{"state": "detect", "stored": cand(true, true, ""), "image": cand(true, true, c2)})
	sel("unreadable-date", "D39 amendment: an unreadable date counts as none.", map[string]any{"state": "detect", "stored": at(cand(true, true, ""), "yesterday"), "image": at(cand(true, true, c2), older)})
	sel("future-date", "D39 amendment: a date further ahead than the clock skew counts as none: a wrong clock must not keep a stale set alive.", map[string]any{"state": "detect", "stored": at(cand(true, true, ""), "2030-01-01T00:00:00Z"), "image": at(cand(true, true, c2), older)})
	sel("skew-date", "D39 amendment: a date within the 120 s of clock skew still counts.", map[string]any{"state": "detect", "stored": at(cand(true, true, ""), "2026-10-26T12:02:00Z"), "image": at(cand(true, true, c2), newerT)})
	sel("pin-beats-newer", "D39 amendment: a pin wins over the rule: the stored set of the pin runs although the image is newer.", map[string]any{"state": "detect", "pin": c1, "stored": at(cand(true, true, c1), older), "image": at(cand(true, true, c2), newerT)})
	sel("pin-image-beats-newer", "D39 amendment: the image of the pin runs although the stored set is newer.", map[string]any{"state": "detect", "pin": c2, "stored": at(cand(true, true, c1), newerT), "image": at(cand(true, true, c2), older)})
	g.retire(c, true) // review-site-observe (rule-effect, D73)
	g.retire(c, true) // review-no-block-entry (rule-effect, D73)
	g.retire(c, true) // review-detect (rule-effect, D73)
	g.retire(c, true) // effect-review-settling (rule-effect, D73)
	g.retire(c, true) // block-autoblock (rule-effect, D73)
	g.retire(c, true) // block-review (rule-effect, D73)
	g.retire(c, true) // block-observe (rule-effect, D73)
	g.retire(c, true) // detect-autoblock (rule-effect, D73)
	g.retire(c, true) // off-review (rule-effect, D73)
	sel("off-newer", "D39 amendment: off still loads nothing.", map[string]any{"state": "off", "stored": at(cand(true, true, ""), older), "image": at(cand(true, true, c2), newerT)})

	// ---- D43: shrink against the image snapshot, the measured cost check
	prev7 := map[string]any{}
	for i := 0; i < 7; i++ {
		prev7[fmt.Sprintf("crowdsecurity/vpatch-CVE-2020-000%d", i)] = map[string]any{"digest": strings.Repeat("d", 64), "first_seen": earlier, "changed_at": earlier}
	}
	up("shrink-way-back", "D43: a running set that grew too large does not block the way back: 2 rules against 7 running and a snapshot of 3 are accepted.", map[string]any{"index": idx, "previous": prev7, "shrink_base": 3})
	up("shrink-image-refused", "D43: the snapshot is the mark: 2 rules against a snapshot of 5 are refused, also with nothing running.", map[string]any{"index": idx, "shrink_base": 5})
	up("shrink-no-walk-down", "D43: the rules running do not lower the mark: a set that shrank once cannot be walked down in steps.", map[string]any{"index": idx, "previous": map[string]any{a: map[string]any{"digest": dig(ya), "first_seen": earlier, "changed_at": earlier}, b: map[string]any{"digest": dig(yb), "first_seen": earlier, "changed_at": earlier}}, "shrink_base": 5})
	up("shrink-half-of-image", "D43: exactly half of the snapshot is accepted.", map[string]any{"index": idx, "shrink_base": 4})
	up("shrink-no-image", "D43: without a snapshot the running set counts, as before.", map[string]any{"index": idx, "previous": prev7})
	up("shrink-pin", "D43: a pin is the operator's choice: no shrink check.", map[string]any{"index": idx, "previous": prev7, "shrink_base": -1})
	up("refuse-set-lines", "D43: refused set_too_large on the SecRule lines of the set (bound lowered here).", map[string]any{"index": idx, "limits": map[string]any{"set_lines": 1}})
	cost := func(vec, desc string, base, ref, cand, rounds int) {
		ok("set-cost-"+vec, "D43: "+desc, map[string]any{"op": "set_cost", "baseline_ns": base, "reference_ns": ref, "candidate_ns": cand, "rounds": rounds})
	}
	cost("normal", "the snapshot against itself, as measured: 72 us added.", 22000, 94000, 94000, 16)
	cost("at-bound", "exactly four times what the snapshot adds is accepted.", 20000, 90000, 300000, 16)
	cost("over-bound", "one nanosecond more is refused.", 20000, 90000, 300001, 16)
	cost("hostile", "the hostile shape of the measurement.", 51000, 114000, 54533000, 16)
	cost("slow-machine", "a machine ten times slower decides the same: the numbers are relative.", 220000, 940000, 940000, 16)
	cost("smaller-set", "a set smaller than the snapshot adds less.", 22000, 94000, 45000, 16)
	cost("cheaper-than-baseline", "noise: a candidate below the baseline adds nothing.", 22000, 94000, 21000, 16)
	cost("floor", "noise: a reference at the baseline counts as adding two baselines.", 22000, 21000, 198000, 16)
	cost("no-snapshot", "without a snapshot the reference is the baseline, and the real set still fits.", 22000, 22000, 94000, 16)
	cost("no-snapshot-hostile", "without a snapshot a hostile set is refused.", 22000, 22000, 1600000, 16)
	cost("no-round", "a set that did not finish one round within the budget is refused.", 22000, 94000, 0, 0)
	cost("one-round", "the budget ended early: the finished rounds count.", 22000, 94000, 94000, 1)

	// ---- Broken inputs of the vector itself
	bad("oversize", "Input above 1 MiB.", contract.CodeOversize, []byte(`{"op":"switch","x":"`+strings.Repeat("a", crowdsec.MaxInputBytes)+`"}`), nil)
	bad("not-json", "Not JSON.", contract.CodeMalformed, []byte(`{"op":`), nil)
	bad("duplicate-key", "Strict JSON: duplicate key.", contract.CodeMalformed, []byte(`{"op":"switch","op":"switch"}`), nil)
	inv := func(vec, desc string, m map[string]any) { bad(vec, desc, contract.CodeSchema, mustJSON(m), m) }
	inv("unknown-op", "Unknown op.", map[string]any{"op": "delete"})
	inv("convert-no-content", "convert needs content.", map[string]any{"op": "convert", "name": name, "version": "0.2"})
	inv("update-no-now", "update needs now.", map[string]any{"op": "update", "index": "{}"})
	inv("update-bad-previous", "previous entries are closed.", map[string]any{"op": "update", "index": "{}", "now": hubT0, "previous": map[string]any{a: map[string]any{"digest": "x"}}})
	g.retire(c, false) // effect-bad-state (rule-effect, D73)
	g.retire(c, false) // effect-bad-mode (rule-effect, D73)
	g.retire(c, false) // effect-negative (rule-effect, D73)
	inv("select-no-image", "select needs both candidates.", map[string]any{"op": "select", "state": "detect", "stored": cand(false, false, "")})
	inv("select-bad-pin", "A pin is a commit.", map[string]any{"op": "select", "state": "detect", "pin": "master", "stored": cand(false, false, ""), "image": cand(false, false, "")})
	g.retire(c, false) // switch-bad-state (rule-effect, D73)
	g.retire(c, false) // switch-extra (rule-effect, D73)
	g.retire(c, false) // switch-bad-actor (rule-effect, D73)
	inv("select-no-now", "D39 amendment: the date check needs the clock.", map[string]any{"op": "select", "state": "detect", "stored": cand(false, false, ""), "image": cand(false, false, "")})
	g.retire(c, false) // gateway-effect-bad-mode (rule-effect, D73)
	g.retire(c, false) // agent-write-no-scope (rule-effect, D73)
	inv("set-cost-no-rounds", "D43: the sample says how many rounds finished.", map[string]any{"op": "set_cost", "baseline_ns": 1, "reference_ns": 1, "candidate_ns": 1})
	inv("set-cost-negative", "D43: times are not negative.", map[string]any{"op": "set_cost", "baseline_ns": -1, "reference_ns": 1, "candidate_ns": 1, "rounds": 1})
	inv("update-bad-shrink-base", "D43: -1 is the only value below zero.", map[string]any{"op": "update", "index": "{}", "now": hubT0, "shrink_base": -2})

	// ---- A stored set or image snapshot
	const sc = "crowdsec-set"
	item := func(n, content string) map[string]any {
		return map[string]any{"name": n, "version": "0.2", "digest": dig(content), "content": base64.StdEncoding.EncodeToString([]byte(content)), "first_seen": earlier, "changed_at": hubT0}
	}
	set := func(rules ...any) map[string]any {
		return map[string]any{"schema": crowdsec.SetSchemaVersion, "index_sha256": strings.Repeat("a", 64), "fetched_at": hubT0, "not_selected": 30, "rules": rules}
	}
	setOK := func(vec, desc string, m map[string]any) { g.add(sc, vec, true, "", desc, ctx, mustJSON(m), m) }
	setBad := func(vec, desc string, m map[string]any) {
		g.add(sc, vec, false, contract.CodeSchema, desc, ctx, mustJSON(m), m)
	}
	setOK("stored", "D39: a stored last good set: the selected hub items as they came.", set(item(b, yb), item(a, ya)))
	setOK("one-rule", "D39: one rule is enough.", set(item(a, ya)))
	snap := set(item(b, yb), item(a, ya))
	snap["hub_commit"] = "1111111111111111111111111111111111111111"
	setOK("image-snapshot", "D39: the image snapshot has the same format and names its commit.", snap)
	withSkipped := set(item(x, yx), item(b, yb), item(a, ya))
	setOK("with-unconvertible", "D39: a rule that does not convert stays in the set: the load lists it as skipped with its reason.", withSkipped)
	desc := set(item(a, ya))
	desc["rules"].([]any)[0].(map[string]any)["description"] = "From the index."
	setOK("with-description", "D39: the description of the index is kept.", desc)
	dated := set(item(a, ya))
	dated["hub_commit"], dated["hub_commit_at"] = "1111111111111111111111111111111111111111", "2026-10-25T09:00:00Z"
	setOK("commit-time", "D39 amendment: the commit time says how new a set of a known commit is.", dated)
	setBad("empty", "D39: an empty set is never stored.", set())
	unsorted := set(item(a, ya), item(b, yb))
	setBad("unsorted", "D39: rules are sorted by name.", unsorted)
	setBad("duplicate", "D39: a name occurs once.", set(item(a, ya), item(a, ya)))
	tampered := set(item(a, ya))
	tampered["rules"].([]any)[0].(map[string]any)["digest"] = strings.Repeat("0", 64)
	setBad("digest", "D39: a digest that does not fit the content: the set is not used.", tampered)
	badB64 := set(item(a, ya))
	badB64["rules"].([]any)[0].(map[string]any)["content"] = "!!!"
	setBad("bad-base64", "D39: content is base64.", badB64)
	early := set(item(a, ya))
	early["rules"].([]any)[0].(map[string]any)["changed_at"] = "2026-09-01T00:00:00Z"
	setBad("changed-before-first", "D39: a rule cannot change before it was first seen.", early)
	wrongName := set(item("somebody/rule", ya))
	setBad("foreign-name", "D39: only rules of the source.", wrongName)
	seclangField := set(item(a, ya))
	seclangField["rules"].([]any)[0].(map[string]any)["seclang"] = "SecRule ..."
	setBad("converted-text", "D39: a set holds hub items, never SecLang: a tampered file cannot bring rule text past the converter.", seclangField)
	badSchema := set(item(a, ya))
	badSchema["schema"] = "schild.crowdsec_set/9"
	setBad("schema-version", "D39: the format version is fixed.", badSchema)
	noDigest := set(item(a, ya))
	delete(noDigest, "index_sha256")
	setBad("no-index-digest", "D39: the identity of the set is required.", noDigest)
	badCommit := set(item(a, ya))
	badCommit["hub_commit"] = "master"
	setBad("bad-commit", "D39: a commit, not a branch.", badCommit)
	g.add(sc, "not-json", false, contract.CodeMalformed, "D39: truncated file.", ctx, []byte(`{"schema":`), nil)
	lone := set(item(a, ya))
	lone["hub_commit_at"] = "2026-10-25T09:00:00Z"
	setBad("commit-time-alone", "D39 amendment: a commit time belongs to a commit.", lone)
	badTime := set(item(a, ya))
	badTime["hub_commit"], badTime["hub_commit_at"] = "1111111111111111111111111111111111111111", "yesterday"
	setBad("commit-time-unreadable", "D39 amendment: the file format allows no unreadable date; a set that has one is not used.", badTime)

	// ---- The network subset did not change
	secl := vectors.Context{MaxAction: "observe"}
	chain := func(id, vars, ts string) []byte {
		return []byte(`SecRule REQUEST_FILENAME "@contains /wp-json/example/v1/" "id:` + id + `,phase:2,pass,t:none,severity:CRITICAL,msg:'x',chain"` + "\n" + `SecRule ` + vars + ` "@contains x" "t:none` + ts + `"`)
	}
	notNet := func(vec, desc string, raw []byte) {
		g.add("seclang", vec, false, contract.CodeSecLang, desc, secl, raw, nil)
	}
	notNet("hub-id-not-network", "D39: the id range of the hub source is not open to network rules.", chain("62846312", "ARGS_GET:a", ""))
	notNet("hub-uppercase-not-network", "D39: t:uppercase is hub profile only.", chain("7700001", "ARGS_GET:a", ",t:uppercase"))
	notNet("hub-tx-not-network", "D39: TX:json_request_body is hub profile only.", chain("7700001", "TX:json_request_body", ""))
	notNet("hub-bracket-not-network", "D39: brackets in selectors are hub profile only.", chain("7700001", "ARGS_GET:a[]", ""))
	notNet("hub-regex-selector-not-network", "D39: /regex/ selectors are hub profile only.", chain("7700001", "ARGS_GET:/a/", ""))

	// ---- schild.yaml
	const cfg = "config/schild"
	add := func(valid bool, code contract.Code, vec, desc string, v any) {
		m := siteConfig()
		m["rules"] = map[string]any{"crowdsec": v}
		g.add(cfg, vec, valid, code, desc, ctx, mustJSON(m), m)
	}
	add(true, "", "rules-crowdsec-full", "D39: the whole section.", map[string]any{"state": "block", "auto_update": true, "interval_s": 86400,
		"pin": "1111111111111111111111111111111111111111", "disabled_rules": []any{a}, "settling_s": 172800})
	add(true, "", "rules-crowdsec-empty", "D39: an empty section keeps the defaults: detect, auto_update, hourly, 24 h settling.", map[string]any{})
	add(true, "", "rules-crowdsec-off", "D39: the one switch: off.", map[string]any{"state": "off"})
	add(true, "", "rules-crowdsec-detect", "D39: the one switch: detect (Erkannt).", map[string]any{"state": "detect"})
	add(true, "", "rules-crowdsec-no-updates", "D39: updates can be switched off.", map[string]any{"auto_update": false})
	add(true, "", "rules-crowdsec-no-settling", "D39: settling_s 0.", map[string]any{"settling_s": 0})
	add(false, contract.CodeSchema, "rules-crowdsec-bad-state", "D39: three states only.", map[string]any{"state": "on"})
	add(false, contract.CodeSchema, "rules-crowdsec-enabled", "D39: one switch: there is no enabled or effect key.", map[string]any{"enabled": true})
	add(false, contract.CodeSchema, "rules-crowdsec-url", "D39: the hub URL is not configurable.", map[string]any{"url": "https://mirror.example/index.json"})
	add(false, contract.CodeSchema, "rules-crowdsec-interval-low", "D39: at least 5 minutes between checks.", map[string]any{"interval_s": 60})
	add(false, contract.CodeSchema, "rules-crowdsec-interval-high", "D39: at most a week.", map[string]any{"interval_s": 2592000})
	add(false, contract.CodeSchema, "rules-crowdsec-bad-pin", "D39: a pin is a commit, not a branch.", map[string]any{"pin": "master"})
	add(false, contract.CodeSchema, "rules-crowdsec-bad-rule", "D39: disabled_rules are hub names of the source.", map[string]any{"disabled_rules": []any{"62846312"}})
	add(false, contract.CodeSchema, "rules-crowdsec-duplicate-rule", "D39: no duplicates.", map[string]any{"disabled_rules": []any{a, a}})
	add(false, contract.CodeSchema, "rules-crowdsec-settling-high", "D39: at most 30 days.", map[string]any{"settling_s": 2592001})

	// ---- Events
	const evc = "events"
	addEv := func(valid bool, code contract.Code, vec, desc string, ev map[string]any) {
		g.add(evc, vec, valid, code, desc, ctx, mustJSON(ev), ev)
	}
	matched := func(extra map[string]any) map[string]any {
		d := reqData("req-hub-match")
		mr := map[string]any{"id": 62846312, "repository": "crowdsec", "msg": "crowdsec hub " + a,
			"crowdsec": map[string]any{"name": a, "version": "0.2", "label": "Example - RCE", "cves": []any{"CVE-2026-1207"}}}
		for k, v := range extra {
			mr[k] = v
		}
		d["rules"], d["outcome"] = []any{mr}, "logged"
		return cloudEvent("schild.request.evaluated.v1", "hub", d)
	}
	addEv(true, "", "crowdsec-match", "D73: a crowdsec rule matched in detect: outcome logged, repository crowdsec, name, version, label, CVE.", matched(nil))
	upd := func(name string, m map[string]any) map[string]any {
		m["repository"] = "crowdsec"
		return cloudEvent("schild.rule.repository_updated.v1", name, m)
	}
	addEv(true, "", "crowdsec-updated", "D39: a set was swapped in.", upd("hub-ok", map[string]any{"outcome": "accepted", "set_source": "stored", "index_sha256": strings.Repeat("a", 64), "rules_loaded": 201, "rules_skipped": 5, "added": []any{a}, "changed": []any{}, "removed": []any{}}))
	addEv(true, "", "crowdsec-refused", "D39: an update was refused, the running set stayed.", upd("hub-no", map[string]any{"outcome": "refused", "code": "shrink", "set_source": "image", "rules_loaded": 199, "rules_skipped": 5}))
	addEv(false, contract.CodeSchema, "crowdsec-bad-source", "D73: the repository is a fixed enum; the old source value is gone.", func() map[string]any {
		e := matched(map[string]any{"repository": "crowdsec_hub"})
		return e
	}())
	addEv(false, contract.CodeSchema, "crowdsec-bad-name", "D39: the hub reference has the name of a rule of the source.", matched(map[string]any{"crowdsec": map[string]any{"name": "somebody/else", "version": "0.2"}}))
	addEv(false, contract.CodeSchema, "crowdsec-no-reference", "D73: repository crowdsec always names the hub rule.", func() map[string]any {
		e := matched(nil)
		rs := e["data"].(map[string]any)["rules"].([]any)
		delete(rs[0].(map[string]any), "crowdsec")
		return e
	}())
	addEv(false, contract.CodeSchema, "crowdsec-score-field", "D39: the hub reference carries no points: this source has no anomaly score.", matched(map[string]any{"crowdsec": map[string]any{"name": a, "version": "0.2", "points": 5}}))
	addEv(false, contract.CodeSchema, "crowdsec-refused-no-code", "D39: a refusal names its code.", upd("hub-nocode", map[string]any{"outcome": "refused", "set_source": "image", "rules_loaded": 1, "rules_skipped": 0}))
	addEv(false, contract.CodeSchema, "crowdsec-accepted-code", "D39: an accepted update has no code.", upd("hub-code", map[string]any{"outcome": "accepted", "code": "shrink", "set_source": "stored", "rules_loaded": 1, "rules_skipped": 0}))
	sw2 := func(name string, m map[string]any) map[string]any {
		m["repository"] = "crowdsec"
		return cloudEvent("schild.rule.repository_switched.v1", name, m)
	}
	addEv(true, "", "crowdsec-switched-dashboard", "D39 amendment: the change history: a change in the dashboard.", sw2("hub-sw-d", map[string]any{"from": "detect", "to": "off", "actor": "dashboard", "state_source": "dashboard"}))
	addEv(true, "", "crowdsec-switched-agent", "D39 amendment: a change through the agent API, with the token and its name.", sw2("hub-sw-a", map[string]any{"from": "detect", "to": "block", "actor": "agent", "state_source": "agent", "token_id": "tok_000000000001", "token_label": "Local agent"}))
	addEv(true, "", "crowdsec-switched-reset", "D39 amendment: reset_state: schild.yaml counts again.", sw2("hub-sw-r", map[string]any{"from": "off", "to": "detect", "actor": "agent", "state_source": "config", "reset": true, "token_id": "tok_000000000001", "token_label": "Local agent"}))
	addEv(false, contract.CodeSchema, "crowdsec-switched-no-token", "D39 amendment: an agent write always names the token.", sw2("hub-sw-n", map[string]any{"from": "detect", "to": "block", "actor": "agent", "state_source": "agent"}))
	addEv(false, contract.CodeSchema, "crowdsec-switched-dashboard-token", "D39 amendment: the dashboard has no token.", sw2("hub-sw-t", map[string]any{"from": "detect", "to": "off", "actor": "dashboard", "state_source": "dashboard", "token_id": "tok_000000000001", "token_label": "x"}))
	addEv(true, "", "crowdsec-reset", "D43: the operator went back to the image snapshot.", upd("hub-reset", map[string]any{"outcome": "reset", "set_source": "image", "rules_loaded": 201, "rules_skipped": 5}))
	addEv(false, contract.CodeSchema, "crowdsec-reset-code", "D43: a reset is no refusal and has no code.", upd("hub-reset-code", map[string]any{"outcome": "reset", "code": "shrink", "set_source": "image", "rules_loaded": 201, "rules_skipped": 5}))
	addEv(true, "", "crowdsec-refused-cost", "D43: an update was refused by the measured cost check.", upd("hub-cost", map[string]any{"outcome": "refused", "code": "set_too_costly", "set_source": "image", "rules_loaded": 201, "rules_skipped": 5}))
}
