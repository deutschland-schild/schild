// Package grammar generates SecLang rule texts from a grammar of the allowed
// subset plus a catalogue of forbidden constructs (ctl actions, setvar beyond
// the score, logdata/msg with header or cookie macros, catch-all patterns,
// catastrophic-backtracking regex shapes, IP/geo/Host targeting). It is the
// input source for the SecLang validator fuzzer (cmd/seclang-fuzzer, M4).
//
// Generation is deterministic given a seed, so a finding always has a
// reproducer: the same seed and index regenerate the exact rule.
package grammar

import "math/rand/v2"

// Rule is one generated rule text with metadata.
type Rule struct {
	Text      string
	MaxAction string
	// Forbidden names the construct class injected on purpose (empty for a
	// rule built only from allowed productions). It documents intent; the
	// authority on acceptance is the reference validator, cross-checked by
	// seclang3.
	Forbidden string
}

// Gen is a seeded generator.
type Gen struct{ r *rand.Rand }

// New returns a generator seeded deterministically.
func New(seed uint64) *Gen { return &Gen{r: rand.New(rand.NewPCG(seed, 0x5c117d))} }

func (g *Gen) pick(xs []string) string { return xs[g.r.IntN(len(xs))] }

var (
	collections = []string{"ARGS", "ARGS_GET", "ARGS_POST", "ARGS_NAMES", "REQUEST_COOKIES", "FILES", "FILES_NAMES"}
	scalars     = []string{"REQUEST_URI", "REQUEST_FILENAME", "REQUEST_BASENAME", "QUERY_STRING", "REQUEST_BODY", "REQUEST_METHOD"}
	goodRx      = []string{
		`\.\./`, `<script`, `union\s+select`, `\x00`, `\.(php|phtml)$`, `[A-Z]{3,8}_[0-9]{1,4}`,
		`(?i)etc/passwd`, `cmd=(ls|cat|id)`, `\$\{jndi:`, `onerror=`, `/wp-content/plugins/[a-z-]{3,20}/`,
	}
	goodPhrases = []string{"sqlmap nikto", "acunetix", "../../ ..\\..\\", "<?php", "base64_decode exec"}
	severities  = []string{"CRITICAL", "ERROR", "WARNING", "NOTICE", "2", "3", "4", "5"}
	transforms  = []string{"t:none", "t:lowercase", "t:urlDecodeUni", "t:compressWhitespace", "t:htmlEntityDecode", "t:normalizePath"}

	// Forbidden constructs, grouped by class. The fuzzer expects the reference
	// validator to reject every rule that contains one of these and seclang3
	// (where it has a sound detector) to flag it.
	badActions = []string{
		"ctl:ruleEngine=Off", "ctl:ruleRemoveById=942100", "ctl:requestBodyAccess=Off",
		"allow", "skipAfter:END", "skip:1", "exec:/bin/sh", "append:'x'", "prepend:'x'",
		"redirect:http://evil.example", "drop", "setenv:x=1", "nolog", "noauditlog", "capture", "pause:100",
	}
	badSetvar = []string{
		"setvar:tx.inbound_anomaly_score_pl1=-5", "setvar:tx.allowed_methods=GET",
		"setvar:tx.anomaly_score=0", "setvar:'tx.foo=%{REQUEST_HEADERS.Cookie}'", "setvar:ip.count=+1",
	}
	badMacros = []string{
		`logdata:'%{ARGS.password}'`, `msg:'leak %{REQUEST_HEADERS.Cookie}'`,
		`msg:'ua %{REQUEST_HEADERS.User-Agent}'`, `logdata:'%{MATCHED_VAR}'`,
	}
	badOpMacro = []string{
		`"@streq %{REMOTE_ADDR}"`, `"@contains %{REQUEST_HEADERS.host}"`, `"@beginsWith %{SERVER_NAME}"`,
	}
	badVars = []string{
		"REMOTE_ADDR", "SERVER_NAME", "GEO:COUNTRY_CODE", "TX:anomaly_score", "REQUEST_HEADERS:Host",
		"REQUEST_HEADERS:X-Forwarded-For", "REQUEST_HEADERS:X-Real-IP", "REQUEST_HEADERS", "SESSION", "RESPONSE_BODY",
	}
	badOperators = []string{
		`"@ipMatch 198.51.100.0/24"`, `"@geoLookup"`, `"@pmFromFile bad.txt"`, `"@unconditionalMatch"`,
		`"@rbl sbl.example"`, `"@inspectFile /bin/check"`,
	}
	// Catch-all / universal patterns.
	badCatchAll = []string{
		`"@rx .*"`, `"@rx ."`, `"@rx ^"`, `"@rx a?"`, `"@rx (?:)"`, `"@rx .?"`, `"@rx \s*"`,
		`"@beginsWith /"`, `"@streq GET"`, `"@pm a  b"`,
	}
	// Catastrophic-backtracking shapes (nested quantifiers, alternation under
	// repetition) and oversized counted repetition.
	badReDoS = []string{
		`"@rx (a+)+$"`, `"@rx (a|aa)+"`, `"@rx (.*)*"`, `"@rx (x+x+)+y"`, `"@rx (?:ab?)*c{2,}"`,
		`"@rx a{1001}"`, `"@rx a{600}b{600}"`, `"@rx (a|b|c|ab){3,}"`,
	}
)

// badGroups maps a forbidden class to a generator of a rule with that defect.
func (g *Gen) withAction(bad string, class string) Rule {
	v := g.pick(scalars)
	text := `SecRule ` + v + ` "@detectSQLi" "id:7700001,phase:2,deny,severity:CRITICAL,msg:'x',` + bad + `"`
	return Rule{Text: text, MaxAction: "block", Forbidden: class}
}

func (g *Gen) withOp(opField, class string) Rule {
	v := g.pick(scalars)
	text := `SecRule ` + v + ` ` + opField + ` "id:7700001,phase:2,deny,severity:CRITICAL,msg:'x',t:none"`
	return Rule{Text: text, MaxAction: "block", Forbidden: class}
}

func (g *Gen) withVar(v, class string) Rule {
	text := `SecRule ` + v + ` "@detectSQLi" "id:7700001,phase:2,deny,severity:CRITICAL,msg:'x',t:none"`
	return Rule{Text: text, MaxAction: "block", Forbidden: class}
}

// Good generates a rule from allowed productions only. It is not guaranteed to
// be accepted (it may still trip a corpus/portability rule), but it carries no
// injected forbidden construct.
func (g *Gen) Good() Rule {
	var op string
	switch g.r.IntN(3) {
	case 0:
		op = `"@rx ` + g.pick(goodRx) + `"`
	case 1:
		op = `"@pm ` + g.pick(goodPhrases) + `"`
	default:
		op = `"@detectSQLi"`
	}
	v := g.pick(append(append([]string{}, collections...), scalars...))
	t := g.pick(transforms)
	act := g.pick([]string{"deny,status:403", "pass", "block"})
	ma := map[string]string{"deny,status:403": "block", "block": "block", "pass": "observe"}[act]
	text := `SecRule ` + v + ` ` + op + ` "id:7700001,phase:2,` + act + `,severity:` + g.pick(severities) + `,msg:'generated rule',` + t + `"`
	return Rule{Text: text, MaxAction: ma}
}

// Bad generates a rule that contains exactly one forbidden construct.
func (g *Gen) Bad() Rule {
	switch g.r.IntN(8) {
	case 0:
		return g.withAction(g.pick(badActions), "action")
	case 1:
		return g.withAction(g.pick(badSetvar), "setvar")
	case 2:
		return g.withAction(g.pick(badMacros), "macro")
	case 3:
		return g.withOp(g.pick(badOpMacro), "macro-operator")
	case 4:
		return g.withVar(g.pick(badVars), "variable")
	case 5:
		return g.withOp(g.pick(badOperators), "operator")
	case 6:
		return g.withOp(g.pick(badCatchAll), "catch-all")
	default:
		return g.withOp(g.pick(badReDoS), "redos")
	}
}

// Next returns the i-th rule for this generator run; roughly half carry a
// forbidden construct.
func (g *Gen) Next() Rule {
	if g.r.IntN(2) == 0 {
		return g.Bad()
	}
	return g.Good()
}
