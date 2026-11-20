// Package seclang3 is a third, independent checker for the SecLang subset
// (contracts/seclang-subset.md), written only from the specification and
// sharing no code with contract/seclang (the Go reference) or
// contracts/tools/crosscheck.py (the Python cross-check). The contracts team
// noted a common-mode risk: both existing implementations were written by one
// agent. This checker exists to break that: the fuzzer (cmd/seclang-fuzzer)
// diffs it against the reference validator and reports every rule that is
// forbidden here but accepted there as a bypass finding (M4).
//
// Design choice for soundness: seclang3 is a *detector of forbidden
// constructs*, not a full parser. It never needs to accept a rule the
// reference accepts; it only asserts that anything it flags as forbidden is
// truly forbidden under the spec, so that "forbidden here, accepted there"
// is always a real defect. Every detector below flags only constructs the
// spec forbids unconditionally (macros, disallowed actions/operators/
// variables, forbidden headers, universal catch-alls). It deliberately does
// not try to reproduce the heuristic benign-corpus catch-all check beyond the
// universal case (patterns that match the empty string), which is forbidden
// under any corpus.
package seclang3

import (
	"regexp"
	"strings"
)

// Finding is one forbidden construct found in a rule text.
type Finding struct {
	Class  string // macro | action | operator | variable | header | directive | catch-all | structure
	Detail string
}

// Forbidden action names (any occurrence disables protection, exfiltrates, or
// changes control flow). seclang-subset.md "Actions".
var forbiddenActions = []string{
	"ctl", "allow", "skip", "skipAfter", "exec", "append", "prepend", "proxy",
	"redirect", "drop", "setenv", "setuid", "setsid", "setrsc", "initcol",
	"expirevar", "deprecatevar", "sanitise", "sanitize", "sanitiseArg", "sanitizeArg",
	"sanitiseMatched", "sanitizeMatched", "xmlns", "capture", "nolog", "noauditlog", "pause",
}

// Forbidden operators (IP/geo/file/unconditional and other disallowed ones).
var forbiddenOperators = []string{
	"ipMatch", "ipMatchF", "ipMatchFromFile", "geoLookup", "rbl", "pmFromFile",
	"pmf", "inspectFile", "fuzzyHash", "unconditionalMatch", "noMatch", "rsub",
	"gsbLookup", "verifyCC", "validateByteRange", "validateDTD", "validateSchema",
}

// Variables that are never allowed in network rules (address, host, geo, tx,
// response/session/global state). seclang-subset.md "Variables".
var forbiddenVars = []string{
	"REMOTE_ADDR", "REMOTE_HOST", "REMOTE_PORT", "REMOTE_USER", "SERVER_NAME",
	"SERVER_ADDR", "SERVER_PORT", "GEO", "TX", "IP", "SESSION", "USER", "GLOBAL",
	"RESOURCE", "ENV", "XML", "DURATION", "HIGHEST_SEVERITY", "AUTH_TYPE", "PATH_INFO",
}

var forbiddenVarPrefixes = []string{"RESPONSE_", "MATCHED_", "TIME", "WEBSERVER_", "MULTIPART_", "SDBM_", "PERF_", "STREAM_", "FULL_REQUEST", "SESSIONID", "USERID", "RULE"}

// Header selectors that identify the site or the client (case-insensitive).
var forbiddenHeaders = map[string]bool{
	"host": true, "x-forwarded-host": true, "x-forwarded-server": true, "x-original-host": true,
	"x-host": true, "forwarded": true, "forwarded-for": true, "x-forwarded": true, "x-forwarded-for": true,
	"x-real-ip": true, "x-client-ip": true, "x-cluster-client-ip": true, "client-ip": true,
	"true-client-ip": true, "cf-connecting-ip": true, "cf-connecting-ipv6": true, "fastly-client-ip": true,
	"x-envoy-external-address": true, "x-originating-ip": true, "x-remote-ip": true, "x-remote-addr": true, "via": true,
}

// setvar values that only raise the anomaly score are allowed; anything else
// is forbidden. Independent regex written from the spec.
var reScoreSetvar = regexp.MustCompile(`^tx\.(inbound_anomaly_score_pl[1-4]|schild_remote_hits)=\+([1-9]|10|%\{tx\.(critical|error|warning|notice)_anomaly_score\})$`)

// Check returns every forbidden construct it finds in text. An empty slice
// means seclang3 found nothing forbidden (it does not claim the rule is
// valid, only that none of its sound detectors fired).
func Check(text string) []Finding {
	var out []Finding
	add := func(class, detail string) { out = append(out, Finding{class, detail}) }

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "SecRule ") && !strings.HasPrefix(trimmed, "SecRule\t") {
			// Any non-SecRule directive (SecAction, SecMarker, Include,
			// SecRuleEngine, SecDefaultAction, SecRuleRemove*, ...).
			kw := trimmed
			if sp := strings.IndexAny(kw, " \t"); sp >= 0 {
				kw = kw[:sp]
			}
			add("directive", "non-SecRule directive: "+kw)
			continue
		}
		opField, actField := fields(trimmed)
		checkOperator(opField, add)
		checkVariables(variablesOf(trimmed), add)
		checkActions(actField, add)
	}
	return out
}

// variablesOf returns the VARIABLES field (between "SecRule " and the first
// space before the operator).
func variablesOf(line string) string {
	rest := strings.TrimPrefix(line, "SecRule ")
	rest = strings.TrimLeft(rest, " \t")
	if sp := strings.IndexAny(rest, " \t"); sp >= 0 {
		return rest[:sp]
	}
	return rest
}

// fields returns the operator and actions double-quoted fields of a line, as
// raw inner text (best effort, independent of the reference parser).
func fields(line string) (op, act string) {
	var quoted []string
	i := 0
	for i < len(line) {
		if line[i] == '"' {
			j := strings.IndexByte(line[i+1:], '"')
			if j < 0 {
				break
			}
			quoted = append(quoted, line[i+1:i+1+j])
			i = i + 1 + j + 1
			continue
		}
		i++
	}
	if len(quoted) >= 1 {
		op = quoted[0]
	}
	if len(quoted) >= 2 {
		act = quoted[len(quoted)-1]
	}
	return op, act
}

func checkOperator(op string, add func(string, string)) {
	if op == "" {
		return
	}
	if strings.Contains(op, "%{") {
		add("macro", "operator expands a macro %{...}: "+op)
	}
	body := strings.TrimPrefix(op, "!")
	if !strings.HasPrefix(body, "@") {
		return // implicit @rx is caught by the reference; not a sound seclang3 claim
	}
	name := body[1:]
	if sp := strings.IndexByte(name, ' '); sp >= 0 {
		name = name[:sp]
	}
	for _, f := range forbiddenOperators {
		if name == f {
			add("operator", "@"+f+" is not allowed")
		}
	}
	// Universal catch-all: @rx that matches the empty string is forbidden
	// under any corpus (the benign corpus contains the empty string).
	if name == "rx" {
		if arg := strings.TrimPrefix(body, "@rx"); arg != "" {
			arg = strings.TrimPrefix(arg, " ")
			if matchesEmpty(arg) {
				add("catch-all", "@rx matches the empty string: "+arg)
			}
		}
	}
}

func checkVariables(vars string, add func(string, string)) {
	if vars == "" {
		return
	}
	for _, part := range strings.Split(vars, "|") {
		p := strings.TrimLeft(part, "!&")
		name, sel, hasSel := strings.Cut(p, ":")
		up := strings.ToUpper(name)
		for _, f := range forbiddenVars {
			if up == f {
				add("variable", "variable "+name+" is not allowed")
			}
		}
		for _, pre := range forbiddenVarPrefixes {
			if strings.HasPrefix(up, pre) {
				add("variable", "variable "+name+" is not allowed")
			}
		}
		if up == "REQUEST_HEADERS" {
			if !hasSel {
				add("header", "REQUEST_HEADERS without a header name includes Host")
			} else if forbiddenHeaders[strings.ToLower(sel)] {
				add("header", "header "+sel+" identifies the site or the client")
			}
		}
	}
}

func checkActions(act string, add func(string, string)) {
	if act == "" {
		return
	}
	for _, it := range splitActions(act) {
		name, val, _ := strings.Cut(it, ":")
		name = strings.TrimSpace(name)
		for _, f := range forbiddenActions {
			if name == f {
				add("action", "action "+f+" is not allowed")
			}
		}
		switch name {
		case "setvar":
			if !reScoreSetvar.MatchString(unquote(val)) {
				add("action", "setvar does more than raise the anomaly score: "+val)
			}
		case "msg", "logdata", "tag", "rev", "ver", "maturity", "accuracy":
			if strings.Contains(unquote(val), "%{") {
				add("macro", name+" expands a macro (exfiltration): "+val)
			}
		}
	}
}

// splitActions splits on commas outside single quotes (independent of the
// reference splitter).
func splitActions(s string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && s[i+1] == '\'':
			b.WriteByte(c)
			b.WriteByte(s[i+1])
			i++
		case c == '\'':
			inQ = !inQ
			b.WriteByte(c)
		case c == ',' && !inQ:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	out = append(out, b.String())
	return out
}

func unquote(v string) string {
	if strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'") && len(v) >= 2 {
		return strings.ReplaceAll(v[1:len(v)-1], `\'`, `'`)
	}
	return v
}

// matchesEmpty reports whether pattern matches the empty string (a universal
// catch-all). It anchors at both ends: Coraza's @rx is an unanchored search,
// so "matches somewhere in the empty string" means the whole pattern can
// match nothing, i.e. it matches every input.
func matchesEmpty(pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false // does not compile: the reference rejects it anyway
	}
	return re.MatchString("")
}
