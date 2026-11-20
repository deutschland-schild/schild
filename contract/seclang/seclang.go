// Package seclang validates network (remote) rules against the SecLang subset
// of contracts/seclang-subset.md (K7, M4). Remote rules can only protect: they
// can never disable protection, exfiltrate data, target a single site, or use
// IPs or geo data. Everything not explicitly allowed is rejected.
package seclang

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/deutschland-schild/schild/contract"
)

// Options tune validation for one rule.
type Options struct {
	// MaxAction of the rule (observe, challenge, block). observe requires
	// the disruptive action pass.
	MaxAction string
	// Hub selects the profile of the CrowdSec Hub source (D39,
	// contracts/crowdsec-hub.md section 5) instead of the network subset:
	// SecRule ids in contract.HubRuleIDMin..Max, up to MaxHubLines lines,
	// wider selectors, t:uppercase and the one variable TX:json_request_body.
	// Everything else is the same check.
	Hub bool
}

// ErrCatchAll marks the failure of the catch-all check (errors.Is).
var ErrCatchAll = errors.New("catch-all")

// Rule is the parsed result of a valid rule.
type Rule struct {
	ID         int
	Phase      int
	Disruptive string
	Lines      int
}

func errf(format string, args ...any) error {
	return contract.Errf(contract.CodeSecLang, format, args...)
}

// Limits of the subset.
const (
	MaxLines       = 4
	MaxVariables   = 16
	MaxOperatorLen = 2048
	MaxRegexLen    = 1024
	MaxPhrases     = 100
	MaxTags        = 8
	MaxTransforms  = 16
	MaxSetvar      = 2
	MaxMsgLen      = 200
	MaxRepeat      = 1000
	MaxRepeatTotal = 1000
	// MaxHubLines: lines of one rule in the hub profile (the largest
	// AND-group of the hub had 8 leaves on 2026-10-30).
	MaxHubLines = 8
	// MaxHubSelector: bytes of a selector in the hub profile.
	MaxHubSelector = 128
)

// HubJSONBody is the one TX variable of the hub profile: Coraza keeps the raw
// JSON body there (D39).
const HubJSONBody = "TX:json_request_body"

var collections = map[string]bool{
	"ARGS": true, "ARGS_GET": true, "ARGS_POST": true, "ARGS_NAMES": true, "ARGS_GET_NAMES": true, "ARGS_POST_NAMES": true,
	"REQUEST_COOKIES": true, "REQUEST_COOKIES_NAMES": true, "REQUEST_HEADERS": true, "REQUEST_HEADERS_NAMES": true,
	"FILES": true, "FILES_NAMES": true,
}

var scalars = map[string]bool{
	"REQUEST_URI": true, "REQUEST_URI_RAW": true, "REQUEST_FILENAME": true, "REQUEST_BASENAME": true, "REQUEST_LINE": true,
	"REQUEST_METHOD": true, "REQUEST_PROTOCOL": true, "QUERY_STRING": true, "REQUEST_BODY": true,
}

// Header selectors that identify the target site or the client address.
var forbiddenHeaders = map[string]bool{
	"host": true, "x-forwarded-host": true, "x-forwarded-server": true, "x-original-host": true, "x-host": true,
	"forwarded": true, "forwarded-for": true, "x-forwarded": true, "x-forwarded-for": true, "x-real-ip": true,
	"x-client-ip": true, "x-cluster-client-ip": true, "client-ip": true, "true-client-ip": true,
	"cf-connecting-ip": true, "cf-connecting-ipv6": true, "fastly-client-ip": true, "x-envoy-external-address": true,
	"x-originating-ip": true, "x-remote-ip": true, "x-remote-addr": true, "via": true,
}

// Header selectors that carry the site's own host name. They may only be
// inspected by the argument-free detection operators, which cannot encode a
// host name (no targeting of one site through its own links).
var detectOnlyHeaders = map[string]bool{"referer": true, "origin": true}

var stringOps = map[string]bool{"rx": true, "pm": true, "streq": true, "contains": true, "beginsWith": true, "endsWith": true, "within": true}
var numericOps = map[string]bool{"eq": true, "gt": true, "ge": true, "lt": true, "le": true}
var noArgOps = map[string]bool{"detectSQLi": true, "detectXSS": true, "validateUrlEncoding": true, "validateUtf8Encoding": true}

var transforms = map[string]bool{
	"none": true, "lowercase": true, "urlDecode": true, "urlDecodeUni": true, "htmlEntityDecode": true, "jsDecode": true,
	"cssDecode": true, "cmdLine": true, "compressWhitespace": true, "removeWhitespace": true, "removeNulls": true,
	"replaceNulls": true, "removeComments": true, "replaceComments": true, "normalizePath": true, "normalisePath": true,
	"normalizePathWin": true, "normalisePathWin": true, "base64Decode": true, "base64DecodeExt": true, "hexDecode": true,
	"utf8toUnicode": true, "length": true, "trim": true, "trimLeft": true, "trimRight": true, "escapeSeqDecode": true,
	"sqlHexDecode": true,
}

var severities = map[string]bool{"CRITICAL": true, "ERROR": true, "WARNING": true, "NOTICE": true, "2": true, "3": true, "4": true, "5": true}

var (
	reVarName  = regexp.MustCompile(`^[A-Z_]+$`)
	reSelector = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	reHubSel   = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,128}$`)
	reOpName   = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	reActName  = regexp.MustCompile(`^[a-zA-Z]+$`)
	reStatic   = regexp.MustCompile(`^[A-Za-z0-9 _.:;/()\[\]#+=-]*$`)
	reSetvar   = regexp.MustCompile(`^tx\.(inbound_anomaly_score_pl[1-4]|schild_remote_hits)=\+([1-9]|10|%\{tx\.(critical|error|warning|notice)_anomaly_score\})$`)
	reInt      = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)
	reRepeat   = regexp.MustCompile(`\{([0-9]+)(,([0-9]*))?\}`)
	reRepeatAt = regexp.MustCompile(`^\{([0-9]+)(,([0-9]*))?\}`)
)

// Validate checks one remote rule text and returns its parsed head.
func Validate(text string, opts Options) (*Rule, error) {
	if len(text) == 0 || len(text) > contract.MaxSecLangBytes {
		return nil, errf("rule text length %d outside 1..%d", len(text), contract.MaxSecLangBytes)
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c != '\n' && (c < 0x20 || c > 0x7e) {
			return nil, errf("byte 0x%02x at %d: only printable ASCII and LF", c, i)
		}
	}
	lines := strings.Split(text, "\n")
	maxLines := MaxLines
	if opts.Hub {
		maxLines = MaxHubLines
	}
	if len(lines) > maxLines {
		return nil, errf("%d lines, at most %d (one rule plus chain)", len(lines), maxLines)
	}
	var head *Rule
	specific := false
	for i, line := range lines {
		r, chain, isSpecific, err := validateLine(line, i == 0, opts)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if i == 0 {
			head = r
		}
		specific = specific || isSpecific
		last := i == len(lines)-1
		if chain && last {
			return nil, errf("line %d: chain without a following rule", i+1)
		}
		if !chain && !last {
			return nil, errf("line %d: more than one rule (only chained rules may follow)", i+1)
		}
	}
	// A chain matches only if every line matches, so one specific line is
	// enough. Without one, the rule is a catch-all (it would hit ordinary
	// traffic of every site).
	if !specific {
		return nil, fmt.Errorf("%w: %w", ErrCatchAll, errf("catch-all: no line has a specific condition (each operator matches a value of the benign corpus, is negated or numeric)"))
	}
	head.Lines = len(lines)
	return head, nil
}

// validateLine checks one SecRule line. It reports whether the line's
// condition is specific: not negated, and either an argument-free detection
// operator or a string operator that matches no value of BenignCorpus.
func validateLine(line string, isHead bool, opts Options) (*Rule, bool, bool, error) {
	rest, ok := strings.CutPrefix(line, "SecRule ")
	if !ok {
		return nil, false, false, errf("only SecRule directives are allowed")
	}
	sp := strings.IndexByte(rest, ' ')
	if sp <= 0 {
		return nil, false, false, errf("missing variables")
	}
	vars, err := validateVariables(rest[:sp], opts.Hub)
	if err != nil {
		return nil, false, false, err
	}
	rest = rest[sp+1:]
	opText, rest, err := quoted(rest)
	if err != nil {
		return nil, false, false, err
	}
	if !strings.HasPrefix(rest, " ") {
		return nil, false, false, errf("expected one space before actions")
	}
	acts, rest, err := quoted(rest[1:])
	if err != nil {
		return nil, false, false, err
	}
	if rest != "" {
		return nil, false, false, errf("trailing characters after actions")
	}
	op, err := validateOperator(opText, isHead)
	if err != nil {
		return nil, false, false, err
	}
	r, chain, length, err := validateActions(acts, isHead, opts)
	if err != nil {
		return nil, false, false, err
	}
	numeric := numericOps[op.name]
	if vars.count && !numeric {
		return nil, false, false, errf("& (count) variables only with a numeric operator")
	}
	if length && !numeric {
		return nil, false, false, errf("t:length only with a numeric operator")
	}
	if vars.detectOnly != "" && !noArgOps[op.name] {
		return nil, false, false, errf("header %s only with @detectSQLi, @detectXSS, @validateUrlEncoding or @validateUtf8Encoding (it carries the site's host name)", vars.detectOnly)
	}
	isSpecific := !op.negated && (noArgOps[op.name] || (stringOps[op.name] && !MatchesBenign(op.name, op.arg)))
	return r, chain, isSpecific, nil
}

// quoted reads a double-quoted argument up to the next double quote. The
// subset has no escaped quotes (write \x22 inside @rx): Coraza ends an
// argument at a quote preceded by an even number of backslashes, other
// parsers differ, so `\"` is never allowed. An argument may not end with a
// backslash, which also rules out `\"`.
func quoted(s string) (string, string, error) {
	if !strings.HasPrefix(s, `"`) {
		return "", "", errf("expected a double-quoted argument")
	}
	end := strings.IndexByte(s[1:], '"')
	if end < 0 {
		return "", "", errf("unterminated quoted argument")
	}
	v := s[1 : 1+end]
	if strings.HasSuffix(v, `\`) {
		return "", "", errf(`argument may not end with a backslash (no \" escapes; use \x22 inside @rx)`)
	}
	return v, s[2+end:], nil
}

type varInfo struct {
	count      bool   // a & (count) variable is used
	detectOnly string // a header that may only be used with detection operators
}

func validateVariables(s string, hub bool) (varInfo, error) {
	var info varInfo
	parts := strings.Split(s, "|")
	if len(parts) > MaxVariables {
		return info, errf("%d variables, at most %d", len(parts), MaxVariables)
	}
	positive := 0
	for _, p := range parts {
		neg, count := false, false
		switch {
		case strings.HasPrefix(p, "!"):
			neg, p = true, p[1:]
		case strings.HasPrefix(p, "&"):
			count, p = true, p[1:]
		}
		if hub && p == HubJSONBody {
			positive++
			continue
		}
		name, sel, hasSel := strings.Cut(p, ":")
		if !reVarName.MatchString(name) {
			return info, errf("invalid variable %q", p)
		}
		isColl := collections[name]
		if !isColl && !scalars[name] {
			return info, errf("variable %s is not allowed in network rules", name)
		}
		if hasSel {
			if !isColl {
				return info, errf("variable %s takes no selector", name)
			}
			if err := validateSelector(name, sel, hub); err != nil {
				return info, err
			}
		}
		if name == "REQUEST_HEADERS" {
			if !hasSel {
				return info, errf("REQUEST_HEADERS needs an explicit header name (all headers include Host)")
			}
			h := strings.ToLower(sel)
			if forbiddenHeaders[h] {
				return info, errf("header %s identifies the site or the client and is not allowed", sel)
			}
			if detectOnlyHeaders[h] && !neg {
				info.detectOnly = sel
			}
		}
		if neg {
			if !isColl || !hasSel {
				return info, errf("exclusion only for a named member of a collection")
			}
			continue
		}
		if count {
			info.count = true
		}
		positive++
	}
	if positive == 0 {
		return info, errf("no variable to inspect")
	}
	return info, nil
}

// validateSelector checks a selector. The hub profile also takes brackets
// (PHP array names), longer names (json.a.b.c) and /regex/ selectors whose
// pattern passes the @rx subset, but never on REQUEST_HEADERS: the header name
// must stay readable for the forbidden lists.
func validateSelector(name, sel string, hub bool) error {
	if !hub {
		if !reSelector.MatchString(sel) {
			return errf("selector %q not allowed (literal names only, no regex)", sel)
		}
		return nil
	}
	if reHubSel.MatchString(sel) {
		return nil
	}
	if name != "REQUEST_HEADERS" && len(sel) >= 3 && len(sel) <= MaxHubSelector && sel[0] == '/' && sel[len(sel)-1] == '/' {
		p := sel[1 : len(sel)-1]
		if !strings.ContainsAny(p, "| \"/") {
			return validateRegex(p)
		}
	}
	return errf("selector %q not allowed", sel)
}

// ValidateHubSelector checks one selector of variable name in the hub profile.
func ValidateHubSelector(name, sel string) error { return validateSelector(name, sel, true) }

// ValidateRegex checks a pattern against the @rx subset.
func ValidateRegex(p string) error { return validateRegex(p) }

// HeaderClass says how the subset treats a header name: "forbidden" (it
// identifies the site or the client), "detect_only" (it carries the site's
// host name) or "" for an ordinary header.
func HeaderClass(name string) string {
	h := strings.ToLower(name)
	switch {
	case forbiddenHeaders[h]:
		return "forbidden"
	case detectOnlyHeaders[h]:
		return "detect_only"
	}
	return ""
}

type opInfo struct {
	name    string
	arg     string
	negated bool
}

func validateOperator(op string, isHead bool) (opInfo, error) {
	var info opInfo
	if len(op) == 0 || len(op) > MaxOperatorLen {
		return info, errf("operator length %d outside 1..%d", len(op), MaxOperatorLen)
	}
	if strings.Contains(op, "%{") {
		// Coraza expands macros in @streq, @contains, @beginsWith, @endsWith,
		// @within and the numeric operators: %{REMOTE_ADDR}, %{REQUEST_HEADERS.host}.
		return info, errf("operator arguments may not contain %%{ (macro expansion reads address, host or request data)")
	}
	if strings.HasPrefix(op, "!") {
		info.negated, op = true, op[1:]
	}
	if !strings.HasPrefix(op, "@") {
		return info, errf("operator must be explicit (@name), no implicit @rx")
	}
	name, arg, hasArg := strings.Cut(op[1:], " ")
	info.name, info.arg = name, arg
	if !reOpName.MatchString(name) {
		return info, errf("invalid operator name %q", name)
	}
	if info.negated && isHead {
		return info, errf("negated operator only in chained rules (a negated head matches almost everything)")
	}
	if hasArg && (arg == "" || arg[0] == ' ' || arg[len(arg)-1] == ' ') {
		// Coraza trims the argument: "@rx  .*" would become the catch-all ".*".
		return info, errf("operator argument may not start or end with a space")
	}
	switch {
	case stringOps[name]:
		if !hasArg {
			return info, errf("@%s needs an argument", name)
		}
		switch name {
		case "rx":
			return info, validateRegex(arg)
		case "pm":
			// Coraza splits on single spaces: "a  b" adds the empty phrase,
			// which matches every value.
			phrases := strings.Split(arg, " ")
			if len(phrases) > MaxPhrases {
				return info, errf("@pm with %d phrases, at most %d", len(phrases), MaxPhrases)
			}
			for _, ph := range phrases {
				if ph == "" {
					return info, errf("@pm phrases are separated by exactly one space (an empty phrase matches everything)")
				}
			}
		}
		return info, nil
	case numericOps[name]:
		if isHead {
			return info, errf("numeric operator @%s only in chained rules (it cannot be the only condition)", name)
		}
		if !hasArg || !reInt.MatchString(arg) {
			return info, errf("@%s needs an integer argument", name)
		}
		return info, nil
	case noArgOps[name]:
		if hasArg {
			return info, errf("@%s takes no argument", name)
		}
		return info, nil
	}
	return info, errf("operator @%s is not allowed in network rules", name)
}

// validateRegex keeps @rx inside a portable subset on which Go RE2 (used by
// Coraza) and Python re (the cross-check) agree, without nested quantifiers
// (catastrophic backtracking in PCRE-based engines and in the Python
// cross-check) and with a bounded program size.
func validateRegex(p string) error {
	if len(p) > MaxRegexLen {
		return errf("@rx pattern longer than %d", MaxRegexLen)
	}
	for _, bad := range []string{"(?=", "(?!", "(?<", "(?>", "(?P", "(?#", "[[:", "*+", "++", "?+", "}+", "{,", "[]", "[^]"} {
		if strings.Contains(p, bad) {
			return errf("@rx construct %q not allowed", bad)
		}
	}
	type frame struct{ quant, alt bool }
	stack := []frame{{}}
	inClass := false
	afterAssertion := false // ^ $ \b \B cannot be quantified (Python rejects, RE2 accepts)
	atomComplex := false    // the atom before the current position is a group with quantifiers or alternation
	prevQuant := false      // the previous token was a quantifier (a following ? makes it lazy)
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !inClass && afterAssertion && strings.IndexByte("*+?{", c) >= 0 {
			return errf("@rx quantifier after an assertion")
		}
		afterAssertion = !inClass && (c == '^' || c == '$')
		switch {
		case c == '\\':
			if i+1 >= len(p) {
				return errf("@rx ends with a backslash")
			}
			e := p[i+1]
			i++
			switch {
			case !isAlnum(e):
				// escaped punctuation is always literal
			case strings.IndexByte("dDwWsSnrtfv", e) >= 0:
			case (e == 'b' || e == 'B') && !inClass:
				afterAssertion = true
			case e == 'x':
				if i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
					return errf(`@rx \x needs exactly two hex digits`)
				}
				i += 2
			default:
				return errf(`@rx escape \%c not allowed`, e)
			}
			if !inClass {
				atomComplex, prevQuant = false, false
			}
		case inClass:
			if c == ']' {
				inClass = false
				atomComplex, prevQuant = false, false
			}
			// A range next to a class escape ([\d-z], [a-\w]) is an error in
			// Python and a literal in RE2: not portable.
			if c == '-' && i+1 < len(p) && p[i+1] != ']' {
				if i >= 2 && p[i-2] == '\\' && strings.IndexByte("dDwWsS", p[i-1]) >= 0 {
					return errf("@rx range next to a class escape")
				}
				if i+2 < len(p) && p[i+1] == '\\' && strings.IndexByte("dDwWsS", p[i+2]) >= 0 {
					return errf("@rx range next to a class escape")
				}
			}
		case c == '[':
			inClass = true
		case c == '(':
			atomComplex, prevQuant = false, false
			if i+1 < len(p) && p[i+1] == '?' {
				tail := p[i+2:]
				skip := -1
				for _, f := range []string{":", "i:", "s:", "is:", "si:"} {
					if strings.HasPrefix(tail, f) {
						skip = len(f)
					}
				}
				if skip >= 0 {
					stack = append(stack, frame{})
					i += 1 + skip
					continue
				}
				for _, f := range []string{"i)", "s)", "is)", "si)"} {
					if strings.HasPrefix(tail, f) && i == 0 {
						skip = len(f)
					}
				}
				if skip < 0 {
					return errf("@rx group flags not allowed (only (?:, (?i: and leading (?i))")
				}
				i += 1 + skip // global flags: not a group
				continue
			}
			stack = append(stack, frame{})
		case c == ')':
			prevQuant = false
			if len(stack) == 1 {
				atomComplex = false // unbalanced: the compile step rejects it
				continue
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			top := &stack[len(stack)-1]
			top.quant = top.quant || f.quant
			top.alt = top.alt || f.alt
			atomComplex = f.quant || f.alt
		case c == '|':
			stack[len(stack)-1].alt = true
			atomComplex, prevQuant = false, false
		case c == '*' || c == '+' || c == '?' || (c == '{' && reRepeatAt.MatchString(p[i:])):
			if c == '?' && prevQuant {
				prevQuant = false // lazy modifier
				continue
			}
			repeating := c == '*' || c == '+'
			if c == '{' {
				m := reRepeatAt.FindStringSubmatch(p[i:])
				n, _ := strconv.Atoi(m[1])
				hi := n
				if m[2] != "" {
					hi = -1
					if m[3] != "" {
						hi, _ = strconv.Atoi(m[3])
					}
				}
				repeating = hi < 0 || hi >= 2
				i += len(m[0]) - 1
			}
			if repeating && atomComplex {
				return errf("@rx nested quantifier: a repeated group may not contain quantifiers or alternation")
			}
			stack[len(stack)-1].quant = true
			atomComplex, prevQuant = false, true
		default:
			atomComplex, prevQuant = false, false
		}
	}
	if inClass {
		return errf("@rx unterminated character class")
	}
	total := 0
	for _, m := range reRepeat.FindAllStringSubmatch(p, -1) {
		hi := 0
		for _, g := range []string{m[1], m[3]} {
			if g == "" {
				continue
			}
			if len(g) > 1 && g[0] == '0' {
				return errf("@rx repeat count %s with leading zero", g)
			}
			n, err := strconv.Atoi(g)
			if err != nil || n > MaxRepeat {
				return errf("@rx repeat count %s above %d", g, MaxRepeat)
			}
			hi = max(hi, n)
		}
		total += hi
	}
	if total > MaxRepeatTotal {
		// RE2 expands counted repetition: the sum bounds the program size and
		// with it the matching cost on every client.
		return errf("@rx counted repetitions sum to %d, at most %d", total, MaxRepeatTotal)
	}
	if _, err := regexp.Compile(p); err != nil {
		return errf("@rx does not compile: %v", err)
	}
	return nil
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func splitActions(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQ && c == '\\' && i+1 < len(s) && s[i+1] == '\'':
			b.WriteString(`\'`)
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
	if inQ {
		return nil, errf("unterminated single quote in actions")
	}
	out = append(out, b.String())
	return out, nil
}

// actionValue strips optional single quotes and reports whether it was quoted.
func actionValue(v string) (string, bool, error) {
	if strings.HasPrefix(v, "'") {
		if len(v) < 2 || !strings.HasSuffix(v, "'") {
			return "", false, errf("bad quoting in %q", v)
		}
		inner := v[1 : len(v)-1]
		inner = strings.ReplaceAll(inner, `\'`, `'`)
		if strings.Contains(strings.ReplaceAll(v[1:len(v)-1], `\'`, ""), "'") {
			return "", false, errf("stray quote in %q", v)
		}
		return inner, true, nil
	}
	if strings.Contains(v, "'") {
		return "", false, errf("stray quote in %q", v)
	}
	return v, false, nil
}

var once = map[string]bool{
	"id": true, "phase": true, "deny": true, "block": true, "pass": true, "status": true, "severity": true, "msg": true,
	"logdata": true, "rev": true, "ver": true, "maturity": true, "accuracy": true, "chain": true, "multiMatch": true,
	"log": true, "auditlog": true,
}

var headOnly = map[string]bool{
	"id": true, "phase": true, "deny": true, "block": true, "pass": true, "status": true, "severity": true, "msg": true,
	"logdata": true, "rev": true, "ver": true, "maturity": true, "accuracy": true, "tag": true, "setvar": true,
	"log": true, "auditlog": true,
}

func validateActions(s string, isHead bool, opts Options) (*Rule, bool, bool, error) {
	if s == "" {
		return nil, false, false, errf("empty actions (use t:none in chained rules)")
	}
	if strings.Contains(s, `\`) {
		// No action value needs a backslash; parsers disagree on escapes.
		return nil, false, false, errf("actions may not contain a backslash")
	}
	items, err := splitActions(s)
	if err != nil {
		return nil, false, false, err
	}
	r := &Rule{}
	seen := map[string]int{}
	chain := false
	length := false
	hasSeverity := false
	status := ""
	for _, it := range items {
		name, val, hasVal := strings.Cut(it, ":")
		if !reActName.MatchString(name) {
			return nil, false, false, errf("invalid action %q", it)
		}
		if !isHead && headOnly[name] {
			return nil, false, false, errf("action %s only allowed in the first rule of a chain", name)
		}
		seen[name]++
		if once[name] && seen[name] > 1 {
			return nil, false, false, errf("action %s more than once", name)
		}
		v, _, err := actionValue(val)
		if err != nil {
			return nil, false, false, err
		}
		switch name {
		case "id":
			idMin, idMax := contract.RemoteRuleIDMin, contract.RemoteRuleIDMax
			if opts.Hub {
				idMin, idMax = contract.HubRuleIDMin, contract.HubRuleIDMax
			}
			n, err := strconv.Atoi(v)
			if err != nil || !reInt.MatchString(v) || n < idMin || n > idMax {
				return nil, false, false, errf("id must be in %d..%d", idMin, idMax)
			}
			r.ID = n
		case "phase":
			if v != "1" && v != "2" {
				return nil, false, false, errf("phase must be 1 or 2 (request phases only)")
			}
			r.Phase, _ = strconv.Atoi(v)
		case "deny", "block", "pass":
			if hasVal {
				return nil, false, false, errf("%s takes no value", name)
			}
			if r.Disruptive != "" {
				return nil, false, false, errf("more than one disruptive action")
			}
			r.Disruptive = name
		case "status":
			if v != "403" && v != "429" {
				return nil, false, false, errf("status must be 403 or 429")
			}
			status = v
		case "severity":
			if !severities[v] {
				return nil, false, false, errf("invalid severity %q", v)
			}
			hasSeverity = true
		case "msg", "logdata", "tag", "rev", "ver", "maturity", "accuracy":
			max := MaxMsgLen
			if name != "msg" && name != "logdata" {
				max = 64
			}
			if !hasVal || v == "" || len(v) > max {
				return nil, false, false, errf("%s needs a value of 1..%d characters", name, max)
			}
			if strings.Contains(v, "%{") {
				return nil, false, false, errf("%s may not expand macros (no request data in logs)", name)
			}
			if !reStatic.MatchString(v) {
				return nil, false, false, errf("%s contains characters outside the static text set", name)
			}
			if name == "tag" && seen[name] > MaxTags {
				return nil, false, false, errf("more than %d tags", MaxTags)
			}
		case "t":
			if !transforms[v] && !(opts.Hub && v == "uppercase") {
				return nil, false, false, errf("transformation t:%s not allowed", v)
			}
			length = length || v == "length"
			if seen[name] > MaxTransforms {
				return nil, false, false, errf("more than %d transformations", MaxTransforms)
			}
		case "setvar":
			if !reSetvar.MatchString(v) {
				return nil, false, false, errf("setvar only to raise the anomaly score (tx.inbound_anomaly_score_plN=+N)")
			}
			if seen[name] > MaxSetvar {
				return nil, false, false, errf("more than %d setvar", MaxSetvar)
			}
		case "chain":
			if hasVal {
				return nil, false, false, errf("chain takes no value")
			}
			chain = true
		case "multiMatch", "log", "auditlog":
			if hasVal {
				return nil, false, false, errf("%s takes no value", name)
			}
		default:
			return nil, false, false, errf("action %s is not allowed in network rules", name)
		}
	}
	if isHead {
		switch {
		case r.ID == 0:
			return nil, false, false, errf("id is required")
		case r.Phase == 0:
			return nil, false, false, errf("phase is required")
		case r.Disruptive == "":
			return nil, false, false, errf("one disruptive action (deny, block or pass) is required")
		case !hasSeverity:
			return nil, false, false, errf("severity is required")
		case seen["msg"] == 0:
			return nil, false, false, errf("msg is required")
		}
		if status != "" && r.Disruptive != "deny" {
			return nil, false, false, errf("status only with deny")
		}
		if opts.MaxAction == "observe" && r.Disruptive != "pass" {
			return nil, false, false, errf("max_action observe requires pass")
		}
	}
	return r, chain, length, nil
}
