package crowdsec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/seclang"
)

// Skip is a refused rule: the code is the contract, the detail is for logs.
type Skip struct {
	Code   string
	Detail string
}

func (s *Skip) Error() string { return s.Code + ": " + s.Detail }

func skip(code, format string, args ...any) *Skip {
	return &Skip{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Rule is a converted hub rule. SecLang holds one text per AND-group; the
// group with index g has the SecRule id BaseID+g.
type Rule struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Digest      string   `json:"digest"`
	BaseID      int      `json:"base_id"`
	SecLang     []string `json:"seclang"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	CVEs        []string `json:"cves"`
	CWEs        []string `json:"cwes"`
	Attack      []string `json:"attack"`
	Notes       []string `json:"notes"`
}

// yamlTree parses one hub YAML document into maps, slices, strings and nil.
// Every scalar stays the text it was written as: `value: 1` and `value: false`
// are the strings "1" and "false", as yaml.v3 decodes them into CrowdSec's
// string field. Anchors, aliases, explicit tags, merge keys, duplicate keys,
// non-scalar keys and more than one document are refused.
func yamlTree(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("not UTF-8")
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one document")
	}
	return yamlValue(doc.Content[0], 0)
}

func yamlValue(n *yaml.Node, depth int) (any, error) {
	if depth > contract.MaxJSONDepth {
		return nil, errors.New("nested too deep")
	}
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return nil, fmt.Errorf("line %d: anchors and aliases are not allowed", n.Line)
	}
	if n.Style&yaml.TaggedStyle != 0 {
		return nil, fmt.Errorf("line %d: explicit tags are not allowed", n.Line)
	}
	switch n.Kind {
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Style&yaml.TaggedStyle != 0 || k.Anchor != "" {
				return nil, fmt.Errorf("line %d: keys must be plain scalars", k.Line)
			}
			if k.Value == "<<" {
				return nil, fmt.Errorf("line %d: merge keys are not allowed", k.Line)
			}
			if _, dup := m[k.Value]; dup {
				return nil, fmt.Errorf("line %d: duplicate key %q", k.Line, k.Value)
			}
			v, err := yamlValue(n.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			m[k.Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		a := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlValue(c, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		return a, nil
	case yaml.ScalarNode:
		plain := n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0
		if plain {
			switch n.Value {
			case "", "~", "null", "Null", "NULL":
				return nil, nil
			}
		}
		return n.Value, nil
	}
	return nil, fmt.Errorf("line %d: unsupported node", n.Line)
}

// The mappings of contracts/crowdsec-hub.md section 3; they follow
// pkg/appsec/appsec_rule/modsecurity.go of crowdsecurity/crowdsec.
var (
	zones = map[string]string{
		"ARGS": "ARGS_GET", "ARGS_NAMES": "ARGS_GET_NAMES", "BODY_ARGS": "ARGS_POST", "BODY_ARGS_NAMES": "ARGS_POST_NAMES",
		"COOKIES": "REQUEST_COOKIES", "COOKIES_NAMES": "REQUEST_COOKIES_NAMES", "FILES": "FILES", "FILES_NAMES": "FILES_NAMES",
		"FILENAMES": "FILES", "HEADERS": "REQUEST_HEADERS", "HEADERS_NAMES": "REQUEST_HEADERS_NAMES", "METHOD": "REQUEST_METHOD",
		"PROTOCOL": "REQUEST_PROTOCOL", "URI": "REQUEST_FILENAME", "URI_FULL": "REQUEST_URI", "RAW_BODY": "REQUEST_BODY",
	}
	// Zones that are one value: a selector is meaningless.
	scalarZones = map[string]bool{"METHOD": true, "PROTOCOL": true, "URI": true, "URI_FULL": true, "RAW_BODY": true}

	transformsMap = map[string]string{
		"lowercase": "lowercase", "uppercase": "uppercase", "length": "length", "trim": "trim", "trim_left": "trimLeft", "trim_right": "trimRight",
		"htmlentitydecode": "htmlEntityDecode", "html_entity_decode": "htmlEntityDecode", "js_decode": "jsDecode", "css_decode": "cssDecode",
		"urldecode": "urlDecode", "hexdecode": "hexDecode", "cmdline": "cmdLine", "b64decode": "base64Decode", "b64decode_lenient": "base64DecodeExt",
		"normalize_path": "normalizePath", "normalizepath": "normalizePath", "normalize_path_win": "normalizePathWin", "normalizepathwin": "normalizePathWin",
		"remove_whitespaces": "removeWhitespace", "compress_whitespaces": "compressWhitespace", "remove_nulls": "removeNulls", "replace_nulls": "replaceNulls",
		"remove_comments": "removeComments", "replace_comments": "replaceComments",
	}

	stringMatches  = map[string]string{"regex": "rx", "equals": "streq", "startsWith": "beginsWith", "endsWith": "endsWith", "contains": "contains"}
	noArgMatches   = map[string]string{"libinjectionSQL": "detectSQLi", "libinjectionXSS": "detectXSS"}
	numericMatches = map[string]string{"gt": "gt", "lt": "lt", "gte": "ge", "lte": "le", "eq": "eq"}
	reHubInt       = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)
)

type line struct {
	vars, op string
	ts       []string
	late     bool // numeric or negated: never the head of a chain
}

func asMap(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

func stringList(v any, what string) ([]string, *Skip) {
	if v == nil {
		return nil, nil
	}
	a, ok := v.([]any)
	if !ok {
		return nil, skip(SkipNodeShape, "%s is not a list", what)
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		s, ok := x.(string)
		if !ok {
			return nil, skip(SkipNodeShape, "%s entry is not a scalar", what)
		}
		out = append(out, s)
	}
	return out, nil
}

// checkValue applies the text rules of the subset to a match value, so that
// the refusal names the reason. An @rx value may also be refused by the regex
// check.
func checkValue(v string) *Skip {
	if v == "" {
		return skip(SkipMissingValue, "empty value")
	}
	if len(v) > seclang.MaxOperatorLen-32 {
		return skip(SkipValueChars, "value too long")
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 || c > 0x7e {
			return skip(SkipValueChars, "byte 0x%02x", c)
		}
	}
	switch {
	case strings.ContainsRune(v, '"'):
		return skip(SkipValueChars, "double quote")
	case strings.HasSuffix(v, `\`):
		return skip(SkipValueChars, "trailing backslash")
	case v[0] == ' ' || v[len(v)-1] == ' ':
		return skip(SkipValueChars, "leading or trailing space")
	case strings.Contains(v, "%{"):
		return skip(SkipValueChars, "macro")
	}
	return nil
}

func convertLeaf(n map[string]any) (*line, *Skip, []string) {
	for _, k := range sortedKeys(n) {
		switch k {
		case "zones", "variables", "transform", "match", "name":
		default:
			return nil, skip(SkipUnknownKey, "leaf key %q", k), nil
		}
	}
	zs, sk := stringList(n["zones"], "zones")
	if sk != nil {
		return nil, sk, nil
	}
	if len(zs) == 0 {
		return nil, skip(SkipNodeShape, "leaf without zones"), nil
	}
	vs, sk := stringList(n["variables"], "variables")
	if sk != nil {
		return nil, sk, nil
	}
	ts, sk := stringList(n["transform"], "transform")
	if sk != nil {
		return nil, sk, nil
	}
	count, length := false, false
	mapped := []string{"none"}
	for _, t := range ts {
		switch t {
		case "count":
			count = true
			continue
		case "length":
			length = true
		}
		m, ok := transformsMap[t]
		if !ok {
			return nil, skip(SkipTransform, "%q", t), nil
		}
		mapped = append(mapped, m)
	}
	if len(mapped) > seclang.MaxTransforms {
		return nil, skip(SkipTransform, "more than %d", seclang.MaxTransforms), nil
	}
	var notes []string
	var out []string
	for _, z := range zs {
		mz, ok := zones[z]
		if !ok {
			return nil, skip(SkipZone, "%q", z), nil
		}
		if len(vs) > 0 && scalarZones[z] {
			return nil, skip(SkipSelector, "zone %s takes no variable", z), nil
		}
		if z == "HEADERS" && len(vs) == 0 {
			return nil, skip(SkipHeadersNoName, "all headers include Host"), nil
		}
		if count && len(vs) == 0 {
			return nil, skip(SkipCountNoVar, "zone %s", z), nil
		}
		if z == "RAW_BODY" {
			notes = append(notes, NoteRawBodyPartial)
			if count {
				return nil, skip(SkipSelector, "count on RAW_BODY"), nil
			}
			out = append(out, mz, seclang.HubJSONBody)
			continue
		}
		if len(vs) == 0 {
			out = append(out, mz)
			continue
		}
		for _, v := range vs {
			if err := seclang.ValidateHubSelector(mz, v); err != nil {
				return nil, skip(SkipSelector, "%v", err), nil
			}
			if z == "HEADERS" && seclang.HeaderClass(v) == "forbidden" {
				return nil, skip(SkipForbiddenHdr, "%q", v), nil
			}
			p := ""
			if count {
				p = "&"
			}
			out = append(out, p+mz+":"+v)
		}
	}
	if len(out) > seclang.MaxVariables {
		return nil, skip(SkipTooManyVars, "%d", len(out)), nil
	}
	m, ok := asMap(n["match"])
	if !ok {
		return nil, skip(SkipNodeShape, "leaf without match"), nil
	}
	for _, k := range sortedKeys(m) {
		if k != "type" && k != "value" && k != "not" {
			return nil, skip(SkipUnknownKey, "match key %q", k), nil
		}
	}
	mt, ok := m["type"].(string)
	if !ok {
		return nil, skip(SkipNodeShape, "match without type"), nil
	}
	not := false
	switch nv := m["not"].(type) {
	case nil:
	case string:
		switch nv {
		case "true":
			not = true
		case "false":
		default:
			return nil, skip(SkipNodeShape, "match.not %q", nv), nil
		}
	default:
		return nil, skip(SkipNodeShape, "match.not is not a scalar"), nil
	}
	val, hasVal := m["value"].(string)
	if m["value"] != nil && !hasVal {
		return nil, skip(SkipNodeShape, "match.value is not a scalar"), nil
	}
	l := &line{ts: mapped}
	neg := ""
	if not {
		neg = "!"
		l.late = true
	}
	numeric := func(op string) *Skip {
		if !hasVal || val == "" {
			return skip(SkipMissingValue, "%s", mt)
		}
		if !reHubInt.MatchString(val) {
			return skip(SkipNotNumeric, "%q", val)
		}
		l.op, l.late = neg+"@"+op+" "+val, true
		return nil
	}
	switch {
	case numericMatches[mt] != "":
		if sk := numeric(numericMatches[mt]); sk != nil {
			return nil, sk, nil
		}
	case mt == "equals" && (count || length):
		// A count or length is a number: @streq on its digits is @eq.
		if sk := numeric("eq"); sk != nil {
			return nil, sk, nil
		}
	case noArgMatches[mt] != "":
		l.op = neg + "@" + noArgMatches[mt]
	case stringMatches[mt] != "":
		if !hasVal || val == "" {
			return nil, skip(SkipMissingValue, "%s", mt), nil
		}
		if sk := checkValue(val); sk != nil {
			return nil, sk, nil
		}
		if mt == "regex" {
			if err := seclang.ValidateRegex(val); err != nil {
				return nil, skip(SkipRegex, "%v", err), nil
			}
		}
		l.op = neg + "@" + stringMatches[mt] + " " + val
	default:
		return nil, skip(SkipMatch, "%q", mt), nil
	}
	if !strings.HasPrefix(strings.TrimPrefix(l.op, "!"), "@detect") {
		for _, z := range zs {
			if z != "HEADERS" {
				continue
			}
			for _, v := range vs {
				if seclang.HeaderClass(v) == "detect_only" {
					return nil, skip(SkipForbiddenHdr, "%q only with libinjection", v), nil
				}
			}
		}
	}
	l.vars = strings.Join(out, "|")
	return l, nil, notes
}

// dnf flattens a rule node into AND-groups, as flattenToDNF of the CrowdSec
// compiler does, with a lower bound. A node is exactly one of and, or, leaf.
func dnf(v any, depth int, notes *[]string) ([][]*line, *Skip) {
	n, ok := asMap(v)
	if !ok {
		return nil, skip(SkipNodeShape, "rule node is not a mapping")
	}
	if depth > MaxNodeDepth {
		return nil, skip(SkipNodeShape, "nested deeper than %d", MaxNodeDepth)
	}
	_, isAnd := n["and"]
	_, isOr := n["or"]
	_, isZones := n["zones"]
	_, isMatch := n["match"]
	leaf := isZones || isMatch
	if (isAnd && isOr) || ((isAnd || isOr) && leaf) || (!isAnd && !isOr && !leaf) {
		return nil, skip(SkipNodeShape, "a node is exactly one of and, or, leaf")
	}
	if leaf {
		l, sk, ns := convertLeaf(n)
		if sk != nil {
			return nil, sk
		}
		*notes = append(*notes, ns...)
		return [][]*line{{l}}, nil
	}
	key := "and"
	if isOr {
		key = "or"
	}
	for _, k := range sortedKeys(n) {
		if k != key && k != "name" {
			return nil, skip(SkipUnknownKey, "group key %q", k)
		}
	}
	kids, ok := n[key].([]any)
	if !ok || len(kids) == 0 {
		return nil, skip(SkipNodeShape, "empty %s", key)
	}
	var acc [][]*line
	for i, c := range kids {
		d, sk := dnf(c, depth+1, notes)
		if sk != nil {
			return nil, sk
		}
		switch {
		case isOr:
			acc = append(acc, d...)
		case i == 0:
			acc = d
		default:
			next := make([][]*line, 0, len(acc)*len(d))
			for _, a := range acc {
				for _, b := range d {
					g := make([]*line, 0, len(a)+len(b))
					g = append(append(g, a...), b...)
					next = append(next, g)
				}
			}
			acc = next
		}
		if len(acc) > MaxGroups {
			return nil, skip(SkipTooManyGroups, "more than %d", MaxGroups)
		}
	}
	return acc, nil
}

// render writes one AND-group as a chain. Numeric and negated lines go last
// (stable): AND is commutative, and the subset wants a plain string head.
func render(group []*line, name string, id int) string {
	ordered := make([]*line, 0, len(group))
	for _, l := range group {
		if !l.late {
			ordered = append(ordered, l)
		}
	}
	for _, l := range group {
		if l.late {
			ordered = append(ordered, l)
		}
	}
	var b strings.Builder
	for i, l := range ordered {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, `SecRule %s "%s" "`, l.vars, l.op)
		if i == 0 {
			fmt.Fprintf(&b, "id:%d,phase:2,pass,", id)
		}
		for j, t := range l.ts {
			if j > 0 {
				b.WriteByte(',')
			}
			b.WriteString("t:" + t)
		}
		if i == 0 {
			fmt.Fprintf(&b, ",severity:CRITICAL,msg:'crowdsec hub %s',tag:%s", name, Tag)
		}
		if i < len(ordered)-1 {
			b.WriteString(",chain")
		}
		b.WriteByte('"')
	}
	return b.String()
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// clean keeps printable characters and cuts to n characters. Hub text is
// shown to people, never put into a rule.
func clean(s string, n int) string {
	var b strings.Builder
	c := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			continue
		}
		if c == n {
			break
		}
		b.WriteRune(r)
		c++
	}
	return strings.TrimSpace(b.String())
}

func classification(labels map[string]any) (cves, cwes, attack []string) {
	cves, cwes, attack = []string{}, []string{}, []string{}
	list, _ := labels["classification"].([]any)
	add := func(out *[]string, s string) {
		for _, x := range *out {
			if x == s {
				return
			}
		}
		*out = append(*out, s)
	}
	for _, x := range list {
		s, _ := x.(string)
		if m := reCVE.FindStringSubmatch(s); m != nil {
			add(&cves, m[1])
		} else if m := reCWE.FindStringSubmatch(s); m != nil {
			add(&cwes, m[1])
		} else if m := reAttack.FindStringSubmatch(s); m != nil {
			add(&attack, m[1])
		}
	}
	sort.Strings(cves)
	sort.Strings(cwes)
	sort.Strings(attack)
	return
}

// Convert turns the YAML of one hub rule into a Rule. Any refusal is the whole
// rule: nothing loads partly. fallbackDesc is the description of the index.
func Convert(name, version, digest string, content []byte, fallbackDesc string) (*Rule, *Skip) {
	if !reName.MatchString(name) {
		return nil, skip(SkipBadName, "%q", name)
	}
	if len(content) > MaxContentBytes {
		return nil, skip(SkipTooLong, "%d bytes", len(content))
	}
	t, err := yamlTree(content)
	if err != nil {
		return nil, skip(SkipYAML, "%v", err)
	}
	y, ok := asMap(t)
	if !ok {
		return nil, skip(SkipYAML, "not a mapping")
	}
	if y["name"] != name {
		return nil, skip(SkipNameMismatch, "yaml name %v", y["name"])
	}
	if _, ok := y["seclang_rules"]; ok {
		return nil, skip(SkipRawSecLang, "seclang_rules")
	}
	if _, ok := y["seclang_files_rules"]; ok {
		return nil, skip(SkipRawSecLang, "seclang_files_rules")
	}
	if _, ok := y["data"]; ok {
		return nil, skip(SkipExternalData, "data")
	}
	for _, k := range sortedKeys(y) {
		switch k {
		case "name", "description", "rules", "labels":
		default:
			return nil, skip(SkipUnknownKey, "top-level key %q", k)
		}
	}
	entries, ok := y["rules"].([]any)
	if !ok || len(entries) == 0 {
		return nil, skip(SkipNoRules, "no rules")
	}
	var groups [][]*line
	var notes []string
	for _, e := range entries {
		g, sk := dnf(e, 0, &notes)
		if sk != nil {
			return nil, sk
		}
		groups = append(groups, g...)
		if len(groups) > MaxGroups {
			return nil, skip(SkipTooManyGroups, "more than %d", MaxGroups)
		}
	}
	base := BaseID(name)
	r := &Rule{Name: name, Version: version, Digest: digest, BaseID: base, SecLang: []string{}, Notes: []string{}}
	for i, g := range groups {
		if len(g) > seclang.MaxHubLines {
			return nil, skip(SkipTooManyLines, "%d", len(g))
		}
		head := false
		for _, l := range g {
			head = head || !l.late
		}
		if !head {
			return nil, skip(SkipCatchAll, "only numeric or negated lines")
		}
		text := render(g, name, base+i)
		if len(text) > contract.MaxSecLangBytes {
			return nil, skip(SkipTooLong, "%d bytes of SecLang", len(text))
		}
		if _, err := seclang.Validate(text, seclang.Options{MaxAction: "observe", Hub: true}); err != nil {
			if errors.Is(err, seclang.ErrCatchAll) {
				return nil, skip(SkipCatchAll, "%v", err)
			}
			return nil, skip(SkipSubset, "%v", err)
		}
		r.SecLang = append(r.SecLang, text)
	}
	seen := map[string]bool{}
	for _, n := range notes {
		if !seen[n] {
			seen[n] = true
			r.Notes = append(r.Notes, n)
		}
	}
	labels, _ := asMap(y["labels"])
	lbl, _ := labels["label"].(string)
	r.Label = clean(lbl, MaxLabelChars)
	desc, _ := y["description"].(string)
	if desc == "" {
		desc = fallbackDesc
	}
	r.Description = clean(desc, MaxDescriptionChars)
	r.CVEs, r.CWEs, r.Attack = classification(labels)
	return r, nil
}

func programSize(pattern string) int {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0
	}
	p, err := syntax.Compile(re.Simplify())
	if err != nil {
		return 0
	}
	return len(p.Inst)
}

// CheckRegexCost bounds the compiled size of a regex (an update's cost check
// before a set goes live). RE2 matching is linear in the input but its factor
// is this program; it is the only check that needs the real compiler, so it
// is Go only and not part of the vectors: the gateway runs it after Convert
// over every @rx operator and every /regex/ selector, and a rule over the
// bound is skipped with SkipRegexCost.
func CheckRegexCost(pattern string) error {
	if n := programSize(pattern); n == 0 || n > MaxRegexInstructions {
		return errors.New("program of " + strconv.Itoa(n) + " instructions, at most " + strconv.Itoa(MaxRegexInstructions))
	}
	return nil
}
