package websites

import (
	"regexp"
	"strconv"
	"strings"
)

// Exception snippets (v0.5, D36): the narrow local exception that a
// "möglicher Fehlalarm" hint (MVP-22 listFalsePositiveHints) offers to copy
// into rules.d. It is scoped to the website of the hint: a Host condition
// with the website's hosts heads a chain, so an exception for one app never
// relaxes the others on the same gateway. Only a website without hosts
// (proxy-mode default, _any) gets a gateway-wide snippet, and says so
// (scope gateway). schild never applies a snippet (D32).

// SchemaException is the vector input schema.
const SchemaException = "website-exception"

// Snippet scopes.
const (
	ScopeWebsite = "website"
	ScopeGateway = "gateway"
)

// ExceptionInput of ExceptionSnippet.
type ExceptionInput struct {
	SiteID string
	Hosts  []string // Website.Hosts
	RuleID string
	Path   string // exact path or path template ({name} segments)
	Target string // optional, e.g. ARGS:comment
	ID     int64  // fresh local rule id
}

// Exception is the result.
type Exception struct {
	Scope   string `json:"scope"`
	Snippet string `json:"snippet"`
}

var placeholderRe = regexp.MustCompile(`\{[a-z0-9_]{1,32}\}`)

// rxEscape escapes the regex metacharacters \ . + * ? ( ) | [ ] { } ^ $ with
// a backslash (identical in every implementation, unlike QuoteMeta and
// re.escape).
func rxEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// pathOperator returns the operator for the page: @streq for an exact path,
// @rx with [^/]+ per {name} segment for a path template.
func pathOperator(p string) string {
	if !strings.ContainsAny(p, "{}") {
		return "@streq " + p
	}
	var b strings.Builder
	b.WriteString("@rx ^")
	rest := p
	for {
		loc := placeholderRe.FindStringIndex(rest)
		if loc == nil {
			break
		}
		b.WriteString(rxEscape(rest[:loc[0]]))
		b.WriteString("[^/]+")
		rest = rest[loc[1]:]
	}
	b.WriteString(rxEscape(rest))
	b.WriteString("$")
	return b.String()
}

// hostRegex matches the Host header of the website's hosts (lower-cased by
// t:lowercase), with an optional port.
func hostRegex(hosts []string) string {
	alts := make([]string, len(hosts))
	for i, h := range hosts {
		if strings.Contains(h, ":") {
			alts[i] = `\[` + rxEscape(h) + `\]`
			continue
		}
		labels := strings.Split(h, ".")
		for j, l := range labels {
			if l == "*" {
				labels[j] = "[a-z0-9-]+"
			} else {
				labels[j] = rxEscape(l)
			}
		}
		alts[i] = strings.Join(labels, `\.`)
	}
	return "^(?:" + strings.Join(alts, "|") + `)(?::[0-9]{1,5})?$`
}

// ExceptionSnippet renders the snippet.
func ExceptionSnippet(in ExceptionInput) (Exception, error) {
	if strings.ContainsAny(placeholderRe.ReplaceAllString(in.Path, ""), "{}") {
		return Exception{}, schemaErr("path: braces only as {name} segments")
	}
	op := pathOperator(in.Path)
	ctl := "ctl:ruleRemoveById=" + in.RuleID
	if in.Target != "" {
		ctl = "ctl:ruleRemoveTargetById=" + in.RuleID + ";" + in.Target
	}
	id := strconv.FormatInt(in.ID, 10)
	if len(in.Hosts) == 0 {
		return Exception{Scope: ScopeGateway, Snippet: "# schild: exception for rule " + in.RuleID + " on " + in.Path + ", every website of this gateway\n" +
			`SecRule REQUEST_FILENAME "` + op + `" "id:` + id + `,phase:1,pass,nolog,t:none,` + ctl + "\"\n"}, nil
	}
	return Exception{Scope: ScopeWebsite, Snippet: "# schild: exception for rule " + in.RuleID + " on " + in.Path + ", website " + in.SiteID + " only\n" +
		`SecRule REQUEST_HEADERS:Host "@rx ` + hostRegex(in.Hosts) + `" "id:` + id + `,phase:1,pass,nolog,t:none,t:lowercase,chain"` + "\n" +
		`    SecRule REQUEST_FILENAME "` + op + `" "t:none,` + ctl + "\"\n"}, nil
}

// RuleExceptionInput of RuleExceptionRule (D54, D73).
type RuleExceptionInput struct {
	Hosts  []string
	Path   string
	Target string // ARGS:name, REQUEST_COOKIES:name or REQUEST_HEADERS:name, * for one part of a name
	// Rules are SecRule ids or id ranges ("60000000-60000007": every group
	// of a crowdsec rule), as ctl:ruleRemoveTargetById takes them.
	Rules []string
	ID    int
	// SplitArgs: an ARGS target also names ARGS_GET and ARGS_POST. Converted
	// CrowdSec Hub rules read those, and a target of ARGS does not reach them.
	SplitArgs bool
}

var ctlIDRe = regexp.MustCompile(`^[1-9][0-9]{0,8}(-[1-9][0-9]{0,8})?$`)

// targetOperand renders a target for ctl as a regular expression over the whole
// name. It ignores case: Coraza compares a regular expression with the name in
// lower case, so without (?i) a name like chatgptText would never match.
func targetOperand(t string) string {
	coll, name, _ := strings.Cut(t, ":")
	parts := strings.Split(name, "*")
	for i, p := range parts {
		parts[i] = rxEscape(p)
	}
	return coll + ":/(?i)^" + strings.Join(parts, "[^.]+") + "$/"
}

// RuleExceptionRule renders a running exception: a Host condition with the
// website's hosts heads a chain, as in ExceptionSnippet. The caller validated
// path and target (agentapi.ValidException), and hosts are never empty.
func RuleExceptionRule(in RuleExceptionInput) (string, error) {
	if len(in.Hosts) == 0 {
		return "", schemaErr("hosts: a rule exception needs a website with hosts")
	}
	if strings.ContainsAny(placeholderRe.ReplaceAllString(in.Path, ""), "{}") {
		return "", schemaErr("path: braces only as {name} segments")
	}
	targets := []string{in.Target}
	if name, ok := strings.CutPrefix(in.Target, "ARGS:"); ok && in.SplitArgs {
		targets = append(targets, "ARGS_GET:"+name, "ARGS_POST:"+name)
	}
	var ctl strings.Builder
	for _, r := range in.Rules {
		if !ctlIDRe.MatchString(r) {
			return "", schemaErr("rules: an id or an id range")
		}
		for _, t := range targets {
			ctl.WriteString(",ctl:ruleRemoveTargetById=" + r + ";" + targetOperand(t))
		}
	}
	return `SecRule REQUEST_HEADERS:Host "@rx ` + hostRegex(in.Hosts) + `" "id:` + strconv.Itoa(in.ID) + `,phase:1,pass,nolog,t:none,t:lowercase,chain"` + "\n" +
		`    SecRule REQUEST_FILENAME "` + pathOperator(in.Path) + `" "t:none` + ctl.String() + "\"\n", nil
}

// RunExceptionVector parses and validates a website-exception vector input
// and renders the snippet.
func RunExceptionVector(raw []byte) (Exception, error) {
	v, err := parse(raw, SchemaException)
	if err != nil {
		return Exception{}, err
	}
	w := v["website"].(map[string]any)
	id, _ := v["id"].(interface{ Int64() (int64, error) }).Int64()
	in := ExceptionInput{SiteID: w["id"].(string), Hosts: strs(w["hosts"]), RuleID: v["rule_id"].(string), Path: v["path"].(string), ID: id}
	if t, ok := v["target"].(string); ok {
		in.Target = t
	}
	return ExceptionSnippet(in)
}
