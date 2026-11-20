package agentapi

import (
	"regexp"
	"strconv"
	"strings"
)

// Request test (D55, D73): an agent that knows the code of a website reads
// which rules run (listAgentRules) and sends a sample request to the WAF before
// it goes live, then sets the narrowest exception that lets it pass. The test
// forwards nothing, stores nothing and changes nothing, so every reading token
// may run it.
const (
	// OpTestRequest is the only POST of this API that is no write.
	OpTestRequest = "testAgentRequest"
	// MaxTestBody of a sample body, MaxTestHeaders of its headers.
	MaxTestBody    = 64 << 10
	MaxTestHeaders = 16
	// MaxTestRequest of the whole JSON body of testAgentRequest.
	MaxTestRequest = 2*MaxTestBody + 8<<10
)

// TestRequest is the body of testAgentRequest: a request as the website's code
// would send it.
type TestRequest struct {
	Website     string            `json:"website"`
	Method      string            `json:"method"`
	Path        string            `json:"path"` // with query
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
}

// TestMatch is one rule the sample hit.
type TestMatch struct {
	Repository string `json:"repository"` // crs | local | crowdsec
	Rule       string `json:"rule"`       // crowdsec: the base id
	Msg        string `json:"msg"`
	Severity   string `json:"severity,omitempty"`
	Points     int    `json:"points"`
	// Target is where it hit, e.g. ARGS:json.components.0.updates.text or
	// REQUEST_FILENAME. Empty when Coraza named no variable.
	Target string `json:"target,omitempty"`
}

// TestResult is the answer of testAgentRequest.
type TestResult struct {
	Website          string      `json:"website"`
	Anomaly          int         `json:"anomaly"`
	AnomalyThreshold int         `json:"anomaly_threshold"`
	WouldBlock       bool        `json:"would_block"`
	Matches          []TestMatch `json:"matches"`
	// Suggestions: per field and repository, the rules that hit it, ready
	// for createAgentException with a reason. Hits outside a named field and
	// local rules have none.
	Suggestions []ExceptionSuggestion `json:"suggestions"`
}

// ExceptionSuggestion is an ExceptionRequest without its reason.
type ExceptionSuggestion struct {
	Website    string   `json:"website"`
	Path       string   `json:"path"`
	Target     string   `json:"target"`
	Repository string   `json:"repository"`
	Rules      []string `json:"rules"`
}

var (
	testMethods  = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}
	testPathRe   = regexp.MustCompile(`^/[\x21-\x7e]*$`)
	testHeaderRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	testCTypeRe  = regexp.MustCompile(`^[\x20-\x7e]{0,256}$`)
	numericPart  = regexp.MustCompile(`^[0-9]+$`)
)

// ValidTestRequest checks the shape of a sample request.
func ValidTestRequest(r TestRequest) bool {
	if r.Website == "" || !testMethods[r.Method] || len(r.Path) > 2048 || !testPathRe.MatchString(r.Path) || !testCTypeRe.MatchString(r.ContentType) {
		return false
	}
	if len(r.Body) > MaxTestBody || len(r.Headers) > MaxTestHeaders {
		return false
	}
	for k, v := range r.Headers {
		lk := strings.ToLower(k)
		if !testHeaderRe.MatchString(k) || len(v) > 1024 || strings.ContainsAny(v, "\r\n\x00") || lk == "host" || lk == "content-length" || lk == "transfer-encoding" {
			return false
		}
	}
	return true
}

// SuggestTarget turns where a rule hit into an exception target, or "" when
// no field is named. Numbered parts become *, so one exception holds for every
// index of a list (json.components.*.updates.text).
func SuggestTarget(variable, key string) string {
	coll := variable
	switch variable {
	case "ARGS", "ARGS_GET", "ARGS_POST":
		coll = "ARGS"
	case "REQUEST_COOKIES", "REQUEST_HEADERS":
	default:
		return ""
	}
	if key == "" {
		return ""
	}
	parts := strings.Split(key, ".")
	for i, p := range parts {
		if numericPart.MatchString(p) {
			parts[i] = "*"
		}
	}
	t := coll + ":" + strings.Join(parts, ".")
	if !exceptionTargetRe.MatchString(t) || !exceptionNameRe.MatchString(t) {
		return ""
	}
	return t
}

// SuggestPath is the path of an exception for a sample path, or "".
func SuggestPath(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if !exceptionPathRe.MatchString(path) || strings.ContainsAny(path, "{}") {
		return ""
	}
	return path
}

// IsExceptionRule reports whether an exception of repository may name rule id.
func IsExceptionRule(repository string, id int) bool {
	return ExceptionRuleID(repository, strconv.Itoa(id))
}
