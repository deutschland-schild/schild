// Package waitingpage is the v0.5 contract of the waiting page (D37, MVP-23
// step 1, an MVP-19 addendum): which fail-closed 503 answers schild sends as
// a calm waiting page instead of the block page or problem details, the
// Retry-After range, the page language and the website name shown. The
// rules are fixed by the waiting-page vectors (Go and Python agree); the
// page itself is described in contracts/waiting-page.md.
//
// The waiting page never changes what happens to a request: it is answered
// 503 and never passed (fail closed stays fail closed).
package waitingpage

import (
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Fail-closed reasons (TrafficCounters.fail_closed_by). Only the overload
// reasons get the waiting page: body_busy (D41), waf_busy (no evaluation slot, the
// client's share of expensive slots or the memory budget of expensive
// evaluations within the queue wait) and waf_timeout (the evaluation did
// not finish within its budget). not_ready and panic keep their answer.
const (
	ReasonWAFBusy    = "waf_busy"
	ReasonWAFTimeout = "waf_timeout"
	ReasonNotReady   = "not_ready"
	ReasonPanic      = "panic"
	// ReasonBodyBusy (D41): the gateway-wide body limits are full, or a client
	// of a shared address is over its share (contract/bodylimit).
	ReasonBodyBusy = "body_busy"
)

// Answers.
const (
	// AnswerWaitingPage: 503, text/html, the waiting page.
	AnswerWaitingPage = "waiting_page"
	// AnswerProblem: 503, application/problem+json whatever the client's
	// Accept says: the block page's problem body with code ProblemCode
	// (waiting, D37 amendment 2026-10-29; was timeout) and the marker header.
	AnswerProblem = "problem"
	// AnswerUnchanged: the fail-closed answer as before D37 (block page or
	// problem details by blockpage.WantsJSON, Retry-After 5).
	AnswerUnchanged = "unchanged"
)

// Marker (initiator, 2026-10-29, D37 amendment): every waiting page and
// every problem answer of this decision carries the response header
// MarkerHeader with MarkerValue, so measurements, logs and operators tell an
// overload 503 from every other 503 without parsing the body. The problem
// body of the AnswerProblem answers has code ProblemCode (type
// https://schild.invalid/problems/waiting) instead of the block page's
// timeout; the waiting page keeps having no incident number. Answers
// unchanged by this decision (not_ready, panic, waiting_page.enabled false)
// carry no marker and keep code timeout.
const (
	MarkerHeader = "Schild-Waiting"
	MarkerValue  = "1"
	ProblemCode  = "waiting"
)

// Variants of the waiting page.
const (
	// VariantReload (GET, HEAD): meta refresh and CSS countdown of
	// Retry-After seconds.
	VariantReload = "reload"
	// VariantForm (POST): no meta refresh (it would load the URL with GET
	// and silently drop what the form sent); the copy asks to go back and
	// send it again in a few seconds.
	VariantForm = "form"
)

// Languages of the page; DefaultLanguage when Accept-Language names
// neither.
const (
	LangDE          = "de"
	LangEN          = "en"
	DefaultLanguage = LangDE
)

// Retry-After of every waf_busy and waf_timeout 503 while the waiting page
// is enabled (waiting page and problem alike): RetryBaseS plus a uniform
// jitter of 0..RetryJitterS whole seconds, drawn per response, so reloads
// and client retries do not come back in waves. Bounds [5, 8].
const (
	RetryBaseS   = 5
	RetryJitterS = 3
	RetryMinS    = RetryBaseS
	RetryMaxS    = RetryBaseS + RetryJitterS
)

// Parsing bounds: only the first MaxListElements comma-separated elements
// of Accept and Accept-Language are read (the request-shape limits bound
// the headers anyway).
const MaxListElements = 32

// CSP is the Content-Security-Policy of the waiting page, the same as the
// block page's: no script, no external resource, inline styles and inline
// SVG only.
const CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// MaxPageBytes bounds the rendered page (variant A of the drafts is about
// 5.8 KB).
const MaxPageBytes = 8 << 10

// Headers are the request headers the decision reads; absent = "". A
// repeated header is its values joined with ", " (as net/http's
// Header.Values joined).
type Headers struct {
	Accept         string
	AcceptLanguage string
	SecFetchDest   string
	SecFetchMode   string
	XRequestedWith string
}

// Input of one decision.
type Input struct {
	// Reason is the fail-closed reason of the request.
	Reason string
	// Enabled is waiting_page.enabled of schild.yaml (default true).
	Enabled bool
	Method  string
	Headers Headers
	// Host is the request's Host (HTTP/2 :authority); Website the D36
	// website id it resolved to ("" = none).
	Host    string
	Website string
	// JitterDraw is a uniform random 32-bit value drawn per response (not
	// security relevant; math/rand is fine).
	JitterDraw uint32
}

// Result of one decision. Pointer fields are null where they do not apply.
type Result struct {
	Answer string `json:"answer"`
	// Variant of the waiting page (reload, form); null otherwise.
	Variant *string `json:"variant"`
	// Language of the waiting page (Content-Language, <html lang>); null
	// otherwise (the problem body stays as the block page's).
	Language *string `json:"language"`
	// RetryAfter in seconds (header, and retry_after of the problem body);
	// null for unchanged.
	RetryAfter *int `json:"retry_after"`
	// Refresh is the meta refresh in seconds (reload variant only), equal
	// to RetryAfter.
	Refresh *int `json:"refresh"`
	// Body: false for HEAD (headers only); null for unchanged.
	Body *bool `json:"body"`
	// SiteName is the website name shown on the waiting page; null shows
	// the generic wording ("Diese Website").
	SiteName *string `json:"site_name"`
	// Marker (D37 amendment 2026-10-29): the response carries
	// MarkerHeader: MarkerValue (waiting page and problem); false for
	// unchanged.
	Marker bool `json:"marker"`
	// ProblemCode is the code of the problem body (ProblemCode) for
	// AnswerProblem; null otherwise (the waiting page is HTML, unchanged
	// keeps the block page's code timeout).
	ProblemCode *string `json:"problem_code"`
}

// Overload reports whether a fail-closed reason may get the waiting page.
func Overload(reason string) bool {
	return reason == ReasonWAFBusy || reason == ReasonWAFTimeout || reason == ReasonBodyBusy
}

// RetryAfter returns the Retry-After seconds for a jitter draw.
func RetryAfter(draw uint32) int { return RetryBaseS + int(draw%(RetryJitterS+1)) }

// Document reports whether a request is a document navigation that gets the
// waiting page (method GET, HEAD or POST). Fetch Metadata wins over Accept:
//  1. a method other than GET, HEAD, POST: no;
//  2. X-Requested-With present: no (XHR libraries);
//  3. Sec-Fetch-Mode present and not navigate: no (fetch, XHR, cors, no-cors,
//     same-origin, websocket);
//  4. Sec-Fetch-Dest present: yes exactly for document (iframe, frame,
//     empty, image, script ... get the problem);
//  5. otherwise (older browsers, plain HTTP, non-browsers): yes when Accept
//     lists text/html or application/xhtml+xml with a q above 0 and above
//     every JSON type (application/json or a +json suffix). */* or no Accept
//     is no document.
//
// Header values are trimmed of spaces and tabs and compared ASCII
// case-insensitively.
func Document(method string, h Headers) bool {
	if method != "GET" && method != "HEAD" && method != "POST" {
		return false
	}
	if trim(h.XRequestedWith) != "" {
		return false
	}
	if mode := lower(trim(h.SecFetchMode)); mode != "" && mode != "navigate" {
		return false
	}
	if dest := lower(trim(h.SecFetchDest)); dest != "" {
		return dest == "document"
	}
	return htmlWins(h.Accept)
}

// htmlWins: the best q of an HTML type is above 0 and above the best q of a
// JSON type (a tie goes to JSON).
func htmlWins(accept string) bool {
	html, json := 0, 0
	for _, e := range parseList(accept) {
		switch {
		case e.rng == "text/html" || e.rng == "application/xhtml+xml":
			html = max(html, e.q)
		case e.rng == "application/json" || strings.HasSuffix(e.rng, "+json"):
			json = max(json, e.q)
		}
	}
	return html > 0 && html > json
}

// Language picks de or en from Accept-Language: among the language ranges
// whose primary subtag is de or en (de-CH, en-GB ...) the one with the
// highest q above 0, the first listed on a tie; DefaultLanguage when there
// is none (no header, only other languages, *, or q=0).
func Language(acceptLanguage string) string {
	best, bestQ := "", 0
	for _, e := range parseList(acceptLanguage) {
		primary, _, _ := strings.Cut(e.rng, "-")
		if (primary == LangDE || primary == LangEN) && e.q > bestQ {
			best, bestQ = primary, e.q
		}
	}
	if best == "" {
		return DefaultLanguage
	}
	return best
}

// SiteName returns the website name shown on the page: the request's host
// (port and one trailing dot removed, ASCII lower case) when it resolved to
// a website with hosts and is a DNS name or IPv4 literal (labels of 1..63
// characters a-z, 0-9 and -, not starting or ending with -, at most 253
// characters). No name for no website, _any (any host matches it), default
// (proxy mode without upstream.site_hosts), IPv6 literals and anything else.
// Punycode A-labels are shown as they are. The page HTML-escapes it anyway.
func SiteName(host, website string) (string, bool) {
	if website == "" || website == "_any" || website == "default" {
		return "", false
	}
	h := host
	if strings.HasPrefix(h, "[") {
		return "", false
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		p := h[i+1:]
		if p == "" || len(p) > 5 || strings.Trim(p, "0123456789") != "" {
			return "", false
		}
		h = h[:i]
	}
	h = lower(strings.TrimSuffix(h, "."))
	if len(h) == 0 || len(h) > 253 {
		return "", false
	}
	for _, l := range strings.Split(h, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return h, true
}

// Decide returns the answer to a fail-closed request.
func Decide(in Input) Result {
	if !in.Enabled || !Overload(in.Reason) {
		return Result{Answer: AnswerUnchanged}
	}
	retry := RetryAfter(in.JitterDraw)
	body := in.Method != "HEAD"
	if !Document(in.Method, in.Headers) {
		code := ProblemCode
		return Result{Answer: AnswerProblem, RetryAfter: &retry, Body: &body, Marker: true, ProblemCode: &code}
	}
	lang := Language(in.Headers.AcceptLanguage)
	r := Result{Answer: AnswerWaitingPage, Language: &lang, RetryAfter: &retry, Body: &body, Marker: true}
	v := VariantReload
	if in.Method == "POST" {
		v = VariantForm
	} else {
		refresh := retry
		r.Refresh = &refresh
	}
	r.Variant = &v
	if name, ok := SiteName(in.Host, in.Website); ok {
		r.SiteName = &name
	}
	return r
}

type element struct {
	rng string
	q   int // thousandths, 0..1000
}

// parseList reads the first MaxListElements comma-separated elements of an
// Accept or Accept-Language value: the range (trimmed, ASCII lower case)
// and its q (thousandths; absent = 1000). Elements with an empty range or
// an invalid q (RFC 9110 qvalue: 0, 0.d, 0.dd, 0.ddd, 1, 1.0 ... 1.000) are
// skipped; the first q parameter counts, other parameters are ignored.
func parseList(v string) []element {
	parts := strings.Split(v, ",")
	if len(parts) > MaxListElements {
		parts = parts[:MaxListElements]
	}
	var out []element
	for _, p := range parts {
		params := strings.Split(p, ";")
		rng := lower(trim(params[0]))
		if rng == "" {
			continue
		}
		q, ok := 1000, true
		for _, pr := range params[1:] {
			pr = trim(pr)
			if len(pr) >= 2 && lower(pr[:2]) == "q=" {
				q, ok = qvalue(pr[2:])
				break
			}
		}
		if ok {
			out = append(out, element{rng, q})
		}
	}
	return out
}

func qvalue(s string) (int, bool) {
	if s == "" || len(s) > 5 || (s[0] != '0' && s[0] != '1') {
		return 0, false
	}
	n := int(s[0]-'0') * 1000
	if len(s) > 1 {
		if s[1] != '.' {
			return 0, false
		}
		scale := 100
		for i := 2; i < len(s); i++ {
			c := s[i]
			if c < '0' || c > '9' || (s[0] == '1' && c != '0') {
				return 0, false
			}
			n += int(c-'0') * scale
			scale /= 10
		}
	}
	return n, true
}

func trim(s string) string { return strings.Trim(s, " \t") }

// lower is ASCII lower case (strings.ToLower would also map non-ASCII).
func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// Schema is the input schema of the waiting-page vectors.
const Schema = schema.WaitingPage

// MaxInputBytes bounds a vector input.
const MaxInputBytes = 64 << 10

// RunVector parses and validates a waiting-page vector input and returns
// the decision.
func RunVector(raw []byte) (Result, error) {
	if len(raw) > MaxInputBytes {
		return Result{}, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return Result{}, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(Schema, v); err != nil {
		return Result{}, err
	}
	h, _ := v["headers"].(map[string]any)
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	in := Input{
		Reason:  v["fail_closed"].(string),
		Enabled: v["enabled"].(bool),
		Method:  v["method"].(string),
		Headers: Headers{
			Accept: str(h, "accept"), AcceptLanguage: str(h, "accept_language"),
			SecFetchDest: str(h, "sec_fetch_dest"), SecFetchMode: str(h, "sec_fetch_mode"),
			XRequestedWith: str(h, "x_requested_with"),
		},
		Host:    v["host"].(string),
		Website: str(v, "website"),
	}
	d, err := v["jitter_draw"].(interface{ Int64() (int64, error) }).Int64()
	if err != nil {
		return Result{}, contract.Errf(contract.CodeSchema, "jitter_draw: %v", err)
	}
	in.JitterDraw = uint32(d) // the schema bounds it to 0..4294967295
	return Decide(in), nil
}
