package logcheck

import (
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/pathtpl"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// Defaults mirrored from the client: waf.DefaultLimits (body, arguments) and
// the schild.yaml default waf.eval_timeout_ms (contract/config).
const (
	DefaultEvalTimeoutMS = 1000
	// MSPerKiB is the measured CRS cost of one urlencoded value in Coraza
	// (gateway/README.md, "Large urlencoded fields": ~9 ms per KiB of a single
	// form field). Used only to estimate the 503 risk.
	MSPerKiB = 9.0
	// MaxBodyLimit is the schema maximum of waf.request_body_limit_bytes.
	MaxBodyLimit = 134217728
	// MaxEvalTimeoutMS is the schema maximum of waf.eval_timeout_ms.
	MaxEvalTimeoutMS = 10000
)

// Limits are the client limits the check applies.
type Limits struct {
	BodyBytes     int64  `json:"request_body_limit_bytes"`
	Args          int    `json:"args_limit"`
	EvalTimeoutMS int    `json:"eval_timeout_ms"`
	Source        string `json:"source"` // where the limits came from
}

// DefaultLimits returns the limits of a schild.yaml without overrides.
func DefaultLimits() Limits {
	return Limits{BodyBytes: waf.DefaultLimits.Body, Args: waf.DefaultLimits.Args, EvalTimeoutMS: DefaultEvalTimeoutMS, Source: "defaults (client code)"}
}

// Categories (codes equal the client's LimitError codes where they exist).
const (
	CatBodyTooLarge = "body_too_large" // 413
	CatBodyEncoding = "body_encoding"  // 415
	CatTooManyArgs  = "too_many_args"  // 400
	CatLongParam    = "long_param"     // 503 risk: one long query value
	CatLargeForm    = "large_form"     // 503 risk: large urlencoded body
)

var catStatus = map[string]int{CatBodyTooLarge: 413, CatBodyEncoding: 415, CatTooManyArgs: 400, CatLongParam: 503, CatLargeForm: 503}

var catOrder = []string{CatBodyTooLarge, CatBodyEncoding, CatTooManyArgs, CatLongParam, CatLargeForm}

// Options of an analysis.
type Options struct {
	Limits   Limits
	ShowIPs  bool // include client IPs in examples (local use only)
	Examples int  // example paths per category (default 5)
}

// Analyzer accumulates records per site.
type Analyzer struct {
	opt   Options
	sites map[string]*site
	order []string
}

type example struct {
	count int
	ips   map[string]bool
}

type category struct {
	certain, possible int
	examples          map[string]*example // path template -> count
	maxValue          int64               // largest size/length seen in this category
}

type site struct {
	name                 string
	lines, records, errs int
	errSamples           []string
	first, last          time.Time
	formats              map[string]int
	statuses             map[int]int
	bodies               []int64 // known non-zero body sizes
	bodyKnown, bodyZero  int
	rlOnly               []int64 // request_length where the body size is unknown
	encodingKnown        int
	maxArgs, maxParamLen int
	maxFormBody          int64
	cats                 map[string]*category
}

// New returns an analyzer.
func New(opt Options) *Analyzer {
	if opt.Examples <= 0 {
		opt.Examples = 5
	}
	if opt.Limits.BodyBytes <= 0 {
		opt.Limits.BodyBytes = waf.DefaultLimits.Body
	}
	if opt.Limits.Args <= 0 {
		opt.Limits.Args = waf.DefaultLimits.Args
	}
	if opt.Limits.EvalTimeoutMS <= 0 {
		opt.Limits.EvalTimeoutMS = DefaultEvalTimeoutMS
	}
	return &Analyzer{opt: opt, sites: map[string]*site{}}
}

func (a *Analyzer) site(name string) *site {
	s := a.sites[name]
	if s == nil {
		s = &site{name: name, formats: map[string]int{}, statuses: map[int]int{}, cats: map[string]*category{}}
		a.sites[name] = s
		a.order = append(a.order, name)
	}
	return s
}

// Line parses and adds one raw line. Returns the parse error (ErrSkip for
// blank and comment lines, which are not counted).
func (a *Analyzer) Line(siteName, format, line string) error {
	r, err := Parse(line, format)
	if err == ErrSkip {
		return err
	}
	s := a.site(siteName)
	s.lines++
	if err != nil {
		s.errs++
		if len(s.errSamples) < 3 {
			s.errSamples = append(s.errSamples, err.Error())
		}
		return err
	}
	a.Add(siteName, r)
	return nil
}

// nonEmpty is a request body that is not http.NoBody (Precheck only checks
// presence and ContentLength).
type nonEmpty struct{}

func (nonEmpty) Read([]byte) (int, error) { return 0, io.EOF }
func (nonEmpty) Close() error             { return nil }

// precheck runs the gate's Precheck without a Content-Type (not every log
// format has one), so a body has no class here and only the whole body
// limit applies: the raw body limit of D41 is not checked.
func precheck(lim Limits, cl int64, ce string, query string) string {
	r := &http.Request{Header: http.Header{}, URL: &url.URL{RawQuery: query}, ContentLength: cl}
	if cl != 0 {
		r.Body = nonEmpty{}
	}
	if ce != "" {
		r.Header.Set("Content-Encoding", ce)
	}
	if err := waf.Precheck(r, waf.Limits{Body: lim.BodyBytes, Raw: lim.BodyBytes, Args: lim.Args}); err != nil {
		if le, ok := waf.IsLimit(err); ok {
			return le.Code
		}
	}
	return ""
}

var bodyMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// Add adds a parsed record.
func (a *Analyzer) Add(siteName string, r Record) {
	s := a.site(siteName)
	s.records++
	s.formats[r.Format]++
	if r.Status > 0 {
		s.statuses[r.Status]++
	}
	if !r.Time.IsZero() {
		if s.first.IsZero() || r.Time.Before(s.first) {
			s.first = r.Time
		}
		if r.Time.After(s.last) {
			s.last = r.Time
		}
	}
	lim := a.opt.Limits
	path, query, _ := strings.Cut(r.URI, "?")
	if i := strings.IndexByte(query, '#'); i >= 0 {
		query = query[:i]
	}
	tpl := pathtpl.Template(path)
	method := strings.ToUpper(r.Method)

	// Body size: bytes actually read, else the declared Content-Length.
	body := r.BodyBytes
	if body < 0 || (r.ContentLength > body) {
		if r.ContentLength >= 0 {
			body = r.ContentLength
		}
	}
	// The schild_check formats log Content-Length; when it is absent on a
	// method without a body (GET, HEAD, ...), there is no body. Body methods
	// without it may be chunked: only request_length bounds them.
	if body < 0 && (r.Format == "nginx-json" || r.Format == "apache-check") && method != "" && !bodyMethods[method] {
		body = 0
	}
	switch {
	case body > 0:
		s.bodyKnown++
		s.bodies = append(s.bodies, body)
	case body == 0:
		s.bodyKnown++
		s.bodyZero++
	case r.RequestLength > 0:
		s.rlOnly = append(s.rlOnly, r.RequestLength)
	}

	// 413: the gate rejects a declared or streamed body above the limit.
	if body >= 0 {
		if precheck(lim, body, "", "") == CatBodyTooLarge {
			a.hit(s, CatBodyTooLarge, true, tpl, r.IP, body)
		}
	} else if r.RequestLength > lim.BodyBytes {
		// request_length includes the request line and headers: an upper bound.
		a.hit(s, CatBodyTooLarge, false, tpl, r.IP, r.RequestLength)
	}

	// 415: compressed request body.
	if r.EncodingKnown {
		s.encodingKnown++
		if ce := strings.TrimSpace(r.ContentEncoding); ce != "" {
			switch {
			case body > 0:
				if precheck(lim, body, ce, "") == CatBodyEncoding {
					a.hit(s, CatBodyEncoding, true, tpl, r.IP, body)
				}
			case body < 0 && bodyMethods[method]:
				if precheck(lim, -1, ce, "") == CatBodyEncoding {
					a.hit(s, CatBodyEncoding, false, tpl, r.IP, 0)
				}
			}
		}
	}

	// 400: more than Args query arguments (same count as the gate).
	if query != "" {
		n := strings.Count(query, "&") + 1
		if n > s.maxArgs {
			s.maxArgs = n
		}
		if precheck(lim, 0, "", query) == CatTooManyArgs {
			a.hit(s, CatTooManyArgs, true, tpl, r.IP, int64(n))
		}
		// 503 risk: one long query value (CRS cost grows with the value).
		longest := 0
		for _, kv := range strings.Split(query, "&") {
			_, v, _ := strings.Cut(kv, "=")
			if len(v) > longest {
				longest = len(v)
			}
		}
		if longest > s.maxParamLen {
			s.maxParamLen = longest
		}
		if est := estimateMS(int64(longest)); est >= float64(lim.EvalTimeoutMS)/2 {
			a.hit(s, CatLongParam, est >= float64(lim.EvalTimeoutMS), tpl, r.IP, int64(longest))
		}
	}

	// 503 risk: a large urlencoded body. The log has only the body size, not
	// the length of the longest field, so this is an upper bound.
	if mt, _, _ := mime.ParseMediaType(r.ContentType); mt == "application/x-www-form-urlencoded" && body > 0 {
		if body > s.maxFormBody {
			s.maxFormBody = body
		}
		if estimateMS(body) >= float64(lim.EvalTimeoutMS)/2 {
			a.hit(s, CatLargeForm, false, tpl, r.IP, body)
		}
	}
}

func estimateMS(bytes int64) float64 { return float64(bytes) / 1024 * MSPerKiB }

func (a *Analyzer) hit(s *site, cat string, certain bool, tpl, ip string, value int64) {
	c := s.cats[cat]
	if c == nil {
		c = &category{examples: map[string]*example{}}
		s.cats[cat] = c
	}
	if certain {
		c.certain++
	} else {
		c.possible++
	}
	if value > c.maxValue {
		c.maxValue = value
	}
	e := c.examples[tpl]
	if e == nil {
		e = &example{ips: map[string]bool{}}
		c.examples[tpl] = e
	}
	e.count++
	if a.opt.ShowIPs && ip != "" && len(e.ips) < 10 {
		e.ips[ip] = true
	}
}

// ---------------------------------------------------------------- report

// Report is the result of a check (also the --json output).
type Report struct {
	Schema      string       `json:"schema"`
	GeneratedAt string       `json:"generated_at"`
	Limits      Limits       `json:"limits"`
	Sites       []SiteReport `json:"sites"`
	Notes       []string     `json:"notes"`
}

// SiteReport is the result for one site.
type SiteReport struct {
	Site        string         `json:"site"`
	Lines       int            `json:"lines"`
	Records     int            `json:"records"`
	Unparsed    int            `json:"unparsed"`
	UnparsedEx  []string       `json:"unparsed_examples,omitempty"`
	From        string         `json:"from,omitempty"`
	To          string         `json:"to,omitempty"`
	Formats     map[string]int `json:"formats"`
	Coverage    Coverage       `json:"coverage"`
	Findings    []Finding      `json:"findings"`
	Sizes       SizeStats      `json:"body_sizes"`
	Query       QueryStats     `json:"query"`
	AppStatuses map[string]int `json:"app_statuses"` // 400/413/415/503 answered by the application itself
	Suggest     Suggestion     `json:"suggested"`
}

// Coverage tells which checks the log allowed.
type Coverage struct {
	BodySizeKnown      int `json:"body_size_known"`
	RequestLengthOnly  int `json:"request_length_only"`
	ContentEncodingLog int `json:"content_encoding_logged"`
}

// Finding is one category with its counts and example paths.
type Finding struct {
	Category string    `json:"category"`
	Status   int       `json:"status"`
	Certain  int       `json:"certain"`
	Possible int       `json:"possible"`
	MaxValue int64     `json:"max_value"`
	Examples []Example `json:"examples"`
}

// Example is a path template with its count (and IPs only with ShowIPs).
type Example struct {
	Path  string   `json:"path"`
	Count int      `json:"count"`
	IPs   []string `json:"ips,omitempty"`
}

// SizeStats is the distribution of known non-zero request body sizes.
type SizeStats struct {
	Known   int           `json:"known"`
	Empty   int           `json:"empty"`
	P50     int64         `json:"p50"`
	P90     int64         `json:"p90"`
	P99     int64         `json:"p99"`
	P999    int64         `json:"p999"`
	Max     int64         `json:"max"`
	Buckets []BucketCount `json:"buckets"`
	RLMax   int64         `json:"request_length_max,omitempty"`
}

// BucketCount is one histogram bucket.
type BucketCount struct {
	Bucket string `json:"bucket"`
	Count  int    `json:"count"`
}

// QueryStats summarises query strings.
type QueryStats struct {
	MaxArgs        int `json:"max_args"`
	MaxParamLength int `json:"max_param_length"`
}

// Suggestion holds suggested per-site values for schild.yaml.
type Suggestion struct {
	RequestBodyLimitBytes int64    `json:"request_body_limit_bytes"`
	EvalTimeoutMS         int      `json:"eval_timeout_ms"`
	Notes                 []string `json:"notes"`
}

func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

const mib = 1 << 20

// Report builds the report.
func (a *Analyzer) Report(now time.Time) *Report {
	rep := &Report{Schema: "schild.logcheck/0", GeneratedAt: now.UTC().Format(time.RFC3339), Limits: a.opt.Limits, Sites: []SiteReport{}}
	names := append([]string(nil), a.order...)
	sort.Strings(names)
	for _, n := range names {
		rep.Sites = append(rep.Sites, a.siteReport(a.sites[n]))
	}
	rep.Notes = []string{
		"413/415/400 use the client's own Precheck; 503 risks are estimates (~9 ms per KiB of one urlencoded value, gateway/README.md).",
		"Not visible in access logs: arguments inside request bodies (urlencoded, JSON values, multipart parts), JSON depth and validity, body parse errors. Check these through the application (runbook section 5.3).",
		"certain = the log shows the value the gate checks; possible = an upper bound or a missing field (request_length includes headers, encoding without a known body size, form size instead of field size).",
	}
	if !a.opt.ShowIPs {
		rep.Notes = append(rep.Notes, "Client IPs are not part of this report (use -show-ips for local use only).")
	}
	return rep
}

func (a *Analyzer) siteReport(s *site) SiteReport {
	lim := a.opt.Limits
	sr := SiteReport{Site: s.name, Lines: s.lines, Records: s.records, Unparsed: s.errs, UnparsedEx: s.errSamples, Formats: s.formats,
		Coverage:    Coverage{BodySizeKnown: s.bodyKnown, RequestLengthOnly: len(s.rlOnly), ContentEncodingLog: s.encodingKnown},
		Findings:    []Finding{},
		Query:       QueryStats{MaxArgs: s.maxArgs, MaxParamLength: s.maxParamLen},
		AppStatuses: map[string]int{}}
	if !s.first.IsZero() {
		sr.From, sr.To = s.first.Format(time.RFC3339), s.last.Format(time.RFC3339)
	}
	for _, st := range []int{400, 413, 415, 503} {
		if n := s.statuses[st]; n > 0 {
			sr.AppStatuses[strconv.Itoa(st)] = n
		}
	}
	for _, name := range catOrder {
		c := s.cats[name]
		if c == nil {
			continue
		}
		f := Finding{Category: name, Status: catStatus[name], Certain: c.certain, Possible: c.possible, MaxValue: c.maxValue, Examples: []Example{}}
		type kv struct {
			k string
			e *example
		}
		var xs []kv
		for k, e := range c.examples {
			xs = append(xs, kv{k, e})
		}
		sort.Slice(xs, func(i, j int) bool {
			if xs[i].e.count != xs[j].e.count {
				return xs[i].e.count > xs[j].e.count
			}
			return xs[i].k < xs[j].k
		})
		for i, x := range xs {
			if i >= a.opt.Examples {
				break
			}
			ex := Example{Path: x.k, Count: x.e.count}
			if a.opt.ShowIPs {
				for ip := range x.e.ips {
					ex.IPs = append(ex.IPs, ip)
				}
				sort.Strings(ex.IPs)
			}
			f.Examples = append(f.Examples, ex)
		}
		sr.Findings = append(sr.Findings, f)
	}
	// Size distribution.
	sorted := append([]int64(nil), s.bodies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	sz := SizeStats{Known: s.bodyKnown, Empty: s.bodyZero, P50: percentile(sorted, 0.5), P90: percentile(sorted, 0.9), P99: percentile(sorted, 0.99), P999: percentile(sorted, 0.999)}
	if len(sorted) > 0 {
		sz.Max = sorted[len(sorted)-1]
	}
	for _, v := range s.rlOnly {
		if v > sz.RLMax {
			sz.RLMax = v
		}
	}
	bounds := []struct {
		name string
		max  int64
	}{{"1 B - 1 KiB", 1 << 10}, {"1 - 64 KiB", 64 << 10}, {"64 KiB - 1 MiB", mib}, {"1 MiB - limit", lim.BodyBytes}, {"> limit", math.MaxInt64}}
	counts := make([]int, len(bounds))
	for _, v := range sorted {
		for i, b := range bounds {
			if v <= b.max {
				counts[i]++
				break
			}
		}
	}
	sz.Buckets = append(sz.Buckets, BucketCount{"0 (no body)", s.bodyZero})
	for i, b := range bounds {
		sz.Buckets = append(sz.Buckets, BucketCount{b.name, counts[i]})
	}
	sr.Sizes = sz
	sr.Suggest = suggest(lim, s, sz)
	return sr
}

func roundUp(v, step int64) int64 {
	if v%step == 0 {
		return v
	}
	return (v/step + 1) * step
}

// suggest applies the rules of runbook section 6.1: body limit = largest
// legitimate body x 2, rounded up to a MiB, at most 128 MiB, never below the
// current limit; eval timeout only when the log shows values whose estimated
// evaluation time exceeds the current timeout.
func suggest(lim Limits, s *site, sz SizeStats) Suggestion {
	sg := Suggestion{RequestBodyLimitBytes: lim.BodyBytes, EvalTimeoutMS: lim.EvalTimeoutMS, Notes: []string{}}
	maxBody := sz.Max
	// The logged size is client-controlled: cap it before doubling, so a
	// huge Content-Length cannot overflow into "no change".
	if want := roundUp(min(maxBody, MaxBodyLimit)*2, mib); maxBody > 0 && want > lim.BodyBytes {
		if want > MaxBodyLimit {
			want = MaxBodyLimit
		}
		sg.RequestBodyLimitBytes = want
		sg.Notes = append(sg.Notes, "raise waf.request_body_limit_bytes: largest body seen x 2, rounded up to a MiB (only if those bodies are legitimate)")
		if maxBody > MaxBodyLimit {
			sg.Notes = append(sg.Notes, "largest body exceeds the 128 MiB maximum: route that path around schild or leave the site out (runbook 6.2)")
		}
	}
	if sz.Max == 0 && sz.RLMax > lim.BodyBytes {
		sg.Notes = append(sg.Notes, "body size not logged; request_length exceeds the limit: add $content_length to the log (runbook 5.1) before deciding")
	}
	worst := math.Max(estimateMS(int64(s.maxParamLen)), estimateMS(s.maxFormBody))
	if worst > float64(lim.EvalTimeoutMS) {
		want := int(roundUp(int64(worst*1.5), 100))
		if want > MaxEvalTimeoutMS {
			want = MaxEvalTimeoutMS
			sg.Notes = append(sg.Notes, "estimated evaluation time exceeds the 10 s maximum of waf.eval_timeout_ms: such requests would get 503")
		}
		sg.EvalTimeoutMS = want
		sg.Notes = append(sg.Notes, "raise waf.eval_timeout_ms only if these long values are legitimate (estimate 9 ms per KiB, x 1.5 headroom); every raise into the ops log")
	}
	if c := s.cats[CatTooManyArgs]; c != nil {
		sg.Notes = append(sg.Notes, "more than 1000 query arguments is a fixed limit: bypass_waf for own admin addresses, route the path around schild, or change the application (runbook 6.2)")
	}
	if c := s.cats[CatBodyEncoding]; c != nil {
		sg.Notes = append(sg.Notes, "compressed request bodies are always rejected (415): send them uncompressed, bypass_waf for own admin addresses, or route the path around schild (runbook 6.2)")
	}
	if s.encodingKnown == 0 && s.records > 0 {
		sg.Notes = append(sg.Notes, "Content-Encoding not logged: the 415 check could not run (use the schild_check log format, runbook 5.1)")
	}
	if s.bodyKnown == 0 && len(s.rlOnly) == 0 && s.records > 0 {
		sg.Notes = append(sg.Notes, "no body sizes in this log: the 413 check could not run (use the schild_check log format, runbook 5.1)")
	}
	return sg
}
