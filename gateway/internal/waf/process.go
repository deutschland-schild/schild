package waf

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"

	"github.com/corazawaf/coraza/v3/types"

	"github.com/deutschland-schild/schild/contract/bodylimit"
)

// Hard limit violations. They are rejected in every mode: a request that
// cannot be inspected never reaches the backend (M1, K3).
var (
	ErrBodyTooLarge    = &LimitError{Status: http.StatusRequestEntityTooLarge, Code: bodylimit.CodeTooLarge}
	ErrRawTooLarge     = &LimitError{Status: http.StatusRequestEntityTooLarge, Code: bodylimit.CodeRawTooLarge}
	ErrBodyEncoding    = &LimitError{Status: http.StatusUnsupportedMediaType, Code: "body_encoding"}
	ErrTooManyArgs     = &LimitError{Status: http.StatusBadRequest, Code: "too_many_args"}
	ErrJSONTooDeep     = &LimitError{Status: http.StatusBadRequest, Code: "json_too_deep"}
	ErrMultipartParts  = &LimitError{Status: http.StatusBadRequest, Code: "multipart_too_many_parts"}
	ErrBodyUnparseable = &LimitError{Status: http.StatusBadRequest, Code: "body_unparseable"}
	ErrBodyRead        = &LimitError{Status: http.StatusBadRequest, Code: bodylimit.CodeBodyRead}
	ErrTimeout         = &LimitError{Status: http.StatusServiceUnavailable, Code: "waf_timeout"}
	// ErrBusy: every evaluation slot was taken for longer than the queue wait.
	ErrBusy = &LimitError{Status: http.StatusServiceUnavailable, Code: "waf_busy"}
	// Request shape limits checked before any rule (MVP-19 re-measurement,
	// finding 2): every argument, header and cookie costs evaluation memory
	// and CPU in Coraza, so their number and size are bounded up front.
	ErrQueryTooLong    = &LimitError{Status: http.StatusBadRequest, Code: "query_too_long"}
	ErrTargetTooLong   = &LimitError{Status: http.StatusRequestURITooLong, Code: "uri_too_long"}
	ErrTooManyHeaders  = &LimitError{Status: http.StatusBadRequest, Code: "too_many_headers"}
	ErrHeadersTooLarge = &LimitError{Status: http.StatusBadRequest, Code: "headers_too_large"}
	ErrTooManyCookies  = &LimitError{Status: http.StatusBadRequest, Code: "too_many_cookies"}
	// Body limits (D41, contracts/body-limits.md). They act in every mode and
	// write no incident. ErrBodyShare is a client over its share, ErrBodyShareBusy
	// the same on a shared address, which never gets a 429 (D29).
	ErrBodyShare     = &LimitError{Status: http.StatusTooManyRequests, Code: bodylimit.CodeClientShare}
	ErrBodyShareBusy = &LimitError{Status: http.StatusServiceUnavailable, Code: bodylimit.CodeClientShare}
	ErrBodyBusy      = &LimitError{Status: http.StatusServiceUnavailable, Code: bodylimit.CodeBusy}
	// ErrBodyWaitShare: a client or network holds its share of memory in bodies
	// waiting for the backend (D44), ErrBodyWaitShareBusy the same on a shared
	// address.
	ErrBodyWaitShare     = &LimitError{Status: http.StatusTooManyRequests, Code: bodylimit.CodeWaitingShare}
	ErrBodyWaitShareBusy = &LimitError{Status: http.StatusServiceUnavailable, Code: bodylimit.CodeWaitingShare}
	// ErrRequestShare: a client or network holds its share of the requests
	// waiting for the backend (D45), ErrRequestShareBusy the same on a shared
	// address, ErrRequestBusy the whole gateway. No incident, in every mode.
	ErrRequestShare     = &LimitError{Status: http.StatusTooManyRequests, Code: bodylimit.CodeRequestShare}
	ErrRequestShareBusy = &LimitError{Status: http.StatusServiceUnavailable, Code: bodylimit.CodeRequestShare}
	ErrRequestBusy      = &LimitError{Status: http.StatusServiceUnavailable, Code: bodylimit.CodeRequestBusy}
	// ErrClientGone: the client left, or stalled until a read timeout of the
	// server, while its body was read (D45). The status is what the request is
	// recorded with; a client that only stalled gets to read it.
	ErrClientGone = &LimitError{Status: http.StatusBadRequest, Code: bodylimit.CodeClientGone}
)

// LimitError is a hard limit violation with its HTTP status.
type LimitError struct {
	Status int
	Code   string
}

func (e *LimitError) Error() string { return "waf: " + e.Code }

// Limits are the hard parse limits.
type Limits struct {
	Body int64
	// Raw bounds a body of no known text or multipart type (D41), at most Body.
	Raw       int64
	Args      int
	JSONDepth int
	// QueryBytes bounds the raw query string, TargetBytes the request target
	// (path and query), Headers the number of header values, HeaderBytes
	// their total size (names and values, Host included) and Cookies the
	// number of cookies (each one is an argument for the CRS).
	QueryBytes  int
	TargetBytes int
	Headers     int
	HeaderBytes int
	Cookies     int
}

// DefaultLimits mirror schild.yaml defaults (Body) and schild's fixed hard
// limits. Args 1000 is PHP's default max_input_vars, so a Laravel or
// WordPress backend never sees more anyway. The query, header and cookie
// limits are far above what browsers, Laravel, WordPress and Livewire send
// (nginx and Apache refuse request lines over 8 KiB by default; browsers send
// 10-20 headers in a few KiB), so they only stop requests built to be
// expensive. The request target may hold the whole query plus 8 KiB of path.
var DefaultLimits = Limits{Body: 13107200, Raw: bodylimit.DefaultRawLimitBytes, Args: 1000, JSONDepth: 64, QueryBytes: 32 << 10, TargetBytes: 40 << 10,
	Headers: 100, HeaderBytes: 64 << 10, Cookies: 150}

func (l Limits) norm() Limits {
	if l.Body <= 0 {
		l.Body = DefaultLimits.Body
	}
	if l.Raw <= 0 {
		l.Raw = DefaultLimits.Raw
	}
	if l.Args <= 0 {
		l.Args = DefaultLimits.Args
	}
	if l.JSONDepth <= 0 {
		l.JSONDepth = DefaultLimits.JSONDepth
	}
	if l.QueryBytes <= 0 {
		l.QueryBytes = DefaultLimits.QueryBytes
	}
	if l.TargetBytes <= 0 {
		l.TargetBytes = DefaultLimits.TargetBytes
	}
	if l.Headers <= 0 {
		l.Headers = DefaultLimits.Headers
	}
	if l.HeaderBytes <= 0 {
		l.HeaderBytes = DefaultLimits.HeaderBytes
	}
	if l.Cookies <= 0 {
		l.Cookies = DefaultLimits.Cookies
	}
	return l
}

// Precheck runs the cheap checks before any rule: declared body size,
// compressed request bodies (cannot be inspected) and the request shape.
func Precheck(r *http.Request, lim Limits) error {
	lim = lim.norm()
	if err := sizeError(BodyClass(r), r.ContentLength, lim); err != nil {
		return err
	}
	if HasBody(r) && encoded(r.Header.Values("Content-Encoding")) {
		return ErrBodyEncoding
	}
	q := r.URL.RawQuery
	if len(q) > lim.QueryBytes {
		return ErrQueryTooLong
	}
	if q != "" && QueryArgs(q) > lim.Args {
		return ErrTooManyArgs
	}
	if TargetBytes(r) > lim.TargetBytes {
		return ErrTargetTooLong
	}
	// net/http keeps Host out of r.Header; the rules read it as a header.
	n, size := 0, len("Host")+len(r.Host)
	for k, vs := range r.Header {
		n += len(vs)
		for _, v := range vs {
			size += len(k) + len(v)
		}
	}
	if n > lim.Headers {
		return ErrTooManyHeaders
	}
	if size > lim.HeaderBytes {
		return ErrHeadersTooLarge
	}
	if CookieCount(r) > lim.Cookies {
		return ErrTooManyCookies
	}
	return nil
}

// TargetBytes is the length of the request target as the client sent it
// (path and query).
func TargetBytes(r *http.Request) int {
	if r.RequestURI != "" {
		return len(r.RequestURI)
	}
	return len(r.URL.RequestURI())
}

// encoded reports whether any Content-Encoding value names a coding other than
// identity. Every header line and every listed coding counts: a backend that
// decodes "identity" followed by "gzip" would see a body the rules never read.
func encoded(values []string) bool {
	for _, v := range values {
		for _, c := range strings.Split(v, ",") {
			if c = strings.TrimSpace(strings.ToLower(c)); c != "" && c != "identity" {
				return true
			}
		}
	}
	return false
}

// QueryArgs counts the arguments of a raw query string as Coraza splits them.
func QueryArgs(q string) int {
	if q == "" {
		return 0
	}
	return strings.Count(q, "&") + 1
}

// CookieCount counts the cookies of all Cookie headers.
func CookieCount(r *http.Request) int {
	n := 0
	for _, v := range r.Header.Values("Cookie") {
		if strings.TrimSpace(v) != "" {
			n += strings.Count(v, ";") + 1
		}
	}
	return n
}

// sizeError applies the size limits to n bytes of a body of class.
func sizeError(class string, n int64, lim Limits) error {
	switch bodylimit.CheckSize(class, n, lim.Raw, lim.Body) {
	case bodylimit.CodeTooLarge:
		return ErrBodyTooLarge
	case bodylimit.CodeRawTooLarge:
		return ErrRawTooLarge
	}
	return nil
}

// BodyClass is the class of a request's body, from every Content-Type value.
func BodyClass(r *http.Request) string {
	return bodylimit.ClassifyValues(r.Header.Values("Content-Type"))
}

// corazaMultipart reports whether Coraza picks its multipart parser for this
// Content-Type value, in its own words (Transaction.AddRequestHeader). It is
// wider than the class: a longer subtype is parsed there and raw here.
func corazaMultipart(contentType string) bool {
	return strings.HasPrefix(strings.TrimSpace(strings.ToLower(contentType)), bodylimit.MultipartForm)
}

// HasBody reports whether a request has a body: its declared length is above
// 0 or unknown (chunked, HTTP/2 and HTTP/3 without a length).
func HasBody(r *http.Request) bool {
	return r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}

// ProcessHeaders feeds connection, URI and headers into tx and runs phase 1.
func ProcessHeaders(tx types.Transaction, r *http.Request, clientIP string, clientPort int) {
	_, sport := splitPort(r.Context().Value(http.LocalAddrContextKey))
	tx.ProcessConnection(clientIP, clientPort, "", sport)
	uri := r.RequestURI
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	// Coraza cuts the URI at the first '#' as a fragment, but net/http keeps a
	// raw '#' in the request target as part of the path or query, and the proxy
	// forwards everything after it (escaped in the path). Unescaped,
	// "/a#?id=1'--" would reach the backend with id while no rule saw an
	// argument; only CRS 920610 (5 points) noticed the '#'. Escaped, the rules
	// see the path and arguments the backend gets.
	uri = strings.ReplaceAll(uri, "#", "%23")
	tx.ProcessURI(uri, r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		tx.SetServerName(host)
	}
	if len(r.TransferEncoding) > 0 {
		tx.AddRequestHeader("Transfer-Encoding", r.TransferEncoding[0])
	} else if r.Header.Get("Content-Length") == "" && r.ContentLength > 0 {
		// net/http keeps the length in r.ContentLength; CRS 920180 needs the header.
		tx.AddRequestHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	tx.ProcessRequestHeaders()
}

func splitPort(v any) (string, int) {
	a, ok := v.(net.Addr)
	if !ok || a == nil {
		return "", 0
	}
	h, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return "", 0
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

type limitedReader struct {
	r     io.Reader
	left  int64
	over  bool
	front bool // a body limit in front of schild ended the body, not this one
	total int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left < 0 {
		l.over = true
		return 0, ErrBodyTooLarge
	}
	if int64(len(p)) > l.left+1 {
		p = p[:l.left+1]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	l.total += int64(n)
	if l.left < 0 {
		l.over = true
		return n, ErrBodyTooLarge
	}
	var mbe *http.MaxBytesError
	if err != nil && errors.As(err, &mbe) {
		// A body limit in front of schild (Caddy's request_body max_size
		// wraps the body in http.MaxBytesReader): 413 as in stock Caddy,
		// not a read error (MVP-19 measurement 3, finding 4).
		l.over, l.front = true, true
		return n, ErrBodyTooLarge
	}
	return n, err
}

// ReadBody buffers the request body into tx (Coraza keeps up to 128 KiB in
// memory and spills the rest to a temporary file), enforces the hard size
// limit and the structural parse limits, and returns a reader with the
// complete body for the backend. It never runs phase 2.
func ReadBody(tx types.Transaction, r *http.Request, lim Limits) (io.Reader, int64, error) {
	rd, info, err := ReadBodyInfo(tx, r, lim)
	return rd, info.Bytes, err
}

// BodyInfo describes a buffered request body for the cost estimate.
type BodyInfo struct {
	Bytes int64
	// Args: urlencoded arguments, JSON keys and values, multipart parts.
	Args int
	// Files: a body of the class multipart (file content is cheap to inspect;
	// the CRS looks at names and headers of the parts, not at the content). Any
	// other body is text for the rules, whatever its header says (D44).
	Files bool
	// Text: the bytes of a multipart body the rules read as text, its parts
	// without a file name.
	Text int64
}

// ReadBodyInfo is ReadBody that also reports the body's shape.
func ReadBodyInfo(tx types.Transaction, r *http.Request, lim Limits) (io.Reader, BodyInfo, error) {
	lim = lim.norm()
	if !HasBody(r) {
		return nil, BodyInfo{}, nil
	}
	ct := r.Header.Get("Content-Type")
	class := BodyClass(r)
	if tx.IsRuleEngineOff() || !tx.IsRequestBodyAccessible() {
		// Coraza would buffer nothing and the backend would get an empty
		// body. Build refuses the operator rules that lead here
		// (checkEngineSettings); this is the net behind it.
		return nil, BodyInfo{}, ErrBodyBusy
	}
	lr := &limitedReader{r: r.Body, left: bodylimit.LimitOf(class, lim.Raw, lim.Body)}
	_, _, err := tx.ReadRequestBodyFrom(lr)
	info := BodyInfo{Bytes: lr.total}
	if lr.over {
		if serr := sizeError(class, lr.total, lim); serr != nil && !lr.front {
			return nil, info, serr
		}
		return nil, info, ErrBodyTooLarge
	}
	if err != nil {
		if errors.Is(err, syscall.ENOSPC) {
			return nil, info, ErrBodyBusy // our disk, not the client's fault
		}
		return nil, info, ErrBodyRead
	}
	info.Args, err = checkStructureValues(tx, r.Header.Values("Content-Type"), lim)
	if err != nil {
		return nil, info, err
	}
	info.Files = class == bodylimit.BodyMultipart
	if info.Files {
		rd, err := tx.RequestBodyReader()
		if err != nil {
			return nil, info, ErrBodyRead
		}
		info.Text = multipartText(ct, rd, info.Bytes)
	}
	fwd, err := tx.RequestBodyReader()
	if err != nil {
		return nil, info, ErrBodyRead
	}
	return fwd, info, nil
}

// multipartText counts the bytes of the parts Coraza hands to the rules as
// arguments, not as files. A part counts as a file only when mime/multipart
// finds a file name, and a body it cannot read to the end counts as text
// whole: an estimate that is too high costs the sender a heavy slot, one that
// is too low costs everybody else a reserved slot.
func multipartText(contentType string, body io.Reader, total int64) int64 {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return total
	}
	mr := multipart.NewReader(body, params["boundary"])
	var text int64
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return text
		}
		if err != nil {
			return total
		}
		n, err := io.Copy(io.Discard, p)
		if err != nil {
			return total
		}
		if p.FileName() == "" {
			text += n
		}
	}
}

// checkStructureValues checks the body against every Content-Type header that
// can select a structured parser in Coraza or a backend. Coraza's phase 1 rules
// (200001, 200006) match every Content-Type value, so inspecting only the first
// header would let a second "Content-Type: application/json" header bypass the
// JSON depth and strict syntax check. Multipart is checked on the first header
// only, matching Coraza's AddRequestHeader selection.
func checkStructureValues(tx types.Transaction, values []string, lim Limits) (int, error) {
	var checkedForm, checkedJSON bool
	maxArgs := 0
	run := func(ct string) error {
		rd, err := tx.RequestBodyReader()
		if err != nil {
			return ErrBodyRead
		}
		n, err := checkStructure(ct, rd, lim)
		if err != nil {
			return err
		}
		if n > maxArgs {
			maxArgs = n
		}
		return nil
	}
	for i, v := range values {
		mt, _, _ := mime.ParseMediaType(v)
		switch {
		case mt == "application/x-www-form-urlencoded":
			if checkedForm {
				continue
			}
			checkedForm = true
			if err := run(v); err != nil {
				return maxArgs, err
			}
		case isJSONMediaType(mt, v):
			if checkedJSON {
				continue
			}
			checkedJSON = true
			if err := run(v); err != nil {
				return maxArgs, err
			}
		case i == 0 && corazaMultipart(v):
			if err := run(v); err != nil {
				return maxArgs, err
			}
		}
	}
	return maxArgs, nil
}

func isJSONMediaType(mt, raw string) bool {
	if mt == "application/json" || strings.HasSuffix(mt, "+json") {
		return true
	}
	low := strings.TrimSpace(strings.ToLower(raw))
	return strings.HasPrefix(low, "application/json")
}

// checkStructure counts arguments, JSON depth and multipart parts without
// parsing values, so that Coraza never silently drops arguments beyond
// SecArgumentsLimit (a classic bypass). It returns the number of arguments
// (urlencoded arguments, JSON keys and values, multipart parts).
func checkStructure(contentType string, body io.Reader, lim Limits) (int, error) {
	mt, params, _ := mime.ParseMediaType(contentType)
	br := bufio.NewReaderSize(body, 32<<10)
	switch {
	case mt == "application/x-www-form-urlencoded":
		n := 1
		for {
			b, err := br.ReadByte()
			if err != nil {
				break
			}
			if b == '&' {
				n++
				if n > lim.Args {
					return n, ErrTooManyArgs
				}
			}
		}
		return n, nil
	case isJSONMediaType(mt, contentType):
		return scanJSON(br, lim)
	case corazaMultipart(contentType):
		// A value Go cannot parse has no parameters. Coraza fails on it too, but
		// only in phase 2.
		boundary := params["boundary"]
		if boundary == "" {
			return 0, ErrBodyUnparseable
		}
		delim := []byte("--" + boundary)
		count := 0
		var carry []byte
		buf := make([]byte, 32<<10)
		for {
			n, err := br.Read(buf)
			if n > 0 {
				data := make([]byte, 0, len(carry)+n)
				data = append(append(data, carry...), buf[:n]...)
				count += bytes.Count(data, delim)
				// a delimiter cannot fit completely into the carry, so it is never counted twice
				k := len(delim) - 1
				if k > len(data) {
					k = len(data)
				}
				carry = append(carry[:0], data[len(data)-k:]...)
			}
			if err != nil {
				break
			}
		}
		if count-1 > lim.Args {
			return count - 1, ErrMultipartParts
		}
		return max(count-1, 0), nil
	}
	return 0, nil
}

// scanJSON checks depth, value count and syntax with a streaming decoder.
// Coraza's JSON processor (gjson) accepts broken JSON silently, which would
// let the WAF and the backend see different arguments.
func scanJSON(br *bufio.Reader, lim Limits) (int, error) {
	dec := json.NewDecoder(br)
	dec.UseNumber()
	depth, values := 0, 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if values == 0 || depth != 0 {
				return values, ErrBodyUnparseable
			}
			return values, nil
		}
		if err != nil {
			return values, ErrBodyUnparseable
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if depth == 0 && values > 0 {
					return values, ErrBodyUnparseable // second top-level value
				}
				depth++
				if depth > lim.JSONDepth {
					return values, ErrJSONTooDeep
				}
				values++
			default:
				depth--
			}
		default:
			if depth == 0 && values > 0 {
				return values, ErrBodyUnparseable
			}
			values++
			if values > lim.Args*2 { // keys and values
				return values, ErrTooManyArgs
			}
		}
	}
}

// IsLimit reports whether err is a hard limit violation.
func IsLimit(err error) (*LimitError, bool) {
	var le *LimitError
	if errors.As(err, &le) {
		return le, true
	}
	return nil, false
}
