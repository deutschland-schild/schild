// Package logcheck reads web server access logs and reports, per site, the
// requests that schild's hard limits would reject even in observe mode (D23):
// bodies above the body limit (413), compressed request bodies (415), more
// than 1000 query arguments (400), and very long single parameters or large
// urlencoded forms that risk the WAF evaluation timeout (503).
//
// Supported formats:
//
//	combined      nginx/Apache "combined" (no body size, no Content-Encoding)
//	combined-rl   combined followed by $request_length (nginx) or %I (Apache mod_logio)
//	nginx-json    the runbook's schild_check JSON (t, m, s, cl, rl, ce, ct, uri, rt)
//	apache-check  the runbook's Apache schild_check LogFormat
//	caddy         Caddy JSON access log (request.headers, bytes_read)
//	auto          per line: Caddy JSON, nginx JSON, combined, apache-check
//
// The 413, 415 and 400 decisions call the client's own waf.Precheck for
// the body limit, compressed bodies and the argument count. Not checked
// (yet): the raw body limit of non-form bodies (D41, raw_body_too_large)
// and the query length (query_too_long), which the gate rejects too.
// Arguments in request bodies, JSON depth and JSON validity are not visible
// in access logs.
package logcheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Formats accepted by Parse.
var Formats = []string{"auto", "combined", "combined-rl", "nginx-json", "apache-check", "caddy"}

// Record is one parsed access log line. Sizes are -1 when the log does not
// carry them.
type Record struct {
	Time            time.Time
	IP              string
	Method          string
	Host            string
	URI             string // path and query as requested
	Status          int
	ContentLength   int64 // Content-Length request header, -1 unknown
	BodyBytes       int64 // request body bytes actually read (Caddy bytes_read), -1 unknown
	RequestLength   int64 // request line + headers + body (nginx $request_length, Apache %I), -1 unknown
	ContentEncoding string
	EncodingKnown   bool // the log carries the Content-Encoding request header
	ContentType     string
	Format          string // format that parsed the line
}

// ErrSkip marks lines that are not access log records (blank, comments).
var ErrSkip = errors.New("logcheck: not a record")

var (
	quoted    = `"((?:[^"\\]|\\.)*)"`
	combinedR = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] ` + quoted + ` (\d{3}) (\S+)(?: ` + quoted + ` ` + quoted + `)?(.*)$`)
	apacheChk = regexp.MustCompile(`^(\S+) (\S+) (\d{3}) (\S+) (\S+) ` + quoted + ` ` + quoted + ` ` + quoted + `(?: (\S+))?\s*$`)
)

// Parse parses one line in the given format ("auto" detects per line).
func Parse(line, format string) (Record, error) {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
		return Record{}, ErrSkip
	}
	switch format {
	case "", "auto":
		if strings.HasPrefix(strings.TrimSpace(line), "{") {
			var probe map[string]json.RawMessage
			if err := json.Unmarshal([]byte(line), &probe); err != nil {
				return Record{}, fmt.Errorf("json: %w", err)
			}
			if _, ok := probe["request"]; ok {
				return parseCaddy(line)
			}
			return parseNginxJSON(line)
		}
		if r, err := parseCombined(line, false); err == nil {
			return r, nil
		}
		return parseApacheCheck(line)
	case "combined":
		return parseCombined(line, false)
	case "combined-rl", "nginx-rl", "apache-logio":
		return parseCombined(line, true)
	case "nginx-json":
		return parseNginxJSON(line)
	case "apache-check":
		return parseApacheCheck(line)
	case "caddy", "caddy-json":
		return parseCaddy(line)
	}
	return Record{}, fmt.Errorf("unknown format %q (one of %s)", format, strings.Join(Formats, ", "))
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'x':
				if i+2 < len(s) {
					if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
						b.WriteByte(byte(v))
						i += 2
						continue
					}
				}
				b.WriteByte('x')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func splitRequestLine(rl string) (method, uri string) {
	parts := strings.Fields(rl)
	switch len(parts) {
	case 0:
		return "", ""
	case 1:
		return "", parts[0]
	}
	return parts[0], parts[1]
}

func parseCombined(line string, withRL bool) (Record, error) {
	m := combinedR.FindStringSubmatch(line)
	if m == nil {
		return Record{}, errors.New("not a combined log line")
	}
	r := Record{IP: m[1], ContentLength: -1, BodyBytes: -1, RequestLength: -1, Format: "combined"}
	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2]); err == nil {
		r.Time = t.UTC()
	}
	r.Method, r.URI = splitRequestLine(unescape(m[3]))
	r.Status, _ = strconv.Atoi(m[4])
	if withRL {
		r.Format = "combined-rl"
		rest := strings.Fields(m[8])
		if len(rest) == 0 {
			return Record{}, errors.New("combined-rl: request length missing after the user agent")
		}
		n, err := strconv.ParseInt(strings.Trim(rest[0], `"`), 10, 64)
		if err != nil || n < 0 {
			return Record{}, fmt.Errorf("combined-rl: request length %q is not a number", rest[0])
		}
		r.RequestLength = n
	}
	return r, nil
}

func parseApacheCheck(line string) (Record, error) {
	m := apacheChk.FindStringSubmatch(line)
	if m == nil {
		return Record{}, errors.New("not a combined, JSON or apache-check log line")
	}
	r := Record{ContentLength: -1, BodyBytes: -1, RequestLength: -1, Format: "apache-check", EncodingKnown: true}
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, m[1]); err == nil {
			r.Time = t.UTC()
			break
		}
	}
	r.Method = m[2]
	r.Status, _ = strconv.Atoi(m[3])
	r.ContentLength = num(m[4])
	r.RequestLength = num(m[5])
	r.ContentEncoding = unescape(m[6])
	if r.ContentEncoding == "-" {
		r.ContentEncoding = ""
	}
	r.ContentType = unescape(m[7])
	if r.ContentType == "-" {
		r.ContentType = ""
	}
	r.URI = unescape(m[8])
	return r, nil
}

func num(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return -1
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// anyNum reads a JSON value that may be a number or a numeric string.
func anyNum(v any) int64 {
	switch x := v.(type) {
	case float64:
		if x < 0 {
			return -1
		}
		return int64(x)
	case string:
		return num(x)
	case json.Number:
		return num(x.String())
	}
	return -1
}

func anyStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func first(m map[string]any, keys ...string) (any, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v, true
		}
	}
	return nil, false
}

func parseTimeAny(v any) time.Time {
	switch x := v.(type) {
	case float64:
		sec := int64(x)
		return time.Unix(sec, int64((x-float64(sec))*1e9)).UTC()
	case string:
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "02/Jan/2006:15:04:05 -0700"} {
			if t, err := time.Parse(layout, x); err == nil {
				return t.UTC()
			}
		}
		if f, err := strconv.ParseFloat(x, 64); err == nil {
			return parseTimeAny(f)
		}
	}
	return time.Time{}
}

func parseNginxJSON(line string) (Record, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return Record{}, fmt.Errorf("nginx-json: %w", err)
	}
	r := Record{ContentLength: -1, BodyBytes: -1, RequestLength: -1, Format: "nginx-json"}
	if v, ok := first(m, "t", "time", "time_iso8601", "time_local"); ok {
		r.Time = parseTimeAny(v)
	}
	if v, ok := first(m, "m", "method", "request_method"); ok {
		r.Method = anyStr(v)
	}
	if v, ok := first(m, "s", "status"); ok {
		// A status is three digits; anything else is no status (and never
		// overflows an int on a 32-bit build).
		if n := anyNum(v); n >= 0 && n <= 999 {
			r.Status = int(n)
		}
	}
	if v, ok := first(m, "cl", "content_length"); ok {
		r.ContentLength = anyNum(v)
	}
	if v, ok := first(m, "rl", "request_length"); ok {
		r.RequestLength = anyNum(v)
	}
	if v, ok := first(m, "ce", "http_content_encoding", "content_encoding"); ok {
		r.ContentEncoding, r.EncodingKnown = anyStr(v), true
		if r.ContentEncoding == "-" {
			r.ContentEncoding = ""
		}
	}
	if v, ok := first(m, "ct", "content_type"); ok {
		r.ContentType = anyStr(v)
	}
	if v, ok := first(m, "uri", "request_uri"); ok {
		r.URI = anyStr(v)
	} else if v, ok := first(m, "request"); ok {
		r.Method, r.URI = splitRequestLine(anyStr(v))
	}
	if v, ok := first(m, "host", "h", "server_name"); ok {
		r.Host = anyStr(v)
	}
	if v, ok := first(m, "ip", "remote_addr", "client_ip"); ok {
		r.IP = anyStr(v)
	}
	if r.Method == "" && r.URI == "" {
		return Record{}, errors.New("nginx-json: neither method nor uri present")
	}
	return r, nil
}

type caddyLine struct {
	TS        any   `json:"ts"`
	Status    int   `json:"status"`
	BytesRead int64 `json:"bytes_read"`
	Request   *struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Method   string              `json:"method"`
		Host     string              `json:"host"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
}

func header(h map[string][]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return strings.Join(v, ", "), true
		}
	}
	return "", false
}

func parseCaddy(line string) (Record, error) {
	var c caddyLine
	if err := json.Unmarshal([]byte(line), &c); err != nil {
		return Record{}, fmt.Errorf("caddy: %w", err)
	}
	if c.Request == nil {
		return Record{}, errors.New("caddy: no request object")
	}
	r := Record{Time: parseTimeAny(c.TS), Method: c.Request.Method, Host: c.Request.Host, URI: c.Request.URI, Status: c.Status,
		ContentLength: -1, BodyBytes: c.BytesRead, RequestLength: -1, Format: "caddy"}
	r.IP = c.Request.ClientIP
	if r.IP == "" {
		r.IP = c.Request.RemoteIP
	}
	if c.Request.Headers != nil {
		if v, ok := header(c.Request.Headers, "Content-Length"); ok {
			r.ContentLength = num(v)
		}
		r.ContentEncoding, _ = header(c.Request.Headers, "Content-Encoding")
		r.EncodingKnown = true
		r.ContentType, _ = header(c.Request.Headers, "Content-Type")
	}
	return r, nil
}
