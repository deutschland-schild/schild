package waf

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/crs/v4"

	"github.com/deutschland-schild/schild/contract/seclang"
	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
)

var (
	crsOnce sync.Once
	crsInst *Instance
	crsErr  error
)

func crs(t testing.TB) *Instance {
	t.Helper()
	crsOnce.Do(func() { crsInst, crsErr = Build(Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5}) })
	if crsErr != nil {
		t.Fatal(crsErr)
	}
	return crsInst
}

func eval(t testing.TB, inst *Instance, r *http.Request) (*Analysis, error) {
	t.Helper()
	if err := Precheck(r, DefaultLimits); err != nil {
		return nil, err
	}
	tx := inst.WAF.NewTransaction()
	defer tx.Close()
	ProcessHeaders(tx, r, "203.0.113.7", 40000)
	if _, _, err := ReadBody(tx, r, DefaultLimits); err != nil {
		return nil, err
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		return nil, err
	}
	return inst.Analyze(tx.MatchedRules()), nil
}

func browserReq(method, target, ctype, body string) *http.Request {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	r.Host = "shop.example"
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	r.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	return r
}

var benign = []struct{ method, uri, ctype, body string }{
	{"GET", "/", "", ""},
	{"GET", "/index.php?page=2&q=test", "", ""},
	{"GET", "/blog/2026/10/hello-world/", "", ""},
	{"POST", "/wp-login.php", "application/x-www-form-urlencoded", "log=admin&pwd=correct+horse&wp-submit=Log+In"},
	{"POST", "/api/contact", "application/json", `{"name":"Max Mustermann","email":"max@example.org","text":"Hallo, wie geht es?"}`},
	{"GET", "/search?q=schild+waf", "", ""},
}

// The version the dashboard and the logs name is the CRS that is embedded.
// buildinfo cannot read it itself: schild-agent links buildinfo, not the rules.
func TestCRSVersionIsTheEmbeddedOne(t *testing.T) {
	if "v"+buildinfo.CRSVersion != coreruleset.Version {
		t.Fatalf("buildinfo.CRSVersion %s, embedded %s", buildinfo.CRSVersion, coreruleset.Version)
	}
}

func TestCRSLoadsAndScores(t *testing.T) {
	inst := crs(t)
	t.Logf("CRS build time %s", inst.BuildTime)
	for _, b := range benign {
		a, err := eval(t, inst, browserReq(b.method, b.uri, b.ctype, b.body))
		if err != nil {
			t.Fatal(err)
		}
		if a.CRSAnomaly != 0 || a.CRSBlock {
			t.Errorf("benign %s %s scored %d: %+v", b.method, b.uri, a.CRSAnomaly, a.Matches)
		}
	}
	a, err := eval(t, inst, browserReq("GET", "/?id=1%27%20OR%20%271%27%3D%271%27--", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !a.CRSBlock || a.Score < 40 || a.Category != "sqli" {
		t.Fatalf("sqli not detected: anomaly %d score %d cat %q %+v", a.CRSAnomaly, a.Score, a.Category, a.Matches)
	}
	a, _ = eval(t, inst, browserReq("POST", "/comment", "application/x-www-form-urlencoded", "c=%3Cscript%3Ealert(1)%3C%2Fscript%3E"))
	if !a.CRSBlock || a.Category != "xss" {
		t.Fatalf("xss not detected: %+v", a)
	}
	a, _ = eval(t, inst, browserReq("GET", "/download?file=../../../../etc/passwd", "", ""))
	if !a.CRSBlock {
		t.Fatalf("lfi not detected: %+v", a)
	}
	for _, m := range a.Matches {
		if m.Location != "" && !strings.HasPrefix(m.Location, "ARGS") && !strings.HasPrefix(m.Location, "REQUEST_") && !strings.HasPrefix(m.Location, "QUERY_STRING") {
			t.Errorf("unexpected location %q", m.Location)
		}
	}
}

func TestJSONBodyInspected(t *testing.T) {
	a, err := eval(t, crs(t), browserReq("POST", "/api/search", "application/json", `{"q":"1' UNION SELECT password FROM users--"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !a.CRSBlock {
		t.Fatalf("sqli in JSON not detected: %+v", a.Matches)
	}
	if _, err = eval(t, crs(t), browserReq("POST", "/api/search", "application/json", `{"q":`)); !errors.Is(err, ErrBodyUnparseable) {
		t.Fatalf("broken JSON must be rejected: %v", err)
	}
	if _, err = eval(t, crs(t), browserReq("POST", "/api/search", "application/json", `{"q":1}{"q":2}`)); !errors.Is(err, ErrBodyUnparseable) {
		t.Fatalf("two JSON documents must be rejected: %v", err)
	}
}

// TestCorazaConformance: every valid SecLang vector of the contract loads in
// Coraza and fires on none of the ordinary requests (seclang-subset.md). The
// gateway loads no network rules (D72); the vectors run as local rules with
// their ids moved out of the reserved range, which keeps the Coraza
// semantics the subset relies on pinned to the Coraza version shipped here.
func TestCorazaConformance(t *testing.T) {
	files, _ := filepath.Glob("../../../contracts/vectors/seclang/valid/*.json")
	if len(files) == 0 {
		t.Skip("contracts/vectors not present")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			InputRaw string `json:"input_raw"`
			Context  struct {
				MaxAction string `json:"max_action"`
			} `json:"context"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		if _, err := seclang.Validate(v.InputRaw, seclang.Options{MaxAction: v.Context.MaxAction}); err != nil {
			t.Fatalf("%s: contract validator rejects a valid vector: %v", f, err)
		}
		inst, err := Build(Config{LocalRules: asLocal(v.InputRaw)})
		if err != nil {
			t.Errorf("%s: Coraza rejects: %v", filepath.Base(f), err)
			continue
		}
		for _, r := range benign {
			req := browserReq(r.method, r.uri, r.ctype, r.body)
			req.Header.Set("Referer", "https://shop.example/")
			req.Header.Set("Cookie", "session=0123456789abcdef")
			a, err := eval(t, inst, req)
			if err != nil {
				t.Fatal(err)
			}
			if len(a.Matches) > 0 {
				t.Errorf("%s fires on ordinary request %s %s", filepath.Base(f), r.method, r.uri)
			}
		}
	}
	t.Logf("%d valid vectors checked", len(files))
}

// wrapErr wraps read errors like Caddy's request_body (caddyhttp.Error
// around the *http.MaxBytesError).
type wrapErr struct{ io.ReadCloser }

type wrappedErr struct{ err error }

func (e wrappedErr) Error() string { return "handler error: " + e.err.Error() }
func (e wrappedErr) Unwrap() error { return e.err }

func (w wrapErr) Read(p []byte) (int, error) {
	n, err := w.ReadCloser.Read(p)
	if err != nil && err != io.EOF { //nolint:errorlint // io.EOF is returned unwrapped
		err = wrappedErr{err}
	}
	return n, err
}

func TestHardLimits(t *testing.T) {
	inst, err := Build(Config{})
	if err != nil {
		t.Fatal(err)
	}
	lim := Limits{Body: 1024, Args: 10, JSONDepth: 8}
	cases := []struct {
		name string
		req  *http.Request
		want *LimitError
	}{
		{"declared too large", func() *http.Request {
			r := browserReq("POST", "/", "text/plain", strings.Repeat("a", 2000))
			return r
		}(), ErrBodyTooLarge},
		{"chunked too large", func() *http.Request {
			r := browserReq("POST", "/", "text/plain", strings.Repeat("a", 2000))
			r.ContentLength = -1
			return r
		}(), ErrBodyTooLarge},
		// Caddy's request_body max_size in front of schild: 413 as in stock
		// Caddy, never 400 body_read_error (MVP-19 measurement 3, finding 4).
		{"request_body max_size in front", func() *http.Request {
			r := browserReq("POST", "/", "text/plain", strings.Repeat("a", 600))
			r.ContentLength = -1
			r.Body = http.MaxBytesReader(nil, r.Body, 500)
			return r
		}(), ErrBodyTooLarge},
		{"request_body max_size wrapped", func() *http.Request {
			r := browserReq("POST", "/", "text/plain", strings.Repeat("a", 600))
			r.ContentLength = -1
			r.Body = wrapErr{http.MaxBytesReader(nil, r.Body, 500)}
			return r
		}(), ErrBodyTooLarge},
		{"gzip body", func() *http.Request {
			r := browserReq("POST", "/", "application/json", `{"a":1}`)
			r.Header.Set("Content-Encoding", "gzip")
			return r
		}(), ErrBodyEncoding},
		// Every header line counts, not only the first.
		{"gzip in a second header", func() *http.Request {
			r := browserReq("POST", "/", "application/json", `{"a":1}`)
			r.Header.Add("Content-Encoding", "identity")
			r.Header.Add("Content-Encoding", "gzip")
			return r
		}(), ErrBodyEncoding},
		{"gzip after identity in a list", func() *http.Request {
			r := browserReq("POST", "/", "application/json", `{"a":1}`)
			r.Header.Set("Content-Encoding", "identity, gzip")
			return r
		}(), ErrBodyEncoding},
		{"too many query args", browserReq("GET", "/?"+strings.Repeat("a=1&", 11)+"b=2", "", ""), ErrTooManyArgs},
		{"too many form args", browserReq("POST", "/", "application/x-www-form-urlencoded", strings.Repeat("a=1&", 11)+"b=2"), ErrTooManyArgs},
		{"json too deep", browserReq("POST", "/", "application/json", strings.Repeat("[", 9)+strings.Repeat("]", 9)), ErrJSONTooDeep},
		{"json too many values", browserReq("POST", "/", "application/json", "["+strings.Repeat("1,", 25)+"1]"), ErrTooManyArgs},
		{"multipart too many parts", func() *http.Request {
			var b strings.Builder
			for i := 0; i < 12; i++ {
				b.WriteString("--XyZ\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n")
			}
			b.WriteString("--XyZ--\r\n")
			return browserReq("POST", "/", "multipart/form-data; boundary=XyZ", b.String())
		}(), ErrMultipartParts},
	}
	for _, c := range cases {
		err := Precheck(c.req, lim)
		if err == nil {
			tx := inst.WAF.NewTransaction()
			_, _, err = ReadBody(tx, c.req, lim)
			tx.Close()
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	// Within limits: the body is forwarded completely.
	tx := inst.WAF.NewTransaction()
	defer tx.Close()
	body := strings.Repeat("x", 1000)
	rd, n, err := ReadBody(tx, browserReq("POST", "/", "text/plain", body), lim)
	if err != nil || n != 1000 {
		t.Fatal(err, n)
	}
	got, _ := io.ReadAll(rd)
	if string(got) != body {
		t.Fatal("body not forwarded intact")
	}
}

func TestLocalRuleKindsBlocking(t *testing.T) {
	ids := LocalRuleKinds("SecRule ARGS \"@rx x\" \"id:1001,phase:2,deny,status:403\"\nSecRule ARGS \"@rx y\" \\\n \"id:1002,phase:2,pass,log\"\n# SecRule id:1003\n")
	if !ids[1001].Blocking || ids[1002].Blocking || len(ids) != 2 {
		t.Fatalf("%v", ids)
	}
	if _, err := Build(Config{LocalRules: "SecRule ARGS \"@rx x\" \"id:7700005,phase:2,deny\""}); err == nil {
		t.Fatal("local rule in the network range must be refused")
	}
}

func BenchmarkCRSCleanGET(b *testing.B) {
	inst := crs(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = eval(b, inst, browserReq("GET", "/blog/2026/10/hello-world/?page=2", "", ""))
	}
}

func BenchmarkCRSFormPOST(b *testing.B) {
	inst := crs(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = eval(b, inst, browserReq("POST", "/wp-login.php", "application/x-www-form-urlencoded", "log=admin&pwd=correct+horse&wp-submit=Log+In"))
	}
}

func TestLocalRuleKinds(t *testing.T) {
	k := LocalRuleKinds(`SecRule ARGS "@rx x" "id:1001,phase:2,deny,status:403"
SecRule ARGS "@rx y" \
 "id:1002,phase:2,pass,log"
SecRule REQUEST_FILENAME "@streq /login" "id:1003,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:password"
SecRule REQUEST_HEADERS:Host "@streq a.example" "id:1004,phase:1,pass,t:none,chain"
  SecRule REQUEST_FILENAME "@streq /x" "t:none,ctl:ruleRemoveById=941100"
SecRule REMOTE_ADDR "@ipMatch 192.0.2.1" "id:1005,phase:1,allow,log"
SecAction "id:1006,phase:1,pass,nolog,setvar:tx.x=1"
SecRule ARGS "@rx z" "id:1007,phase:2,pass,log,chain"
  SecRule ARGS "@rx w" "t:none"
SecRule ARGS "@rx v" "id:1008,phase:2,pass,log"
SecRule ARGS "@rx q" "id:1009,phase:2,pass,nolog,t:none,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
SecRule ARGS "@rx q" "id:1010,phase:2,deny,nolog,status:403"
SecRule REQUEST_FILENAME "@beginsWith /wp-admin" "id:1011,phase:1,pass,nolog,setvar:tx.crs_exclusions_wordpress=1"
SecRule ARGS "@rx q" "id:1012,phase:2,pass,nolog"
`)
	want := map[int]LocalRuleKind{
		1001: {Blocking: true}, 1002: {}, 1003: {Exception: true}, 1004: {Exception: true},
		1005: {Exception: true}, 1006: {Exception: true}, 1007: {}, 1008: {},
		// MVP-19 re-measurement: nolog does not make a detection an exception.
		1009: {}, 1010: {Blocking: true}, 1011: {Exception: true}, 1012: {},
	}
	if len(k) != len(want) {
		t.Fatalf("got %d rules: %+v", len(k), k)
	}
	for id, w := range want {
		if k[id] != w {
			t.Errorf("%d: %+v, want %+v", id, k[id], w)
		}
	}
}
