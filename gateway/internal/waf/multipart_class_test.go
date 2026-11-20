package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/deutschland-schild/schild/contract/bodylimit"
)

const multipartRule = 1001

var (
	parserOnce sync.Once
	parserInst *Instance
	parserErr  error
)

// parserProbe is the CRS with a rule that tells which parser Coraza really took,
// and a rule that sees the text of a parsed field.
func parserProbe(t *testing.T) *Instance {
	t.Helper()
	parserOnce.Do(func() {
		parserInst, parserErr = Build(Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5, BodyLimit: 8 << 20,
			LocalRules: `SecRule REQBODY_PROCESSOR "@streq MULTIPART" "id:1001,phase:2,pass,log,msg:'multipart parser'"`})
	})
	if parserErr != nil {
		t.Fatal(parserErr)
	}
	return parserInst
}

func parseRequest(values []string, body string) *http.Request {
	r := httptest.NewRequest("POST", "/upload", strings.NewReader(body))
	r.Header.Del("Content-Type")
	for _, v := range values {
		r.Header.Add("Content-Type", v)
	}
	return r
}

// corazaVerdict runs Coraza alone, without the checks of the gate.
func corazaVerdict(t *testing.T, inst *Instance, values []string, body string) (multipartParser, refused bool) {
	t.Helper()
	tx, _ := inst.NewTransaction()
	defer tx.Close()
	r := parseRequest(values, body)
	ProcessHeaders(tx, r, "192.0.2.1", 40000)
	if _, _, err := tx.ReadRequestBodyFrom(r.Body); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	a := inst.Analyze(tx.MatchedRules())
	for _, m := range a.Matches {
		multipartParser = multipartParser || m.ID == multipartRule
	}
	return multipartParser, a.BodyError
}

// The class and the file estimate follow what Coraza really does (D44). Coraza
// is the oracle here: when an upgrade changes its choice of parser, this fails.
func TestMultipartClassFollowsCoraza(t *testing.T) {
	const file = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nhello\r\n--b--\r\n"
	const noBoundary = "multipart/form-data"
	cases := []struct {
		name    string
		values  []string
		class   string
		files   bool  // counts as a cheap file
		gateErr error // answer of the gate before phase 2
		coraza  bool  // Coraza takes its multipart parser
		refused bool  // Coraza alone refuses the body
	}{
		{"plain", []string{"multipart/form-data; boundary=b"}, bodylimit.BodyMultipart, true, nil, true, false},
		{"upper case", []string{"MULTIPART/FORM-DATA; boundary=b"}, bodylimit.BodyMultipart, true, nil, true, false},
		{"mixed case", []string{"Multipart/Form-Data; BOUNDARY=b"}, bodylimit.BodyMultipart, true, nil, true, false},
		{"no space", []string{"multipart/form-data;boundary=b"}, bodylimit.BodyMultipart, true, nil, true, false},
		{"space before semicolon", []string{"multipart/form-data ; boundary=b"}, bodylimit.BodyMultipart, true, nil, true, false},
		{"leading space", []string{"  multipart/form-data; boundary=b"}, bodylimit.BodyMultipart, true, nil, true, false},
		{"leading tab", []string{"\tmultipart/form-data; boundary=b"}, bodylimit.BodyMultipart, true, nil, true, false},
		{"unicode space", []string{" multipart/form-data; boundary=b"}, bodylimit.BodyMultipart, true, nil, true, false},
		{"dotted capital i", []string{"MULTİPART/FORM-DATA; boundary=b"}, bodylimit.BodyMultipart, true, nil, true, false},
		{"quoted boundary", []string{`multipart/form-data; boundary="b"`}, bodylimit.BodyMultipart, true, nil, true, false},
		{"extra parameter", []string{"multipart/form-data; charset=utf-8; boundary=b"}, bodylimit.BodyMultipart, true, nil, true, false},
		{"trailing semicolon", []string{"multipart/form-data; boundary=b;"}, bodylimit.BodyMultipart, true, nil, true, false},

		{"mixed", []string{"multipart/mixed; boundary=b"}, bodylimit.BodyRaw, false, nil, false, false},
		{"related", []string{"multipart/related; boundary=b"}, bodylimit.BodyRaw, false, nil, false, false},
		{"alternative", []string{"multipart/alternative; boundary=b"}, bodylimit.BodyRaw, false, nil, false, false},
		{"byteranges", []string{"multipart/byteranges; boundary=b"}, bodylimit.BodyRaw, false, nil, false, false},
		// Raw limit, and the JSON check every +json type gets.
		{"suffix", []string{"multipart/x+json; boundary=b"}, bodylimit.BodyRaw, false, ErrBodyUnparseable, false, false},
		{"mixed without boundary", []string{"multipart/mixed"}, bodylimit.BodyRaw, false, nil, false, false},
		{"no slash", []string{"multipartform-data; boundary=b"}, bodylimit.BodyRaw, false, nil, false, false},

		// Coraza's test is a prefix: its parser runs, the class stays raw and the
		// whole body counts as text, stricter than Coraza.
		{"longer subtype", []string{"multipart/form-data-x; boundary=b"}, bodylimit.BodyRaw, false, nil, true, false},

		// Both sides refuse these, the gate before phase 2.
		{"no boundary", []string{noBoundary}, bodylimit.BodyMultipart, false, ErrBodyUnparseable, true, true},
		{"empty boundary", []string{`multipart/form-data; boundary=""`}, bodylimit.BodyMultipart, false, ErrBodyUnparseable, true, true},
		{"boundary without value", []string{"multipart/form-data; boundary"}, bodylimit.BodyMultipart, false, ErrBodyUnparseable, true, true},
		{"boundary twice", []string{"multipart/form-data; boundary=b; boundary=c"}, bodylimit.BodyMultipart, false, ErrBodyUnparseable, true, true},
		{"comma", []string{"multipart/form-data, text/plain; boundary=b"}, bodylimit.BodyRaw, false, ErrBodyUnparseable, true, true},

		// A header sent twice names no parser.
		{"twice, form first", []string{"multipart/form-data; boundary=b", "text/plain"}, bodylimit.BodyRaw, false, nil, true, false},
		{"twice, form second", []string{"text/plain", "multipart/form-data; boundary=b"}, bodylimit.BodyRaw, false, nil, false, false},
		{"twice, equal", []string{"multipart/form-data; boundary=b", "multipart/form-data; boundary=b"}, bodylimit.BodyRaw, false, nil, true, false},
	}
	inst := parserProbe(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := parseRequest(c.values, file)
			if got := BodyClass(r); got != c.class {
				t.Fatalf("class %s, want %s", got, c.class)
			}
			parser, refused := corazaVerdict(t, inst, c.values, file)
			if parser != c.coraza || refused != c.refused {
				t.Fatalf("Coraza: multipart parser %v, refused %v; want %v, %v", parser, refused, c.coraza, c.refused)
			}
			if c.class == bodylimit.BodyMultipart && c.gateErr == nil && (!parser || refused) {
				t.Fatal("the class promises a parser Coraza does not run")
			}
			tx, _ := inst.NewTransaction()
			defer tx.Close()
			ProcessHeaders(tx, r, "192.0.2.1", 40000)
			_, info, err := ReadBodyInfo(tx, r, Limits{Body: 1 << 20})
			if err != c.gateErr {
				t.Fatalf("gate: %v, want %v", err, c.gateErr)
			}
			if err == nil && info.Files != c.files {
				t.Fatalf("files %v", info.Files)
			}
		})
	}
}

// Only a real form counts as a file: the same bytes under any other type are
// text for the estimate and meet the raw limit, read or declared.
func TestOtherSubtypesFollowRawPath(t *testing.T) {
	body, _ := multipartBody(t, 0, 2<<10)
	const boundary = "; boundary="
	form := "multipart/form-data" + boundary + "x"
	other := "multipart/mixed" + boundary + "x"
	lim := Limits{Raw: 1 << 10, Body: 8 << 10}
	if err := Precheck(parseRequest([]string{other}, body), lim); err != ErrRawTooLarge {
		t.Fatalf("declared: %v", err)
	}
	if err := Precheck(parseRequest([]string{form}, body), lim); err != nil {
		t.Fatalf("form declared: %v", err)
	}
	inst := crs(t)
	tx, _ := inst.NewTransaction()
	defer tx.Close()
	if _, _, err := ReadBodyInfo(tx, unknownLength(other, body), lim); err != ErrRawTooLarge {
		t.Fatalf("streamed: %v", err)
	}
	tx2, _ := inst.NewTransaction()
	defer tx2.Close()
	_, info, err := ReadBodyInfo(tx2, parseRequest([]string{other}, body), Limits{Raw: 1 << 20, Body: 1 << 20})
	if err != nil || info.Files || info.Text != 0 || info.Bytes != int64(len(body)) {
		t.Fatalf("estimate: %v %+v", err, info)
	}
}

type failingBody struct{ err error }

func (f failingBody) Read([]byte) (int, error) { return 0, f.err }
func (f failingBody) Close() error             { return nil }

// A temp disk that fills up is not the client's fault: no 400, no incident.
func TestFullDiskIsBusy(t *testing.T) {
	inst := crs(t)
	tx, _ := inst.NewTransaction()
	defer tx.Close()
	r := unknownLength("text/plain", "")
	r.Body = failingBody{fmt.Errorf("write: %w", syscall.ENOSPC)}
	if _, _, err := ReadBodyInfo(tx, r, Limits{Body: 1 << 20}); err != ErrBodyBusy {
		t.Fatalf("%v", err)
	}
}
