package waf

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/bodylimit"
)

// unknownLength is a request whose body has no declared length, as chunked
// HTTP/1.1 and HTTP/2 without a length.
func unknownLength(ctype, body string) *http.Request {
	r := httptest.NewRequest("POST", "/upload", strings.NewReader(body))
	r.Header.Set("Content-Type", ctype)
	r.ContentLength = -1
	return r
}

// A body over the limit without a declared length is refused before any rule
// reads it: Coraza must never run phase 2 on the partial body by itself.
func TestOverLimitBodyNeverReachesTheRules(t *testing.T) {
	const limit = 256 << 10 // Coraza wants at least its memory limit
	inst, err := Build(Config{BodyLimit: limit, LocalRules: `SecRule REQUEST_BODY "@contains needle" "id:1001,phase:2,pass,log,msg:'seen'"`})
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{limit + 1, limit + 2, limit + 3, 3 * limit} {
		tx, _ := inst.NewTransaction()
		r := unknownLength("application/x-www-form-urlencoded", "a=needle"+strings.Repeat("x", size-8))
		ProcessHeaders(tx, r, "192.0.2.1", 40000)
		_, _, err := ReadBodyInfo(tx, r, Limits{Body: limit})
		if err != ErrBodyTooLarge {
			t.Fatalf("size %d: %v", size, err)
		}
		if m := tx.MatchedRules(); len(m) != 0 {
			t.Fatalf("size %d: %d rules ran on a refused body", size, len(m))
		}
		_ = tx.Close()
	}
	tx, _ := inst.NewTransaction()
	defer tx.Close()
	r := unknownLength("application/x-www-form-urlencoded", "a=needle"+strings.Repeat("x", limit-8))
	if _, _, err := ReadBodyInfo(tx, r, Limits{Body: limit}); err != nil {
		t.Fatalf("a body of exactly the limit: %v", err)
	}
}

func TestBodyClassLimits(t *testing.T) {
	const raw, whole = 1 << 10, 8 << 10
	lim := Limits{Raw: raw, Body: whole}
	cases := []struct {
		ctype string
		size  int
		want  error
	}{
		{"application/octet-stream", raw, nil},
		{"application/octet-stream", raw + 1, ErrRawTooLarge},
		{"image/jpeg", raw + 1, ErrRawTooLarge},
		{"", raw + 1, ErrRawTooLarge},
		{"application/octet-stream", whole + 1, ErrBodyTooLarge},
		{"application/json", whole, nil},
		{"application/json; charset=utf-8", whole + 1, ErrBodyTooLarge},
		{"text/plain", raw + 1, nil},
		{"application/vnd.api+json", raw + 1, nil},
	}
	inst := crs(t)
	for _, c := range cases {
		// Declared length: Precheck.
		r := httptest.NewRequest("POST", "/upload", strings.NewReader(strings.Repeat("a", c.size)))
		if c.ctype != "" {
			r.Header.Set("Content-Type", c.ctype)
		}
		if err := Precheck(r, lim); err != c.want {
			t.Fatalf("%q %d declared: %v, want %v", c.ctype, c.size, err, c.want)
		}
		// Unknown length: while the body streams.
		tx, _ := inst.NewTransaction()
		r = unknownLength(c.ctype, strings.Repeat("a", c.size))
		if c.ctype == "" {
			r.Header.Del("Content-Type")
		}
		_, _, err := ReadBodyInfo(tx, r, lim)
		_ = tx.Close()
		want := c.want
		if c.want == ErrBodyTooLarge && c.ctype == "application/octet-stream" {
			want = ErrRawTooLarge // reading ends at the raw limit, the rest is never seen
		}
		if want != nil && err != want {
			t.Fatalf("%q %d streamed: %v, want %v", c.ctype, c.size, err, want)
		}
		if c.want == nil && (err == ErrRawTooLarge || err == ErrBodyTooLarge) {
			t.Fatalf("%q %d streamed: %v", c.ctype, c.size, err)
		}
	}
}

// A limit in front of schild stays body_too_large, under the raw limit too.
func TestFrontLimitStaysBodyTooLarge(t *testing.T) {
	inst := crs(t)
	tx, _ := inst.NewTransaction()
	defer tx.Close()
	r := unknownLength("application/octet-stream", strings.Repeat("a", 512))
	r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 100)
	if _, _, err := ReadBodyInfo(tx, r, Limits{Raw: 1 << 10, Body: 8 << 10}); err != ErrBodyTooLarge {
		t.Fatalf("%v", err)
	}
}

func multipartBody(t *testing.T, field, file int) (string, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if field > 0 {
		f, _ := w.CreateFormField("text")
		_, _ = io.WriteString(f, strings.Repeat("t", field))
	}
	if file > 0 {
		f, _ := w.CreateFormFile("file", "a.bin")
		_, _ = io.WriteString(f, strings.Repeat("f", file))
	}
	_ = w.Close()
	return b.String(), w.FormDataContentType()
}

// Text fields of a multipart form count as text, file parts do not.
func TestMultipartTextCounts(t *testing.T) {
	inst := crs(t)
	for _, c := range []struct{ field, file int }{{400 << 10, 0}, {0, 400 << 10}, {100 << 10, 300 << 10}} {
		body, ct := multipartBody(t, c.field, c.file)
		tx, _ := inst.NewTransaction()
		r := httptest.NewRequest("POST", "/upload", strings.NewReader(body))
		r.Header.Set("Content-Type", ct)
		_, info, err := ReadBodyInfo(tx, r, Limits{Body: 1 << 20})
		_ = tx.Close()
		if err != nil || !info.Files || info.Text != int64(c.field) {
			t.Fatalf("field %d file %d: %v %+v", c.field, c.file, err, info)
		}
	}
}

// A body the reader cannot finish counts as text whole.
func TestMultipartUnreadableCountsAsText(t *testing.T) {
	const ct = "multipart/form-data; boundary=b"
	body := "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a\"\r\n\r\n" + strings.Repeat("x", 1000)
	if got := multipartText(ct, strings.NewReader(body), int64(len(body))); got != int64(len(body)) {
		t.Fatalf("text %d of %d", got, len(body))
	}
}

func TestHeldCountsMultipartTwice(t *testing.T) {
	if bodylimit.Held(bodylimit.BodyMultipart, 10) != 20 || bodylimit.Held(bodylimit.BodyRaw, 10) != 10 {
		t.Fatal("held")
	}
}
