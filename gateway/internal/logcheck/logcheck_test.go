package logcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

func find(sr SiteReport, cat string) *Finding {
	for i := range sr.Findings {
		if sr.Findings[i].Category == cat {
			return &sr.Findings[i]
		}
	}
	return nil
}

func run(t *testing.T, args ...string) (*Report, string) {
	t.Helper()
	var out, errb bytes.Buffer
	if err := Main(append([]string{"-json"}, args...), strings.NewReader(""), &out, &errb, nil); err != nil {
		t.Fatalf("Main: %v (%s)", err, errb.String())
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("json: %v", err)
	}
	return &rep, out.String()
}

func siteOf(t *testing.T, rep *Report, name string) SiteReport {
	t.Helper()
	for _, s := range rep.Sites {
		if s.Site == name {
			return s
		}
	}
	t.Fatalf("site %q missing in %+v", name, rep.Sites)
	return SiteReport{}
}

func TestDefaultsMirrorClient(t *testing.T) {
	l := DefaultLimits()
	if l.BodyBytes != waf.DefaultLimits.Body || l.Args != waf.DefaultLimits.Args || l.EvalTimeoutMS != 1000 {
		t.Fatalf("defaults %+v", l)
	}
}

func TestNginxJSON(t *testing.T) {
	rep, raw := run(t, "shop=testdata/shop-schild-check.log")
	s := siteOf(t, rep, "shop")
	if s.Records != 8 || s.Unparsed != 1 {
		t.Fatalf("records %d unparsed %d", s.Records, s.Unparsed)
	}
	if f := find(s, CatBodyTooLarge); f == nil || f.Certain != 1 || f.Examples[0].Path != "/wp-admin/async-upload.php" {
		t.Fatalf("413: %+v", f)
	}
	if f := find(s, CatBodyEncoding); f == nil || f.Certain != 1 || f.Examples[0].Path != "/api/sync/{n}" {
		t.Fatalf("415 (identity must not count): %+v", f)
	}
	if f := find(s, CatTooManyArgs); f == nil || f.Certain != 1 || f.MaxValue != 1001 {
		t.Fatalf("400: %+v", f)
	}
	if f := find(s, CatLongParam); f == nil || f.Certain != 1 || f.Examples[0].Path != "/report" {
		t.Fatalf("long param: %+v", f)
	}
	if f := find(s, CatLargeForm); f == nil || f.Possible != 1 || f.Examples[0].Path != "/wp-admin/nav-menus.php" {
		t.Fatalf("large form: %+v", f)
	}
	if s.Sizes.Max != 20971520 || s.AppStatuses["413"] != 1 {
		t.Fatalf("sizes %+v statuses %v", s.Sizes, s.AppStatuses)
	}
	// 20 MiB x 2 = 40 MiB, above the 12.5 MiB default.
	if s.Suggest.RequestBodyLimitBytes != 40*mib {
		t.Fatalf("suggested body limit %d", s.Suggest.RequestBodyLimitBytes)
	}
	// worst estimate: the 200 KiB form, 1800 ms x 1.5 -> 2700 ms
	if s.Suggest.EvalTimeoutMS != 2700 {
		t.Fatalf("suggested timeout %d", s.Suggest.EvalTimeoutMS)
	}
	if strings.Contains(raw, "192.0.2.") || strings.Contains(raw, "2001:db8") {
		t.Fatal("IP in output without -show-ips")
	}
}

func TestQueryArgsCountMatchesGate(t *testing.T) {
	an := New(Options{})
	at := strings.TrimSuffix(strings.Repeat("a=1&", 1000), "&") // exactly 1000
	over := at + "&b=2"
	an.Add("s", Record{Method: "GET", URI: "/?" + at, ContentLength: -1, BodyBytes: -1, RequestLength: -1})
	an.Add("s", Record{Method: "GET", URI: "/?" + over, ContentLength: -1, BodyBytes: -1, RequestLength: -1})
	s := an.Report(timeNow()).Sites[0]
	if f := find(s, CatTooManyArgs); f == nil || f.Certain != 1 {
		t.Fatalf("want exactly one hit (1001 args), got %+v", f)
	}
}

func TestCombinedAndRequestLength(t *testing.T) {
	rep, raw := run(t, "testdata/blog-combined.log", "-format", "auto")
	s := siteOf(t, rep, "blog-combined")
	if s.Records != 3 || s.Unparsed != 0 {
		t.Fatalf("records %d unparsed %d %v", s.Records, s.Unparsed, s.UnparsedEx)
	}
	if f := find(s, CatTooManyArgs); f == nil || f.Certain != 1 {
		t.Fatalf("400: %+v", f)
	}
	if s.Coverage.BodySizeKnown != 0 || s.Coverage.ContentEncodingLog != 0 {
		t.Fatalf("combined must not claim body sizes: %+v", s.Coverage)
	}
	if !strings.Contains(raw, "Content-Encoding not logged") {
		t.Fatal("missing coverage note")
	}

	rep, _ = run(t, "-format", "combined-rl", "-body-limit", "10000000", "shop=testdata/shop-rl.log.gz")
	s = siteOf(t, rep, "shop")
	if s.Records != 2 {
		t.Fatalf("gzip input: records %d (%v)", s.Records, s.UnparsedEx)
	}
	if f := find(s, CatBodyTooLarge); f == nil || f.Possible != 1 || f.Certain != 0 {
		t.Fatalf("request_length over the limit must be 'possible': %+v", f)
	}
	if rep.Limits.BodyBytes != 10000000 {
		t.Fatalf("limits %+v", rep.Limits)
	}
}

func TestApacheCheckAndCaddy(t *testing.T) {
	rep, _ := run(t, "app=testdata/app-apache-check.log")
	s := siteOf(t, rep, "app")
	if s.Records != 3 {
		t.Fatalf("records %d %v", s.Records, s.UnparsedEx)
	}
	if f := find(s, CatBodyEncoding); f == nil || f.Certain != 1 {
		t.Fatalf("br body: %+v", f)
	}
	if find(s, CatBodyTooLarge) != nil {
		t.Fatal("1 MiB is below the default limit")
	}

	rep, raw := run(t, "-by-host", "-show-ips", "testdata/caddy-access.log")
	shop, docs := siteOf(t, rep, "shop.example"), siteOf(t, rep, "docs.example")
	if f := find(shop, CatBodyEncoding); f == nil || f.Certain != 1 {
		t.Fatalf("caddy gzip: %+v", f)
	}
	if f := find(docs, CatBodyTooLarge); f == nil || f.Certain != 1 {
		t.Fatalf("caddy bytes_read: %+v", f)
	}
	if !strings.Contains(raw, "2001:db8::2") {
		t.Fatal("-show-ips must include the IP")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse("", "auto"); !errors.Is(err, ErrSkip) {
		t.Fatal("blank line must be skipped")
	}
	if _, err := Parse("x", "nope"); err == nil {
		t.Fatal("unknown format accepted")
	}
	var out, errb bytes.Buffer
	if err := Main([]string{"-format", "nope"}, strings.NewReader(""), &out, &errb, nil); err == nil {
		t.Fatal("Main accepted an unknown format")
	}
	if err := Main([]string{"-format", "combined"}, strings.NewReader("garbage\n"), &out, &errb, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "unparsed lines 1") {
		t.Fatalf("stdin: %s", out.String())
	}
}

func TestLimitsLoader(t *testing.T) {
	var out, errb bytes.Buffer
	load := func(string) (Limits, error) { return Limits{BodyBytes: 1000, Args: 1000, EvalTimeoutMS: 500}, nil }
	in := `{"t":"2026-11-02T10:00:00+00:00","m":"POST","s":200,"cl":"2000","rl":2400,"ce":"","ct":"text/plain","uri":"/x"}` + "\n"
	if err := Main([]string{"-json", "-config", "schild.yaml"}, strings.NewReader(in), &out, &errb, load); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Limits.Source != "schild.yaml" || rep.Limits.EvalTimeoutMS != 500 {
		t.Fatalf("limits %+v", rep.Limits)
	}
	if f := find(rep.Sites[0], CatBodyTooLarge); f == nil || f.Certain != 1 {
		t.Fatalf("configured limit not applied: %+v", rep.Sites[0].Findings)
	}
	failing := func(string) (Limits, error) { return Limits{}, errors.New("broken") }
	if err := Main([]string{"-config", "schild.yaml"}, strings.NewReader(in), &out, &errb, failing); err == nil {
		t.Fatal("explicit broken config must fail")
	}
}

func timeNow() time.Time { return time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC) }

// A huge logged Content-Length (client-controlled) still suggests the
// maximum limit with its note instead of overflowing into "no change".
func TestSuggestHugeBody(t *testing.T) {
	lim := DefaultLimits()
	sg := suggest(lim, &site{}, SizeStats{Max: 1 << 62})
	if sg.RequestBodyLimitBytes != MaxBodyLimit {
		t.Fatalf("suggested %d, want %d", sg.RequestBodyLimitBytes, MaxBodyLimit)
	}
	found := false
	for _, n := range sg.Notes {
		found = found || strings.Contains(n, "exceeds the 128 MiB maximum")
	}
	if !found {
		t.Fatalf("notes %q", sg.Notes)
	}
}
