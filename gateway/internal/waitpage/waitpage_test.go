package waitpage

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/waitingpage"
)

var at = time.Date(2026, 10, 29, 14, 3, 12, 0, time.UTC)

func result(lang, variant string, retry int, site string, body bool) waitingpage.Result {
	r := waitingpage.Result{Answer: waitingpage.AnswerWaitingPage, Language: &lang, Variant: &variant, RetryAfter: &retry, Body: &body}
	if variant == waitingpage.VariantReload {
		r.Refresh = &retry
	}
	if site != "" {
		r.SiteName = &site
	}
	return r
}

func serve(d waitingpage.Result) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	Write(w, d, at)
	return w
}

func TestHeaders(t *testing.T) {
	w := serve(result("en", waitingpage.VariantReload, 7, "musterverein.example", true))
	want := map[string]string{
		"Content-Type": "text/html; charset=utf-8", "Content-Language": "en", "Cache-Control": "no-store",
		"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Retry-After": "7",
		"Vary":                    "Accept, Accept-Language, Sec-Fetch-Dest, Sec-Fetch-Mode, X-Requested-With",
		"Content-Security-Policy": waitingpage.CSP,
		"Content-Length":          strconv.Itoa(w.Body.Len()),
		waitingpage.MarkerHeader:  waitingpage.MarkerValue, // D37 amendment
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", w.Code)
	}
	for k, v := range want {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if w.Header().Get("X-Schild-Incident") != "" {
		t.Error("the waiting page carries no incident")
	}
}

// Every variant: language, refresh and countdown digits and bar length
// follow Retry-After; the form variant has none of them; the size bound
// holds with the longest name.
func TestVariants(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, lang := range []string{"de", "en"} {
		tx := waitingpage.Texts[lang]
		for n := waitingpage.RetryMinS; n <= waitingpage.RetryMaxS; n++ {
			for _, site := range []string{"", "musterverein.example", long} {
				body := serve(result(lang, waitingpage.VariantReload, n, site, true)).Body.String()
				if len(body) > waitingpage.MaxPageBytes {
					t.Fatalf("%d bytes > %d", len(body), waitingpage.MaxPageBytes)
				}
				for _, s := range []string{`<html lang="` + lang + `">`, `<meta http-equiv="refresh" content="` + strconv.Itoa(n) + `">`,
					"animation:fill " + strconv.Itoa(n) + "s linear both", `<b>` + strconv.Itoa(n) + `</b>`,
					`<b style="--d:` + strconv.Itoa(n-1) + `s">1</b></span>`, "<title>" + tx.Title + "</title>", tx.Headline, tx.NextReload,
					strings.ReplaceAll(tx.Footer, "{time}", "2026-10-29 14:03:12"), `<div class="bar">`, "prefers-reduced-motion"} {
					if !strings.Contains(body, htmlText(s)) {
						t.Errorf("%s %d %q: missing %q", lang, n, site, s)
					}
				}
				if strings.Count(body, "<b>")+strings.Count(body, "<b style=") != n {
					t.Errorf("%s %d: countdown digits do not match", lang, n)
				}
				lead := strings.Replace(tx.Lead, "{site}", "<strong>"+site+"</strong>", 1)
				if site == "" {
					lead = tx.LeadNoSite
				}
				if !strings.Contains(body, "<p>"+htmlText(lead)+"</p>") {
					t.Errorf("%s %q: lead missing", lang, site)
				}
				if strings.Contains(body, markSite) || strings.Contains(body, markTime) || strings.Contains(body, "<script") {
					t.Error("marker or script left in the page")
				}
			}
		}
		form := serve(result(lang, waitingpage.VariantForm, 6, "", true)).Body.String()
		if strings.Contains(form, "http-equiv") || strings.Contains(form, `class="bar"`) || strings.Contains(form, `class="n"`) ||
			!strings.Contains(form, htmlText(tx.NextForm)) || strings.Contains(form, htmlText(tx.NextReload)) {
			t.Errorf("%s: form variant has a refresh or countdown, or the wrong copy", lang)
		}
	}
}

// htmlText is s as html/template writes it in text (the apostrophe of the
// English copy).
func htmlText(s string) string { return strings.ReplaceAll(s, "'", "&#39;") }

func TestNameEscaped(t *testing.T) {
	body := serve(result("de", waitingpage.VariantReload, 5, `<x&"'>`, true)).Body.String()
	if !strings.Contains(body, "<strong>&lt;x&amp;&#34;&#39;&gt;</strong>") {
		t.Fatal("name not escaped")
	}
}

func TestHeadHasNoBody(t *testing.T) {
	w := serve(result("de", waitingpage.VariantReload, 5, "", false))
	if w.Body.Len() != 0 || w.Header().Get("Retry-After") != "5" || w.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD: body %d, headers %v", w.Body.Len(), w.Header())
	}
}

// Serving allocates a fixed small number of objects (the header value
// array and the header map entries), never the page itself.
func TestServeAllocations(t *testing.T) {
	d := result("de", waitingpage.VariantReload, 6, "musterverein.example", true)
	w := &discard{h: http.Header{}}
	n := testing.AllocsPerRun(200, func() {
		clear(w.h)
		Write(w, d, at)
	})
	if n > 2 {
		t.Fatalf("%.1f allocations per page", n)
	}
}

type discard struct{ h http.Header }

func (d *discard) Header() http.Header         { return d.h }
func (d *discard) Write(b []byte) (int, error) { return len(b), nil }
func (d *discard) WriteHeader(int)             {}
