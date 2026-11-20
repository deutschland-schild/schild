// Package waitpage serves the waiting page (contracts v0.5, D37, MVP-23
// step 1): the calm answer to a document navigation that schild refuses
// because it is overloaded (fail-closed reasons waf_busy and waf_timeout).
// The decision (page or problem, variant, language, Retry-After, website
// name) and the copy come from contract/waitingpage; this package only
// renders.
//
// The page is served exactly when the server is overloaded, so it costs
// next to nothing: every combination of language, variant, Retry-After and
// "with or without website name" is rendered once at start into three byte
// slices (before the name, between name and time, after the time). Serving
// appends name and time into a pooled buffer and writes it once. No
// template execution, no WAF, no database, no lookup.
package waitpage

import (
	"bytes"
	"html"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract/waitingpage"
	"github.com/deutschland-schild/schild/gateway/internal/pagekit"
)

// Markers in the pre-rendered page where the website name and the time go.
// Plain ASCII letters, so html/template leaves them alone.
const (
	markSite = "SCHILDWAITSITEMARK"
	markTime = "SCHILDWAITTIMEMARK"
)

// timeLayout is the footer time (UTC), 19 bytes.
const timeLayout = "2006-01-02 15:04:05"

// page is one pre-rendered variant.
type page struct {
	head, mid, tail []byte
	lang            []string // Content-Language value
}

func (p *page) size(site string) int {
	return len(p.head) + len(site) + len(p.mid) + len(timeLayout) + len(p.tail)
}

// Retry-After values and variants: index 0..RetryJitterS for reload
// (Retry-After = RetryBaseS + i), formIdx for the form variant.
const (
	nRetry  = waitingpage.RetryJitterS + 1
	formIdx = nRetry
	nVar    = nRetry + 1
)

var (
	langs = [2]string{waitingpage.LangDE, waitingpage.LangEN}
	// pages[lang][variant][withSite]
	pages [2][nVar][2]*page
	// lengths are the Content-Length strings of every possible size.
	lengths    []string
	minSize    int
	retryValue [waitingpage.RetryMaxS + 1]string
)

var bufs = sync.Pool{New: func() any { b := make([]byte, 0, waitingpage.MaxPageBytes); return &b }}

func init() {
	minSize, maxSize := 1<<30, 0
	for li, lang := range langs {
		for v := 0; v < nVar; v++ {
			for s := 0; s < 2; s++ {
				p := render(lang, v, s == 1)
				pages[li][v][s] = p
				minSize = min(minSize, p.size(""))
				maxSize = max(maxSize, p.size(strings.Repeat("x", 253)))
			}
		}
	}
	if maxSize > waitingpage.MaxPageBytes {
		panic("waitpage: page larger than waitingpage.MaxPageBytes")
	}
	lengths = make([]string, maxSize-minSize+1)
	for i := range lengths {
		lengths[i] = strconv.Itoa(minSize + i)
	}
	for n := waitingpage.RetryMinS; n <= waitingpage.RetryMaxS; n++ {
		retryValue[n] = strconv.Itoa(n)
	}
}

// Header values set on every waiting page.
const (
	contentType = "text/html; charset=utf-8"
	vary        = "Accept, Accept-Language, Sec-Fetch-Dest, Sec-Fetch-Mode, X-Requested-With"
)

// Write sends the waiting page of a decision with Answer waiting_page: 503,
// the headers of contracts/waiting-page.md section 4 and, unless d.Body is
// false (HEAD), the page. now is the footer time.
func Write(w http.ResponseWriter, d waitingpage.Result, now time.Time) {
	li := 0
	if d.Language != nil && *d.Language == waitingpage.LangEN {
		li = 1
	}
	retry := waitingpage.RetryMinS
	if d.RetryAfter != nil {
		retry = min(max(*d.RetryAfter, waitingpage.RetryMinS), waitingpage.RetryMaxS)
	}
	v := retry - waitingpage.RetryBaseS
	if d.Variant != nil && *d.Variant == waitingpage.VariantForm {
		v = formIdx
	}
	site := ""
	if d.SiteName != nil {
		site = *d.SiteName
	}
	s := 0
	if site != "" {
		s = 1
	}
	p := pages[li][v][s]

	bp := bufs.Get().(*[]byte)
	b := append((*bp)[:0], p.head...)
	b = appendEscaped(b, site)
	b = append(b, p.mid...)
	b = now.UTC().AppendFormat(b, timeLayout)
	b = append(b, p.tail...)

	// One allocation for every header value (the slices are not shared
	// between responses, so a later handler may change them in place).
	vals := new([10]string)
	vals[0], vals[1], vals[2] = contentType, p.lang[0], "no-store"
	vals[3], vals[4], vals[5] = "nosniff", "no-referrer", vary
	vals[6], vals[7] = waitingpage.CSP, retryValue[retry]
	vals[9] = waitingpage.MarkerValue
	if i := len(b) - minSize; i >= 0 && i < len(lengths) {
		vals[8] = lengths[i]
	} else {
		vals[8] = strconv.Itoa(len(b))
	}
	h := w.Header()
	h["Content-Type"] = vals[0:1:1]
	h["Content-Language"] = vals[1:2:2]
	h["Cache-Control"] = vals[2:3:3]
	h["X-Content-Type-Options"] = vals[3:4:4]
	h["Referrer-Policy"] = vals[4:5:5]
	h["Vary"] = vals[5:6:6]
	h["Content-Security-Policy"] = vals[6:7:7]
	h["Retry-After"] = vals[7:8:8]
	h["Content-Length"] = vals[8:9:9]
	// D37 amendment: the marker (MarkerHeader is in canonical form).
	h[waitingpage.MarkerHeader] = vals[9:10:10]
	w.WriteHeader(http.StatusServiceUnavailable)
	if d.Body == nil || *d.Body {
		_, _ = w.Write(b)
	}
	*bp = b[:0]
	bufs.Put(bp)
}

// appendEscaped appends s HTML-escaped. waitingpage.SiteName only returns
// a-z, 0-9, '.' and '-', so this copies; it escapes anyway.
func appendEscaped(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '<':
			b = append(b, "&lt;"...)
		case '>':
			b = append(b, "&gt;"...)
		case '&':
			b = append(b, "&amp;"...)
		case '"':
			b = append(b, "&#34;"...)
		case '\'':
			b = append(b, "&#39;"...)
		default:
			b = append(b, c)
		}
	}
	return b
}

// pageData fills the template; the HTML fields are built from escaped copy.
// They are rendered once at start from the fixed texts of contract/waitingpage
// and integers, never from a request: the website name goes in at serve time,
// through appendEscaped.
type pageData struct {
	Lang, Title, Headline string
	Lead, Next, Countdown template.HTML
	Footer                template.HTML
	Refresh               int // 0 = no meta refresh, no countdown, no bar
}

func render(lang string, v int, withSite bool) *page {
	t := waitingpage.Texts[lang]
	d := pageData{Lang: lang, Title: t.Title, Headline: t.Headline}
	if withSite {
		d.Lead = template.HTML(strings.Replace(html.EscapeString(t.Lead), "{site}", "<strong>"+markSite+"</strong>", 1))
	} else {
		d.Lead = template.HTML(html.EscapeString(t.LeadNoSite) + markSite)
	}
	if v == formIdx {
		d.Next = template.HTML(html.EscapeString(t.NextForm))
	} else {
		n := waitingpage.RetryBaseS + v
		d.Refresh = n
		d.Next = template.HTML(html.EscapeString(t.NextReload))
		var digits strings.Builder
		digits.WriteString(`<span class="n">`)
		for i := 0; i < n; i++ {
			if i == 0 {
				digits.WriteString("<b>" + strconv.Itoa(n) + "</b>")
			} else {
				digits.WriteString(`<b style="--d:` + strconv.Itoa(i) + `s">` + strconv.Itoa(n-i) + "</b>")
			}
		}
		digits.WriteString("</span>")
		d.Countdown = template.HTML(strings.Replace(html.EscapeString(t.Countdown), "{n}", digits.String(), 1))
	}
	d.Footer = template.HTML(strings.Replace(html.EscapeString(t.Footer), "{time}", markTime, 1))
	var out bytes.Buffer
	if err := pageTmpl.Execute(&out, d); err != nil {
		panic("waitpage: " + err.Error())
	}
	raw := out.String()
	head, rest, ok1 := strings.Cut(raw, markSite)
	mid, tail, ok2 := strings.Cut(rest, markTime)
	if !ok1 || !ok2 {
		panic("waitpage: markers missing")
	}
	return &page{head: []byte(head), mid: []byte(mid), tail: []byte(tail), lang: []string{lang}}
}

// pageTmpl is illustration A "Parkbank" (tests/results/waiting-page-2026-10-29/
// variant-a.html, chosen by the initiator on 2026-10-29): inline SVG, light
// and dark by prefers-color-scheme through CSS classes, a CSS-only countdown
// (one element per second with an animation delay) and a progress bar of
// Refresh seconds; prefers-reduced-motion stops the illustration and hides
// the bar. No script, no external resource (CSP of the block page).
var pageTmpl = template.Must(template.New("w").Parse(`<!doctype html>
<html lang="{{.Lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
{{if .Refresh}}<meta http-equiv="refresh" content="{{.Refresh}}">
{{end}}<title>{{.Title}}</title>
<style>` + pagekit.BaseCSS + `
:root{--ink:#0A1A33;--wood:#D2AB80;--wood2:#B98D62;--mist:#EDF2F8;--paper:#FAF8F5;--sky:#3D9BF5;--grey:#9AA7B5}
@media (prefers-color-scheme:dark){:root{--ink:#C9D6E3;--wood:#8E6E50;--wood2:#735740;--mist:#1D3660;--paper:#DDE4E0;--grey:#6F7D78}}
main{max-width:34rem}.art{display:block;width:100%;max-width:26rem;height:auto;margin:0 auto 24px}
{{if .Refresh}}.cd{margin:20px 0 6px;color:var(--fg);font-weight:600}
.n{display:inline-grid}.n b{grid-area:1/1;visibility:hidden;animation:on 1s var(--d) step-end}
.n b:first-child{visibility:visible;animation:off 0s 1s forwards}.n b:last-child{animation-fill-mode:forwards}
@keyframes on{from,to{visibility:visible}}@keyframes off{to{visibility:hidden}}
.bar{height:6px;border-radius:3px;background:var(--line);overflow:hidden;margin:0 0 18px}
.bar i{display:block;height:100%;background:var(--g);transform-origin:left;animation:fill {{.Refresh}}s linear both}
@keyframes fill{from{transform:scaleX(0)}to{transform:scaleX(1)}}
{{end}}.mi{fill:var(--mist)}.wd{fill:var(--wood)}.wd2{fill:var(--wood2)}.ik{fill:var(--ink)}.g{fill:var(--g)}.sk{fill:var(--sky)}.pp{fill:var(--paper)}
.fc{fill:var(--card);stroke:var(--ink);stroke-width:3}.o{stroke:var(--ink)}.gl{stroke:var(--grey)}
.ln{fill:none;stroke:var(--ink);stroke-linecap:round}.st{fill:none;stroke:var(--grey);stroke-width:2.5;stroke-linecap:round}
.mh{transform-origin:262px 44px;animation:spin 12s linear infinite}
.eye{transform-box:fill-box;transform-origin:center;animation:blink 6s infinite}
.st path{animation:steam 3s ease-in-out infinite}.st path+path{animation-delay:1.5s}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes blink{0%,94%,100%{transform:scaleY(1)}97%{transform:scaleY(.1)}}
@keyframes steam{0%{opacity:0;transform:translateY(4px)}40%{opacity:1}100%{opacity:0;transform:translateY(-8px)}}
@media (prefers-reduced-motion:reduce){.mh,.eye,.st path,.bar i{animation:none}.bar{display:none}}
</style>
</head>
<body>
<main>
` + pagekit.Mark + `
<svg class="art" viewBox="0 18 320 158" aria-hidden="true">
<circle class="mi" cx="146" cy="98" r="70"/>
<path class="ln" stroke-width="3" d="M14 168H306"/>
<rect class="ik" x="260" y="56" width="4" height="112" rx="2"/>
<circle class="fc" cx="262" cy="44" r="19"/>
<path class="ln" stroke-width="2" d="M262 29v3M262 56v3M247 44h3M274 44h3M262 44v-9"/>
<path class="ln mh" stroke-width="2" d="M262 44h10"/>
<rect class="ik" x="74" y="88" width="5" height="80" rx="2"/>
<rect class="ik" x="213" y="88" width="5" height="80" rx="2"/>
<rect class="wd" x="56" y="92" width="180" height="8" rx="3"/>
<rect class="wd" x="56" y="106" width="180" height="8" rx="3"/>
<rect class="wd2" x="50" y="126" width="192" height="9" rx="3"/>
<rect class="ik" x="62" y="135" width="5" height="33" rx="2"/>
<rect class="ik" x="225" y="135" width="5" height="33" rx="2"/>
<g transform="matrix(1.3 0 0 1.3 -36 -38.4)">
<path class="g" d="M120 84c5 4 11 6 20 6v13c0 13-10 23-20 27c-10-4-20-14-20-27V90c9 0 15-2 20-6z"/>
<g class="eye"><ellipse cx="113" cy="102" rx="4.5" ry="5" fill="#fff"/><ellipse cx="127" cy="102" rx="4.5" ry="5" fill="#fff"/><circle cx="115" cy="100" r="2.2" fill="#0A1A33"/><circle cx="129" cy="100" r="2.2" fill="#0A1A33"/></g>
<path class="ln" stroke-width="4" d="M112 128v22M128 128v22"/>
<ellipse class="ik" cx="115" cy="152" rx="6" ry="3.2"/><ellipse class="ik" cx="131" cy="152" rx="6" ry="3.2"/>
<g transform="rotate(-4 120 120)"><rect class="pp o" stroke-width="1.5" x="92" y="106" width="56" height="28" rx="2"/>
<path class="o" stroke-width="1" d="M120 106v28"/><path class="gl" stroke-width="2.5" d="M96 112h20M124 112h20"/>
<path class="gl" stroke-width="1.2" d="M96 118h20M96 122h20M96 126h16M124 118h20M124 122h20M124 126h14"/></g>
<circle class="g" cx="92" cy="118" r="4"/><circle class="g" cx="148" cy="116" r="4"/></g>
<rect class="sk" x="172" y="100" width="16" height="26" rx="4"/><rect class="ik" x="174" y="95" width="12" height="7" rx="2"/>
<path class="pp o" stroke-width="1.5" d="M193 116h15l-2 10h-11z"/>
<g class="st"><path d="M197 111q-3-4 0-7t0-7"/><path d="M204 111q-3-4 0-7t0-7"/></g>
</svg>
<h1>{{.Headline}}</h1>
<p>{{.Lead}}</p>
<p>{{.Next}}</p>
{{if .Refresh}}<p class="cd">{{.Countdown}}</p>
<div class="bar"><i></i></div>
{{end}}<footer>{{.Footer}}</footer>
</main>
</body>
</html>
`))
