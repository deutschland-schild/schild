// Package pagekit is the look every page schild answers with shares: the
// block and error pages, the maintenance and login page of the access lock,
// the waiting page and the answers of `schild front`. Brand colours of
// docs/brand/tokens.css in light and dark, the mark "Schild & Herz" inline.
// No external resource: the CSP of these pages allows inline styles only,
// and fonts are the system's (Inter when installed).
package pagekit

import (
	"html/template"
	"net/http"
	"strings"
)

// Mark is the mark "Schild & Herz" (docs/brand/assets/mark-a-schild-herz.svg),
// coloured by CSS so it follows light and dark.
const Mark = `<svg class="mark" viewBox="0 0 64 64" width="44" height="44" aria-hidden="true">` +
	`<path class="mk-o" d="M32 4.5C37.39 9.38 45.48 11 56.5 11V24C56.5 43.53 42.29 57 32 59.5C21.71 57 7.5 43.53 7.5 24V11C18.52 11 26.61 9.38 32 4.5Z"/>` +
	`<path class="mk-s" d="M32 11.6C36.03 15.35 42.06 16.6 50.3 16.6V26C50.3 40.41 39.69 49.7 32 52.2C24.31 49.7 13.7 40.41 13.7 26V16.6C21.93 16.6 27.97 15.35 32 11.6Z"/>` +
	`<path class="mk-h" d="M32 29.42C30.85 26.26 27.68 25.3 26.05 25.3C22.88 25.3 22.4 28.66 22.4 30.29C22.4 35.33 27.68 38.86 32 41.38C36.32 38.86 41.6 35.33 41.6 30.29C41.6 28.66 41.12 25.3 37.95 25.3C36.32 25.3 33.15 26.26 32 29.42Z"/></svg>`

// BaseCSS styles the card, the mark, headline, text and the footer: enough
// for the waiting page, which must stay within waitingpage.MaxPageBytes.
const BaseCSS = `:root{color-scheme:light dark;--fg:#0A1A33;--muted:#5B6B82;--bg:#F1ECE4;--card:#fff;--line:#E3DDD3;--soft:#EDF2F8;--soft-line:#D8E2EE;--g:#0F873B;--btn:#0A1A33;--on-btn:#fff;--warn:#B45309}
@media (prefers-color-scheme:dark){:root{--fg:#E6EDF5;--muted:#9FB3CC;--bg:#0A1A33;--card:#13284A;--line:#1D3660;--soft:#0A1A33;--soft-line:#1D3660;--g:#86EFAC;--btn:#E6EDF5;--on-btn:#0A1A33;--warn:#FDBA74}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--bg);color:var(--fg);font:16px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
main{width:100%;max-width:31rem;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:40px 36px 28px;box-shadow:0 1px 2px rgba(10,26,51,.05),0 16px 40px -16px rgba(10,26,51,.18)}
.mark{display:block;width:44px;height:44px;margin:0 0 28px}
.mk-o{fill:none;stroke:var(--fg);stroke-width:3.6;stroke-linejoin:round}.mk-s{fill:var(--fg);stroke:var(--fg);stroke-width:1.4;stroke-linejoin:round}.mk-h{fill:var(--card)}
h1{margin:0 0 12px;font-size:1.55rem;line-height:1.25;font-weight:700;letter-spacing:-.015em}
p{margin:0 0 14px;color:var(--muted);white-space:pre-line}strong{color:var(--fg)}
footer{margin-top:28px;padding-top:16px;border-top:1px solid var(--line);font-size:.8rem;color:var(--muted)}
@media (max-width:480px){body{padding:16px}main{padding:28px 22px 20px}}`

// CSS is BaseCSS plus a kicker line (.kicker), an info box (.box) and the
// login form. Pages add their own rules after it.
const CSS = BaseCSS + `
.kicker{margin:0 0 6px;font:600 .75rem/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
h2{margin:0 0 4px;font-size:1rem;line-height:1.4}
.box{margin:22px 0;padding:14px 16px;background:var(--soft);border:1px solid var(--soft-line);border-radius:12px}
.box span{display:block;font-size:.8rem;color:var(--muted)}
.box strong{font:600 1.3rem/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em}
form{margin:24px 0 0}
form.below{padding:22px 0 0;border-top:1px solid var(--line)}
label{display:block;margin:0 0 6px;font-size:.9rem;font-weight:600}
input{width:100%;font:inherit;padding:11px 14px;border:1px solid var(--soft-line);border-radius:12px;background:var(--card);color:var(--fg)}
input:focus{outline:2px solid var(--g);outline-offset:1px;border-color:transparent}
button{width:100%;margin-top:14px;font:inherit;font-weight:600;padding:11px 16px;border:0;border-radius:12px;background:var(--btn);color:var(--on-btn);cursor:pointer}
button:hover{opacity:.9}button:focus-visible{outline:2px solid var(--g);outline-offset:2px}
.note{margin:12px 0 0;color:var(--warn)}`

var simple = template.Must(template.New("s").Parse(`<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style>` + CSS + `</style>
</head>
<body>
<main>
` + Mark + `
<h1>{{.Title}}</h1>
<p>{{.Lead}}</p>
</main>
</body>
</html>
`))

// CSP is the Content-Security-Policy of a page without a form.
const CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// WriteSimple answers with a title and one paragraph: the page for a
// browser (Accept with text/html), plain text for everything else. The
// caller sets Retry-After and the like before.
func WriteSimple(w http.ResponseWriter, r *http.Request, status int, title, lead string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if !strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(title + " " + lead + "\n"))
		}
		return
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", CSP)
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_ = simple.Execute(w, struct{ Title, Lead string }{title, lead})
	}
}
