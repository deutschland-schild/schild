package accesslock

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
	"github.com/deutschland-schild/schild/gateway/internal/pagekit"
)

// maxRetryAfter caps Retry-After of the maintenance page: search engines
// come back within the hour and keep the index.
const maxRetryAfter = 3600

type pageCopy struct {
	Title, Lead string
}

// German UI copy, du-form, calm. Never a vulnerability, never the word
// Schild; the page carries the mark only (pagekit).
var copies = map[string]pageCopy{
	access.AnswerMaintenance: {Title: "Wir sind gleich wieder da.", Lead: "An dieser Website wird gerade gearbeitet. Schau bitte später noch einmal vorbei."},
	access.AnswerLogin:       {Title: "Anmeldung nötig", Lead: "Für diesen Bereich brauchst du ein Passwort. Du bekommst es von den Betreiber:innen dieser Website."},
	access.AnswerDenied:      {Title: "Kein Zugriff", Lead: "Dieser Bereich ist nur aus bestimmten Netzwerken erreichbar."},
}

// Notes under the form.
const (
	NoteWrong    = "Das Passwort stimmt nicht."
	NoteLocked   = "Zu viele Versuche. Versuch es in 15 Minuten noch einmal."
	NoteBusy     = "Gerade melden sich viele an. Versuch es bitte gleich noch einmal."
	formTitle    = "Mit Passwort weiter"
	formLeadSite = "Wenn du ein Passwort für diese Website hast, meld dich hier an."
)

var page = template.Must(template.New("p").Parse(`<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style>` + pagekit.CSS + `</style>
</head>
<body>
<main>
` + pagekit.Mark + `
<h1>{{.Title}}</h1>
<p>{{.Lead}}</p>
{{if .Form}}<form method="post" action="` + LoginPath + `"{{if .FormTitle}} class="below"{{end}}>
{{if .FormTitle}}<h2>{{.FormTitle}}</h2>
<p>{{.FormLead}}</p>
{{end}}<label for="password">Passwort</label>
<input id="password" name="password" type="password" autocomplete="current-password" required maxlength="128" autofocus>
<input type="hidden" name="return" value="{{.Return}}">
{{if .Note}}<p class="note" role="alert">{{.Note}}</p>
{{end}}<button type="submit">Anmelden</button>
</form>
{{end}}</main>
</body>
</html>
`))

type pageData struct {
	pageCopy
	Form                bool
	FormTitle, FormLead string
	Return, Note        string
}

type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Code   string `json:"code"`
}

// Write answers a locked request (v.Answer is not pass): the page for a
// browser, problem details for an API client, 503 with Retry-After for the
// maintenance page. note is shown under the form (wrong password, lockout).
func Write(w http.ResponseWriter, r *http.Request, v Verdict, note string, now time.Time) {
	writeStatus(w, r, v, v.Status, note, now)
}

func writeStatus(w http.ResponseWriter, r *http.Request, v Verdict, status int, note string, now time.Time) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Referrer-Policy", "no-referrer")
	if v.Answer == access.AnswerMaintenance {
		h.Set("Retry-After", strconv.Itoa(maxRetryAfter))
	}
	c := copies[v.Answer]
	if v.Answer == access.AnswerMaintenance && strings.TrimSpace(v.Entry.Protection.Message) != "" {
		c.Lead = v.Entry.Protection.Message
	}
	if blockpage.WantsJSON(r) {
		h.Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			_ = json.NewEncoder(w).Encode(problem{Type: "https://schild.invalid/problems/access_locked", Title: c.Title, Status: status, Detail: c.Lead, Code: "access_locked"})
		}
		return
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	d := pageData{pageCopy: c, Form: v.LoginForm, Return: returnPath(r.URL.RequestURI()), Note: note}
	if v.Answer == access.AnswerMaintenance {
		d.FormTitle, d.FormLead = formTitle, formLeadSite
	}
	_ = page.Execute(w, d)
}

// returnPath keeps a same-origin path with its query; anything else is /.
// No control character either: a browser drops tabs and line breaks from a
// URL, so "/<TAB>/evil.example" would leave the origin as "//evil.example".
func returnPath(s string) string {
	if len(s) > 2048 || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, `/\`) ||
		strings.IndexFunc(s, unicode.IsControl) >= 0 || strings.HasPrefix(s, LoginPath) {
		return "/"
	}
	return s
}
