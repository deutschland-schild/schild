// Package blockpage renders the answer for a stopped request: a calm German
// HTML page with the incident number for browsers, RFC 9457 problem details
// for API clients. No external assets, nothing that identifies the visitor.
package blockpage

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/waitingpage"
	"github.com/deutschland-schild/schild/gateway/internal/pagekit"
)

// Kind of stop.
const (
	KindBlocked  = "blocked"
	KindTooLarge = "too_large"
	KindInvalid  = "invalid"
	KindTimeout  = "timeout"
	// v0.4 (MVP-17)
	KindPaused      = "paused"       // behaviour block of the client key, ends by itself
	KindRateLimited = "rate_limited" // 429 over a rate limit
)

// KindForStatus maps the HTTP status to a page variant.
func KindForStatus(status int) string {
	switch status {
	case http.StatusRequestEntityTooLarge, http.StatusRequestURITooLong:
		return KindTooLarge
	case http.StatusBadRequest, http.StatusUnsupportedMediaType:
		return KindInvalid
	case http.StatusServiceUnavailable:
		return KindTimeout
	}
	return KindBlocked
}

type copyText struct {
	Title, Lead, Next string
}

// German UI copy, du-form, calm (docs/brand/01-marke.md).
var texts = map[string]copyText{
	KindBlocked: {
		Title: "Anfrage angehalten",
		Lead:  "Die Sicherheitsprüfung dieser Website hat deine Anfrage angehalten. Das passiert selten, manchmal aber auch bei ganz normalen Anfragen.",
		Next:  "Wenn du glaubst, dass das ein Irrtum ist, schick die Vorfallnummer an die Betreiber:innen dieser Website. Sie können die Anfrage damit nachvollziehen und dich freischalten.",
	},
	KindTooLarge: {
		Title: "Anfrage zu groß",
		Lead:  "Deine Anfrage ist größer, als diese Website annimmt. Sie wurde deshalb nicht weitergeleitet.",
		Next:  "Versuch es bitte mit einer kleineren Datei oder weniger Daten. Wenn das nicht geht, schick die Vorfallnummer an die Betreiber:innen dieser Website.",
	},
	KindInvalid: {
		Title: "Anfrage nicht lesbar",
		Lead:  "Die Sicherheitsprüfung konnte deine Anfrage nicht vollständig lesen. Sie wurde deshalb nicht weitergeleitet.",
		Next:  "Lade die Seite bitte neu und versuch es noch einmal. Wenn es wieder passiert, schick die Vorfallnummer an die Betreiber:innen dieser Website.",
	},
	KindTimeout: {
		Title: "Prüfung dauert gerade zu lange",
		Lead:  "Die Sicherheitsprüfung dieser Website ist gerade ausgelastet. Deine Anfrage wurde deshalb nicht weitergeleitet.",
		Next:  "Versuch es bitte in einem Moment noch einmal. Wenn es wieder passiert, schick die Vorfallnummer an die Betreiber:innen dieser Website.",
	},
	KindPaused: {
		Title: "Kurze Pause für deine Adresse",
		Lead:  "Von deiner Adresse kamen in kurzer Zeit viele auffällige Anfragen hintereinander, zum Beispiel fehlgeschlagene Anmeldungen. Deshalb nimmt diese Website von ihr gerade keine Anfragen an. Die Pause endet von selbst.",
		Next:  "Wenn du glaubst, dass das ein Irrtum ist, schick die Vorfallnummer an die Betreiber:innen dieser Website. Sie können die Pause damit sofort beenden.",
	},
	KindRateLimited: {
		Title: "Gerade zu viele Anfragen",
		Lead:  "Von deiner Adresse kamen in kurzer Zeit mehr Anfragen an diese Seite, als die Website annimmt. Das passiert zum Beispiel, wenn ein Programm sehr schnell hintereinander lädt.",
		Next:  "Warte bitte einen Moment und versuch es dann noch einmal.",
	},
}

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
<p class="kicker">Fehlercode {{.Status}}</p>
<h1>{{.Title}}</h1>
<p>{{.Lead}}</p>
{{if .Incident}}<div class="box"><span>Vorfallnummer</span><strong>{{.Incident}}</strong></div>
{{end}}{{if .Until}}<p>Die Pause endet um {{.Until}} UTC.</p>
{{end}}{{if .Retry}}<p>In etwa {{.Retry}} Sekunden geht es wieder.</p>
{{end}}<p>{{.Next}}</p>
<footer>Zeit: {{.Time}} UTC</footer>
</main>
</body>
</html>
`))

type pageData struct {
	copyText
	Incident, Time, Until string
	Retry, Status         int
}

// Problem is the RFC 9457 body for API clients.
type Problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Instance string `json:"instance"`
	Code     string `json:"code"`
	Incident string `json:"incident,omitempty"`
	// v0.4: seconds until the client may try again (429 and behaviour blocks).
	RetryAfter int `json:"retry_after,omitempty"`
}

// WantsJSON reports whether the client prefers a machine-readable answer.
func WantsJSON(r *http.Request) bool {
	acc := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(acc, "text/html") {
		return false
	}
	if strings.Contains(acc, "json") {
		return true
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.Contains(ct, "json") || r.Header.Get("X-Requested-With") != ""
}

// Write sends the stop answer.
func Write(w http.ResponseWriter, r *http.Request, status int, incident string, now time.Time) {
	retry := 0
	if status == http.StatusServiceUnavailable {
		retry = 5
	}
	write(w, r, status, KindForStatus(status), incident, retry, time.Time{}, now)
}

// WritePaused answers a request of a client key that a behaviour scenario
// blocked until `until` (403, Retry-After, incident number for the unblock
// request). MVP-17.
func WritePaused(w http.ResponseWriter, r *http.Request, incident string, until, now time.Time) {
	retry := int(until.Sub(now).Round(time.Second) / time.Second)
	write(w, r, http.StatusForbidden, KindPaused, incident, max(retry, 1), until, now)
}

// WriteRateLimited answers 429 with Retry-After: the calm page for browsers,
// RFC 9457 problem details (code rate_limited) for API clients. No incident:
// the limit ends by itself within seconds. MVP-17.
func WriteRateLimited(w http.ResponseWriter, r *http.Request, retryAfter int, now time.Time) {
	write(w, r, http.StatusTooManyRequests, KindRateLimited, "", max(retryAfter, 1), time.Time{}, now)
}

// WriteBodyShare answers a client over its share of bodies being read (D41):
// 429 with Retry-After, the calm page of rate limits for a document
// navigation, problem details with code for everything else. No incident.
func WriteBodyShare(w http.ResponseWriter, r *http.Request, document bool, code string, retryAfter int, now time.Time) {
	if document {
		write(w, r, http.StatusTooManyRequests, KindRateLimited, "", retryAfter, time.Time{}, now)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Retry-After", strconv.Itoa(retryAfter))
	writeProblemCode(w, http.StatusTooManyRequests, KindRateLimited, code, "", retryAfter, r.Method != http.MethodHead)
}

// WriteProblem sends 503 problem details whatever the client's Accept says:
// the D37 answer to an overloaded request that is no document navigation
// (contracts/waiting-page.md section 4). Code and type are waiting (D37
// amendment, before: timeout), title and detail stay those of the 503
// problem; Retry-After and retry_after are retry, and the response carries
// the marker Schild-Waiting: 1. body false (HEAD) sends the headers only.
func WriteProblem(w http.ResponseWriter, incident string, retry int, body bool) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if incident != "" {
		h.Set("X-Schild-Incident", incident)
	}
	h.Set("Retry-After", strconv.Itoa(retry))
	h.Set(waitingpage.MarkerHeader, waitingpage.MarkerValue)
	writeProblemCode(w, http.StatusServiceUnavailable, KindTimeout, waitingpage.ProblemCode, incident, retry, body)
}

func writeProblem(w http.ResponseWriter, status int, kind, incident string, retry int, body bool) {
	writeProblemCode(w, status, kind, kind, incident, retry, body)
}

// writeProblemCode writes problem details with the copy of kind and the
// code (and type) code.
func writeProblemCode(w http.ResponseWriter, status int, kind, code, incident string, retry int, body bool) {
	t := texts[kind]
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	if !body {
		return
	}
	p := Problem{
		Type:       "https://schild.invalid/problems/" + code,
		Title:      t.Title,
		Status:     status,
		Detail:     t.Lead + " " + t.Next,
		Code:       code,
		Incident:   incident,
		RetryAfter: retry,
	}
	if incident != "" {
		p.Instance = "urn:schild:incident:" + incident
	}
	_ = json.NewEncoder(w).Encode(p)
}

func write(w http.ResponseWriter, r *http.Request, status int, kind, incident string, retry int, until, now time.Time) {
	t := texts[kind]
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if incident != "" {
		h.Set("X-Schild-Incident", incident)
	}
	if retry > 0 {
		h.Set("Retry-After", strconv.Itoa(retry))
	}
	if WantsJSON(r) {
		writeProblem(w, status, kind, incident, retry, true)
		return
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", pagekit.CSP)
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	d := pageData{copyText: t, Incident: incident, Status: status, Time: now.UTC().Format("2006-01-02 15:04:05")}
	if !until.IsZero() {
		d.Until = until.UTC().Format("15:04")
	} else if kind == KindRateLimited {
		d.Retry = retry
	}
	_ = page.Execute(w, d)
}
