package monitoring

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"

	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// HTTP handlers of the seven monitoring operations. The dashboard (session
// auth, /api/v0) and the agent API (bearer token, /agent/v0) register the
// same handlers under their prefix; authentication is the caller's.

type fieldError struct {
	Pointer string `json:"pointer"`
	Detail  string `json:"detail"`
}

type problemBody struct {
	Type   string       `json:"type"`
	Title  string       `json:"title"`
	Status int          `json:"status"`
	Detail string       `json:"detail,omitempty"`
	Code   string       `json:"code"`
	Errors []fieldError `json:"errors,omitempty"`
}

var problemTitles = map[string]string{"invalid": "Invalid input", "monitoring_off": "Monitoring off", "too_many_points": "Too many points",
	"rate_limited": "Too many subscribers", "internal": "Internal error"}

// Problem writes an RFC 9457 problem with a stable code.
func Problem(w http.ResponseWriter, status int, code, detail string, errs ...fieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	t := problemTitles[code]
	if t == "" {
		t = http.StatusText(status)
	}
	_ = json.NewEncoder(w).Encode(problemBody{Type: "https://schild.invalid/problems/" + code, Title: t, Status: status, Detail: detail, Code: code, Errors: errs})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func off(w http.ResponseWriter) {
	Problem(w, http.StatusConflict, "monitoring_off", "Die Auslastungsanzeige ist ausgeschaltet (monitoring.enabled: false in schild.yaml).")
}

func invalid(w http.ResponseWriter, param, detail string) {
	Problem(w, http.StatusBadRequest, "invalid", detail, fieldError{Pointer: "#/query/" + param, Detail: detail})
}

func (m *Monitor) failed(w http.ResponseWriter, err error) {
	var inv *ErrInvalid
	switch {
	case errors.As(err, &inv):
		invalid(w, inv.Param, inv.Msg)
	case errors.Is(err, cm.ErrTooManyPoints):
		Problem(w, http.StatusBadRequest, "too_many_points", "More than 1000 points: choose a coarser resolution or a shorter range.", fieldError{Pointer: "#/query/resolution", Detail: "more than 1000 points"})
	case errors.Is(err, ErrUnknownSite):
		invalid(w, "site", "unknown site")
	case errors.Is(err, ErrFilterUnavailable):
		Problem(w, http.StatusConflict, "filter_unavailable", m.FilterUnavailableText(),
			fieldError{Pointer: "#/query/filter", Detail: "needs the request ring"})
	case errors.Is(err, ErrRingBusy):
		Problem(w, http.StatusTooManyRequests, "rate_limited", "Eine andere Abfrage der Einzelanfragen läuft gerade. Versuch es gleich noch einmal.")
	default:
		if m != nil {
			ratelog.Warn(m.log, "monitoring query failed", "err", err)
		}
		Problem(w, http.StatusInternalServerError, "internal", "")
	}
}

// FilterUnavailableText explains a 409 filter_unavailable (German, du).
func (m *Monitor) FilterUnavailableText() string {
	if m == nil || m.cfg.Requests == nil {
		return "Diese Filter-Kombination braucht die Einzelanfragen, und die hebt dieser Server nicht auf (Anfrage-Speicher aus)."
	}
	return "Diese Filter-Kombination geht nur mit den Einzelanfragen der letzten 48 Stunden. Wähl einen kürzeren Zeitraum oder nimm einen Filter weg."
}

func parseTime(w http.ResponseWriter, r *http.Request, name string, def time.Time) (time.Time, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		invalid(w, name, "RFC 3339 time expected")
		return time.Time{}, false
	}
	return t.UTC(), true
}

// Routes registers the monitoring operations under prefix ("/api/v0" or
// "/agent/v0"); m nil (monitoring.enabled false) answers 409 monitoring_off.
func (m *Monitor) Routes(handle func(pattern string, h http.HandlerFunc), prefix string) {
	g := func(path string, h func(http.ResponseWriter, *http.Request, time.Time)) {
		handle("GET "+prefix+path, func(w http.ResponseWriter, r *http.Request) {
			if m == nil {
				off(w)
				return
			}
			h(w, r, time.Now().UTC())
		})
	}
	g("/monitoring/now", m.serveNow)
	g("/monitoring/stream", m.serveStream)
	g("/monitoring/series", m.serveSeries)
	g("/monitoring/traffic/breakdown", m.serveBreakdown)
	g("/monitoring/server", m.serveServer)
	g("/monitoring/catalogue", m.serveCatalogue)
	g("/monitoring/buckets", m.serveBuckets)
}

func (m *Monitor) serveNow(w http.ResponseWriter, r *http.Request, now time.Time) {
	v, err := m.Nodes(r.URL.Query().Get("node"))
	if err != nil {
		m.failed(w, err)
		return
	}
	out, err := v.Now(r.URL.Query().Get("site"), now)
	if err != nil {
		m.failed(w, err)
		return
	}
	writeJSON(w, out)
}

func (m *Monitor) serveServer(w http.ResponseWriter, _ *http.Request, now time.Time) {
	writeJSON(w, m.Snapshot(now))
}

func (m *Monitor) serveCatalogue(w http.ResponseWriter, _ *http.Request, now time.Time) {
	writeJSON(w, m.Catalogue(now))
}

func (m *Monitor) serveSeries(w http.ResponseWriter, r *http.Request, now time.Time) {
	q := r.URL.Query()
	to, ok := parseTime(w, r, "to", now)
	if !ok {
		return
	}
	from, ok := parseTime(w, r, "from", to.Add(-time.Hour))
	if !ok {
		return
	}
	res := q.Get("resolution")
	if res != "" && res != "auto" && res != "10s" && res != "1m" && res != "10m" {
		invalid(w, "resolution", "auto, 10s, 1m or 10m")
		return
	}
	obj := q.Get("object")
	if obj != "" && !validObject(obj) {
		invalid(w, "object", "mount, device or interface name")
		return
	}
	v, err := m.Nodes(q.Get("node"))
	if err != nil {
		m.failed(w, err)
		return
	}
	out, err := v.Series(SeriesQuery{Metrics: q["metric"], From: from, To: to, Resolution: res, Site: q.Get("site"), Object: obj, Filters: q["filter"]}, now)
	if err != nil {
		m.failed(w, err)
		return
	}
	out.Cluster = v.Scope(from, to, now)
	writeJSON(w, out)
}

func (m *Monitor) serveBreakdown(w http.ResponseWriter, r *http.Request, now time.Time) {
	q := r.URL.Query()
	to, ok := parseTime(w, r, "to", now)
	if !ok {
		return
	}
	from, ok := parseTime(w, r, "from", to.Add(-time.Hour))
	if !ok {
		return
	}
	top := 20
	if v := q.Get("top"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			invalid(w, "top", "1 to 100")
			return
		}
		top = n
	}
	v, err := m.Nodes(q.Get("node"))
	if err != nil {
		m.failed(w, err)
		return
	}
	out, err := v.Breakdown(q.Get("by"), from, to, q.Get("site"), q["filter"], top, now)
	if err != nil {
		m.failed(w, err)
		return
	}
	out.Cluster = v.Scope(from, to, now)
	writeJSON(w, out)
}

func (m *Monitor) serveBuckets(w http.ResponseWriter, r *http.Request, now time.Time) {
	q := r.URL.Query()
	from, ok := parseTime(w, r, "from", time.Time{})
	if !ok {
		return
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			invalid(w, "limit", "1 to 500")
			return
		}
		limit = n
	}
	out, err := m.Buckets(q.Get("resolution"), from, q.Get("cursor"), limit, now)
	if err != nil {
		m.failed(w, err)
		return
	}
	writeJSON(w, out)
}

// KeepAlive of the tick stream.
const streamKeepAlive = 15 * time.Second

func (m *Monitor) serveStream(w http.ResponseWriter, r *http.Request, _ time.Time) {
	if err := m.CheckSite(r.URL.Query().Get("site")); err != nil {
		invalid(w, "site", "unknown site")
		return
	}
	var last int64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 || len(v) > 12 {
			Problem(w, http.StatusBadRequest, "invalid", "Last-Event-ID: Unix second expected")
			return
		}
		last = n
	}
	ch, replay, cancel, ok := m.Subscribe(last)
	if !ok {
		w.Header().Set("Retry-After", "10")
		Problem(w, http.StatusTooManyRequests, "rate_limited", "At most 16 live subscribers.")
		return
	}
	defer cancel()
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	send := func(data []byte) bool {
		if _, err := w.Write([]byte("id: " + TickID(data) + "\nevent: tick\ndata: ")); err != nil {
			return false
		}
		if _, err := w.Write(data); err != nil {
			return false
		}
		if _, err := w.Write([]byte("\n\n")); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	_, _ = w.Write([]byte("retry: 3000\n\n"))
	for _, d := range replay {
		if !send(d) {
			return
		}
	}
	_ = rc.Flush()
	ka := time.NewTicker(streamKeepAlive)
	defer ka.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case d := <-ch:
			if !send(d) {
				return
			}
		case <-ka.C:
			if _, err := w.Write([]byte(": keep-alive\n\n")); err != nil || rc.Flush() != nil {
				return
			}
		}
	}
}
