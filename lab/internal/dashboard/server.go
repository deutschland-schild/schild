// Package dashboard serves the lab dashboard (MVP-10): the embedded UI and
// the API of contracts/api/lab-dashboard.openapi.yaml under /api/v0, on its
// own listener (default 127.0.0.1:8789), apart from ingest (M6).
//
// Security baseline (conventions §9): login (PBKDF2 passwords) or localhost,
// session cookie HttpOnly/SameSite=Strict, X-CSRF-Token on every state
// change, strict CSP, no third-party requests. Decisions (approve, reject,
// co-sign, withdraw, emergency stop, revoke) need a named user who logged in
// with a password, so every approval names a person. The lab holds no
// visitor IPs, and nothing here returns one.
package dashboard

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/lab/internal/feed"
	"github.com/deutschland-schild/schild/lab/internal/ingest"
	"github.com/deutschland-schild/schild/lab/internal/peers"
	"github.com/deutschland-schild/schild/lab/internal/queue"
	"github.com/deutschland-schild/schild/lab/internal/rules"
	"github.com/deutschland-schild/schild/lab/internal/scoring"
	"github.com/deutschland-schild/schild/lab/internal/settings"
	"github.com/deutschland-schild/schild/lab/internal/store"
	"github.com/deutschland-schild/schild/lab/internal/webui"
)

// Deps are the lab parts the dashboard reads and drives.
type Deps struct {
	DB       *store.DB
	Engine   *rules.Engine
	Scorer   *scoring.Scorer
	Ingest   *ingest.Ingest
	Queue    *queue.Queue
	Feed     *feed.Feed
	Peers    *peers.Manager
	Settings *settings.Manager
	Log      *slog.Logger
	Now      func() time.Time
}

// Server is the dashboard HTTP handler.
type Server struct {
	d    Deps
	Auth *Auth
	live *liveHub
	mux  *http.ServeMux
}

// New builds the dashboard.
func New(d Deps, sessionTTL time.Duration) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &Server{d: d, Auth: newAuth(d.DB, sessionTTL, d.Now), live: newLiveHub()}
	s.routes()
	return s
}

func (s *Server) routes() {
	m := http.NewServeMux()
	api := func(pattern string, h http.HandlerFunc, opts ...opt) {
		method, path, _ := strings.Cut(pattern, " ")
		m.Handle(method+" /api/v0"+path, s.guard(h, opts...))
	}
	api("GET /auth/session", s.getSession, public())
	api("POST /auth/setup", s.setup, public(), noCSRF())
	api("POST /auth/login", s.login, public(), noCSRF())
	api("POST /auth/logout", s.logout)
	api("GET /health", s.health)
	api("GET /events/stream", s.liveStream)
	api("GET /patterns", s.listPatterns)
	api("GET /patterns/{pattern_id}", s.getPattern)
	api("GET /signals", s.listSignals)
	api("GET /proposals", s.listProposals)
	api("POST /proposals", s.createProposal)
	api("GET /proposals/{id}", s.getProposal)
	api("PATCH /proposals/{id}", s.updateProposal)
	api("POST /proposals/{id}/evidence", s.addEvidence)
	api("POST /proposals/{id}/approve", s.approve, named())
	api("POST /proposals/{id}/reject", s.reject, named())
	api("GET /bundles", s.listBundles)
	api("POST /bundles", s.assembleBundle, named())
	api("GET /bundles/{version}", s.getBundle)
	api("POST /bundles/{version}/cosign", s.cosignBundle, named())
	api("GET /withdrawals", s.listWithdrawals)
	api("POST /withdrawals", s.createWithdrawal, named())
	api("POST /emergency-stop", s.emergencyStop, named())
	api("POST /withdrawals/{seq}/cosign", s.cosignWithdrawal, named())
	api("GET /relays", s.listRelays)
	api("GET /peers", s.listPeers)
	api("GET /log", s.listLog)
	api("GET /log/{index}", s.getLogEntry)
	api("GET /issuers", s.listIssuers)
	api("PATCH /issuers/{id}", s.updateIssuer, named())
	api("POST /issuers/{id}/revoke", s.revokeIssuer, named())
	api("GET /clients", s.listClients)
	api("PATCH /clients/{keyid}", s.updateClient, named())
	api("POST /clients/{keyid}/revoke", s.revokeClient, named())
	api("GET /settings", s.getSettings)
	api("PATCH /settings", s.updateSettings, named())
	m.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		problem(w, http.StatusNotFound, "not_found", "no such API endpoint", nil)
	}))
	m.Handle("/", webui.Handler())
	s.mux = m
}

// ServeHTTP adds the security headers to every response.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	s.mux.ServeHTTP(w, r)
}

type guardOpts struct{ public, noCSRF, named bool }
type opt func(*guardOpts)

func public() opt { return func(o *guardOpts) { o.public = true } }
func noCSRF() opt { return func(o *guardOpts) { o.noCSRF = true } }
func named() opt  { return func(o *guardOpts) { o.named = true } }

type ctxKey struct{}

// guard enforces session, CSRF and named-user rules.
func (s *Server) guard(h http.HandlerFunc, opts ...opt) http.Handler {
	var o guardOpts
	for _, f := range opts {
		f(&o)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		sess := s.Auth.lookup(r)
		if !o.public && sess == nil {
			problem(w, http.StatusUnauthorized, "unauthenticated", "log in first", nil)
			return
		}
		if sess != nil && !o.noCSRF && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if tok := r.Header.Get(csrfHeader); len(tok) < 16 || tok != sess.csrf {
				problem(w, http.StatusForbidden, "csrf", "missing or wrong X-CSRF-Token", nil)
				return
			}
		}
		if o.named && (sess == nil || sess.via != "password") {
			problem(w, http.StatusForbidden, "forbidden", "decisions need a named person: log in with your user name and password", nil)
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			h(w, r.WithContext(withSession(r, sess)))
			return
		}
		// State changes notify live views of the topic they touched.
		sw := &statusWriter{ResponseWriter: w}
		h(sw, r.WithContext(withSession(r, sess)))
		if sw.status < 300 {
			if topic := topicOf(r.URL.Path); topic != "" {
				s.live.publish(topic, liveNotice{Topic: topic, Ref: r.PathValue("id") + r.PathValue("version") + r.PathValue("seq") + r.PathValue("keyid")})
			}
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// --- helpers --------------------------------------------------------------------

type fieldError struct {
	Pointer string `json:"pointer"`
	Detail  string `json:"detail"`
}

func problem(w http.ResponseWriter, status int, code, detail string, errs []fieldError) {
	body := map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code}
	if detail != "" {
		body["detail"] = detail
	}
	if len(errs) > 0 {
		body["errors"] = errs
	}
	b, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	w.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "response could not be encoded", nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

// fail maps domain errors to problems.
func (s *Server) fail(w http.ResponseWriter, err error) {
	var re *rules.Error
	var nf settings.ErrNotFound
	switch {
	case errors.As(err, &re):
		var errs []fieldError
		if re.Pointer != "" {
			errs = []fieldError{{Pointer: re.Pointer, Detail: re.Detail}}
		}
		problem(w, re.Status, re.Code, re.Detail, errs)
	case errors.As(err, &nf):
		problem(w, http.StatusNotFound, "not_found", nf.What, nil)
	default:
		s.d.Log.Error("dashboard request failed", "err", err)
		problem(w, http.StatusInternalServerError, "internal", "internal error", nil)
	}
}

// decode reads a JSON body strictly (unknown fields are an error).
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 256<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var ute *json.UnmarshalTypeError
		var errs []fieldError
		if errors.As(err, &ute) {
			errs = []fieldError{{Pointer: "/" + strings.ReplaceAll(ute.Field, ".", "/"), Detail: "wrong type"}}
		}
		problem(w, http.StatusBadRequest, "invalid", "request body: "+err.Error(), errs)
		return false
	}
	return true
}

// page parses cursor (opaque offset) and limit.
func page(w http.ResponseWriter, r *http.Request) (offset, limit int, ok bool) {
	limit = 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			problem(w, http.StatusBadRequest, "invalid", "limit must be 1..500", []fieldError{{Pointer: "#/query/limit", Detail: "1..500"}})
			return 0, 0, false
		}
		limit = n
	}
	if c := r.URL.Query().Get("cursor"); c != "" {
		b, err := base64.RawURLEncoding.DecodeString(c)
		n, err2 := strconv.Atoi(strings.TrimPrefix(string(b), "o:"))
		if err != nil || err2 != nil || n < 0 || !strings.HasPrefix(string(b), "o:") {
			problem(w, http.StatusBadRequest, "invalid", "unknown cursor", []fieldError{{Pointer: "#/query/cursor", Detail: "unknown cursor"}})
			return 0, 0, false
		}
		offset = n
	}
	return offset, limit, true
}

func nextCursor(next int) *string {
	if next < 0 {
		return nil
	}
	c := base64.RawURLEncoding.EncodeToString([]byte("o:" + strconv.Itoa(next)))
	return &c
}

func queryTime(w http.ResponseWriter, r *http.Request, name string) (time.Time, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return time.Time{}, true
	}
	if i := strings.IndexByte(v, '.'); i > 0 && strings.HasSuffix(v, "Z") {
		v = v[:i] + "Z"
	}
	t, err := msg.ParseTime(v)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid", name+" must be an RFC 3339 UTC timestamp", []fieldError{{Pointer: "#/query/" + name, Detail: "timestamp"}})
		return time.Time{}, false
	}
	return t, true
}

func fmtTimePtr(t *time.Time) *string {
	if t == nil || t.IsZero() {
		return nil
	}
	s := msg.FormatTime(*t)
	return &s
}
