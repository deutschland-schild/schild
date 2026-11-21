// Package dashboard serves the client dashboard API (/api/v0, contracts/api/
// client-dashboard.openapi.yaml) and the embedded dashboard UI on the
// dashboard port (default 127.0.0.1:8788, never on the proxy port).
//
// Security: login with an argon2id password (first password needs the
// one-time setup code from the server log, also from localhost),
// session cookie HttpOnly + SameSite=Strict (+ Secure whenever the browser
// came over HTTPS, D76), X-CSRF-Token on every change, Origin check, Host
// check against DNS rebinding (dashboard.allowed_hosts), login rate limit,
// strict CSP, no third-party requests. Full visitor IPs are shown here (E7);
// nothing in this API is ever sent anywhere.
package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/firewall"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/gate"
	"github.com/deutschland-schild/schild/gateway/internal/geo"
	"github.com/deutschland-schild/schild/gateway/internal/hosts"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/passhash"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Server is the dashboard.
type Server struct {
	St          *store.Store
	Gate        *gate.Gate
	Allow       *allowlist.List
	Geo         *geo.DB
	Events      *eventlog.Log
	Config      func() *config.Site
	Apply       func(ctx context.Context, p SettingsPatch) (*config.Site, error)
	ReloadAllow func(ctx context.Context) error
	// SetupCode is the first-run code printed to the server log; a reset
	// on the host (ResetAccess, LoadPendingSetup) replaces it by a hash.
	SetupCode string
	// Listen is listen.dashboard; its host passes the Host check (D76).
	Listen     string
	Version    string
	CRSVersion string
	Started    time.Time
	Log        *slog.Logger
	Now        func() time.Time
	UI         http.Handler
	// ScriptHashes are CSP hashes of inline scripts in the UI's index.html.
	ScriptHashes []string
	// ProxiesTooBroad: ingress.trusted_proxies is too broad, forwarding
	// headers are ignored (trusted_proxies_too_broad, D40).
	ProxiesTooBroad bool
	// ProxyMissing: a proxy in front is not trusted (trusted_proxies_missing,
	// D91); nil never.
	ProxyMissing func(time.Time) bool
	// SettingsDropped: settings stored by the dashboard did not fit
	// schild.yaml at start and are not applied (dashboard_settings_dropped,
	// D78); nil is false.
	SettingsDropped func() bool
	// Hosts is the v0.3 server check and agents (MVP-11); nil without
	// host_check in schild.yaml (the Server section is then empty).
	Hosts *hosts.Gateway
	// Repos are the rule repositories (D73), the same service as the agent
	// API's; nil answers 404.
	Repos *ruleset.Registry
	// Access is the access lock of the websites (D56).
	Access AccessFuncs
	// HumanCheck is browser verification and Under Attack (MVP-12 v1_cut).
	HumanCheck HumanCheckFuncs
	// Exceptions lists the rule exceptions in force (D83); nil: none.
	Exceptions func(ctx context.Context) []contractapi.RuleException
	// CreateException and RemoveException set and remove one in the dashboard
	// (D84); a refusal is an *ExceptionRefused. nil: not available.
	CreateException func(ctx context.Context, req contractapi.ExceptionRequest) (contractapi.RuleException, error)
	// RemoveException with rules takes only those out (D86).
	RemoveException func(ctx context.Context, id int, rules []string) (bool, error)
	// Crawlers is crawler control of the websites (D57).
	Crawlers CrawlerFuncs
	// Behaviour is MVP-17 (v0.4); nil disables the behaviour operations.
	Behaviour *behaviour.Engine
	// FirewallState is what `schild firewall run` said in its last call
	// (D87); nil or ok false: no firewall has called.
	FirewallState func() (firewall.Report, bool)
	// OwnAddress and GeoOf serve createBlock (D88): an own address is never
	// blocked, the net class of a shared one needs a confirmation.
	OwnAddress         func(ip netip.Addr) bool
	GeoOf              func(ip netip.Addr) events.Geo
	ApplyBehaviour     func(ctx context.Context, scenarios map[string]string, thresholds map[string]config.Thresholds, presetLimitModes map[string]string) (*config.Site, error)
	SetDashboardLimits func(ctx context.Context, limits []config.RateLimit) (*config.Site, error)
	DashboardLimits    func() []config.RateLimit
	InstalledAt        func(ctx context.Context) time.Time
	// ApplyDistributed switches MVP-18 detectors (settings overlay).
	ApplyDistributed func(ctx context.Context, detectors map[string]string, thresholds map[string]config.DetectorThresholds) (*config.Site, error)
	// Monitor is MVP-21 (v0.4 tag monitoring); nil answers 409 monitoring_off.
	Monitor *monitoring.Monitor
	// Requests is the MVP-22 request ring (nil: off, 409 requests_off).
	Requests *reqring.Ring
	// Bots is the MVP-22 bot catalogue and verification (nil: none).
	Bots reqring.BotDirectory
	// fp caches the possible false positives per website (AlertItem).
	fp fpCache
	// Sites are the websites of this gateway (v0.5, D36).
	Sites *sites.Registry

	mu           sync.Mutex
	once         sync.Once
	reasonsSince map[string]time.Time
	// loginFails holds the password and setup code attempts per key (see
	// attempt): failed ones and the ones still being checked.
	loginFails map[string][]time.Time
	// hashes bounds the password checks running at once (maxHashes).
	hashes chan struct{}
	// streamCheck is the keep-alive interval of the event stream, which
	// also re-checks the session (0: 15 s; tests shorten it).
	streamCheck time.Duration
	// setupMu guards SetupCode after start and setupHash (SHA-256 of the
	// pending code of `schild dashboard reset-password`).
	setupMu   sync.Mutex
	setupHash []byte
}

const (
	cookieName = "schild_session"
	apiPrefix  = "/api/v0"
)

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Handler returns the dashboard handler (API, UI, health).
func (s *Server) Handler() http.Handler {
	s.once.Do(func() {
		s.reasonsSince = map[string]time.Time{}
		s.loginFails = map[string][]time.Time{}
		s.hashes = make(chan struct{}, maxHashes)
	})
	mux := http.NewServeMux()
	a := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.auth(h)) }
	mux.HandleFunc("GET "+apiPrefix+"/auth/session", s.getSession)
	mux.HandleFunc("POST "+apiPrefix+"/auth/setup", s.setup)
	mux.HandleFunc("POST "+apiPrefix+"/auth/login", s.login)
	a("POST "+apiPrefix+"/auth/logout", s.logout)
	a("POST "+apiPrefix+"/auth/password", s.changePassword)
	a("GET "+apiPrefix+"/overview", s.getOverview)
	a("GET "+apiPrefix+"/events", s.listEvents)
	a("GET "+apiPrefix+"/events/stream", s.streamEvents)
	a("GET "+apiPrefix+"/events/{id}", s.getEvent)
	a("GET "+apiPrefix+"/incidents/{incident}", s.getIncident)
	a("POST "+apiPrefix+"/incidents/{incident}/export", s.exportIncident)
	a("POST "+apiPrefix+"/incidents/{incident}/unblock", s.unblock)
	a("GET "+apiPrefix+"/rule-repositories", s.listRuleRepositories)
	a("GET "+apiPrefix+"/rule-repositories/{repository}", s.getRuleRepository)
	a("PATCH "+apiPrefix+"/rule-repositories/{repository}", s.updateRuleRepository)
	a("PATCH "+apiPrefix+"/rule-repositories/{repository}/settings", s.updateRuleRepositorySettings)
	a("POST "+apiPrefix+"/rule-repositories/{repository}/sync", s.syncRuleRepository)
	a("POST "+apiPrefix+"/rule-repositories/{repository}/reset", s.resetRuleRepository)
	a("GET "+apiPrefix+"/rule-exceptions", s.listRuleExceptions)
	a("POST "+apiPrefix+"/rule-exceptions", s.createRuleException)
	a("DELETE "+apiPrefix+"/rule-exceptions/{id}", s.removeRuleException)
	a("DELETE "+apiPrefix+"/rule-exceptions/{id}/rules/{rule}", s.removeRuleExceptionRule)
	a("GET "+apiPrefix+"/rules", s.listRules)
	a("GET "+apiPrefix+"/rules/{repository}/{rule}", s.getRule)
	a("PATCH "+apiPrefix+"/rules/{repository}/{rule}", s.updateRule)
	a("GET "+apiPrefix+"/allowlist", s.listAllow)
	a("POST "+apiPrefix+"/allowlist", s.addAllow)
	a("GET "+apiPrefix+"/allowlist/mine", s.getMine)
	a("POST "+apiPrefix+"/allowlist/mine", s.allowMine)
	a("DELETE "+apiPrefix+"/allowlist/{id}", s.deleteAllow)
	a("GET "+apiPrefix+"/settings", s.getSettings)
	a("PATCH "+apiPrefix+"/settings", s.patchSettings)
	a("GET "+apiPrefix+"/privacy/search", s.privacySearch)
	a("POST "+apiPrefix+"/privacy/export", s.privacyExport)
	a("POST "+apiPrefix+"/privacy/delete", s.privacyDelete)
	s.hostRoutes(a)
	s.behaviourRoutes(a)
	s.distributedRoutes(a)
	s.Monitor.Routes(func(pattern string, h http.HandlerFunc) {
		if strings.HasSuffix(pattern, "/monitoring/stream") {
			h = s.whileSession(h)
		}
		a(pattern, h)
	}, apiPrefix)
	s.websiteRoutes(a)
	mux.HandleFunc(apiPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
		problem(w, http.StatusNotFound, "not_found", "Diese Schnittstelle gibt es nicht.", nil)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.Gate != nil && !s.Gate.Ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "not ready\n")
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	if s.UI != nil {
		mux.Handle("/", s.UI)
	}
	return s.secure(s.checkHost(mux))
}

func (s *Server) secure(next http.Handler) http.Handler {
	scripts := "'self'"
	for _, h := range s.ScriptHashes {
		scripts += " " + h
	}
	csp := "default-src 'self'; script-src " + scripts + "; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
		"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		if strings.HasPrefix(r.URL.Path, apiPrefix) {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

var titles = map[string]string{
	"unauthenticated": "Not logged in", "csrf": "CSRF token missing or wrong", "forbidden": "Forbidden", "not_found": "Not found",
	"conflict": "Conflict", "invalid": "Invalid input", "rate_limited": "Too many attempts", "internal": "Internal error",
	"config_limit": "Set in schild.yaml",
}

func problem(w http.ResponseWriter, status int, code, detail string, errs []FieldError) {
	t := titles[code]
	if t == "" {
		t = http.StatusText(status)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Problem{Type: "https://schild.invalid/problems/" + code, Title: t, Status: status, Detail: detail, Code: code, Errors: errs})
}

func invalid(w http.ResponseWriter, detail string, errs ...FieldError) {
	problem(w, http.StatusBadRequest, "invalid", detail, errs)
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	if s.Log != nil {
		ratelog.Error(s.Log, "dashboard", "err", err)
	}
	problem(w, http.StatusInternalServerError, "internal", "Das hat nicht geklappt. Versuch es bitte noch einmal; Details stehen im Server-Log.", nil)
}

// bodyReadTimeout bounds reading a request body (at most 1 MiB). The
// dashboard server sets only ReadHeaderTimeout (a ReadTimeout would also
// end the event stream), so without it a client could hold a connection,
// login and setup included, by sending its body a byte at a time.
var bodyReadTimeout = 30 * time.Second

// decode reads a JSON body strictly (unknown fields are errors).
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	// The whole body (at most 1 MiB) must arrive within bodyReadTimeout.
	// The deadline is lifted once the body is read: net/http then watches
	// the connection with a background read, and a deadline that expired
	// would cancel the request's context while the handler still works.
	// After a failed read it stays, so the server does not wait for the
	// rest of a stalled body either. Writers without deadlines (tests)
	// report ErrNotSupported.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(bodyReadTimeout))
	body := http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		_, err = io.Copy(io.Discard, body)
	}
	if err != nil {
		var ute *json.UnmarshalTypeError
		var fe []FieldError
		if errors.As(err, &ute) && ute.Field != "" {
			fe = append(fe, FieldError{Pointer: "/" + strings.ReplaceAll(ute.Field, ".", "/"), Detail: "falscher Typ"})
		} else if f, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
			fe = append(fe, FieldError{Pointer: "/" + strings.Trim(f, `"`), Detail: "unbekanntes Feld"})
		}
		invalid(w, "Die Anfrage ist kein gültiges JSON für diese Schnittstelle.", fe...)
		return false
	}
	_ = rc.SetReadDeadline(time.Time{})
	return true
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func tsp(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	v := ts(t)
	return &v
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------- passwords

// HashPassword returns an encoded argon2id hash.
func HashPassword(pw string) string { return passhash.Hash(pw) }

// dummyHash makes a login for an unknown user cost as much as a wrong
// password, so timing does not tell which user names exist.
var dummyHash = sync.OnceValue(func() string { return HashPassword("schild-no-such-user") })

// CheckPassword verifies pw against an encoded argon2id hash.
func CheckPassword(encoded, pw string) bool { return passhash.Check(encoded, pw) }

// ---------------------------------------------------------------- sessions

type ctxKey struct{}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func (s *Server) sessionTTL() time.Duration {
	if s.Config != nil {
		if c := s.Config(); c != nil && c.Dashboard.SessionTTLMinutes > 0 {
			return time.Duration(c.Dashboard.SessionTTLMinutes) * time.Minute
		}
	}
	return 12 * time.Hour
}

// secureCookie decides the Secure attribute of the session cookie (D76).
//
// Secure whenever the browser reached the dashboard over HTTPS: TLS on this
// connection, a proxy that says so, or an https Origin. Not Secure on
// loopback, and not when the browser itself says it is on plain HTTP on this
// very host (Origin http://<Host>, a VPN or LAN address): browsers drop a
// Secure cookie set over plain HTTP, so the login would succeed and the next
// request would be logged out again. Leaving the attribute off there takes
// nothing away, the cookie already travels in the clear. Without an Origin
// (no browser) the cookie stays Secure outside loopback, as before.
func secureCookie(r *http.Request) bool {
	if r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	if loopbackHost(r.Host) {
		return false
	}
	return r.Header.Get("Origin") != "http://"+r.Host
}

// hostName is the host of a Host header or listen address: without port,
// brackets and trailing dot, in lower case.
func hostName(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
}

func loopbackHost(hostport string) bool {
	host := hostName(hostport)
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// AllowedHostsKey is the config key named by the answer to a refused Host.
const AllowedHostsKey = "dashboard.allowed_hosts"

// hostAllowed is the Host check of the dashboard (D76). It stops DNS
// rebinding: a page on a foreign name that resolves to the dashboard's
// address would otherwise be the same origin for the browser. Allowed are
// localhost, every IP address (an address cannot be rebound: the browser's
// origin is then the dashboard itself, also behind a port mapping), the host
// of listen.dashboard and the names of dashboard.allowed_hosts. A request
// without Host (HTTP/1.0, no browser) passes.
func (s *Server) hostAllowed(hostport string) bool {
	host := hostName(hostport)
	if host == "" || host == "localhost" {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if s.Listen != "" && host == hostName(s.Listen) {
		return true
	}
	if s.Config != nil {
		if c := s.Config(); c != nil {
			for _, h := range c.Dashboard.AllowedHosts {
				if host == hostName(h) {
					return true
				}
			}
		}
	}
	return false
}

// checkHost refuses requests for a host name the dashboard does not know.
// The health paths stay open for probes that send any name.
func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || s.hostAllowed(r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		name := hostName(r.Host)
		if len(name) > 80 {
			name = name[:80]
		}
		if s.Log != nil {
			ratelog.Warn(s.Log, "dashboard: request for a host name that is not allowed refused", "host", name, "config_key", AllowedHostsKey)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, "schild dashboard: the host name %q is not allowed here.\n\n"+
			"Open the dashboard with localhost or the IP address of this server, or add the name to %s in schild.yaml and restart schild:\n\n"+
			"dashboard:\n  allowed_hosts: [%q]\n", name, AllowedHostsKey, name)
	})
}

func (s *Server) startSession(ctx context.Context, w http.ResponseWriter, r *http.Request, user string) (*store.Session, error) {
	tok := make([]byte, 32)
	_, _ = rand.Read(tok)
	t := base64.RawURLEncoding.EncodeToString(tok)
	now := s.now()
	se := store.Session{TokenHash: hashToken(t), User: user, CSRF: randHex(16), Created: now, Expires: now.Add(s.sessionTTL())}
	if err := s.St.CreateSession(ctx, se); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: t, Path: "/", HttpOnly: true, Secure: secureCookie(r),
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.sessionTTL() / time.Second)})
	return &se, nil
}

func (s *Server) currentSession(r *http.Request) *store.Session {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return nil
	}
	se, err := s.St.GetSession(r.Context(), hashToken(c.Value), s.now())
	if err != nil {
		return nil
	}
	return se
}

// whileSession ends a long-running answer (the monitoring stream) when its
// session ends: the session is checked at the start of a request only, and
// a logout, a password change, `schild dashboard reset-password` or the
// expiry must close an open stream as well. It cancels the request context,
// which the handler watches.
func (s *Server) whileSession(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		every := s.streamCheck
		if every <= 0 {
			every = 15 * time.Second
		}
		go func() {
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if s.currentSession(r) == nil {
						cancel()
						return
					}
				}
			}
		}()
		h(w, r.WithContext(ctx))
	}
}

func sessionOf(r *http.Request) *store.Session {
	se, _ := r.Context().Value(ctxKey{}).(*store.Session)
	return se
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// originOK rejects cross-site requests: when a browser sends Origin it must
// be this dashboard.
func originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	return o == "http://"+r.Host || o == "https://"+r.Host
}

func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		se := s.currentSession(r)
		if se == nil {
			problem(w, http.StatusUnauthorized, "unauthenticated", "Bitte melde dich an.", nil)
			return
		}
		if unsafeMethod(r.Method) {
			tok := r.Header.Get("X-CSRF-Token")
			if !originOK(r) || tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(se.CSRF)) != 1 {
				problem(w, http.StatusForbidden, "csrf", "Die Sitzung passt nicht zu dieser Anfrage. Lade die Seite neu und versuch es noch einmal.", nil)
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, se)))
	})
}

func (s *Server) sessionView(se *store.Session) Session {
	return Session{Authenticated: true, FirstRun: false, User: se.User, Role: "admin", CSRFToken: se.CSRF, ExpiresAt: ts(se.Expires), Via: "password"}
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	if !s.St.HasUsers(r.Context()) {
		writeJSON(w, 200, Session{Authenticated: false, FirstRun: true})
		return
	}
	se := s.currentSession(r)
	if se == nil {
		writeJSON(w, 200, Session{Authenticated: false, FirstRun: false})
		return
	}
	writeJSON(w, 200, s.sessionView(se))
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var req SetupRequest
	if !originOK(r) {
		problem(w, http.StatusForbidden, "csrf", "Anfrage von einer fremden Seite.", nil)
		return
	}
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	if s.St.HasUsers(ctx) {
		problem(w, http.StatusConflict, "conflict", "Das Passwort ist schon gesetzt. Melde dich an.", nil)
		return
	}
	// Always the code, also from loopback (D40): a process on this host or a
	// request a local proxy forwards without its headers is no proof of an
	// operator. Nobody with host access is locked out: the code is in the log.
	succeeded, ok := s.attempt(w, loginKey(r))
	if !ok {
		return
	}
	if !s.setupCodeOK(req.SetupCode) {
		problem(w, http.StatusForbidden, "forbidden", "Der Einrichtungscode stimmt nicht. Du findest ihn im Server-Log von schild.",
			[]FieldError{{Pointer: "/setup_code", Detail: "Code aus dem Server-Log eingeben"}})
		return
	}
	succeeded()
	if len(req.Password) < 12 || len(req.Password) > 256 {
		invalid(w, "Das Passwort braucht mindestens 12 Zeichen.", FieldError{Pointer: "/password", Detail: "mindestens 12 Zeichen"})
		return
	}
	if err := s.St.CreateFirstUser(ctx, store.User{Name: "admin", Hash: HashPassword(req.Password), Role: "admin"}); err != nil {
		problem(w, http.StatusConflict, "conflict", "Das Passwort ist schon gesetzt. Melde dich an.", nil)
		return
	}
	if err := s.setupDone(ctx); err != nil && s.Log != nil {
		s.Log.Warn("dashboard: pending setup code not cleared", "err", err)
	}
	se, err := s.startSession(ctx, w, r, "admin")
	if err != nil {
		s.internal(w, err)
		return
	}
	if s.Log != nil {
		s.Log.Info("dashboard password set")
	}
	writeJSON(w, 200, s.sessionView(se))
}

// loginKey is the peer address, for IPv6 its /64: one host usually owns a
// whole /64, so single addresses would each bring a fresh budget.
func loginKey(r *http.Request) string {
	p, _ := clientip.Peer(r.RemoteAddr)
	if p.IsValid() && !p.Is4() {
		if pre, err := p.Prefix(64); err == nil {
			return pre.String()
		}
	}
	return p.String()
}

// sessionKey is the attempt key of the password checks behind a session
// (password change, the confirmation of updateSettings): a stolen session
// gets a few guesses at the password, not an unlimited number, and the
// owner's other sessions and logins keep their own budget.
func sessionKey(se *store.Session) string { return "session:" + se.TokenHash }

// maxAttempts per key in the 15 minute window.
const maxAttempts = 5

// attempt takes one of the maxAttempts attempts of key before a password or
// setup code is checked. The attempt is taken under the lock, so parallel
// requests cannot all pass the limit before the first failure is counted
// (each password check takes a while). A failed check keeps it: it is the
// failure. A successful one gives it back with succeeded. Without an
// attempt left, attempt answers 429 itself and returns ok false.
func (s *Server) attempt(w http.ResponseWriter, key string) (succeeded func(), ok bool) {
	now := s.now()
	s.mu.Lock()
	var recent []time.Time
	for _, t := range s.loginFails[key] {
		if now.Sub(t) < 15*time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= maxAttempts {
		s.loginFails[key] = recent
		s.mu.Unlock()
		w.Header().Set("Retry-After", "900")
		problem(w, http.StatusTooManyRequests, "rate_limited", "Zu viele Versuche. Warte bitte 15 Minuten.", nil)
		return nil, false
	}
	s.loginFails[key] = append(recent, now)
	s.evictLoginFails()
	s.mu.Unlock()
	return func() { s.giveBack(key, now) }, true
}

// giveBack removes the attempt of key taken at t (a successful check).
func (s *Server) giveBack(key string, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.loginFails[key]
	for i := len(ts) - 1; i >= 0; i-- {
		if ts[i].Equal(t) {
			ts = slices.Delete(ts, i, i+1)
			break
		}
	}
	if len(ts) == 0 {
		delete(s.loginFails, key)
		return
	}
	s.loginFails[key] = ts
}

// maxHashes bounds the argon2id password checks running at once (19 MiB of
// memory each), whatever the number of addresses that try to log in.
const maxHashes = 4

// checkPassword is CheckPassword within maxHashes; false when ctx ends
// while it waits.
func (s *Server) checkPassword(ctx context.Context, encoded, pw string) bool {
	select {
	case s.hashes <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	defer func() { <-s.hashes }()
	return CheckPassword(encoded, pw)
}

// maxLoginKeys bounds the failed-login map.
const maxLoginKeys = 10000

// evictLoginFails keeps the map bounded without forgetting a running count:
// above the bound it drops keys with nothing left in the 15 minute window,
// then the key with the fewest attempts (oldest first among equals), so a
// key close to its limit outlives a flood of one-off addresses. Flushing the
// map instead would let 10,000 addresses reset the budget of every other
// one. Runs under s.mu, only when an attempt is taken and only above the
// bound, so its O(n) is cheap next to the password hash that follows.
func (s *Server) evictLoginFails() {
	if len(s.loginFails) <= maxLoginKeys {
		return
	}
	now := s.now()
	for k, ts := range s.loginFails {
		if n := len(ts); n == 0 || now.Sub(ts[n-1]) >= 15*time.Minute {
			delete(s.loginFails, k)
		}
	}
	for len(s.loginFails) > maxLoginKeys {
		var pick string
		var fails int
		var at time.Time
		for k, ts := range s.loginFails {
			t := ts[len(ts)-1]
			if pick == "" || len(ts) < fails || (len(ts) == fails && t.Before(at)) {
				pick, fails, at = k, len(ts), t
			}
		}
		delete(s.loginFails, pick)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !originOK(r) {
		problem(w, http.StatusForbidden, "csrf", "Anfrage von einer fremden Seite.", nil)
		return
	}
	var req LoginRequest
	if !decode(w, r, &req) {
		return
	}
	succeeded, ok := s.attempt(w, loginKey(r))
	if !ok {
		return
	}
	user := req.User
	if user == "" {
		user = "admin"
	}
	u, err := s.St.GetUser(r.Context(), user)
	if err != nil {
		s.checkPassword(r.Context(), dummyHash(), req.Password) // same work as for a known user
	}
	if err != nil || !s.checkPassword(r.Context(), u.Hash, req.Password) {
		problem(w, http.StatusUnauthorized, "unauthenticated", "Benutzername oder Passwort stimmen nicht.", []FieldError{{Pointer: "/password", Detail: "stimmt nicht"}})
		return
	}
	succeeded()
	se, err := s.startSession(r.Context(), w, r, u.Name)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, s.sessionView(se))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	_ = s.St.DeleteSession(r.Context(), sessionOf(r).TokenHash)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: secureCookie(r), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req PasswordChange
	if !decode(w, r, &req) {
		return
	}
	se := sessionOf(r)
	succeeded, ok := s.attempt(w, sessionKey(se))
	if !ok {
		return
	}
	u, err := s.St.GetUser(r.Context(), se.User)
	if err != nil || !s.checkPassword(r.Context(), u.Hash, req.CurrentPassword) {
		problem(w, http.StatusUnauthorized, "unauthenticated", "Das aktuelle Passwort stimmt nicht.", []FieldError{{Pointer: "/current_password", Detail: "stimmt nicht"}})
		return
	}
	succeeded()
	if len(req.NewPassword) < 12 || len(req.NewPassword) > 256 {
		invalid(w, "Das neue Passwort braucht mindestens 12 Zeichen.", FieldError{Pointer: "/new_password", Detail: "mindestens 12 Zeichen"})
		return
	}
	if err := s.St.SetPassword(r.Context(), se.User, HashPassword(req.NewPassword)); err != nil {
		s.internal(w, err)
		return
	}
	if _, err := s.startSession(r.Context(), w, r, se.User); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// NewSetupCode returns a one-time setup code (printed to the server log).
func NewSetupCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	out := make([]byte, 0, 14)
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(c)%len(alphabet)])
	}
	return string(out)
}
