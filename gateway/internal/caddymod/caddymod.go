// Package caddymod embeds Caddy v2 as the HTTP server of `schild run`.
// Schild's request path is the Caddy module http.handlers.schild. Two ways to
// load it:
//
//   - Proxy mode (listen.proxy + upstream): BuildConfig renders one route,
//     schild before reverse_proxy, TLS terminates in front of schild.
//   - Ingress mode (ingress.caddyfile, MVP-19, D31): the operator's Caddyfile
//     is adapted with Caddy's stock Caddyfile adapter and every site block
//     uses the Caddyfile directive `schild` (ingress.go, directive.go). Caddy
//     does TLS and ACME as stock Caddy of the pinned version.
//
// Every http.handlers.schild instance of every config load uses the one gate
// bound with Bind, so a second load never creates a second gate or resets
// counters. The gate itself stays independent of Caddy (internal/gate uses
// plain net/http); this package is only the adapter.
//
// Standard Caddy modules are compiled in as in the stock `caddy` binary
// (modules/standard), so a Caddyfile behaves as with stock Caddy for
// everything schild does not decide. The stock coraza-caddy module
// (http.handlers.waf) is compiled in as well, for operators who build their
// own Caddy routes; schild does not use it: it needs per-request decisions
// (mode, rule sources with their own state), fail-closed timeouts,
// hard limits and an atomic rule swap, which the stock module (one static WAF
// per config load) does not offer. Both use the same Coraza and the same CRS.
package caddymod

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile" // stock Caddyfile adapter
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/standard" // every module of the stock caddy binary
	_ "github.com/corazawaf/coraza-caddy/v2"             // stock http.handlers.waf for custom routes

	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
	"github.com/deutschland-schild/schild/gateway/internal/gate"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// binding is the gate of this process. It is set once per run (Bind) and
// cannot be replaced while bound: a config load provisions new handler
// instances, and each of them picks up the same gate.
var binding struct {
	mu sync.Mutex
	g  *gate.Gate
}

// ErrOtherGate is returned by Bind when a different gate is bound already.
var ErrOtherGate = errors.New("caddymod: a different gate is bound in this process")

// Bind binds g to every http.handlers.schild instance of this process,
// including those of later config loads. Binding the same gate again is a
// no-op; binding a different gate fails until release is called. release
// unbinds g (after Stop; used when a process runs several apps in tests).
func Bind(g *gate.Gate) (release func(), err error) {
	if g == nil {
		return nil, errors.New("caddymod: nil gate")
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	if binding.g != nil && binding.g != g {
		return nil, ErrOtherGate
	}
	binding.g = g
	return func() {
		binding.mu.Lock()
		defer binding.mu.Unlock()
		if binding.g == g {
			binding.g = nil
		}
	}, nil
}

// Bound returns the bound gate or nil.
func Bound() *gate.Gate {
	binding.mu.Lock()
	defer binding.mu.Unlock()
	return binding.g
}

// SetGate binds g, replacing any earlier gate. Kept for benchmarks and
// tests that run one gate after another; `schild run` uses Bind.
func SetGate(g *gate.Gate) {
	binding.mu.Lock()
	binding.g = g
	binding.mu.Unlock()
}

func init() { caddy.RegisterModule(Handler{}) }

// Handler is the Caddy module http.handlers.schild.
type Handler struct {
	// WriteErrors makes the handler write errors of the next handler itself
	// (plain text) instead of returning them to Caddy. Proxy mode sets it so
	// the gate records the real upstream status; in ingress mode errors go
	// back to Caddy so that handle_errors works as in stock Caddy.
	WriteErrors bool `json:"write_errors,omitempty"`

	// Website is the website of the site block this handler is in (D69),
	// set by BindWebsites when schild loads an ingress config, never from
	// the Caddyfile. Empty: the gate reads the website from the Host.
	Website string `json:"website,omitempty"`

	g *gate.Gate
}

// CaddyModule implements caddy.Module.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.schild", New: func() caddy.Module { return new(Handler) }}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(caddy.Context) error {
	h.g = Bound()
	if h.g == nil {
		return errors.New("schild: no gate bound (Bind)")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler. A panic anywhere below
// (gate or later handlers) answers this one request with 503 and never stops
// the server (MVP-19); http.ErrAbortHandler keeps its meaning.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) (err error) {
	if m, _ := caddyhttp.GetVar(r.Context(), passedVar).(*passMark); m != nil && m.matches(r) {
		// schild already inspected and passed this very request, as it
		// looks now, earlier in the chain (typically the site's schild, now
		// handle_errors' schild after a later handler failed). One request,
		// one evaluation and one event; the decision stands.
		return next.ServeHTTP(w, r)
	}
	// What the gate inspects: Caddy runs handle_errors with the original
	// method and URI, which may differ from what a route rewrote before the
	// site's schild (MVP-19 measurement 3, finding 1). The marker only
	// skips a second evaluation of the same method and URI.
	mark := markOf(r)
	// One re-check state per request, shared by every schild evaluation of
	// it, so a request schild inspects twice counts once (D33 amendment).
	st, _ := caddyhttp.GetVar(r.Context(), recheckVar).(*gate.Recheck)
	if st == nil {
		st = gate.NewRecheck()
		caddyhttp.SetVar(r.Context(), recheckVar, st)
	}
	tw := &trackWriter{ResponseWriter: w}
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel compared as net/http does
			panic(rec)
		}
		if h.g != nil && h.g.Log != nil {
			ratelog.Error(h.g.Log, "schild handler panic recovered, answered 503", "panic", fmt.Sprint(rec), "path", r.URL.Path)
		}
		if h.g != nil && h.g.Metrics != nil {
			h.g.Metrics.HardLimits.WithLabelValues("panic").Inc()
		}
		if h.g != nil {
			h.g.RecordPanic(r)
		}
		if tw.wrote {
			// The response has started: abort it rather than corrupt it.
			panic(http.ErrAbortHandler)
		}
		blockpage.Write(tw.ResponseWriter, r, http.StatusServiceUnavailable, "", time.Now())
		err = nil
	}()
	var nextErr error
	h.g.ServeRouted(tw, r, http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
		caddyhttp.SetVar(r2.Context(), passedVar, mark)
		e := next.ServeHTTP(w2, r2)
		if e == nil {
			return
		}
		status := http.StatusInternalServerError
		var he caddyhttp.HandlerError
		if errors.As(e, &he) && he.StatusCode != 0 {
			status = he.StatusCode
		} else if h.WriteErrors {
			status = http.StatusBadGateway
		}
		if status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
			// The proxy got no (timely) answer from the app (MVP-21).
			gate.NoteUpstream(w2, status)
		}
		if h.WriteErrors {
			// Write the upstream error ourselves so that the gate records
			// the real status (Caddy would write it after we return).
			w2.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w2.WriteHeader(status)
			_, _ = io.WriteString(w2, http.StatusText(status)+"\n")
			return
		}
		// Ingress mode: Caddy writes the error (handle_errors); the gate
		// records the status it will get.
		gate.NoteStatus(w2, status)
		st.MayFollow()
		nextErr = e
	}), st, h.Website)
	return nextErr
}

// recheckVar is the Caddy request variable holding the request's
// *gate.Recheck (unexported to configs as passedVar).
const recheckVar = "schild.recheck"

// passedVar is the Caddy request variable that marks a request schild has
// inspected and passed (handle_errors with schild inside, MVP-19 fix round 2).
// Its value has an unexported type, so no config (vars, map) can forge it;
// vars and map only ever store strings or other plain values. Since fix
// round 3 the mark carries what was inspected (method, request URI, path
// and query, host, remote address): a later schild skips only when the
// request still looks the same, else it inspects again.
const passedVar = "schild.passed"

type passMark struct {
	method, requestURI, uri, host, remote string
}

func markOf(r *http.Request) *passMark {
	return &passMark{method: r.Method, requestURI: r.RequestURI, uri: r.URL.RequestURI(), host: r.Host, remote: r.RemoteAddr}
}

// matches reports whether r has the method and URI schild inspected.
// r.URL.RequestURI() covers path and query (the WAF reads RawQuery),
// RequestURI the raw form Coraza gets.
func (m *passMark) matches(r *http.Request) bool {
	return m.method == r.Method && m.requestURI == r.RequestURI && m.uri == r.URL.RequestURI() && m.host == r.Host && m.remote == r.RemoteAddr
}

// trackWriter remembers whether the response has started, so that a
// recovered panic only writes a 503 when nothing was sent yet.
type trackWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackWriter) WriteHeader(code int) {
	if code >= 200 || code == http.StatusSwitchingProtocols {
		t.wrote = true
	}
	t.ResponseWriter.WriteHeader(code)
}

func (t *trackWriter) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

func (t *trackWriter) Flush() {
	t.wrote = true
	_ = http.NewResponseController(t.ResponseWriter).Flush()
}

func (t *trackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	t.wrote = true
	return http.NewResponseController(t.ResponseWriter).Hijack()
}

func (t *trackWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ http.Flusher                = (*trackWriter)(nil)
	_ http.Hijacker               = (*trackWriter)(nil)
)

// CaddyVersion is the version of the embedded Caddy (module version from the
// build info; "unknown" without it).
func CaddyVersion() string {
	simple, _ := caddy.Version()
	return simple
}

// Options of the embedded server.
type Options struct {
	Listen          string // host:port of the proxy
	Upstream        string // http(s)://host:port of the application
	UpstreamTimeout time.Duration
	TrustedProxies  []string
	DataDir         string
	LogLevel        string // DEBUG INFO WARN ERROR
	// WithoutGate leaves the schild handler out (baseline benchmarks only).
	WithoutGate bool
}

// BuildConfig renders the Caddy JSON config.
func BuildConfig(o Options) ([]byte, error) {
	u, err := url.Parse(o.Upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("caddymod: upstream %q must be http(s)://host[:port]", o.Upstream)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("caddymod: upstream with a path (%q) is not supported; put the prefix into the application or the front proxy", u.Path)
	}
	dial := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			dial = net.JoinHostPort(u.Hostname(), "443")
		} else {
			dial = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	timeout := o.UpstreamTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	transport := map[string]any{
		"protocol":                "http",
		"dial_timeout":            "5s",
		"response_header_timeout": timeout.String(),
	}
	if u.Scheme == "https" {
		transport["tls"] = map[string]any{}
	}
	level := strings.ToUpper(o.LogLevel)
	if level == "" {
		level = "WARN"
	}
	handlers := []any{map[string]any{"handler": "schild"}, map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": []any{map[string]any{"dial": dial}},
		"transport": transport,
	}}
	if o.WithoutGate {
		handlers = handlers[1:]
	}
	server := map[string]any{
		"listen":              []string{o.Listen},
		"automatic_https":     map[string]any{"disable": true},
		"read_header_timeout": "10s",
		"read_timeout":        "5m",
		"idle_timeout":        "2m",
		"max_header_bytes":    1 << 20,
		"protocols":           []string{"h1"}, // no h2c: nothing here needs it, and a front proxy passing Upgrade: h2c would open a stream it cannot see into
		"routes":              []any{map[string]any{"handle": handlers}},
	}
	if len(o.TrustedProxies) > 0 {
		server["trusted_proxies"] = map[string]any{"source": "static", "ranges": o.TrustedProxies}
	}
	limitConns(server)
	cfg := map[string]any{
		"admin":   map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": level, "encoder": map[string]any{"format": "json"}}}},
		"storage": map[string]any{"module": "file_system", "root": filepath.Join(o.DataDir, "caddy")},
		"apps": map[string]any{
			"http": map[string]any{"servers": map[string]any{"schild": server}},
			// TLS terminates in front of schild: no certificate storage work.
			"tls": map[string]any{"disable_storage_check": true, "disable_storage_clean": true, "disable_ocsp_stapling": true},
		},
	}
	return json.Marshal(cfg)
}

// Start loads the proxy-mode config into the embedded Caddy (non-blocking).
func Start(o Options) error {
	cfg, err := BuildConfig(o)
	if err != nil {
		return err
	}
	return Load(cfg)
}

// Load loads a Caddy JSON config into the embedded Caddy (non-blocking). A
// second Load in the same process replaces the config; the handlers of the
// new config use the same bound gate.
func Load(cfg []byte) error { return caddy.Load(cfg, true) }

// Stop stops the embedded Caddy gracefully.
func Stop() error { return caddy.Stop() }
