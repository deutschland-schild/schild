// Package failopen is a reference front proxy for the rule "fail-open only
// on connection refused, never on timeout" (MVP-02, concept 13): requests go
// to schild; only when schild refuses the connection (process down) they go
// straight to the application; when schild times out the answer is 503 and
// nothing reaches the application uninspected.
//
// The same behaviour for nginx and Caddy is documented in gateway/README.md
// and client/deploy/. `schild front` runs this proxy for test labs and for
// setups without another web server.
package failopen

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"syscall"
	"time"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/contract/waitingpage"
	"github.com/deutschland-schild/schild/gateway/internal/pagekit"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// Front is the front proxy.
type Front struct {
	schild *httputil.ReverseProxy
	app    *httputil.ReverseProxy
	log    *slog.Logger
	// OnBypass is called for every request sent around schild.
	OnBypass func(r *http.Request)
	// AccessDir is the storage path of schild (D56): while an access lock
	// is in force there, a refused connection gets 503 instead of the app.
	// A lock state the front cannot read counts as a lock (D71): no path,
	// no file (schild writes it at every start) or a broken one.
	AccessDir string
	// NoAccessLock fails open without reading the lock state, only for
	// gateways that never use an access lock.
	NoAccessLock bool
}

// DefaultAccessDir is schild's storage path in the image.
const DefaultAccessDir = "/var/lib/schild"

// accessLocked reports whether the front must not fail open (D56, D71).
func (f *Front) accessLocked() bool {
	if f.NoAccessLock {
		return false
	}
	if f.AccessDir == "" {
		ratelog.Error(f.log, "access lock state unknown (no -access-dir), not failing open")
		return true
	}
	a, err := access.ReadActive(f.AccessDir)
	if err != nil {
		ratelog.Error(f.log, "access lock state unknown (mount schild's storage read-only, or -no-access-lock), not failing open", "err", err)
		return true
	}
	return a.InForce()
}

// IsRefused reports whether err means the connection was refused.
func IsRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		var se *net.DNSError
		if errors.As(err, &se) {
			return false
		}
		return errors.Is(op.Err, syscall.ECONNREFUSED)
	}
	return false
}

// IsTimeout reports whether err is a timeout.
func IsTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// New returns a front proxy. timeout bounds the wait for schild's response headers.
func New(schildURL, appURL string, timeout time.Duration, log *slog.Logger) (*Front, error) {
	s, err := url.Parse(schildURL)
	if err != nil {
		return nil, err
	}
	a, err := url.Parse(appURL)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	f := &Front{log: log}
	st := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
	}
	at := st.Clone()
	f.app = httputil.NewSingleHostReverseProxy(a)
	f.app.Transport = at
	// The bypass answer comes from the app: it may not carry schild's
	// waiting page marker (D37 amendment).
	f.app.ModifyResponse = func(res *http.Response) error {
		res.Header.Del(waitingpage.MarkerHeader)
		return nil
	}
	f.app.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		ratelog.Error(log, "application unreachable", "err", err)
		w.WriteHeader(http.StatusBadGateway)
	}
	f.schild = httputil.NewSingleHostReverseProxy(s)
	f.schild.Transport = st
	f.schild.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		switch {
		case IsRefused(err) && f.accessLocked():
			// schild is down while a website or some paths need a way in:
			// nothing may reach the app unchecked (D56).
			ratelog.Warn(log, "schild refused the connection while an access lock is in force: 503, no fail-open")
			w.Header().Set("Retry-After", "60")
			pagekit.WriteSimple(w, r, http.StatusServiceUnavailable, "Wir sind gleich wieder da.", "Bitte versuch es später noch einmal.")
		case IsRefused(err):
			// schild is down: fail open, the site stays reachable (T12).
			ratelog.Warn(log, "schild refused the connection, passing directly to the application (fail-open)")
			if f.OnBypass != nil {
				f.OnBypass(r)
			}
			// r is the outgoing request; restore the incoming forwarding
			// header (the app proxy appends the client address again).
			if xff, ok := r.Context().Value(xffKey{}).([]string); ok && len(xff) > 0 {
				r.Header["X-Forwarded-For"] = xff
			} else {
				r.Header.Del("X-Forwarded-For")
			}
			f.app.ServeHTTP(w, r)
		case IsTimeout(err):
			// never pass on timeout
			w.Header().Set("Retry-After", "5")
			pagekit.WriteSimple(w, r, http.StatusServiceUnavailable, "Die Prüfung dauert gerade zu lange.", "Bitte versuch es gleich noch einmal.")
		default:
			ratelog.Error(log, "schild error", "err", err)
			w.WriteHeader(http.StatusBadGateway)
		}
	}
	return f, nil
}

type xffKey struct{}

// Server returns the HTTP server of `schild front` on addr. The front faces the
// clients itself, so slow headers and idle keep-alive connections end: without
// IdleTimeout (and without ReadTimeout, which would cut long uploads) net/http
// keeps an idle connection open forever, and one request per connection would
// let a client hold every file descriptor of the process. The values are those
// of `schild run` in proxy mode (caddymod.BuildConfig).
func (f *Front) Server(addr string) *http.Server {
	return &http.Server{Addr: addr, Handler: f, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 1 << 20}
}

// ServeHTTP implements http.Handler.
func (f *Front) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// http.Transport closes the request body on a failed dial; keep it open
	// so that a refused connection can still be passed to the application
	// (no body byte has been sent at that point).
	if r.Body != nil && r.Body != http.NoBody {
		orig := r.Body
		defer orig.Close()
		r.Body = io.NopCloser(orig)
	}
	r = r.WithContext(context.WithValue(r.Context(), xffKey{}, append([]string(nil), r.Header.Values("X-Forwarded-For")...)))
	f.schild.ServeHTTP(w, r)
}
