package caddymod

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/connlimit"
)

// The limit of open connections (D46) sits in a listener wrapper before TLS, on
// every server of the config, so a refused connection costs no handshake.

// connWrapperName is the wrapper of ConnWrapper in a Caddy config. The operator
// never writes it: limitConns adds it to the adapted JSON.
const connWrapperName = "schild_conns"

// bindingConns is the limiter of this process, as binding is for the gate.
var bindingConns struct {
	mu sync.Mutex
	l  *connlimit.Limiter
}

// BindConns sets the limiter of every ConnWrapper of later config loads. nil, and
// any validation, leaves the listeners as they are.
func BindConns(l *connlimit.Limiter) (release func()) {
	bindingConns.mu.Lock()
	bindingConns.l = l
	bindingConns.mu.Unlock()
	return func() {
		bindingConns.mu.Lock()
		if bindingConns.l == l {
			bindingConns.l = nil
		}
		bindingConns.mu.Unlock()
	}
}

func boundConns() *connlimit.Limiter {
	bindingConns.mu.Lock()
	defer bindingConns.mu.Unlock()
	return bindingConns.l
}

func init() {
	caddy.RegisterModule(ConnWrapper{})
	caddy.RegisterModule(RequestSeen{})
}

// ConnWrapper is the Caddy module caddy.listeners.schild_conns.
type ConnWrapper struct {
	// Proxied: the server reads the proxy protocol, so the address of a connection
	// at this point is the proxy's, never the client's.
	Proxied bool `json:"proxied,omitempty"`

	ka    net.KeepAliveConfig
	fresh *atomic.Int64
}

// CaddyModule implements caddy.Module.
func (ConnWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "caddy.listeners." + connWrapperName, New: func() caddy.Module { return new(ConnWrapper) }}
}

// Provision hooks the state of connections into the server: only the server knows
// which of them run a request.
func (w *ConnWrapper) Provision(ctx caddy.Context) error {
	w.fresh = new(atomic.Int64)
	if srv, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok {
		// As Caddy sets it on the sockets it opens.
		w.ka = net.KeepAliveConfig{Enable: srv.KeepAliveInterval >= 0, Interval: time.Duration(srv.KeepAliveInterval),
			Idle: time.Duration(srv.KeepAliveIdle), Count: srv.KeepAliveCount}
		var counted sync.Map // connections in fresh
		srv.RegisterConnState(func(c net.Conn, s http.ConnState) {
			if s == http.StateNew {
				w.fresh.Add(1)
				counted.Store(c, struct{}{})
			} else if _, was := counted.LoadAndDelete(c); was {
				w.fresh.Add(-1)
			}
			connlimit.Track(c, s)
		})
		srv.RegisterConnContext(connlimit.WithConn)
		srv.RegisterConnContext(limitStreams())
		ev, err := ctx.App("events")
		if err != nil {
			return err
		}
		// Every wrapper of a config does it, the first call does the work.
		return ev.(*caddyevents.App).On("started", onStarted{})
	}
	return nil
}

// limitStreams sets the HTTP/2 streams per connection of a server (D60). Caddy
// builds its http.Server after Provision and has no option for it, so the first
// connection sets it, before the server reads it for that connection. Every
// accept loop of the server passes the Once, so no connection reads it earlier.
func limitStreams() func(context.Context, net.Conn) context.Context {
	var once sync.Once
	return func(ctx context.Context, _ net.Conn) context.Context {
		once.Do(func() {
			hs, ok := ctx.Value(http.ServerContextKey).(*http.Server)
			if !ok {
				return
			}
			if hs.HTTP2 == nil {
				hs.HTTP2 = &http.HTTP2Config{}
			}
			if hs.HTTP2.MaxConcurrentStreams == 0 {
				hs.HTTP2.MaxConcurrentStreams = bodylimit.H2MaxStreams
			}
		})
		return ctx
	}
}

// WrapListener implements caddy.ListenerWrapper.
func (w *ConnWrapper) WrapListener(ln net.Listener) net.Listener {
	ln = keepSocket(ln, w.ka, w.fresh)
	if l := boundConns(); l != nil {
		return l.Listen(ln, w.Proxied)
	}
	return ln
}

// requestSeenName is the handler of RequestSeen, the first route of every server.
const requestSeenName = "schild_request_seen"

// RequestSeen is the Caddy module http.handlers.schild_request_seen: it tells the
// limiter that a request reached the routes of its connection, so the connection
// may keep its place (D46).
type RequestSeen struct{}

// CaddyModule implements caddy.Module.
func (RequestSeen) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers." + requestSeenName, New: func() caddy.Module { return new(RequestSeen) }}
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (RequestSeen) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	connlimit.Served(r.Context())
	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*ConnWrapper)(nil)
	_ caddy.ListenerWrapper       = (*ConnWrapper)(nil)
	_ caddyhttp.MiddlewareHandler = (*RequestSeen)(nil)
)

// limitConns puts the wrapper in front of a server's wrappers, and RequestSeen in
// front of its routes. Caddy runs what
// stands before the tls placeholder below TLS, and adds the placeholder at the
// front when there is none, so it is written out here. With proxy_protocol in the
// list the address is the proxy's at this point: reading the header earlier would
// block the accept loop on any client that sends nothing.
func limitConns(server map[string]any) {
	wrappers, _ := server["listener_wrappers"].([]any)
	proxied, hasTLS := false, false
	for _, w := range wrappers {
		m, _ := w.(map[string]any)
		switch m["wrapper"] {
		case "proxy_protocol":
			proxied = true
		case "tls":
			hasTLS = true
		}
	}
	mine := map[string]any{"wrapper": connWrapperName}
	if proxied {
		mine["proxied"] = true
	}
	out := []any{mine}
	if !hasTLS {
		out = append(out, map[string]any{"wrapper": "tls"})
	}
	server["listener_wrappers"] = append(out, wrappers...)
	routes, _ := server["routes"].([]any)
	server["routes"] = append([]any{map[string]any{"handle": []any{map[string]any{"handler": requestSeenName}}}}, routes...)
}

// limitAllConns adds the wrapper to every server of an adapted Caddyfile. The
// server Caddy creates for its HTTP to HTTPS redirects takes no wrappers, so it is
// written out with the port it would have, and Caddy puts the redirects into it.
func limitAllConns(m map[string]any) {
	apps, _ := m["apps"].(map[string]any)
	h, _ := apps["http"].(map[string]any)
	servers, _ := h["servers"].(map[string]any)
	if len(servers) == 0 {
		return
	}
	for _, addr := range redirectListeners(h, servers) {
		name := "schild_redirects"
		for i := 2; servers[name] != nil; i++ {
			name = fmt.Sprintf("schild_redirects_%d", i)
		}
		servers[name] = map[string]any{"listen": []any{addr}}
	}
	for _, s := range servers {
		if server, ok := s.(map[string]any); ok {
			limitConns(server)
		}
	}
}

// redirectListeners returns the addresses of the redirects Caddy will add: the
// hosts of servers with automatic HTTPS at the HTTP port, when no server listens
// there yet.
func redirectListeners(h, servers map[string]any) []string {
	httpPort := portOf(h["http_port"], 80)
	taken, want := map[string]bool{}, map[string]bool{}
	for _, s := range servers {
		server, _ := s.(map[string]any)
		listen, _ := server["listen"].([]any)
		auto, _ := server["automatic_https"].(map[string]any)
		off := auto["disable"] == true || auto["disable_redirects"] == true
		for _, l := range listen {
			addr, _ := l.(string)
			host, port, ok := splitListen(addr)
			if !ok {
				continue
			}
			taken[host+":"+port] = true
			if !off && port != httpPort && hasHost(server) {
				want[host+":"+httpPort] = true
			}
		}
	}
	var out []string
	for a := range want {
		if !taken[a] {
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

func portOf(v any, def int) string {
	if n, ok := v.(float64); ok && n > 0 {
		return fmt.Sprint(int(n))
	}
	return fmt.Sprint(def)
}

// splitListen reads a listen address of a server: plain tcp only.
func splitListen(addr string) (host, port string, ok bool) {
	if strings.Contains(addr, "/") {
		return "", "", false
	}
	host, port, err := net.SplitHostPort(addr)
	return host, port, err == nil
}

// hasHost reports a route with a host matcher: without a name Caddy has no
// certificate to manage and adds no redirect.
func hasHost(server map[string]any) bool {
	routes, _ := server["routes"].([]any)
	for _, r := range routes {
		rm, _ := r.(map[string]any)
		sets, _ := rm["match"].([]any)
		for _, set := range sets {
			if sm, _ := set.(map[string]any); sm["host"] != nil {
				return true
			}
		}
	}
	return false
}
