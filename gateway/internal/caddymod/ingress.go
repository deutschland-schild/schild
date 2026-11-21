package caddymod

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"

	"github.com/deutschland-schild/schild/contract/ingress"
	"github.com/deutschland-schild/schild/gateway/internal/gate"
)

// IngressOptions describe the operator's Caddyfile (schild.yaml ingress,
// MVP-19).
type IngressOptions struct {
	// Caddyfile is the absolute path of the operator's Caddyfile.
	Caddyfile string
	// Storage is ingress.storage: the Caddy storage root for certificates
	// and ACME state. It wins over a storage option in the Caddyfile.
	Storage string
	// DefaultStorage is used when neither ingress.storage nor the Caddyfile
	// set a storage (schild data dir/caddy).
	DefaultStorage string
	// Unprotected is ingress.unprotected_sites: hosts that may reach a
	// backend without the schild directive.
	Unprotected []string
	// Cluster is cluster.enabled (MVP-27): the proxy protocol then needs
	// an allow list (ProxyProtocolOpen).
	Cluster bool
	// TrustedProxies is ingress.trusted_proxies (a warning when Caddy does
	// not share it, see TrustedProxiesWarning).
	TrustedProxies []string
	// ExposeServerHeaders is ingress.expose_server_headers: keep Server and Via.
	ExposeServerHeaders bool
}

// Ingress is an adapted and checked Caddyfile, ready for Load.
type Ingress struct {
	// JSON is the Caddy config: the stock adapter's output with the admin
	// API disabled and the storage root set.
	JSON []byte
	// StorageRoot is the effective Caddy storage root.
	StorageRoot string
	// Check is the result of the directive check.
	Check Check
}

// Check is the result of the directive check on the adapted config.
type Check struct {
	Sites    []SiteCheck `json:"sites"`
	Errors   []string    `json:"errors,omitempty"`
	Warnings []string    `json:"warnings,omitempty"`
	// RollDisabled are the log files written with roll_disabled (one
	// log_roll_disabled warning each, D38); the CLI prints a logrotate rule
	// for them.
	RollDisabled []string `json:"-"`
}

// Err returns the errors as one error (nil without errors).
func (c *Check) Err() error {
	if len(c.Errors) == 0 {
		return nil
	}
	return fmt.Errorf("caddyfile: %s", strings.Join(c.Errors, "; "))
}

// SiteCheck is one site block (one top-level route of one server).
type SiteCheck struct {
	Server string   `json:"server"`
	Hosts  []string `json:"hosts"`
	// Schild: the site uses the schild directive in front of everything it
	// serves.
	Schild bool `json:"schild"`
	// Listed: every host is in ingress.unprotected_sites.
	Listed bool `json:"listed,omitempty"`
	// Backends are reverse_proxy / php_fastcgi handlers reached without
	// schild; Files is true when file_server is reached without schild.
	Backends []string `json:"backends,omitempty"`
	Files    bool     `json:"files,omitempty"`
	// Errors: the entry is a handle_errors route of the server.
	Errors bool `json:"errors,omitempty"`
	// Guarded: schild runs in the site and no backend is reached without
	// it, also when schild is not at the top but in every branch (each
	// handle / handle_path that reaches a backend runs schild first). The
	// validator accepts such a site, so the website derivation counts it
	// as running schild (D36 fix round 2, finding B 3.1 handle branches).
	Guarded bool `json:"-"`
	// Reason explains a refusal that is not obvious from Backends.
	Reason string `json:"reason,omitempty"`
}

// Name is the site's display name.
func (s SiteCheck) Name() string {
	if len(s.Hosts) == 0 {
		return "every host on server " + s.Server
	}
	return strings.Join(s.Hosts, ", ")
}

// ReadCaddyfile reads and adapts a Caddyfile with Caddy's stock Caddyfile
// adapter (imports relative to the file, environment placeholders, global
// options), exactly as `caddy adapt` of the same Caddy version does.
func ReadCaddyfile(path string) ([]byte, []string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("caddyfile: %w", err)
	}
	ad := caddyconfig.GetAdapter("caddyfile")
	if ad == nil {
		return nil, nil, errors.New("caddyfile: adapter not compiled in")
	}
	cfg, warns, err := ad.Adapt(body, map[string]any{"filename": path})
	if err != nil {
		return nil, nil, fmt.Errorf("caddyfile %s: %w", path, err)
	}
	var out []string
	for _, w := range warns {
		out = append(out, w.String())
	}
	return cfg, out, nil
}

// PrepareIngress adapts the operator's Caddyfile, checks that every site
// that reaches a backend uses the schild directive (unless listed as
// unprotected), disables the admin API and sets the storage root. With
// check errors it returns the Ingress (for the report) and an error.
// Automatic HTTPS and the storage checks stay as the Caddyfile says.
func PrepareIngress(o IngressOptions) (*Ingress, error) {
	if o.Caddyfile == "" {
		return nil, errors.New("caddyfile: ingress.caddyfile is not set")
	}
	raw, warns, err := ReadCaddyfile(o.Caddyfile)
	if err != nil {
		return nil, err
	}
	ing := &Ingress{}
	ing.Check, err = CheckConfig(raw, o.Unprotected)
	if err != nil {
		return nil, err
	}
	ing.Check.Warnings = append(warns, ing.Check.Warnings...)
	ing.Check.RollDisabled = LogRollDisabled(raw)
	for _, p := range ing.Check.RollDisabled {
		ing.Check.Warnings = append(ing.Check.Warnings, LogRollWarning(p))
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("caddyfile: adapted config: %w", err)
	}
	if a, ok := m["admin"].(map[string]any); ok && a["disabled"] != true {
		ing.Check.Warnings = append(ing.Check.Warnings, "the admin option of the Caddyfile is ignored: the Caddy admin API stays disabled under schild (changes need a restart)")
	}
	if w := trustedProxiesWarning(raw, o.TrustedProxies); w != "" {
		ing.Check.Warnings = append(ing.Check.Warnings, w)
	}
	if o.Cluster {
		if why := ProxyProtocolOpen(m); why != "" {
			return nil, errors.New("caddyfile: cluster.enabled and " + why + ". Anyone who reaches this node could then name any address as theirs, and a block of that address would act on every node of the group. Give proxy_protocol an allow list with the addresses of your load balancers, and no fallback_policy use or require")
		}
	}
	m["admin"] = map[string]any{"disabled": true, "config": map[string]any{"persist": false}}
	limitAllConns(m)
	refuseEarlyData(m)
	if !o.ExposeServerHeaders {
		hideServerHeaders(m)
	}
	root := o.Storage
	cur, _ := m["storage"].(map[string]any)
	switch {
	case root != "":
		if cur != nil && (cur["module"] != "file_system" || cur["root"] != root) {
			ing.Check.Warnings = append(ing.Check.Warnings, "the storage option of the Caddyfile is replaced by ingress.storage "+root)
		}
	case cur != nil:
		if o.Cluster && cur["module"] != "file_system" && cur["module"] != clusterStorageName {
			return nil, errors.New("caddyfile: cluster.enabled and a storage module of its own in the Caddyfile: in a group schild shares the certificates itself, remove the storage option")
		}
		if cur["module"] != "file_system" && cur["module"] != clusterStorageName {
			// Another storage module (e.g. a cluster storage) stays as is.
			ing.JSON, err = json.Marshal(m)
			return ing, errors.Join(err, ing.Check.Err())
		}
		root, _ = cur["root"].(string)
	default:
		root = o.DefaultStorage
	}
	if root == "" {
		return nil, errors.New("caddyfile: no storage root (set ingress.storage)")
	}
	ing.StorageRoot = root
	m["storage"] = map[string]any{"module": "file_system", "root": root}
	if o.Cluster {
		// The same files, and the group next to them (ClusterStorage).
		m["storage"] = map[string]any{"module": clusterStorageName, "root": root}
		shareTicketKeys(m)
	}
	ing.JSON, err = json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return ing, ing.Check.Err()
}

// refuseEarlyData turns off QUIC 0-RTT on every server. Caddy allows it unless a
// server says otherwise, and early data can be replayed: a captured request
// would run again, and before the handshake completes the client address is
// not proven yet.
func refuseEarlyData(m map[string]any) {
	apps, _ := m["apps"].(map[string]any)
	h, _ := apps["http"].(map[string]any)
	servers, _ := h["servers"].(map[string]any)
	for _, s := range servers {
		if server, ok := s.(map[string]any); ok {
			server["allow_0rtt"] = false
		}
	}
}

// hideServerHeaders removes Server and Via from the answers of every server (D47).
// Caddy sets Server before any route runs, so the first handler takes it off the
// header map at once, which also covers an answer of the error path. The second
// acts when the answer is written: Via and the backend's Server come later.
func hideServerHeaders(m map[string]any) {
	apps, _ := m["apps"].(map[string]any)
	h, _ := apps["http"].(map[string]any)
	servers, _ := h["servers"].(map[string]any)
	for _, s := range servers {
		server, ok := s.(map[string]any)
		if !ok {
			continue
		}
		routes, _ := server["routes"].([]any)
		server["routes"] = append([]any{map[string]any{"handle": []any{
			map[string]any{"handler": "headers", "response": map[string]any{"delete": []any{"Server"}}},
			map[string]any{"handler": "headers", "response": map[string]any{"delete": []any{"Server", "Via"}, "deferred": true}},
		}}}, routes...)
	}
}

// trustedProxiesWarning: ingress.trusted_proxies drives schild's own client
// attribution in every mode, but in ingress mode Caddy reads its proxies from
// the Caddyfile. Without them there, Caddy replaces X-Forwarded-For towards
// the backend with the proxy's address. Loopback entries (the default) do not
// matter: nothing forwards through them in ingress mode.
func trustedProxiesWarning(cfgJSON []byte, trusted []string) string {
	external := false
	for _, c := range trusted {
		if p, err := netip.ParsePrefix(c); err == nil && !p.Addr().IsLoopback() {
			external = true
		}
	}
	if !external {
		return ""
	}
	var c struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					TrustedProxies json.RawMessage `json:"trusted_proxies"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if json.Unmarshal(cfgJSON, &c) != nil {
		return ""
	}
	for _, s := range c.Apps.HTTP.Servers {
		if len(s.TrustedProxies) == 0 {
			return "ingress.trusted_proxies only sets the client address schild sees; the Caddyfile has no trusted_proxies, so the backend gets the proxy's address in X-Forwarded-For. Add `servers { trusted_proxies static ... }` to the global options with the same ranges"
		}
	}
	return ""
}

// ValidateIngress provisions the prepared config without starting it, as
// `caddy validate` does (modules, TLS policies, log writers), with a
// temporary storage root so that validation never touches certificates.
// The temporary directory is made in the system's temp directory, else in
// the first of fallbackDirs that allows it (a container with a read-only
// root file system has no writable /tmp, but a data volume); it is removed
// again.
func ValidateIngress(ing *Ingress, fallbackDirs ...string) error {
	var m map[string]any
	if err := json.Unmarshal(ing.JSON, &m); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "schild-validate-")
	for _, d := range fallbackDirs {
		if err == nil {
			break
		}
		if d == "" {
			continue
		}
		if t, e := os.MkdirTemp(d, ".schild-validate-"); e == nil {
			tmp, err = t, nil
		}
	}
	if err != nil {
		return fmt.Errorf("no writable place for a temporary directory: %w", err)
	}
	defer os.RemoveAll(tmp)
	m["storage"] = map[string]any{"module": "file_system", "root": tmp}
	if err := discardLogWriters(m); err != nil {
		return err
	}
	quietDefaultLog(m)
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var cfg caddy.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	if Bound() == nil {
		release, err := Bind(gate.New(gate.Settings{}))
		if err == nil {
			defer release()
		}
	}
	return caddy.Validate(&cfg)
}

// discardLogWriters keeps validation free of side effects: Caddy opens every
// log writer while provisioning a config, and a file writer creates its
// directory and file (a net writer dials). Each writer of the logging
// section (sink and logs) is loaded and provisioned here as Caddy would
// (module, fields, placeholders in the file name) without opening it, then
// replaced in m by the discard writer.
// quietDefaultLog keeps provisioning from printing Caddy's JSON lines in
// the middle of a report: the default log stays on stderr (a move away from
// it would itself be logged) and shows errors only. Runs after
// discardLogWriters, which has checked a writer the Caddyfile names.
func quietDefaultLog(m map[string]any) {
	logging, _ := m["logging"].(map[string]any)
	if logging == nil {
		logging = map[string]any{}
		m["logging"] = logging
	}
	logs, _ := logging["logs"].(map[string]any)
	if logs == nil {
		logs = map[string]any{}
		logging["logs"] = logs
	}
	def, _ := logs["default"].(map[string]any)
	if def == nil {
		def = map[string]any{}
		logs["default"] = def
	}
	delete(def, "writer")
	def["level"] = "ERROR"
}

func discardLogWriters(m map[string]any) error {
	logging, _ := m["logging"].(map[string]any)
	if logging == nil {
		return nil
	}
	var holders []map[string]any
	if s, ok := logging["sink"].(map[string]any); ok {
		holders = append(holders, s)
	}
	logs, _ := logging["logs"].(map[string]any)
	names := make([]string, 0, len(logs))
	for n := range logs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if l, ok := logs[n].(map[string]any); ok {
			holders = append(holders, l)
		}
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	for _, h := range holders {
		w, ok := h["writer"].(map[string]any)
		if !ok {
			continue
		}
		output, _ := w["output"].(string)
		fields := map[string]any{}
		for k, v := range w {
			if k != "output" {
				fields[k] = v
			}
		}
		raw, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		if _, err := ctx.LoadModuleByID("caddy.logging.writers."+output, raw); err != nil {
			return fmt.Errorf("log writer %q: %w", output, err)
		}
		h["writer"] = map[string]any{"output": "discard"}
	}
	return nil
}

// --------------------------------------------------------------- checking

type jsonConfig struct {
	Apps struct {
		HTTP *struct {
			Servers map[string]*jsonServer `json:"servers"`
		} `json:"http"`
	} `json:"apps"`
}

type jsonServer struct {
	Listen []string `json:"listen"`
	Routes []route  `json:"routes"`
	Errors *struct {
		Routes []route `json:"routes"`
	} `json:"errors"`
	NamedRoutes map[string]*route `json:"named_routes"`
}

type route struct {
	Group  string                       `json:"group"`
	Match  []map[string]json.RawMessage `json:"match"`
	Handle []json.RawMessage            `json:"handle"`
}

type handler struct {
	Handler   string  `json:"handler"`
	Routes    []route `json:"routes"`
	Name      string  `json:"name"`
	Upstreams []struct {
		Dial string `json:"dial"`
	} `json:"upstreams"`
	Dynamic   json.RawMessage `json:"dynamic_upstreams"`
	Transport *struct {
		Protocol string `json:"protocol"`
	} `json:"transport"`
}

// knownHandlers are the HTTP handlers compiled into schild. A handler outside
// this list is something the check does not understand; reached without
// schild it is refused (when unsure, refuse).
var knownHandlers = map[string]bool{
	"acme_server": true, "authentication": true, "copy_response": true, "copy_response_headers": true, "encode": true, "error": true,
	"file_server": true, "headers": true, "intercept": true, "invoke": true, "log_append": true, "map": true, "metrics": true, "push": true,
	"request_body": true, "reverse_proxy": true, "rewrite": true, "schild": true, "static_response": true, "subroute": true,
	"templates": true, "tracing": true, "vars": true, "waf": true,
}

type walker struct {
	named map[string]*route
	depth int
	// out of the walk
	schild   bool
	backends []string
	files    bool
	// slashStar: schild only under the path matcher /*, which is not
	// unconditional (the request target * of OPTIONS * does not match).
	slashStar bool
}

// routes walks rs in order and reports whether an unconditional schild
// handler guards everything after it at this level.
//
// Conservative by design (MVP-19 measurement, finding 2): a route runs
// unconditionally only without matchers and as the first route of its group
// (handle blocks are mutually exclusive: a later handle without a matcher
// runs only when no earlier one matched). Route lists nested anywhere inside
// a handler (handle_response of intercept and reverse_proxy, the errors of a
// subroute) are walked too; they never guard what follows them.
func (w *walker) routes(rs []route, protected bool) bool {
	if w.depth > 32 {
		w.backends = append(w.backends, "routes nested too deep to check")
		return false
	}
	w.depth++
	defer func() { w.depth-- }()
	guards := false
	groups := map[string]bool{}
	for _, r := range rs {
		conditional := len(r.Match) > 0
		if r.Group != "" {
			if groups[r.Group] {
				conditional = true
			}
			groups[r.Group] = true
		}
		p := protected
		for _, raw := range r.Handle {
			var h handler
			if json.Unmarshal(raw, &h) != nil {
				if !p {
					w.backends = append(w.backends, "a handler the check cannot read")
				}
				continue
			}
			switch h.Handler {
			case "schild":
				p, w.schild = true, true
				if conditional && onlySlashStar(r.Match) {
					w.slashStar = true
				}
				if !conditional {
					protected, guards = true, true
				}
			case "reverse_proxy":
				if !p {
					w.backends = append(w.backends, describeBackend(h))
				}
			case "file_server":
				if !p {
					w.files = true
				}
			case "subroute":
				if w.routes(h.Routes, p) {
					p = true
					if !conditional {
						protected, guards = true, true
					}
				}
			case "invoke":
				// Caddy compiles the named route with the rest of this
				// chain as its next handler (invoke.go, route.Compile(next)),
				// so a named route whose schild guards it unconditionally
				// guards what follows the invoke as well.
				if nr := w.named[h.Name]; nr != nil {
					if w.routes([]route{*nr}, p) {
						p = true
						if !conditional {
							protected, guards = true, true
						}
					}
				} else if !p {
					w.backends = append(w.backends, "invoke of an unknown named route "+h.Name)
				}
			default:
				if !knownHandlers[h.Handler] && !p {
					w.backends = append(w.backends, "handler "+h.Handler+" (unknown to the check)")
				}
			}
			// Route lists elsewhere in the handler: handle_response of
			// intercept and reverse_proxy, the errors of a subroute.
			for _, n := range nestedRoutes(raw, h.Handler == "subroute") {
				pp := p
				if n.errors {
					pp = false // errors of a subroute may come from before its schild
				}
				w.routes(n.routes, pp)
			}
		}
	}
	return guards
}

// onlySlashStar reports whether the matcher sets are exactly one path
// matcher /*.
func onlySlashStar(sets []map[string]json.RawMessage) bool {
	if len(sets) != 1 || len(sets[0]) != 1 {
		return false
	}
	var paths []string
	return json.Unmarshal(sets[0]["path"], &paths) == nil && len(paths) == 1 && paths[0] == "/*"
}

type nestedList struct {
	routes []route
	errors bool
}

// nestedRoutes finds route lists anywhere inside a handler's JSON (any key
// "routes" whose value is a list of routes). skipTop skips the handler's own
// "routes" (a subroute's, walked by the caller).
func nestedRoutes(raw json.RawMessage, skipTop bool) []nestedList {
	var out []nestedList
	var visit func(v any, top, inErrors bool)
	visit = func(v any, top, inErrors bool) {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				c := t[k]
				if k == "routes" {
					if top && skipTop {
						continue
					}
					if b, err := json.Marshal(c); err == nil {
						var rs []route
						if json.Unmarshal(b, &rs) == nil && len(rs) > 0 {
							out = append(out, nestedList{routes: rs, errors: inErrors})
							continue
						}
					}
				}
				visit(c, false, inErrors || k == "errors")
			}
		case []any:
			for _, c := range t {
				visit(c, false, inErrors)
			}
		}
	}
	var v any
	if json.Unmarshal(raw, &v) == nil {
		visit(v, true, false)
	}
	return out
}

func describeBackend(h handler) string {
	kind := "reverse_proxy"
	if h.Transport != nil && h.Transport.Protocol == "fastcgi" {
		kind = "php_fastcgi"
	}
	var dials []string
	for _, u := range h.Upstreams {
		dials = append(dials, u.Dial)
	}
	switch {
	case len(dials) > 0:
		return kind + " " + strings.Join(dials, " ")
	case len(h.Dynamic) > 0:
		return kind + " (dynamic upstreams)"
	}
	return kind
}

// siteRoute drops the matcher of a top-level route: it selects the site
// (host, and a path for addresses like example.de/api), so within the site
// its handlers run unconditionally.
func siteRoute(r route) route {
	r.Match = nil
	return r
}

func routeHosts(r route) []string {
	var hosts []string
	for _, set := range r.Match {
		if raw, ok := set["host"]; ok {
			var hs []string
			if json.Unmarshal(raw, &hs) == nil {
				hosts = append(hosts, hs...)
			}
		}
	}
	return hosts
}

// HostListed reports whether host is in the unprotected list: an exact
// name, or "*.example.de" for one more label (and the literal wildcard).
func HostListed(host string, list []string) bool {
	host = strings.ToLower(host)
	for _, e := range list {
		e = strings.ToLower(e)
		if e == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(e, "*"); ok && strings.HasPrefix(suffix, ".") && strings.HasSuffix(host, suffix) {
			label := strings.TrimSuffix(host, suffix)
			if label != "" && !strings.Contains(label, ".") {
				return true
			}
		}
	}
	return false
}

// CheckConfig checks an adapted Caddy JSON config: every site block that
// reaches a backend (reverse_proxy, php_fastcgi, also inside handle_errors)
// must do so behind the schild handler, unless all its hosts are in
// unprotected; file_server without schild is a warning. No request rewrite
// may run before the schild handler that first inspects the request
// (contract/ingress, rule rewrite_before_schild, D31 amendment), in listed
// sites too. The check reads the
// adapted JSON, never the Caddyfile text, so imports, snippets and named
// routes count as Caddy sees them.
func CheckConfig(cfgJSON []byte, unprotected []string) (Check, error) {
	var c jsonConfig
	if err := json.Unmarshal(cfgJSON, &c); err != nil {
		return Check{}, fmt.Errorf("caddyfile: adapted config: %w", err)
	}
	out := Check{Sites: []SiteCheck{}}
	if c.Apps.HTTP == nil || len(c.Apps.HTTP.Servers) == 0 {
		out.Errors = append(out.Errors, "the Caddyfile defines no site")
		return out, nil
	}
	names := make([]string, 0, len(c.Apps.HTTP.Servers))
	for n := range c.Apps.HTTP.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	used := map[string]bool{}
	for _, name := range names {
		srv := c.Apps.HTTP.Servers[name]
		for _, r := range srv.Routes {
			w := &walker{named: srv.NamedRoutes}
			g := w.routes([]route{siteRoute(r)}, false)
			sc := SiteCheck{Server: name, Hosts: routeHosts(r), Schild: w.schild && g && len(w.backends) == 0 && !w.files, Backends: w.backends, Files: w.files}
			sc.Guarded = w.schild && len(w.backends) == 0
			if w.slashStar && !g {
				sc.Reason = "`schild /*` does not count as unconditional: Caddy's path matcher /* does not match the request target * (OPTIONS *), so such a request skips schild; write `schild` without a matcher"
			}
			out.add(sc, unprotected, used)
		}
		if srv.Errors != nil {
			// handle_errors belongs to the server (the listener), not to the
			// site block it is written in: Caddy picks the error route by its
			// own matchers for an error of any site on this server, also of a
			// site without schild (a file_server 404, basic_auth 401, error).
			// So an error route that reaches a backend counts as protected
			// only when schild runs inside it (MVP-19 re-measurement,
			// finding 1), whatever site it is attached to.
			for _, r := range srv.Errors.Routes {
				hosts := routeHosts(r)
				w := &walker{named: srv.NamedRoutes}
				w.routes([]route{siteRoute(r)}, false)
				if len(w.backends) == 0 {
					continue
				}
				sc := SiteCheck{Server: name, Hosts: hosts, Backends: w.backends, Errors: true}
				for i := range sc.Backends {
					sc.Backends[i] += " (handle_errors)"
				}
				sc.Reason = "handle_errors belongs to the whole server and also handles errors of other sites on it (a missing file, basic_auth, error), so it must run schild itself"
				out.add(sc, unprotected, used)
			}
		}
	}
	for _, e := range unprotected {
		if !used[strings.ToLower(e)] {
			out.Warnings = append(out.Warnings, fmt.Sprintf("ingress.unprotected_sites: %s matches no site of the Caddyfile", e))
		}
	}
	found, err := orderFindings(cfgJSON)
	if err != nil {
		out.Errors = append(out.Errors, "ingress order check: "+err.Error())
	}
	for _, f := range found {
		out.Errors = append(out.Errors, ingress.Message(f))
	}
	return out, nil
}

// orderFindings applies the contract's order rule (rewrite_before_schild)
// to apps.http.servers of the adapted config, decoded as a generic value
// with json.Number (the form contract/ingress reads).
func orderFindings(cfgJSON []byte) ([]ingress.Finding, error) {
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]any `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	dec := json.NewDecoder(bytes.NewReader(cfgJSON))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return ingress.Check(cfg.Apps.HTTP.Servers)
}

func (c *Check) add(sc SiteCheck, unprotected []string, used map[string]bool) {
	sc.Listed = len(sc.Hosts) > 0
	for _, h := range sc.Hosts {
		if !HostListed(h, unprotected) {
			sc.Listed = false
		}
	}
	if sc.Listed {
		for _, h := range sc.Hosts {
			for _, e := range unprotected {
				if HostListed(h, []string{e}) {
					used[strings.ToLower(e)] = true
				}
			}
		}
	}
	switch {
	case len(sc.Backends) > 0 && !sc.Listed:
		if sc.Errors {
			c.Errors = append(c.Errors, fmt.Sprintf("site %s reaches %s without schild: %s; add `schild` (or `import schild`) as the first line inside handle_errors",
				sc.Name(), strings.Join(sc.Backends, ", "), sc.Reason))
			break
		}
		if sc.Reason != "" {
			c.Errors = append(c.Errors, fmt.Sprintf("site %s reaches %s without schild: %s",
				sc.Name(), strings.Join(sc.Backends, ", "), sc.Reason))
			break
		}
		c.Errors = append(c.Errors, fmt.Sprintf("site %s reaches %s without schild: add `schild` (or `import schild`) to the site block, before it, or list the site in ingress.unprotected_sites",
			sc.Name(), strings.Join(sc.Backends, ", ")))
	case sc.Files && !sc.Listed && len(sc.Backends) == 0:
		c.Warnings = append(c.Warnings, fmt.Sprintf("site %s serves files without schild", sc.Name()))
	}
	c.Sites = append(c.Sites, sc)
}

// DefaultStorage is the Caddy storage root under the schild data dir.
func DefaultStorage(dataDir string) string { return filepath.Join(dataDir, "caddy") }

// ProxyProtocolOpen reports why a proxy_protocol listener wrapper of the
// adapted config believes a PROXY header of a sender the operator did not
// name: it has no allow list, or its fallback policy uses the header of
// senders outside the list (USE, REQUIRE). Empty: no such wrapper.
//
// In a group this is refused (MVP-27, G5): a block follows the client
// address, and a block of the group acts on every node.
func ProxyProtocolOpen(m map[string]any) string {
	apps, _ := m["apps"].(map[string]any)
	h, _ := apps["http"].(map[string]any)
	servers, _ := h["servers"].(map[string]any)
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		server, _ := servers[name].(map[string]any)
		wrappers, _ := server["listener_wrappers"].([]any)
		for _, w := range wrappers {
			pp, _ := w.(map[string]any)
			if pp["wrapper"] != "proxy_protocol" {
				continue
			}
			if allow, _ := pp["allow"].([]any); len(allow) == 0 {
				return "proxy_protocol has no allow list"
			}
			switch policy, _ := pp["fallback_policy"].(string); strings.ToUpper(policy) {
			case "USE", "REQUIRE":
				return "proxy_protocol has fallback_policy " + strings.ToLower(policy) + ", which takes the header of senders outside its allow list"
			}
		}
	}
	return ""
}

// shareTicketKeys lets the nodes of a group share the keys of TLS session
// tickets through the storage (Caddy's distributed key source), so a visitor
// resumes a TLS session on whichever node the balancer picks. A Caddyfile
// that sets session tickets itself is left as it is.
func shareTicketKeys(m map[string]any) {
	apps, _ := m["apps"].(map[string]any)
	if apps == nil {
		return
	}
	t, _ := apps["tls"].(map[string]any)
	if t == nil {
		t = map[string]any{}
		apps["tls"] = t
	}
	if _, set := t["session_tickets"]; !set {
		t["session_tickets"] = map[string]any{"key_source": map[string]any{"provider": "distributed"}}
	}
}
