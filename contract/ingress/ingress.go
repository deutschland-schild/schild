// Package ingress is the v0.5 contract of the ingress validator's order rules
// (initiator decision 2026-10-29, DECISIONS D31 amendment, MVP-19; headers:
// D40): `schild
// ingress validate` refuses a Caddyfile in which a request rewrite (Caddyfile
// `rewrite`, `uri`, `method`, also `try_files`; Caddy JSON handler
// `rewrite`) can run before the schild handler that first inspects the
// request. Such a rewrite can hide part of the request from schild and a
// later rewrite can put it back before the backend (measurement 2026-10-29
// evening, variants P20 and P21). A request header changed before schild
// and written again behind it is the same hiding for headers
// (header_hidden_from_schild).
//
// The rule reads the Caddy JSON that Caddy's stock Caddyfile adapter
// produces (apps.http.servers), never the Caddyfile text, as the gateway's
// validator does, so imports, snippets and named routes count as Caddy sees
// them. Rules in contracts/ingress-order.md; vectors `ingress-order` (Go and
// Python agree).
package ingress

import (
	"sort"
	"strconv"
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Schema is the vector input schema (ingress-order.schema.json).
const Schema = "ingress-order"

// MaxInputBytes bounds a vector input (as a Caddyfile config).
const MaxInputBytes = 1 << 20

// MaxRouteDepth bounds the nesting of route lists the walk follows
// (subroutes, invoked named routes, handle_response); deeper is refused.
const MaxRouteDepth = 32

// Finding codes and message keys of the refusals. Each is an error of
// `schild ingress validate` (the Caddyfile is refused, `schild run` does not
// start), printed as Message returns it.
const (
	CodeRewriteBeforeSchild   = "rewrite_before_schild"
	MsgKeyRewriteBeforeSchild = "ingress.err.rewrite_before_schild"
	// D40: a request header hidden from schild and written again after it.
	CodeHeaderHiddenFromSchild   = "header_hidden_from_schild"
	MsgKeyHeaderHiddenFromSchild = "ingress.err.header_hidden_from_schild"
)

// Directives named in a finding: the Caddyfile directive family of the
// rewrite handler (Caddy JSON handler "rewrite" for all three).
const (
	DirectiveMethod  = "method"  // field method
	DirectiveURI     = "uri"     // strip_path_prefix, strip_path_suffix, uri_substring, path_regexp or query
	DirectiveRewrite = "rewrite" // uri (rewrite, try_files, php_fastcgi's index rewrite)
	// DirectiveRequestHeader is the directive family of a hiding `headers`
	// handler (Caddyfile request_header).
	DirectiveRequestHeader = "request_header"
)

// Finding is one refused site route or handle_errors route. Pointers are
// RFC 6901 JSON pointers relative to the server object; a handler inside an
// invoked named route is addressed under /named_routes/<name>.
type Finding struct {
	Code   string   `json:"code"`
	MsgKey string   `json:"msg_key"`
	Server string   `json:"server"`
	Route  string   `json:"route"`
	Hosts  []string `json:"hosts"`
	// Directive is the Caddyfile directive family of the rewrite or hiding
	// handler.
	Directive string `json:"directive"`
	// Rewrite is the first rewrite (walk order) that runs unguarded before
	// a schild handler; Schild is the first schild handler after it that it
	// can run before. With header_hidden_from_schild, Hide is the unguarded
	// headers handler, Schild the first schild it precedes that a later
	// handler writes the header behind, Restore that handler and Header the
	// header name (lower case).
	Rewrite string `json:"rewrite,omitempty"`
	Hide    string `json:"hide,omitempty"`
	Schild  string `json:"schild"`
	Restore string `json:"restore,omitempty"`
	Header  string `json:"header,omitempty"`
}

// Result of a vector.
type Result struct {
	Findings []Finding `json:"findings"`
}

// Message is the printed form of a finding (one line).
func Message(f Finding) string {
	site := "every host on server " + f.Server
	if len(f.Hosts) > 0 {
		site = strings.Join(f.Hosts, ", ")
	}
	where := "site"
	if strings.HasPrefix(f.Route, "/errors/") {
		where = "handle_errors of"
	}
	if f.Code == CodeHeaderHiddenFromSchild {
		return CodeHeaderHiddenFromSchild + ": " + where + " " + site + " changes request header " + f.Header + " before schild inspects the request and writes it again behind schild (" +
			f.Hide + " before " + f.Schild + ", written at " + f.Restore + "); a value schild never saw could reach the backend. " +
			"Put `schild` (or `import schild`) before the first change of the header"
	}
	return CodeRewriteBeforeSchild + ": " + where + " " + site + " runs `" + f.Directive + "` before schild inspects the request (" +
		f.Rewrite + " before " + f.Schild + "); a part it hides from schild could be put back after it and reach the backend unchecked. " +
		"Put `schild` (or `import schild`) first: at the top of the site block, or as the first line of the route or handle_errors block"
}

// event is one rewrite, schild or header-changing handler met by the walk,
// in execution order.
type event struct {
	schild    bool
	ptr       string
	frames    []frame
	guarded   bool // an unconditional schild ran before it on its path
	directive string
	// headers: a `headers` handler or the header ops of a reverse_proxy.
	headers bool
	hides   []string // lower-case names or patterns schild no longer sees
	writes  []string // lower-case names that can carry a value again
	// hostWrites: names written from the Host of the request only, which is
	// what schild inspected unless a hider changed Host too.
	hostWrites []string
}

// frame is one route on the path from the site route to a handler: the
// route list it belongs to, its index and its group.
type frame struct {
	list  int
	index int
	group string
}

type walker struct {
	named  map[string]any
	lists  int
	events []event
	stack  map[string]bool // named routes being walked (invoke cycle)
}

type item struct {
	route map[string]any
	ptr   string
	// handlePathStrip: the first route of a subroute that is the prefix
	// strip of Caddy's handle_path (see subItems); its rewrite is exempt.
	handlePathStrip bool
}

func esc(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// routes walks one route list in order and reports whether an
// unconditional schild handler guards everything after it at this level
// (as the gateway validator: a route is unconditional without matchers and
// as the first route of its group).
func (w *walker) routes(items []item, guarded bool, frames []frame, depth int) (bool, error) {
	if depth > MaxRouteDepth {
		return false, contract.Errf(contract.CodeSchema, "route lists nested deeper than %d", MaxRouteDepth)
	}
	w.lists++
	list := w.lists
	guards := false
	groups := map[string]bool{}
	for i, it := range items {
		r := it.route
		match, _ := r["match"].([]any)
		conditional := len(match) > 0
		group, _ := r["group"].(string)
		if group != "" {
			if groups[group] {
				conditional = true
			}
			groups[group] = true
		}
		fr := append(append([]frame{}, frames...), frame{list: list, index: i, group: group})
		p := guarded
		handle, _ := r["handle"].([]any)
		for j, x := range handle {
			h := x.(map[string]any)
			hp := it.ptr + "/handle/" + strconv.Itoa(j)
			name, _ := h["handler"].(string)
			switch name {
			case "schild":
				w.events = append(w.events, event{schild: true, ptr: hp, frames: fr, guarded: p})
				p = true
				if !conditional {
					guarded, guards = true, true
				}
			case "rewrite":
				if !it.handlePathStrip {
					w.events = append(w.events, event{ptr: hp, frames: fr, guarded: p, directive: directive(h)})
				}
			case "headers":
				hides, writes, host := headerOps(h["request"])
				if len(hides)+len(writes)+len(host) > 0 {
					w.events = append(w.events, event{headers: true, ptr: hp, frames: fr, guarded: p, hides: hides, writes: writes, hostWrites: host})
				}
			case "reverse_proxy":
				// header_up works on the proxy's copy of the request: before
				// schild it hides nothing, behind schild it can restore.
				if hs, ok := h["headers"].(map[string]any); ok {
					if _, writes, host := headerOps(hs["request"]); len(writes)+len(host) > 0 {
						w.events = append(w.events, event{headers: true, ptr: hp, frames: fr, guarded: p, writes: writes, hostWrites: host})
					}
				}
			case "subroute":
				sub, err := subItems(h["routes"], hp+"/routes", r, len(handle))
				if err != nil {
					return false, err
				}
				g, err := w.routes(sub, p, fr, depth+1)
				if err != nil {
					return false, err
				}
				if g {
					p = true
					if !conditional {
						guarded, guards = true, true
					}
				}
			case "invoke":
				nm, _ := h["name"].(string)
				nr, ok := w.named[nm].(map[string]any)
				if !ok {
					return false, contract.Errf(contract.CodeSchema, "invoke of an unknown named route %q", nm)
				}
				if w.stack[nm] {
					return false, contract.Errf(contract.CodeSchema, "named route %q invokes itself", nm)
				}
				w.stack[nm] = true
				g, err := w.routes([]item{{route: nr, ptr: "/named_routes/" + esc(nm)}}, p, fr, depth+1)
				delete(w.stack, nm)
				if err != nil {
					return false, err
				}
				if g {
					p = true
					if !conditional {
						guarded, guards = true, true
					}
				}
			}
			// Route lists anywhere else in the handler (handle_response of
			// reverse_proxy and intercept, the errors of a subroute); they
			// never guard what follows them. Errors start unguarded.
			nested, err := nestedLists(h, name == "subroute", hp)
			if err != nil {
				return false, err
			}
			for _, n := range nested {
				pp := p
				if n.errors {
					pp = false
				}
				if _, err := w.routes(n.items, pp, fr, depth+1); err != nil {
					return false, err
				}
			}
		}
	}
	return guards, nil
}

// subItems reads a subroute's routes. parent is the route holding the
// subroute handler; when it is the shape handle_path produces (one path
// matcher, the subroute as its only handler, the subroute's first route only
// a strip_path_prefix rewrite of that path's prefix), the first route is
// marked as the exempt prefix strip.
func subItems(v any, ptr string, parent map[string]any, parentHandlers int) ([]item, error) {
	items, err := readList(v, ptr)
	if err != nil {
		return nil, err
	}
	if len(items) > 0 && parentHandlers == 1 {
		if prefix, ok := handlePathPrefix(parent); ok && isStrip(items[0].route, prefix) {
			items[0].handlePathStrip = true
		}
	}
	return items, nil
}

// handlePathPrefix returns the prefix handle_path strips for a route whose
// matcher is exactly one path matcher with one path starting with "/":
// the path without a trailing "/*", else without a trailing "*".
func handlePathPrefix(r map[string]any) (string, bool) {
	match, _ := r["match"].([]any)
	if len(match) != 1 {
		return "", false
	}
	set, _ := match[0].(map[string]any)
	if len(set) != 1 {
		return "", false
	}
	paths, _ := set["path"].([]any)
	if len(paths) != 1 {
		return "", false
	}
	p, _ := paths[0].(string)
	if !strings.HasPrefix(p, "/") {
		return "", false
	}
	switch {
	case strings.HasSuffix(p, "/*"):
		p = p[:len(p)-2]
	case strings.HasSuffix(p, "*"):
		p = p[:len(p)-1]
	}
	return p, p != ""
}

// isStrip: a route without matcher and group whose only handler is
// {"handler": "rewrite", "strip_path_prefix": prefix}.
func isStrip(r map[string]any, prefix string) bool {
	if _, ok := r["match"]; ok {
		return false
	}
	if _, ok := r["group"]; ok {
		return false
	}
	handle, _ := r["handle"].([]any)
	if len(handle) != 1 {
		return false
	}
	h, _ := handle[0].(map[string]any)
	return len(h) == 2 && h["handler"] == "rewrite" && h["strip_path_prefix"] == prefix
}

func directive(h map[string]any) string {
	if _, ok := h["method"]; ok {
		return DirectiveMethod
	}
	for _, k := range []string{"strip_path_prefix", "strip_path_suffix", "uri_substring", "path_regexp", "query"} {
		if _, ok := h[k]; ok {
			return DirectiveURI
		}
	}
	return DirectiveRewrite
}

// serverPlaceholders are the Caddy placeholders no client can put bytes into
// (D43). Anything else counts as carrying a client value: a placeholder that
// is not on this list, a default (`{http.request.scheme:x}`) and every
// `{http.vars.*}`, because `vars` can overwrite any of them, client_ip too.
var serverPlaceholders = []string{"{http.request.scheme}", "{http.request.uuid}", "{http.request.proto}",
	"{http.request.remote}", "{http.request.remote.host}", "{http.request.remote.port}",
	"{http.reverse_proxy.upstream.host}", "{http.reverse_proxy.upstream.hostport}", "{http.reverse_proxy.upstream.port}"}

// hostPlaceholders hold the Host of the request. schild inspects that value,
// so they carry nothing it did not see, unless something before schild changed
// Host: then the value schild saw under Host is a value schild saw under
// another name, and a placeholder could move it (see hidden).
var hostPlaceholders = []string{"{http.request.host}", "{http.request.hostport}", "{http.request.port}"}

// Value classes of valueClass.
const (
	valueLiteral = iota // no placeholder, or only server placeholders
	valueHost           // also a host placeholder
	valueClient         // can carry a client value
)

// valueClass says what a header value can carry.
func valueClass(s string) int {
	for _, p := range serverPlaceholders {
		s = strings.ReplaceAll(s, p, "")
	}
	rest := s
	for _, p := range hostPlaceholders {
		rest = strings.ReplaceAll(rest, p, "")
	}
	switch {
	case strings.Contains(rest, "{"):
		return valueClient
	case rest != s:
		return valueHost
	}
	return valueLiteral
}

// headerOps reads Caddy's HeaderOps of a request. hides: names whose client
// value schild no longer sees (delete, set, replace; add leaves the value).
// writes: names that can carry a client value again (replace, and set or add
// with a value of valueClient; a literal or server-side value cannot bring
// anything back, nor can delete). host: names set or added from the Host only.
// Lower case, sorted, without duplicates.
func headerOps(v any) (hides, writes, host []string) {
	ops, ok := v.(map[string]any)
	if !ok {
		return nil, nil, nil
	}
	hide, write, hosts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	if del, ok := ops["delete"].([]any); ok {
		for _, x := range del {
			if n, ok := x.(string); ok {
				hide[lowerASCII(n)] = true
			}
		}
	}
	for _, op := range []string{"set", "add"} {
		m, _ := ops[op].(map[string]any)
		for n, vals := range m {
			if op == "set" {
				hide[lowerASCII(n)] = true
			}
			list, _ := vals.([]any)
			for _, x := range list {
				s, _ := x.(string)
				switch valueClass(s) {
				case valueClient:
					write[lowerASCII(n)] = true
				case valueHost:
					hosts[lowerASCII(n)] = true
				}
			}
		}
	}
	if m, ok := ops["replace"].(map[string]any); ok {
		for n := range m {
			hide[lowerASCII(n)] = true
			write[lowerASCII(n)] = true
		}
	}
	return sortedKeys(hide), sortedKeys(write), sortedKeys(hosts)
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// overlaps reports whether hide (a name or Caddy delete pattern: "*", "*x",
// "x*", "*x*") can touch the written name. A placeholder in a name can be
// any name, so it overlaps everything.
func overlaps(hide, name string) bool {
	if strings.Contains(hide, "{") || strings.Contains(name, "{") || hide == "*" || name == "*" {
		return true
	}
	pre, suf := strings.HasPrefix(hide, "*"), strings.HasSuffix(hide, "*")
	switch {
	case pre && suf:
		return strings.Contains(name, hide[1:len(hide)-1])
	case pre:
		return strings.HasSuffix(name, hide[1:])
	case suf:
		return strings.HasPrefix(name, hide[:len(hide)-1])
	}
	return hide == name
}

// common returns the first written name (hides, then writes in byte order)
// that a hide overlaps; a wildcard write names the hide instead.
func common(hides, writes []string) (string, bool) {
	for _, h := range hides {
		for _, n := range writes {
			if overlaps(h, n) {
				if n == "*" || strings.Contains(n, "{") {
					return h, true
				}
				return n, true
			}
		}
	}
	return "", false
}

type nestedList struct {
	items  []item
	errors bool
}

// nestedLists finds every key "routes" whose value is an array inside a
// handler's JSON, keys in byte order, depth first; skipTop skips the
// handler's own "routes" (a subroute's, walked by the caller). A list under
// a key "errors" at any depth is an error list.
func nestedLists(h map[string]any, skipTop bool, ptr string) ([]nestedList, error) {
	var out []nestedList
	var visit func(v any, p string, top, inErrors bool) error
	visit = func(v any, p string, top, inErrors bool) error {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				kp := p + "/" + esc(k)
				if k == "routes" {
					if _, isArr := t[k].([]any); isArr {
						if top && skipTop {
							continue
						}
						items, err := readList(t[k], kp)
						if err != nil {
							return err
						}
						if len(items) > 0 {
							out = append(out, nestedList{items: items, errors: inErrors})
						}
						continue
					}
				}
				if err := visit(t[k], kp, false, inErrors || k == "errors"); err != nil {
					return err
				}
			}
		case []any:
			for i, c := range t {
				if err := visit(c, p+"/"+strconv.Itoa(i), false, inErrors); err != nil {
					return err
				}
			}
		}
		return nil
	}
	err := visit(h, ptr, true, false)
	return out, err
}

// readList reads a route list: an array of routes (objects with only group,
// match, handle and terminal; handle an array of objects with a string
// handler). Anything else is a schema error.
func readList(v any, ptr string) ([]item, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, contract.Errf(contract.CodeSchema, "%s: routes is not an array", ptr)
	}
	out := make([]item, 0, len(arr))
	for i, x := range arr {
		p := ptr + "/" + strconv.Itoa(i)
		r, err := readRoute(x, p)
		if err != nil {
			return nil, err
		}
		out = append(out, item{route: r, ptr: p})
	}
	return out, nil
}

func readRoute(x any, p string) (map[string]any, error) {
	r, ok := x.(map[string]any)
	if !ok {
		return nil, contract.Errf(contract.CodeSchema, "%s: a route is not an object", p)
	}
	for k, v := range r {
		switch k {
		case "group":
			if _, ok := v.(string); !ok {
				return nil, contract.Errf(contract.CodeSchema, "%s/group: not a string", p)
			}
		case "match":
			m, ok := v.([]any)
			if !ok {
				return nil, contract.Errf(contract.CodeSchema, "%s/match: not an array", p)
			}
			for i, s := range m {
				if _, ok := s.(map[string]any); !ok {
					return nil, contract.Errf(contract.CodeSchema, "%s/match/%d: not an object", p, i)
				}
			}
		case "terminal":
			if _, ok := v.(bool); !ok {
				return nil, contract.Errf(contract.CodeSchema, "%s/terminal: not a boolean", p)
			}
		case "handle":
			hs, ok := v.([]any)
			if !ok {
				return nil, contract.Errf(contract.CodeSchema, "%s/handle: not an array", p)
			}
			for i, h := range hs {
				o, ok := h.(map[string]any)
				if !ok {
					return nil, contract.Errf(contract.CodeSchema, "%s/handle/%d: not an object", p, i)
				}
				if s, ok := o["handler"].(string); !ok || s == "" {
					return nil, contract.Errf(contract.CodeSchema, "%s/handle/%d: no handler name", p, i)
				}
			}
		default:
			return nil, contract.Errf(contract.CodeSchema, "%s: unknown route field %q", p, k)
		}
	}
	return r, nil
}

// precedes reports whether rewrite r can run before schild s: s comes later
// in walk order and the two are not in different routes of one group of the
// same route list (Caddy runs at most the first matching route of a group).
func precedes(r, s event) bool {
	n := min(len(r.frames), len(s.frames))
	for k := 0; k < n; k++ {
		a, b := r.frames[k], s.frames[k]
		if a == b {
			continue
		}
		return !(a.list == b.list && a.index != b.index && a.group != "" && a.group == b.group)
	}
	return true
}

// first returns the first unguarded rewrite that precedes a later schild
// and that schild, in walk order.
func first(evs []event) (event, event, bool) {
	for i, r := range evs {
		if r.schild || r.headers || r.guarded {
			continue
		}
		for _, s := range evs[i+1:] {
			if s.schild && precedes(r, s) {
				return r, s, true
			}
		}
	}
	return event{}, event{}, false
}

// hidden returns the first unguarded headers handler among the first own
// events that hides a header a later handler writes behind a schild the
// hider precedes, that schild, the writer and the header. evs may continue
// after own with the server's handle_errors routes: Caddy runs them on the
// same request, so a header hidden in a site can come back there.
func hidden(evs []event, own int) (event, event, event, string, bool) {
	hostHidden := false
	for _, e := range evs[:own] {
		for _, x := range e.hides {
			hostHidden = hostHidden || (!e.guarded && overlaps(x, "host"))
		}
	}
	for i, h := range evs[:own] {
		if !h.headers || h.guarded || len(h.hides) == 0 {
			continue
		}
		for j := i + 1; j < len(evs); j++ {
			s := evs[j]
			if !s.schild || !precedes(h, s) {
				continue
			}
			for _, w := range evs[j+1:] {
				if !w.headers {
					continue
				}
				writes := w.writes
				if hostHidden && len(w.hostWrites) > 0 {
					m := map[string]bool{}
					for _, n := range append(append([]string{}, w.writes...), w.hostWrites...) {
						m[n] = true
					}
					writes = sortedKeys(m)
				}
				if len(writes) == 0 || !precedes(h, w) || !precedes(s, w) {
					continue
				}
				if name, ok := common(h.hides, writes); ok {
					return h, s, w, name, true
				}
			}
		}
	}
	return event{}, event{}, event{}, "", false
}

func hostsOf(r map[string]any) []string {
	hosts := []string{}
	match, _ := r["match"].([]any)
	for _, s := range match {
		set, _ := s.(map[string]any)
		hs, _ := set["host"].([]any)
		for _, h := range hs {
			if str, ok := h.(string); ok {
				hosts = append(hosts, str)
			}
		}
	}
	return hosts
}

// Check applies the order rules to apps.http.servers of an adapted Caddy
// config (a generic JSON value as jsonx parses it). Servers in byte order
// of their names; per server every site route (/routes/i) in order, then
// every handle_errors route (/errors/routes/i). A site or error route is
// walked from its start unguarded (its own matcher selects the site and is
// dropped, as in the validator); handle_errors routes start unguarded
// because a site's schild may have inspected a rewritten URI. At most one
// finding per route and code, rewrite_before_schild first.
func Check(servers map[string]any) ([]Finding, error) {
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []Finding{}
	for _, name := range names {
		srv, ok := servers[name].(map[string]any)
		if !ok {
			return nil, contract.Errf(contract.CodeSchema, "server %q is not an object", name)
		}
		named := map[string]any{}
		if nr, ok := srv["named_routes"]; ok {
			m, ok := nr.(map[string]any)
			if !ok {
				return nil, contract.Errf(contract.CodeSchema, "%s/named_routes: not an object", name)
			}
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				r, err := readRoute(m[k], "/named_routes/"+esc(k))
				if err != nil {
					return nil, err
				}
				named[k] = r
			}
		}
		var siteItems []item
		if v, ok := srv["routes"]; ok {
			it, err := readList(v, "/routes")
			if err != nil {
				return nil, err
			}
			siteItems = it
		}
		var errItems []item
		if e, ok := srv["errors"]; ok {
			em, ok := e.(map[string]any)
			if !ok {
				return nil, contract.Errf(contract.CodeSchema, "/errors: not an object")
			}
			if v, ok := em["routes"]; ok {
				it, err := readList(v, "/errors/routes")
				if err != nil {
					return nil, err
				}
				errItems = it
			}
		}
		walk := func(it item) ([]event, error) {
			site := map[string]any{}
			for k, v := range it.route {
				if k != "match" {
					site[k] = v
				}
			}
			w := &walker{named: named, stack: map[string]bool{}}
			_, err := w.routes([]item{{route: site, ptr: it.ptr}}, false, nil, 1)
			return w.events, err
		}
		// Events of every handle_errors route, each under a frame of its own,
		// so a site route's handlers never share a route list with them.
		var errEvents []event
		for k, it := range errItems {
			evs, err := walk(it)
			if err != nil {
				return nil, err
			}
			for _, e := range evs {
				e.frames = append([]frame{{list: -1 - k}}, e.frames...)
				errEvents = append(errEvents, e)
			}
		}
		for i, it := range append(siteItems, errItems...) {
			evs, err := walk(it)
			if err != nil {
				return nil, err
			}
			if r, s, ok := first(evs); ok {
				out = append(out, Finding{Code: CodeRewriteBeforeSchild, MsgKey: MsgKeyRewriteBeforeSchild, Server: name, Route: it.ptr,
					Hosts: hostsOf(it.route), Directive: r.directive, Rewrite: r.ptr, Schild: s.ptr})
			}
			all := evs
			if i < len(siteItems) {
				all = append(append([]event{}, evs...), errEvents...)
			}
			if h, s, r, hdr, ok := hidden(all, len(evs)); ok {
				out = append(out, Finding{Code: CodeHeaderHiddenFromSchild, MsgKey: MsgKeyHeaderHiddenFromSchild, Server: name, Route: it.ptr,
					Hosts: hostsOf(it.route), Directive: DirectiveRequestHeader, Hide: h.ptr, Schild: s.ptr, Restore: r.ptr, Header: hdr})
			}
		}
	}
	return out, nil
}

// RunVector checks one ingress-order vector input: {"servers": {...}} (the
// adapted config's apps.http.servers) and an optional informative
// "caddyfile" (the source text; the gateway's test adapts it and compares).
func RunVector(raw []byte) (Result, error) {
	if len(raw) > MaxInputBytes {
		return Result{}, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return Result{}, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(Schema, v); err != nil {
		return Result{}, err
	}
	f, err := Check(v["servers"].(map[string]any))
	if err != nil {
		return Result{}, err
	}
	return Result{Findings: f}, nil
}
