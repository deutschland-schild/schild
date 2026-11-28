package caddymod

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/deutschland-schild/schild/contract/websites"
)

// SiteBlocks returns the site blocks of the operator's Caddyfile in file
// order as contract/websites blocks (D36): the addresses as written (after
// imports and environment placeholders), Schild and Proxies from the
// directive check.
//
// Each block is adapted on its own (with the global options and the named
// routes of the file) and checked with CheckConfig, so a block is judged by
// what it serves itself. Matching the routes of the whole adapted config by
// host joined blocks that share a host on different listeners: an http
// block that only redirects made the https block of the same host count
// as "without schild" (MVP-21/D36 measurement, finding B.4.1). A block
// that cannot be adapted alone falls back to the routes of chk that serve
// one of its hosts on the same listener kind.
func SiteBlocks(path string, chk Check) ([]websites.Block, error) {
	return SiteBlocksOf(path, nil, chk)
}

// SiteBlocksOf is SiteBlocks for body as the Caddyfile at path; a nil body
// is read from path.
func SiteBlocksOf(path string, body []byte, chk Check) ([]websites.Block, error) {
	if body == nil {
		var err error
		if body, err = os.ReadFile(path); err != nil {
			return nil, fmt.Errorf("caddyfile: %w", err)
		}
	}
	sbs, err := caddyfile.Parse(path, body)
	if err != nil {
		return nil, fmt.Errorf("caddyfile %s: %w", path, err)
	}
	var out []websites.Block
	for i, sb := range sbs {
		keys := sb.GetKeysText()
		if sb.IsNamedRoute || len(keys) == 0 {
			continue // global options, named routes
		}
		b, err := blockAlone(path, body, i)
		if err != nil {
			b = blockFromCheck(keys, chk)
		}
		b.Addresses = keys
		out = append(out, b)
	}
	return out, nil
}

// blockAlone adapts block idx of the Caddyfile together with the global
// options block and every named route, and checks the result.
func blockAlone(path string, body []byte, idx int) (websites.Block, error) {
	// Parse again: Setup rewrites the segments of the blocks it gets.
	sbs, err := caddyfile.Parse(path, body)
	if err != nil || idx >= len(sbs) {
		return websites.Block{}, fmt.Errorf("caddyfile: block %d", idx)
	}
	var keep []caddyfile.ServerBlock
	for i, sb := range sbs {
		switch {
		case i == 0 && len(sb.Keys) == 0: // global options
		case sb.IsNamedRoute:
		case i == idx:
		default:
			continue
		}
		keep = append(keep, sb)
	}
	ad := caddyconfig.GetAdapter("caddyfile")
	if ad == nil {
		return websites.Block{}, fmt.Errorf("caddyfile: adapter not compiled in")
	}
	cf, ok := ad.(caddyfile.Adapter)
	if !ok || cf.ServerType == nil {
		return websites.Block{}, fmt.Errorf("caddyfile: unexpected adapter")
	}
	cfg, _, err := cf.ServerType.Setup(keep, map[string]any{"filename": path})
	if err != nil {
		return websites.Block{}, err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return websites.Block{}, err
	}
	chk, err := CheckConfig(raw, nil)
	if err != nil {
		return websites.Block{}, err
	}
	b := blockFromSites(chk.Sites)
	// Proxies is any backend (contract: the block reaches a backend), also
	// one behind schild; CheckConfig lists only the unguarded ones.
	b.Proxies = b.Proxies || reachesBackend(raw)
	return b, nil
}

// BindWebsites gives every schild handler in the routes of a site block the
// website of that block (D69), so the access lock and crawler control decide
// by the site block Caddy chose, never by a second reading of the Host. A
// top-level route of a server (or of its handle_errors) selects its site
// block by host matchers; website maps those hosts to the website id ("" for
// none or more than one, see websites.Set.RouteWebsite). A schild handler in
// a route without a host matcher or in a named route reads the Host.
func BindWebsites(cfgJSON []byte, website func(hosts []string) string) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(cfgJSON, &m); err != nil {
		return nil, fmt.Errorf("caddyfile: adapted config: %w", err)
	}
	apps, _ := m["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	for _, v := range servers {
		srv, _ := v.(map[string]any)
		bindRoutes(srv["routes"], website)
		if e, ok := srv["errors"].(map[string]any); ok {
			bindRoutes(e["routes"], website)
		}
		setWebsite(srv["named_routes"], "")
	}
	return json.Marshal(m)
}

func bindRoutes(v any, website func(hosts []string) string) {
	routes, _ := v.([]any)
	for _, x := range routes {
		r, _ := x.(map[string]any)
		var hosts []string
		sets, _ := r["match"].([]any)
		for _, set := range sets {
			ms, _ := set.(map[string]any)
			hs, _ := ms["host"].([]any)
			for _, h := range hs {
				if s, ok := h.(string); ok {
					hosts = append(hosts, s)
				}
			}
		}
		id := ""
		if len(hosts) > 0 {
			id = website(hosts)
		}
		setWebsite(r["handle"], id)
	}
}

// setWebsite sets the website of every schild handler in v, or removes it
// when id is empty.
func setWebsite(v any, id string) {
	switch t := v.(type) {
	case map[string]any:
		if t["handler"] == "schild" {
			if id != "" {
				t["website"] = id
			} else {
				delete(t, "website")
			}
		}
		for _, c := range t {
			setWebsite(c, id)
		}
	case []any:
		for _, c := range t {
			setWebsite(c, id)
		}
	}
}

// reachesBackend reports whether an adapted config has a reverse_proxy
// handler (php_fastcgi adapts to one) in the routes of its HTTP servers,
// also inside a named route the block invokes.
func reachesBackend(cfgJSON []byte) bool {
	var c struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes      json.RawMessage            `json:"routes"`
					Errors      json.RawMessage            `json:"errors"`
					NamedRoutes map[string]json.RawMessage `json:"named_routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if json.Unmarshal(cfgJSON, &c) != nil {
		return false
	}
	for _, srv := range c.Apps.HTTP.Servers {
		// Named routes are in the config whether this block invokes them
		// or not: only the invoked ones count.
		invoked := map[string]bool{}
		var visit func(v any) bool
		visit = func(v any) bool {
			switch t := v.(type) {
			case map[string]any:
				switch t["handler"] {
				case "reverse_proxy":
					return true
				case "invoke":
					if n, ok := t["name"].(string); ok {
						invoked[n] = true
					}
				}
				for _, c := range t {
					if visit(c) {
						return true
					}
				}
			case []any:
				for _, c := range t {
					if visit(c) {
						return true
					}
				}
			}
			return false
		}
		for _, raw := range []json.RawMessage{srv.Routes, srv.Errors} {
			var v any
			if len(raw) > 0 && json.Unmarshal(raw, &v) == nil && visit(v) {
				return true
			}
		}
		done := map[string]bool{}
		for {
			var next string
			for n := range invoked {
				if !done[n] {
					next = n
					break
				}
			}
			if next == "" {
				break
			}
			done[next] = true
			var v any
			if raw, ok := srv.NamedRoutes[next]; ok && json.Unmarshal(raw, &v) == nil && visit(v) {
				return true
			}
		}
	}
	return false
}

// blockFromSites: the block runs schild when it serves something and every
// route of it (handle_errors aside) does, at the top or in every branch
// that reaches a backend (SiteCheck.Guarded); it proxies when one of its routes
// reaches a backend without schild.
func blockFromSites(scs []SiteCheck) websites.Block {
	b := websites.Block{}
	routes := 0
	schild := true
	for _, sc := range scs {
		b.Proxies = b.Proxies || len(sc.Backends) > 0
		if sc.Errors {
			continue
		}
		routes++
		schild = schild && (sc.Schild || sc.Guarded)
	}
	b.Schild = routes > 0 && schild
	return b
}

// blockFromCheck is the fallback: the routes of the whole config that serve
// one of the block's hosts (normalised, so every textual form of an IPv6
// literal or a host in upper case matches).
func blockFromCheck(keys []string, chk Check) websites.Block {
	want := map[string]bool{}
	hostless := false
	for _, k := range keys {
		h, err := websites.ParseAddress(k)
		if err != nil {
			continue
		}
		if h.ID() == websites.AnyID {
			hostless = true
			continue
		}
		want[h.Key] = true
	}
	var scs []SiteCheck
	for _, sc := range chk.Sites {
		if sc.Errors {
			continue
		}
		match := hostless && len(sc.Hosts) == 0
		for _, sh := range sc.Hosts {
			if h, err := websites.ParseAddress(matcherHost(sh)); err == nil && want[h.Key] {
				match = true
			}
		}
		if match {
			scs = append(scs, sc)
		}
	}
	return blockFromSites(scs)
}

// matcherHost turns a host of a Caddy host matcher into an address
// ParseAddress reads: an IPv6 literal (written without brackets there) gets
// its brackets.
func matcherHost(h string) string {
	if a, err := netip.ParseAddr(h); err == nil && a.Is6() {
		return "[" + h + "]"
	}
	return h
}
