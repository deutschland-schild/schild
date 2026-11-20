package caddymod

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/deutschland-schild/schild/contract/websites"
)

// TestSiteBlocksRealWorld runs the Caddyfiles of the MVP-21/D36 measurement
// (results/MVP-21-D36-messung/d36/derive/cases, the real-world set r01-r18;
// r15 is refused by Caddy itself): the blocks the gateway derives must be
// the blocks of the measurement's independent reading, and the websites
// must be the same.
func TestSiteBlocksRealWorld(t *testing.T) {
	dirs, err := filepath.Glob("testdata/websites/*")
	if err != nil || len(dirs) < 20 {
		t.Fatalf("cases: %v %d", err, len(dirs))
	}
	for _, d := range dirs {
		t.Run(filepath.Base(d), func(t *testing.T) {
			var c struct {
				Unprotected []string         `json:"unprotected_sites"`
				Resolve     []string         `json:"resolve"`
				Blocks      []websites.Block `json:"blocks"`
			}
			raw, err := os.ReadFile(filepath.Join(d, "case.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			p, _ := filepath.Abs(filepath.Join(d, "Caddyfile"))
			ing, err := PrepareIngress(IngressOptions{Caddyfile: p, DefaultStorage: t.TempDir(), Unprotected: c.Unprotected})
			if ing == nil {
				t.Fatal(err)
			}
			got, err := SiteBlocks(p, ing.Check)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.Blocks) {
				t.Fatalf("blocks\n got %+v\nwant %+v", got, c.Blocks)
			}
			gs, gerr := websites.Derive(websites.Input{Mode: websites.ModeIngress, Blocks: got, UnprotectedSites: c.Unprotected})
			ws, werr := websites.Derive(websites.Input{Mode: websites.ModeIngress, Blocks: c.Blocks, UnprotectedSites: c.Unprotected})
			if (gerr == nil) != (werr == nil) {
				t.Fatalf("derive: %v vs %v", gerr, werr)
			}
			if werr != nil {
				return
			}
			if !reflect.DeepEqual(gs.Websites, ws.Websites) {
				t.Fatalf("websites %+v, want %+v", gs.Websites, ws.Websites)
			}
			for _, h := range c.Resolve {
				if gs.Resolve(h) != ws.Resolve(h) {
					t.Fatalf("resolve %s: %q, want %q", h, gs.Resolve(h), ws.Resolve(h))
				}
			}
		})
	}
}

// TestSiteBlocksRedirectAndApp: the usual setups give one website each, and
// every host a block with schild serves resolves to a website, so the sum
// over websites is the gateway total.
func TestSiteBlocksRedirectAndApp(t *testing.T) {
	cases := []struct {
		name, caddyfile string
		unprotected     []string
		want            []string // id/protection
	}{
		{"http redirect plus https app", `
http://shop.example.org {
	redir https://shop.example.org{uri} 308
}
shop.example.org {
	schild
	reverse_proxy 127.0.0.1:9
}`, nil, []string{"shop.example.org/protected"}},
		{"www redirect", `
www.example.org {
	redir https://example.org{uri}
}
example.org {
	schild
	reverse_proxy 127.0.0.1:9
}`, nil, []string{"example.org/protected"}},
		{"several apps on one server with redirects", `
http://a.example.org, http://b.example.org {
	redir https://{host}{uri}
}
a.example.org {
	schild
	reverse_proxy 127.0.0.1:9
}
b.example.org {
	schild
	reverse_proxy 127.0.0.1:10
}
c.example.org {
	schild
	php_fastcgi 127.0.0.1:9000
}`, nil, []string{"a.example.org/protected", "b.example.org/protected", "c.example.org/protected"}},
		{"mixed protection is partial", `
mixed.example.org {
	schild
	reverse_proxy 127.0.0.1:9
}
http://mixed.example.org {
	reverse_proxy 127.0.0.1:9
}`, []string{"mixed.example.org"}, []string{"mixed.example.org/partial"}},
		{"ipv6 in any textual form", `
[2001:DB8:0:0::1]:8443 {
	schild
	reverse_proxy 127.0.0.1:9
}
http://[2001:db8::1] {
	redir https://[2001:db8::1]:8443{uri}
}`, nil, []string{"ipv6-2001-db8--1/protected"}},
		// D36 fix round 2 (re-measurement B 3.1, n06c/n15): schild in every
		// handle branch instead of at the top; the validator accepts it.
		{"schild in every handle branch", `
full.example.org {
	redir /old /new
	handle_path /api/* {
		schild
		reverse_proxy 127.0.0.1:9
	}
	handle {
		schild
		reverse_proxy 127.0.0.1:9
	}
	handle_errors {
		respond 500
	}
}
blog.example.org {
	schild
	reverse_proxy 127.0.0.1:9
}`, nil, []string{"full.example.org/protected", "blog.example.org/protected"}},
		{"named route with a matcher reaches its backend", `
&(app) {
	schild
	@api path /api/*
	reverse_proxy @api 127.0.0.1:9
}
a.example.org {
	invoke app
}`, nil, []string{"a.example.org/protected"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, t.TempDir(), "Caddyfile", "{\n\tadmin off\n}\n"+tc.caddyfile+"\n")
			ing, err := PrepareIngress(IngressOptions{Caddyfile: p, DefaultStorage: t.TempDir(), Unprotected: tc.unprotected})
			if err != nil {
				t.Fatal(err)
			}
			blocks, err := SiteBlocks(p, ing.Check)
			if err != nil {
				t.Fatal(err)
			}
			set, err := websites.Derive(websites.Input{Mode: websites.ModeIngress, Blocks: blocks, UnprotectedSites: tc.unprotected})
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, w := range set.Websites {
				ids = append(ids, w.ID+"/"+w.Protection)
			}
			if !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("websites %v, want %v (blocks %+v)", ids, tc.want, blocks)
			}
			for _, b := range blocks {
				if !b.Schild {
					continue
				}
				for _, a := range b.Addresses {
					if set.Resolve(hostPort(a)) == "" {
						t.Fatalf("%s resolves to no website", a)
					}
				}
			}
		})
	}
}

// hostPort is the host[:port] of a site address (scheme and path cut).
func hostPort(a string) string {
	if _, rest, ok := strings.Cut(a, "://"); ok {
		a = rest
	}
	a, _, _ = strings.Cut(a, "/")
	return a
}

func TestSiteBlocksDeriveWebsites(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "Caddyfile", `{
	admin off
}
(protect) {
	schild
}
shop.example.org, www.shop.example.org {
	import protect
	reverse_proxy 127.0.0.1:9
}
http://shop.example.org:8443 {
	import protect
	reverse_proxy 127.0.0.1:9
}
verein.example {
	schild
	reverse_proxy 127.0.0.1:10
}
legacy.example.org {
	reverse_proxy 127.0.0.1:11
}
www.verein.example {
	redir https://verein.example{uri}
}
`)
	ing, err := PrepareIngress(IngressOptions{Caddyfile: p, DefaultStorage: t.TempDir(), Unprotected: []string{"legacy.example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := SiteBlocks(p, ing.Check)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 5 || !blocks[0].Schild || !blocks[1].Schild || blocks[3].Schild || !blocks[3].Proxies || blocks[4].Schild || blocks[4].Proxies {
		t.Fatalf("blocks: %+v", blocks)
	}
	set, err := websites.Derive(websites.Input{Mode: websites.ModeIngress, Blocks: blocks, UnprotectedSites: []string{"legacy.example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, w := range set.Websites {
		ids = append(ids, w.ID+"/"+w.Protection)
	}
	want := []string{"shop.example.org/protected", "verein.example/protected", "legacy.example.org/unprotected"}
	if len(ids) != len(want) {
		t.Fatalf("websites %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("websites %v, want %v", ids, want)
		}
	}
	if got := set.Resolve("www.shop.example.org:443"); got != "shop.example.org" {
		t.Fatalf("resolve: %q", got)
	}
}

// FuzzResolveFollowsCaddy: a Host that Caddy's host matcher routes to the
// site address of a website resolves to that website (D69). The seeds are
// the spellings of the security audit of 2026-11-05.
func FuzzResolveFollowsCaddy(f *testing.F) {
	addrs := []string{"secret.example.org", "*.kunden.example.org", "[2001:db8::1]", "192.0.2.10"}
	var in websites.Input
	in.Mode = websites.ModeIngress
	var matchers []caddyhttp.MatchHost
	for _, a := range addrs {
		in.Blocks = append(in.Blocks, websites.Block{Addresses: []string{a}, Schild: true, Proxies: true})
		m := caddyhttp.MatchHost{strings.Trim(a, "[]")} // the adapter writes IPv6 hosts without brackets
		if err := m.Provision(caddy.Context{}); err != nil {
			f.Fatal(err)
		}
		matchers = append(matchers, m)
	}
	set, err := websites.Derive(in)
	if err != nil {
		f.Fatal(err)
	}
	for _, h := range []string{"secret.example.org", "secret.example.org:abc", "secret.example.org:", "secret.example.org:0443", "secret.example.org:70000",
		"[secret.example.org]", "[secret.example.org]:443", "SECRET.example.org", "ſecret.example.org", "a_b.kunden.example.org", "*.kunden.example.org",
		".kunden.example.org", "-a.kunden.example.org:1", "a.Kunden.example.org", "2001:DB8::1", "[2001:db8::1]:x", "192.0.2.10:", "[192.0.2.10]"} {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, host string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		for i, m := range matchers {
			if m.Match(r) {
				if got, want := set.Resolve(host), set.Websites[i].ID; got != want {
					t.Fatalf("Host %q: Caddy routes it to %s, Resolve gives %q", host, addrs[i], got)
				}
			}
		}
	})
}

// TestBindWebsites: every schild handler of a site block carries the website
// of that block, also under handle_errors; a host-less block and a named
// route keep reading the Host (D69).
func TestBindWebsites(t *testing.T) {
	dir := t.TempDir()
	cf := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cf, []byte(`{
	auto_https off
}

&(shared) {
	schild
	reverse_proxy 127.0.0.1:9
}

http://secret.example.org, http://www.secret.example.org {
	schild
	reverse_proxy 127.0.0.1:9
	handle_errors {
		schild
		respond "error"
	}
}

http://*.kunden.example.org {
	route {
		schild
		reverse_proxy 127.0.0.1:9
	}
}

http://shared.example.org {
	invoke shared
}

:8080 {
	schild
	reverse_proxy 127.0.0.1:9
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _, err := ReadCaddyfile(cf)
	if err != nil {
		t.Fatal(err)
	}
	chk, err := CheckConfig(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := SiteBlocks(cf, chk)
	if err != nil {
		t.Fatal(err)
	}
	set, err := websites.Derive(websites.Input{Mode: websites.ModeIngress, Blocks: blocks})
	if err != nil {
		t.Fatal(err)
	}
	out, err := BindWebsites(raw, set.RouteWebsite)
	if err != nil {
		t.Fatal(err)
	}
	// website of every schild handler, keyed by the hosts of its top-level route
	got := map[string][]string{}
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch x := v.(type) {
		case map[string]any:
			if x["handler"] == "schild" {
				w, _ := x["website"].(string)
				got[key] = append(got[key], w)
			}
			for _, c := range x {
				walk(c, key)
			}
		case []any:
			for _, c := range x {
				walk(c, key)
			}
		}
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	for _, s := range m["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any) {
		srv := s.(map[string]any)
		lists := []any{srv["routes"]}
		if e, ok := srv["errors"].(map[string]any); ok {
			lists = append(lists, e["routes"])
		}
		for _, l := range lists {
			for _, rt := range l.([]any) {
				route := rt.(map[string]any)
				key := "(none)"
				if b, err := json.Marshal(route["match"]); err == nil && route["match"] != nil {
					key = string(b)
				}
				walk(route["handle"], key)
			}
		}
		walk(srv["named_routes"], "(named)")
	}
	want := map[string][]string{
		`[{"host":["secret.example.org","www.secret.example.org"]}]`: {"secret.example.org", "secret.example.org"}, // site and handle_errors
		`[{"host":["*.kunden.example.org"]}]`:                        {"_.kunden.example.org"},
		"(none)":                                                     {""},
		"(named)":                                                    {""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schild handlers:\n got %v\nwant %v", got, want)
	}
}

// TestFrontCaddyfileAdapts: the Caddy front template of deploy/ is a valid
// Caddyfile for the pinned Caddy, and its 502 handler refuses to fail open
// while the lock file is missing (D71).
func TestFrontCaddyfileAdapts(t *testing.T) {
	raw, _, err := ReadCaddyfile("../../deploy/Caddyfile.front")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"not":[{"file":{"root":"/var/lib/schild/access","try_files":["active.json"]}}]`) {
		t.Fatalf("no unknown-lock matcher in the adapted config:\n%s", raw)
	}
}
