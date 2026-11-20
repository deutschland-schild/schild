package caddymod

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/deutschland-schild/schild/contract/ingress"
)

// TestIngressPassMarkBoundToURI (MVP-19 fix round 3, measurement 3 finding
// 1): Caddy runs handle_errors with the original method and URI. When a
// route rewrote the URI before the site's schild, the "already checked"
// marker must not skip the inspection of the restored URI in handle_errors.
// Variants M24, M25 and M18 of the measurement, the forging attempts M04-M06
// plus header and query forgeries, and the normal case (same URI: one
// evaluation).
func TestIngressPassMarkBoundToURI(t *testing.T) {
	var hits atomic.Int64
	var lastURI atomic.Value
	backend := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		lastURI.Store(r.URL.RequestURI())
		fmt.Fprintf(w, "backend %s", r.URL.Path)
	})}
	baddr := freePort(t)
	ln, err := net.Listen("tcp", baddr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = backend.Serve(ln) }()
	defer backend.Close()

	g := testGate(t)
	bind(t, g)
	empty := t.TempDir()
	const attack = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&id=1%27%20OR%201%3D1--"

	type probe struct {
		path, host string
		hdr        map[string]string
		status     int
		hits       int64 // backend hits this probe may cause
		evals      int64 // requests the gate counted (once, also when re-checked), 0 = not checked
	}
	cases := []struct {
		name   string
		sites  string // %[1]s port, %[2]s backend, %[3]s empty dir
		probes []probe
	}{
		{"M24 rewrite drops the query before schild, error", `
http://a.example.test:%[1]s {
	route {
		rewrite * /hidden?
		schild
		error "boom" 500
	}
	handle_errors {
		import schild
		reverse_proxy %[2]s
	}
}`, []probe{
			{path: "/app/?" + attack, host: "a", status: 403},
			// A clean request is inspected twice (two different URIs) and
			// served; it counts once (D33 amendment, monitoring.Recheck).
			{path: "/app/?q=hello", host: "a", status: 200, hits: 1, evals: 1},
		}},
		{"M25 rewrite to the path only, file_server 404", `
http://a.example.test:%[1]s {
	route {
		rewrite * {path}?
		schild
		root * %[3]s
		file_server
	}
	handle_errors {
		import schild
		reverse_proxy %[2]s
	}
}`, []probe{
			{path: "/missing?" + attack, host: "a", status: 403},
			{path: "/missing?q=hello", host: "a", status: 200, hits: 1, evals: 1},
		}},
		{"M18 handle_errors restores the original URI after schild", `
http://a.example.test:%[1]s {
	route {
		rewrite * /hidden?
		schild
		error "boom" 500
	}
	handle_errors {
		import schild
		rewrite * {http.request.orig_uri}
		reverse_proxy %[2]s
	}
}`, []probe{{path: "/app/?" + attack, host: "a", status: 403}}},
		{"method change before schild (the query alone is caught)", `
http://a.example.test:%[1]s {
	route {
		method POST
		schild
		error "boom" 500
	}
	handle_errors {
		import schild
		reverse_proxy %[2]s
	}
}`, []probe{{path: "/?" + attack, host: "a", status: 403}}},
		{"M04 vars in a site without schild", `
http://:%[1]s {
	import schild
	reverse_proxy %[2]s
	handle_errors {
		import schild
		reverse_proxy %[2]s
	}
}
http://b.example.test:%[1]s {
	vars schild.passed true
	error "boom" 500
}`, []probe{
			{path: "/?" + attack, host: "b", status: 403},
			{path: "/?" + attack, host: "b", hdr: map[string]string{"Schild-Passed": "1", "X-Schild-Passed": "true"}, status: 403},
			{path: "/?schild.passed=1&" + attack, host: "b", status: 403},
		}},
		{"M05 map output schild.passed", `
http://:%[1]s {
	import schild
	reverse_proxy %[2]s
	handle_errors {
		import schild
		reverse_proxy %[2]s
	}
}
http://b.example.test:%[1]s {
	map {host} {schild.passed} {
		default 1
	}
	error "boom" 500
}`, []probe{{path: "/?" + attack, host: "b", status: 403}}},
		{"M06 vars inside handle_errors before schild", `
http://:%[1]s {
	import schild
	reverse_proxy %[2]s
	handle_errors {
		vars schild.passed 1
		import schild
		reverse_proxy %[2]s
	}
}
http://b.example.test:%[1]s {
	error "boom" 500
}`, []probe{{path: "/?" + attack, host: "b", status: 403}}},
		{"normal: own error with the same URI is checked once", `
http://a.example.test:%[1]s {
	import schild
	error /boom 500
	reverse_proxy %[2]s
	handle_errors {
		import schild
		reverse_proxy %[2]s
	}
}`, []probe{
			{path: "/boom?q=hello", host: "a", status: 200, hits: 1, evals: 1},
			{path: "/boom?" + attack, host: "a", status: 403},
		}},
		{"normal: try_files rewrite after schild, app error", `
http://a.example.test:%[1]s {
	route {
		import schild
		root * %[3]s
		try_files {path} /index.html
		error "boom" 500
	}
	handle_errors {
		import schild
		reverse_proxy %[2]s
	}
}`, []probe{{path: "/page?q=hello", host: "a", status: 200, hits: 1, evals: 1}}},
	}
	refused := map[string]bool{
		cases[0].name: true, cases[1].name: true, cases[2].name: true, cases[3].name: true,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := caddyDir(t)
			addr := freePort(t)
			p := port(addr)
			caddyfile := fmt.Sprintf("{\n\tauto_https off\n\thttp_port %[1]s\n}\n\n(schild) {\n\tschild\n}\n"+tc.sites+"\n", p, baddr, filepath.ToSlash(empty))
			ing, err := PrepareIngress(IngressOptions{Caddyfile: writeFile(t, dir, "Caddyfile", caddyfile), DefaultStorage: filepath.Join(dir, "caddy")})
			if ing == nil {
				t.Fatal(err)
			}
			if err := Load(ing.JSON); err != nil {
				t.Fatal(err)
			}
			defer Stop()
			// A rewrite before schild is refused since the D31 amendment
			// (rule rewrite_before_schild); the marker binding stays the
			// second line, so the refused config is loaded anyway.
			if len(ing.Check.Errors) > 0 != refused[tc.name] {
				t.Fatalf("validator errors %v, want refused=%v", ing.Check.Errors, refused[tc.name])
			}
			for _, e := range ing.Check.Errors {
				if !strings.HasPrefix(e, ingress.CodeRewriteBeforeSchild+": ") {
					t.Fatalf("validator refused: %v", e)
				}
			}
			c := &http.Client{}
			for _, pr := range tc.probes {
				h0 := hits.Load()
				e0 := requestsSettled(t, g, 0)
				r := fetch(t, c, "http://"+addr+pr.path, pr.host+".example.test:"+p, pr.hdr)
				if r.status != pr.status {
					t.Fatalf("%s %s: status %d, want %d (%q)", pr.host, pr.path, r.status, pr.status, r.body)
				}
				if n := hits.Load() - h0; n != pr.hits {
					t.Fatalf("%s %s: backend hits %d, want %d (last %v)", pr.host, pr.path, n, pr.hits, lastURI.Load())
				}
				if n := hits.Load() - h0; n > 0 && strings.Contains(fmt.Sprint(lastURI.Load()), "script") {
					t.Fatalf("attack reached the backend: %v", lastURI.Load())
				}
				if pr.evals > 0 {
					if n := requestsSettled(t, g, e0+pr.evals) - e0; n != pr.evals {
						t.Fatalf("%s %s: evaluations %d, want %d", pr.host, pr.path, n, pr.evals)
					}
				}
			}
		})
	}
}

// TestPassMarkMatches: the marker holds for the same request only; any
// change of method, path, query, raw request URI, host or remote address
// makes schild inspect again.
func TestPassMarkMatches(t *testing.T) {
	base := func() *http.Request {
		r, _ := http.NewRequest("GET", "http://a.example.test/app/?q=1", nil)
		r.RequestURI = "/app/?q=1"
		r.RemoteAddr = "192.0.2.1:4000"
		return r
	}
	m := markOf(base())
	if !m.matches(base()) {
		t.Fatal("same request must match")
	}
	for name, change := range map[string]func(r *http.Request){
		"method":      func(r *http.Request) { r.Method = "POST" },
		"path":        func(r *http.Request) { r.URL.Path = "/other" },
		"query":       func(r *http.Request) { r.URL.RawQuery = "q=%3Cscript%3E" },
		"request uri": func(r *http.Request) { r.RequestURI = "/hidden" },
		"host":        func(r *http.Request) { r.Host = "b.example.test" },
		"remote":      func(r *http.Request) { r.RemoteAddr = "192.0.2.2:4000" },
	} {
		r := base()
		change(r)
		if m.matches(r) {
			t.Errorf("%s changed, marker still matches", name)
		}
	}
}
