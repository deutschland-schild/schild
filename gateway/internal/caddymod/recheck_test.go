package caddymod

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/stats"
)

// TestRecheckCountsOnce (D33 amendment 2026-10-29, contract
// monitoring.Recheck): a request schild evaluates more than once, in
// handle_errors after a handle_path strip (P08) or again after a rewrite
// that follows a schild (nested), counts once and is recorded once with
// the combined outcome; a request whose error goes to a handle_errors
// without schild is still recorded once, when Caddy is done with it.
func TestRecheckCountsOnce(t *testing.T) {
	backend := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	var mu sync.Mutex
	var outcomes []string
	g.Summary = func(outcome, _ string, _ time.Time) {
		mu.Lock()
		outcomes = append(outcomes, outcome)
		mu.Unlock()
	}
	bind(t, g)
	empty := t.TempDir()
	const attack = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&id=1%27%20OR%201%3D1--"

	cases := []struct {
		name, sites, path string
		status            int
		outcome           string
	}{
		{"P08 handle_path strip, re-checked in handle_errors", `
http://a.example.test:%[1]s {
	import schild
	handle_path /app/* {
		root * %[3]s
		file_server
	}
	handle_errors {
		import schild
		reverse_proxy %[2]s
	}
}`, "/app/missing?q=hello", 200, "passed"},
		{"nested: schild, rewrite, schild", `
http://a.example.test:%[1]s {
	route {
		import schild
		rewrite * /inner{path}
		schild
		reverse_proxy %[2]s
	}
}`, "/page?q=hello", 200, "passed"},
		{"nested: the second evaluation blocks", `
http://a.example.test:%[1]s {
	route {
		import schild
		rewrite * /inner?` + attack + `
		schild
		reverse_proxy %[2]s
	}
}`, "/page", 403, "blocked"},
		{"error to a handle_errors without schild", `
http://a.example.test:%[1]s {
	import schild
	error 500
	handle_errors {
		respond "sorry" 500
	}
}`, "/x?q=hello", 500, "passed"},
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
			c := &http.Client{}
			// Warm-up: the first request may be retried while Caddy starts.
			fetch(t, c, "http://"+addr+"/warm", "a.example.test:"+p, nil)
			time.Sleep(50 * time.Millisecond)
			mu.Lock()
			outcomes = nil
			mu.Unlock()
			e0 := g.Counters.Rolling.Sum(stats.Requests, time.Hour, time.Now())
			r := fetch(t, c, "http://"+addr+tc.path, "a.example.test:"+p, nil)
			if r.status != tc.status {
				t.Fatalf("status %d, want %d (%q)", r.status, tc.status, r.body)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				mu.Lock()
				n := len(outcomes)
				mu.Unlock()
				if n > 0 || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond)
			if n := g.Counters.Rolling.Sum(stats.Requests, time.Hour, time.Now()) - e0; n != 1 {
				t.Fatalf("requests counted %d, want 1", n)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(outcomes) != 1 || outcomes[0] != tc.outcome {
				t.Fatalf("records %v, want one %s", outcomes, tc.outcome)
			}
		})
	}
}
