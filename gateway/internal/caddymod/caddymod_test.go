package caddymod

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/gate"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// freePort returns a free TCP address. The UDP port of the same number may be
// taken, so a test that serves TLS on it sets "protocols h1 h2": HTTP/3 would
// bind that UDP port and fail now and then.
// freePort returns a free loopback address whose port no earlier call of this
// test binary returned: the kernel may hand a just released port out again, and
// a config with http_port equal to https_port is refused by Caddy.
func freePort(t testing.TB) string {
	portsMu.Lock()
	defer portsMu.Unlock()
	for range 100 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		if !portsGiven[addr] {
			portsGiven[addr] = true
			return addr
		}
	}
	t.Fatal("no unused free port")
	return ""
}

var (
	portsMu    sync.Mutex
	portsGiven = map[string]bool{}
)

// The proxy listener speaks HTTP/1 only: no h2c (security review 2.2).
func TestProxyListenerHasNoH2C(t *testing.T) {
	b, err := BuildConfig(Options{Listen: ":8080", Upstream: "http://127.0.0.1:9", DataDir: "/tmp/x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "h2c") {
		t.Fatalf("h2c in the proxy config: %s", b)
	}
}

func TestBuildConfig(t *testing.T) {
	if _, err := BuildConfig(Options{Listen: ":8080", Upstream: "ftp://x"}); err == nil {
		t.Fatal("ftp accepted")
	}
	if _, err := BuildConfig(Options{Listen: ":8080", Upstream: "http://app/prefix"}); err == nil {
		t.Fatal("path accepted")
	}
	b, err := BuildConfig(Options{Listen: ":8080", Upstream: "https://app.example", TrustedProxies: []string{"127.0.0.1/32"}, DataDir: "/tmp/x"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"handler":"schild"`, `"dial":"app.example:443"`, `"tls":{}`, `"disabled":true`, `"ranges":["127.0.0.1/32"]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("config lacks %s: %s", want, b)
		}
	}
}

// TestEmbeddedCaddy runs the real Caddy server with the schild handler in
// front of reverse_proxy.
func TestEmbeddedCaddy(t *testing.T) {
	var hits atomic.Int64
	var lastXFF atomic.Value
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		lastXFF.Store(r.Header.Get("X-Forwarded-For"))
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "ok %d", len(b))
	}))
	defer backend.Close()
	inst, err := waf.Build(waf.Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err != nil {
		t.Fatal(err)
	}
	res, _ := clientip.New([]string{"127.0.0.1/32"}, nil)
	g := gate.New(gate.Settings{Mode: decide.ModeAutoblock, EvalTimeout: 2 * time.Second, Resolver: res})
	g.Engine = &waf.Engine{}
	g.Engine.Swap(inst)
	g.Allow = allowlist.New()
	g.Counters = gate.NewCounters()
	g.SetReady(true)
	bind(t, g)
	addr := freePort(t)
	if err := Start(Options{Listen: addr, Upstream: backend.URL, TrustedProxies: []string{"127.0.0.1/32"}, DataDir: t.TempDir(), LogLevel: "ERROR"}); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	base := "http://" + addr
	get := func(path string, hdr map[string]string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", base+path, nil)
		req.Host = "shop.example"
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
		req.Header.Set("Accept", "text/html")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		var resp *http.Response
		var err error
		for i := 0; i < 50; i++ {
			resp, err = http.DefaultClient.Do(req)
			if err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}
	if r, b := get("/hello", map[string]string{"X-Forwarded-For": "198.51.100.23"}); r.StatusCode != 200 || b != "ok 0" {
		t.Fatalf("clean: %d %q", r.StatusCode, b)
	}
	if xff, _ := lastXFF.Load().(string); !strings.Contains(xff, "198.51.100.23") {
		t.Fatalf("X-Forwarded-For not passed on: %q", xff)
	}
	if r, b := get("/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil); r.StatusCode != 403 || !strings.Contains(b, "Vorfallnummer") {
		t.Fatalf("xss: %d", r.StatusCode)
	}
	if hits.Load() != 1 {
		t.Fatalf("backend hits %d", hits.Load())
	}
	if r, _ := get(gate.ReadyPath, nil); r.StatusCode != 200 {
		t.Fatal("readyz")
	}
	backend.Close()
	if r, _ := get("/hello", nil); r.StatusCode != 502 {
		t.Fatalf("upstream down: %d", r.StatusCode)
	}
}

// BenchmarkCaddyPath compares the full HTTP path through the embedded Caddy
// with and without the schild handler (CRS, autoblock) over loopback: the
// difference is schild's overhead per request (B01-style; the real B01
// measurement at 50..2000 rps runs in the test lab, MVP-05).
func BenchmarkCaddyPath(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()
	inst, err := waf.Build(waf.Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err != nil {
		b.Fatal(err)
	}
	res, _ := clientip.New([]string{"127.0.0.1/32"}, nil)
	g := gate.New(gate.Settings{Mode: decide.ModeAutoblock, EvalTimeout: 2 * time.Second, Resolver: res})
	g.Engine = &waf.Engine{}
	g.Engine.Swap(inst)
	g.Allow = allowlist.New()
	g.Counters = gate.NewCounters()
	g.SetReady(true)
	SetGate(g)
	defer SetGate(nil)
	for _, without := range []bool{true, false} {
		name := "caddy+schild"
		if without {
			name = "caddy-only"
		}
		b.Run(name, func(b *testing.B) {
			addr := freePort(b)
			if err := Start(Options{Listen: addr, Upstream: backend.URL, DataDir: b.TempDir(), LogLevel: "ERROR", WithoutGate: without}); err != nil {
				b.Fatal(err)
			}
			defer Stop()
			client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
			url := "http://" + addr + "/blog/2026/10/hello-world/?page=2"
			for i := 0; i < 50; i++ {
				if resp, err := client.Get(url); err == nil {
					resp.Body.Close()
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req, _ := http.NewRequest("GET", url, nil)
					req.Host = "shop.example"
					req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
					req.Header.Set("Accept", "text/html")
					resp, err := client.Do(req)
					if err != nil {
						b.Error(err)
						return
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			})
		})
	}
}
