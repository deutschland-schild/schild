//go:build !release

package app_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
)

// reloadBench is a gateway in ingress mode whose Caddyfile the test writes.
type reloadBench struct {
	*apptest.Harness
	t *testing.T
}

func newReloadBench(t *testing.T, sites string) *reloadBench {
	t.Helper()
	b := &reloadBench{Harness: apptest.New(t, apptest.Options{Listeners: true, Caddyfile: reloadGlobal + sites}), t: t}
	return b
}

const reloadGlobal = "{\n\tauto_https off\n}\n"

// block is a site block that answers with the test backend.
func block(hosts ...string) string {
	for i, h := range hosts {
		hosts[i] = "http://" + h + ":{port}"
	}
	return strings.Join(hosts, ", ") + " {\n\tschild\n\treverse_proxy {backend}\n}\n"
}

func (b *reloadBench) write(text string) {
	b.t.Helper()
	_, port, _ := net.SplitHostPort(b.IngressAddr)
	text = strings.NewReplacer("{backend}", strings.TrimPrefix(b.Backend.URL, "http://"), "{port}", port).Replace(text)
	if err := os.WriteFile(filepath.Join(b.Dir, "Caddyfile"), []byte(text), 0o600); err != nil {
		b.t.Fatal(err)
	}
}

func (b *reloadBench) reload(text string) (app.IngressReload, error) {
	b.t.Helper()
	b.write(reloadGlobal + text)
	return b.App.ReloadIngress(false)
}

// status is the answer to GET / under host ("" for an answer without a
// site: Caddy writes an empty 200).
func (b *reloadBench) body(host string) (int, string) {
	b.t.Helper()
	return getHost(b.t, "http://"+b.IngressAddr+"/", host)
}

func TestIngressReload(t *testing.T) {
	b := newReloadBench(t, block("shop.example"))
	if _, s := b.body("shop.example"); s != "app ok" {
		t.Fatalf("before: %q", s)
	}
	if _, s := b.body("neu.example"); s == "app ok" {
		t.Fatal("a host without a site block reached the backend")
	}
	gateBefore := b.App.Gate
	res, err := b.reload(block("shop.example") + block("neu.example"))
	if err != nil || res.Unchanged || res.Websites != 2 {
		t.Fatalf("reload: %+v %v", res, err)
	}
	for _, h := range []string{"shop.example", "neu.example"} {
		if _, s := b.body(h); s != "app ok" {
			t.Fatalf("%s after the reload: %q", h, s)
		}
	}
	// The new website is checked by the same gate, as website of its own.
	if code, _ := getHost(t, "http://"+b.IngressAddr+"/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "neu.example"); code != 403 {
		t.Fatalf("xss on the new website: %d", code)
	}
	if b.App.Gate != gateBefore {
		t.Fatal("another gate")
	}
	if id := b.App.Sites.ID("neu.example"); id != "neu.example" {
		t.Fatalf("website of the new host: %q", id)
	}
	if res, err = b.App.ReloadIngress(false); err != nil || !res.Unchanged {
		t.Fatalf("the same file again: %+v %v", res, err)
	}
	if res, err = b.App.ReloadIngress(true); err != nil || res.Unchanged {
		t.Fatalf("forced: %+v %v", res, err)
	}
	if _, err = b.reload(block("neu.example")); err != nil {
		t.Fatal(err)
	}
	if _, s := b.body("shop.example"); s == "app ok" {
		t.Fatal("a website that is gone still reaches the backend")
	}
	if err := b.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.App.ReloadIngress(false); err == nil {
		t.Fatal("a stopped gateway reloaded")
	}
}

// TestIngressReloadRefused: whatever schild refuses leaves the running
// Caddyfile in place.
func TestIngressReloadRefused(t *testing.T) {
	b := newReloadBench(t, block("shop.example"))
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	for name, c := range map[string]struct{ text, want string }{
		"syntax":             {reloadGlobal + "http://shop.example:{port} {\n\tschild\n\treverse_prox {backend}\n}\n", "reverse_prox"},
		"unprotected":        {reloadGlobal + block("shop.example") + "http://offen.example:{port} {\n\treverse_proxy {backend}\n}\n", "without schild"},
		"another port":       {reloadGlobal + block("shop.example") + "http://neu.example:" + fmt.Sprint(busy.Addr().(*net.TCPAddr).Port) + " {\n\tschild\n\treverse_proxy {backend}\n}\n", "needs a restart"},
		"no file":            {"", ""},
		"a module it lacks":  {reloadGlobal + block("shop.example") + "http://neu.example:{port} {\n\tschild\n\treverse_proxy {backend} {\n\t\ttransport nix\n\t}\n}\n", "nix"},
		"fails to provision": {reloadGlobal + block("shop.example") + "http://neu.example:{port} {\n\tschild\n\t@x expression \"1 +\"\n\treverse_proxy @x {backend}\n}\n", "load Caddyfile"},
	} {
		t.Run(name, func(t *testing.T) {
			if c.text == "" {
				_ = os.Remove(filepath.Join(b.Dir, "Caddyfile"))
			} else {
				b.write(c.text)
			}
			_, err := b.App.ReloadIngress(false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v, want %q", err, c.want)
			}
			if _, s := b.body("shop.example"); s != "app ok" {
				t.Fatalf("the running Caddyfile does not answer any more: %q", s)
			}
			if _, s := b.body("neu.example"); s == "app ok" {
				t.Fatal("a refused Caddyfile is in force")
			}
			if n := len(b.App.Sites.View().Websites()); n != 1 {
				t.Fatalf("%d websites", n)
			}
		})
	}
	// And a good one works after all of them.
	if _, err := b.reload(block("shop.example") + block("neu.example")); err != nil {
		t.Fatal(err)
	}
	if _, s := b.body("neu.example"); s != "app ok" {
		t.Fatalf("after the refusals: %q", s)
	}
}

// TestIngressReloadKeepsAccessLock: no reload opens what an access lock or
// the maintenance mode closes.
func TestIngressReloadKeepsAccessLock(t *testing.T) {
	b := newReloadBench(t, block("intern.example", "www.intern.example")+block("shop.example"))
	pw := "korrekt-pferd-batterie"
	if _, err := b.App.SetAccess(context.Background(), "intern.example", app.AccessChange{
		Protection: access.Protection{Website: "intern.example", Scope: access.ScopeSite, Password: true}, Password: &pw, Actor: "cli"}); err != nil {
		t.Fatal(err)
	}
	closed := func(when string) {
		t.Helper()
		for _, h := range []string{"intern.example", "www.intern.example"} {
			if code, _ := b.body(h); code != http.StatusServiceUnavailable {
				t.Fatalf("%s: %s answers %d", when, h, code)
			}
		}
	}
	closed("before")
	for name, text := range map[string]string{
		"named by another host": block("www.intern.example", "intern.example") + block("shop.example"),
		"a host moves":          block("intern.example") + block("shop.example", "www.intern.example"),
		"gone":                  block("shop.example"),
	} {
		if _, err := b.reload(text); err == nil || !strings.Contains(err.Error(), "access lock") {
			t.Fatalf("%s: %v", name, err)
		}
		closed(name)
	}
	// It holds through a reload that keeps the block, wherever it stands.
	if _, err := b.reload(block("neu.example") + block("shop.example") + block("intern.example", "www.intern.example")); err != nil {
		t.Fatal(err)
	}
	closed("after a reload")
	if ok, err := b.App.RemoveAccess(context.Background(), "intern.example", "cli", ""); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, err := b.reload(block("shop.example")); err != nil {
		t.Fatalf("after the lock ended: %v", err)
	}
}

// TestIngressReloadUnderLoad: no request fails while the Caddyfile is loaded
// again and again, over HTTP/1.1 with kept and with new connections and over
// HTTP/2, and a request that runs ends with the Caddyfile it started with.
func TestIngressReloadUnderLoad(t *testing.T) {
	t.Run("http", func(t *testing.T) { reloadUnderLoad(t, "http") })
	t.Run("https", func(t *testing.T) { reloadUnderLoad(t, "https") })
}

func reloadUnderLoad(t *testing.T, scheme string) {
	release := make(chan struct{})
	end := sync.OnceFunc(func() { close(release) })
	defer end()
	arrived := make(chan struct{})
	arrive := sync.OnceFunc(func() { close(arrived) })
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrive()
		<-release
		_, _ = io.WriteString(w, "slow ok")
	}))
	t.Cleanup(slow.Close)
	global, tlsLine := reloadGlobal, ""
	if scheme == "https" {
		global, tlsLine = "{\n\tauto_https disable_redirects\n\tskip_install_trust\n\tservers {\n\t\tprotocols h1 h2\n\t}\n}\n", "\ttls internal\n"
	}
	site := func(host, backend string) string {
		return scheme + "://" + host + ":{port} {\n" + tlsLine + "\tschild\n\treverse_proxy " + backend + "\n}\n"
	}
	sites := site("shop.example", "{backend}") + site("slow.example", strings.TrimPrefix(slow.URL, "http://"))
	b := &reloadBench{Harness: apptest.New(t, apptest.Options{Listeners: true, Caddyfile: global + sites}), t: t}
	// This test counts what a reload costs. On a busy machine (the race
	// detector in CI) a request may wait longer than the 100 ms of the queue
	// for the WAF and is answered 503: load, not a reload.
	lim := b.App.Gate.EvalLimits()
	lim.QueueWait = time.Minute
	b.App.Gate.SetEvalLimits(lim)
	client := func(host string, kept, h2 bool) func() (string, error) {
		tr := &http.Transport{DisableKeepAlives: !kept, ForceAttemptHTTP2: h2,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host}} //nolint:gosec // the test's own CA
		c := &http.Client{Transport: tr, Timeout: 30 * time.Second}
		return func() (string, error) {
			req, _ := http.NewRequest("GET", scheme+"://"+b.IngressAddr+"/", nil)
			req.Host = host
			resp, err := c.Do(req)
			if err != nil {
				return "", err
			}
			defer resp.Body.Close()
			s, err := io.ReadAll(resp.Body)
			if h2 && resp.ProtoMajor != 2 {
				return "", fmt.Errorf("%s, want HTTP/2", resp.Proto)
			}
			return string(s), err
		}
	}
	// The certificate of tls internal comes a moment after the start.
	first := client("shop.example", false, false)
	for i := 0; ; i++ {
		s, err := first()
		if s == "app ok" {
			break
		}
		if i == 100 {
			t.Fatalf("before: %q %v", s, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	slowDone := make(chan string, 1)
	get := client("slow.example", true, scheme == "https")
	go func() {
		for i := 0; ; i++ {
			s, err := get()
			if err != nil {
				s = err.Error()
			}
			select {
			case <-arrived:
			default:
				// The certificate of slow.example may come after that of
				// shop.example.
				if i < 100 {
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}
			slowDone <- s
			return
		}
	}()
	select {
	case <-arrived:
	case s := <-slowDone:
		t.Fatalf("the slow request did not arrive: %q", s)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var sent, failed atomic.Int64
	var firstErr atomic.Value
	var wg sync.WaitGroup
	for i := range 6 {
		h2 := scheme == "https" && i < 2
		get := client("shop.example", i%2 == 0, h2)
		wg.Go(func() {
			for ctx.Err() == nil {
				s, err := get()
				sent.Add(1)
				if err == nil && s == "app ok" {
					continue
				}
				failed.Add(1)
				firstErr.CompareAndSwap(nil, fmt.Sprintf("client %d: %q %v", i, s, err))
			}
		})
	}
	for i := range 20 {
		text := sites
		if i%2 == 0 {
			text += site(fmt.Sprintf("neu%d.example", i), "{backend}")
		}
		b.write(global + text)
		if _, err := b.App.ReloadIngress(false); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Millisecond)
	}
	cancel()
	wg.Wait()
	t.Logf("%d of %d requests failed over 20 reloads", failed.Load(), sent.Load())
	if failed.Load() > 0 && runtime.GOOS == "linux" {
		// Elsewhere the socket of an address cannot be kept (caddymod, socket.go).
		t.Fatalf("the first: %v", firstErr.Load())
	}
	select {
	case s := <-slowDone:
		t.Fatalf("the running request ended early: %q", s)
	default:
	}
	end()
	if s := <-slowDone; s != "slow ok" {
		t.Fatalf("the running request: %q", s)
	}
}
