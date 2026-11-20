package failopen

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/testport"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestFailOpenOnlyOnRefused(t *testing.T) {
	var appHits, appBody atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appHits.Add(1)
		b, _ := io.ReadAll(r.Body)
		appBody.Store(int64(len(b)))
		_, _ = io.WriteString(w, "app")
	}))
	defer app.Close()
	var delay atomic.Int64
	var schildHits atomic.Int64
	schild := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		schildHits.Add(1)
		time.Sleep(time.Duration(delay.Load()))
		_, _ = io.WriteString(w, "schild")
	}))
	schildURL := schild.URL
	var bypasses atomic.Int64
	f, err := New(schildURL, app.URL, 200*time.Millisecond, quiet)
	if err != nil {
		t.Fatal(err)
	}
	f.NoAccessLock = true // the lock state has its own test
	f.OnBypass = func(*http.Request) { bypasses.Add(1) }
	front := httptest.NewServer(f)
	defer front.Close()
	post := func() (int, string) {
		resp, err := http.Post(front.URL+"/form", "application/x-www-form-urlencoded", strings.NewReader("a=1&b=2"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if code, body := post(); code != 200 || body != "schild" {
		t.Fatalf("normal: %d %s", code, body)
	}
	// Timeout: 503, the application never sees the request.
	delay.Store(int64(500 * time.Millisecond))
	if code, _ := post(); code != 503 || appHits.Load() != 0 {
		t.Fatalf("timeout: %d, app hits %d", code, appHits.Load())
	}
	delay.Store(0)
	// schild down (connection refused): fail-open, body intact.
	schild.Close()
	if code, body := post(); code != 200 || body != "app" || appBody.Load() != 7 || bypasses.Load() != 1 {
		t.Fatalf("refused: %d %s body=%d bypasses=%d", code, body, appBody.Load(), bypasses.Load())
	}
}

// D37 amendment: on the bypass the app answers directly; its
// Schild-Waiting header is removed. schild's own marker passes.
func TestBypassStripsWaitingMarker(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Schild-Waiting", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer app.Close()
	down := "http://" + testport.Free(t) // nobody listens there
	f, err := New(down, app.URL, time.Second, quiet)
	if err != nil {
		t.Fatal(err)
	}
	f.NoAccessLock = true
	front := httptest.NewServer(f)
	defer front.Close()
	res, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Schild-Waiting") != "" {
		t.Fatalf("bypass: %d %v", res.StatusCode, res.Header)
	}

	f, err = New(app.URL, app.URL, time.Second, quiet) // app plays schild
	if err != nil {
		t.Fatal(err)
	}
	front2 := httptest.NewServer(f)
	defer front2.Close()
	res, err = http.Get(front2.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Header.Get("Schild-Waiting") != "1" {
		t.Fatalf("schild's marker lost: %v", res.Header)
	}
}

func TestClassify(t *testing.T) {
	addr := testport.Free(t) // nobody listens there
	_, err := net.Dial("tcp", addr)
	if !IsRefused(err) {
		t.Fatalf("refused not detected: %v", err)
	}
	if IsTimeout(err) {
		t.Fatal("refused is no timeout")
	}
}

// D56: while an access lock is in force the front never fails open; an
// unreadable lock file counts as a lock. D71 (security audit 2026-11-05): so
// does a lock state the front cannot see, no -access-dir or no file in it,
// as with the shipped compose files that did not mount schild's storage.
func TestNoFailOpenWhileAccessLocked(t *testing.T) {
	var appHits atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appHits.Add(1)
		_, _ = io.WriteString(w, "app")
	}))
	defer app.Close()
	schild := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	schildURL := schild.URL
	schild.Close()
	dir := t.TempDir()
	// get sends one request through a front with the given lock settings.
	get := func(accessDir string, noLock bool) int {
		t.Helper()
		f, err := New(schildURL, app.URL, time.Second, quiet)
		if err != nil {
			t.Fatal(err)
		}
		f.AccessDir, f.NoAccessLock = accessDir, noLock
		front := httptest.NewServer(f)
		defer front.Close()
		resp, err := http.Get(front.URL + "/wp-admin/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("", false); code != 503 || appHits.Load() != 0 {
		t.Fatalf("no -access-dir: %d, app hits %d", code, appHits.Load())
	}
	if code := get(dir, false); code != 503 || appHits.Load() != 0 {
		t.Fatalf("storage without the lock file: %d, app hits %d", code, appHits.Load())
	}
	if err := access.WriteActive(dir, access.Active{}); err != nil {
		t.Fatal(err)
	}
	if code := get(dir, false); code != 200 || appHits.Load() != 1 {
		t.Fatalf("no lock: %d", code)
	}
	if err := access.WriteActive(dir, access.Active{Protections: []access.ActiveRecord{{Website: "a.example", Scope: access.ScopeSite}}}); err != nil {
		t.Fatal(err)
	}
	if code := get(dir, false); code != 503 || appHits.Load() != 1 {
		t.Fatalf("locked: %d, app hits %d", code, appHits.Load())
	}
	if err := os.WriteFile(filepath.Join(dir, access.ActiveDir, access.ActiveFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := get(dir, false); code != 503 || appHits.Load() != 1 {
		t.Fatalf("broken file: %d, app hits %d", code, appHits.Load())
	}
	if err := access.WriteActive(dir, access.Active{}); err != nil {
		t.Fatal(err)
	}
	if code := get(dir, false); code != 200 {
		t.Fatalf("removed lock: %d", code)
	}
	// Opt-out for gateways that never lock: no storage needed.
	if code := get("", true); code != 200 {
		t.Fatalf("-no-access-lock: %d", code)
	}
}

// The front ends idle keep-alive connections and slow headers: net/http keeps
// an idle connection forever without IdleTimeout and ReadTimeout.
func TestServerTimeouts(t *testing.T) {
	f, err := New("http://127.0.0.1:1", "http://127.0.0.1:2", time.Second, quiet)
	if err != nil {
		t.Fatal(err)
	}
	s := f.Server(":0")
	if s.Handler != f || s.ReadHeaderTimeout <= 0 || s.IdleTimeout <= 0 || s.IdleTimeout > 5*time.Minute || s.MaxHeaderBytes <= 0 {
		t.Fatalf("server %+v", s)
	}
}

// D71 (security audit 2026-11-05): every front the repository ships reads
// schild's lock state, so it never fails open past an access lock: the
// compose files pass -access-dir and mount schild's storage read-only, the
// nginx and Caddy templates refuse to fail open without the lock file.
func TestShippedFrontsReadTheLockState(t *testing.T) {
	read := func(p string) []byte {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, doc := range map[string]string{"docker-compose.example.yml": string(read("../../deploy/docker-compose.example.yml"))} {
		// The front service: from "  front:" to the next key at its indent.
		_, svc, ok := strings.Cut(doc, "\n  front:\n")
		if !ok {
			t.Fatalf("%s: no front service", name)
		}
		var lines []string
		for _, l := range strings.Split(svc, "\n") {
			if l != "" && !strings.HasPrefix(l, "   ") {
				break
			}
			lines = append(lines, l)
		}
		svc = strings.Join(lines, "\n")
		if !strings.Contains(svc, `"-access-dir", "/var/lib/schild"`) || !strings.Contains(svc, "- schild-data:/var/lib/schild:ro") {
			t.Errorf("%s: front service without -access-dir on schild's storage mounted read-only:\n%s", name, svc)
		}
	}
	if !strings.Contains(string(read("../../deploy/nginx-front.conf")), "if (!-f /var/lib/schild/access/active.json)") {
		t.Error("nginx-front.conf fails open without the lock file")
	}
	if !strings.Contains(string(read("../../deploy/Caddyfile.front")), "@access_unknown not file {") {
		t.Error("Caddyfile.front fails open without the lock file")
	}
}
