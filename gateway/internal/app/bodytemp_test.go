package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/memlimit"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

func TestPrepareBodyTempCleans(t *testing.T) {
	t.Setenv("TMPDIR", os.Getenv("TMPDIR")) // restored after the test
	data := t.TempDir()
	dir := BodyTempDir(data)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"body123", "crzmp456", "keep.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "body-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	n, err := PrepareBodyTemp(data)
	if err != nil || n != 2 {
		t.Fatalf("removed %d: %v", n, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 || entries[0].Name() != "body-dir" || entries[1].Name() != "keep.txt" {
		t.Fatalf("left: %v", entries)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if os.TempDir() != dir {
		t.Fatalf("TempDir %q", os.TempDir())
	}
}

// Bodies spool under storage.path, also the second copy of multipart files,
// which Coraza places on its own: a WAF built after PrepareBodyTemp must use
// it. The temp files are gone when the transaction closed.
func TestBodiesSpoolToBodyTemp(t *testing.T) {
	t.Setenv("TMPDIR", os.Getenv("TMPDIR"))
	data := t.TempDir()
	if _, err := PrepareBodyTemp(data); err != nil {
		t.Fatal(err)
	}
	dir := BodyTempDir(data)
	inst, err := waf.Build(waf.Config{BodyLimit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	const boundary = "b0undary"
	file := strings.Repeat("x", 300<<10)
	body := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\n\r\n" + file + "\r\n--" + boundary + "--\r\n"
	r := httptest.NewRequest("POST", "/upload", strings.NewReader(body))
	r.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	tx, _ := inst.NewTransaction()
	waf.ProcessHeaders(tx, r, "192.0.2.1", 40000)
	if _, _, err := waf.ReadBodyInfo(tx, r, waf.Limits{Body: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		seen[e.Name()[:4]] = true
	}
	if !seen["body"] || !seen["crzm"] {
		t.Fatalf("temp files in %s: %v", dir, entries)
	}
	if spoolBytes(dir) < 2*int64(len(file)) {
		t.Fatalf("spool %d", spoolBytes(dir))
	}
	_ = tx.Close()
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left after close: %v", entries)
	}
}

func TestBodyMemory(t *testing.T) {
	Parallel(t)
	if got := bodyMemory(memlimit.Result{Source: memlimit.SourceEnv, Limit: 1 << 30}); got != 1<<30 {
		t.Fatalf("GOMEMLIMIT: %d", got)
	}
	if got := bodyMemory(memlimit.Result{Source: memlimit.SourceCgroup, Limit: 1 << 30, Total: 2 << 30}); got != 2<<30 {
		t.Fatalf("cgroup: %d", got)
	}
	if got := bodyMemory(memlimit.Result{Source: memlimit.SourceNone}); bodylimit.InFlightLimit(0, got) != bodylimit.FallbackInFlight {
		t.Fatalf("unknown: %d", got)
	}
}

// Every metric of body-limits.md section 6 is on the metrics port, also
// too_slow before the first abort.
func TestBodyMetricNames(t *testing.T) {
	Parallel(t)
	m := metrics.New()
	m.BodyRate.Observe(1)
	m.BodyReadSeconds.Observe(1)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(context.Background()))
	body := w.Body.String()
	for _, name := range []string{bodylimit.PromBodiesInFlight, bodylimit.PromBodyBytesInFlight, bodylimit.PromBodySpoolBytes, bodylimit.PromBodiesBelowMinRate,
		bodylimit.PromBodyReadSeconds + "_bucket", bodylimit.PromBodyRate + "_bucket", bodylimit.PromBodiesAborted + `{reason="too_slow"} 0`,
		bodylimit.PromBodiesAborted + `{reason="share"} 0`, bodylimit.PromBodiesAborted + `{reason="client_gone"} 0`} {
		if !strings.Contains(body, name) {
			t.Fatalf("%s missing", name)
		}
	}
}
