package gate

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// slowBackend answers nothing until open is closed, and reads the body only
// then, like a worker pool that has no free worker.
type slowBackend struct {
	entered atomic.Int64
	open    chan struct{}
	once    sync.Once
	sums    sync.Map // request id -> checksum of what the backend read
}

// answer lets the waiting requests go on; safe to call more than once.
func (s *slowBackend) answer() { s.once.Do(func() { close(s.open) }) }

func (s *slowBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.entered.Add(1)
	<-s.open
	h := sha256.New()
	_, _ = io.Copy(h, r.Body)
	s.sums.Store(r.Header.Get("X-Test-Id"), fmt.Sprintf("%x", h.Sum(nil)))
}

func waitEnv(t *testing.T) (*tenv, *slowBackend, http.Handler) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	e := newEnv(t, decide.ModeObserve)
	e.g.Metrics = metrics.New()
	s := e.g.Settings()
	s.Limits.Body = 8 << 20
	e.g.SetSettings(s)
	e.patient()
	// Built after TMPDIR is set, so that the files of Coraza lie where the test
	// looks: a transaction left open shows as a second file of the body.
	inst, err := waf.Build(waf.Config{BodyLimit: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	e.g.Engine.Swap(inst)
	b := &slowBackend{open: make(chan struct{})}
	t.Cleanup(b.answer)
	return e, b, e.g.Handler(b)
}

func uploadBody(t *testing.T, size int) (string, string) {
	t.Helper()
	var b strings.Builder
	mw := multipart.NewWriter(&b)
	f, _ := mw.CreateFormFile("file", "a.bin")
	if _, err := io.WriteString(f, strings.Repeat("x", size)); err != nil {
		t.Fatal(err)
	}
	_ = mw.Close()
	return b.String(), mw.FormDataContentType()
}

// post sends one body and leaves its answer on done.
func post(h http.Handler, addr, ct, body, id string) chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("POST", "/upload", strings.NewReader(body))
		r.RemoteAddr = net.JoinHostPort(addr, "40000")
		r.Header.Set("Content-Type", ct)
		r.Header.Set("X-Test-Id", id)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		done <- w
	}()
	return done
}

// answerOf waits for an answer the backend must not delay: a test that loses its
// limit fails here instead of hanging.
func answerOf(t *testing.T, done chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case w := <-done:
		return w
	case <-time.After(20 * time.Second):
		t.Fatal("no answer: the request went to the backend")
		return nil
	}
}

func (e *tenv) waitingBytes() int64 {
	e.g.bodies.mu.Lock()
	defer e.g.bodies.mu.Unlock()
	return e.g.bodies.waiting
}

func spoolFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, prefix := range bodylimit.TempFilePrefixes {
		m, err := filepath.Glob(filepath.Join(os.Getenv("TMPDIR"), prefix+"*"))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m...)
	}
	return out
}

func heapNow() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

// The defect of the measurement before the first live test: bodies up to 1 MiB
// were copied into memory while the backend took its time, counted nowhere. 64
// of them from a client must leave the heap about as it was, stay counted, and
// be gone when the requests ended.
func TestWaitingBodiesLeaveTheHeap(t *testing.T) {
	e, b, h := waitEnv(t)
	body, ct := uploadBody(t, 1000000)
	const n = 64
	before := heapNow()
	var done []chan *httptest.ResponseRecorder
	for i := range n {
		done = append(done, post(h, "198.51.100.7", ct, body, strconv.Itoa(i)))
		waitFor(t, "body at the backend", func() bool { return int(b.entered.Load()) == i+1 })
	}

	if got := heapNow() - before; got > 16<<20 {
		t.Fatalf("%d waiting bodies of 1 MB hold %d MiB of heap", n, got>>20)
	}
	if got := e.g.bodies.held.Load(); got != n*int64(len(body)) {
		t.Fatalf("held bytes %d while the backend waits, want %d", got, n*len(body))
	}
	want := n * bodylimit.Waiting(int64(len(body)))
	if got := e.waitingBytes(); got != want {
		t.Fatalf("waiting bytes %d, want %d", got, want)
	}
	if got := counterOf(t, e.g.Metrics.BodyWaitingBytes); int64(got) != want {
		t.Fatalf("waiting gauge %v, want %d", got, want)
	}
	if got := counterOf(t, e.g.Metrics.BodiesWaiting); got != n {
		t.Fatalf("bodies waiting gauge %v", got)
	}
	// One file per body: the two of its transaction are gone.
	if got := len(spoolFiles(t)); got != n {
		t.Fatalf("%d temp files, want %d", got, n)
	}
	b.answer()
	for i, d := range done {
		if w := <-d; w.Code != http.StatusOK {
			t.Fatalf("body %d: %d", i, w.Code)
		}
	}
	want2 := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
	for i := range n {
		if got, _ := b.sums.Load(strconv.Itoa(i)); got != want2 {
			t.Fatalf("body %d reached the backend changed", i)
		}
	}
	if e.g.bodies.held.Load() != 0 || e.waitingBytes() != 0 {
		t.Fatalf("left: held %d, waiting %d", e.g.bodies.held.Load(), e.waitingBytes())
	}
	if got := counterOf(t, e.g.Metrics.BodyWaitingBytes); got != 0 {
		t.Fatalf("waiting gauge after the end %v", got)
	}
	if f := spoolFiles(t); len(f) != 0 {
		t.Fatalf("temp files left: %v", f)
	}
	if len(e.g.bodies.waitClients)+len(e.g.bodies.waitNetworks) != 0 {
		t.Fatal("waiting counts left")
	}
}

// Over its share a client gets a 429 of its own code, before any WAF work, while
// another client goes on. Tiny bodies count too: the overhead of a request is
// what they cost. The share frees itself when the backend answers.
func TestWaitingShare(t *testing.T) {
	e, b, h := waitEnv(t)
	s := e.g.Settings()
	s.Body.MaxWaitingBytesPerClient = 4 * bodylimit.WaitingOverheadBytes
	e.g.SetSettings(s)
	var phases atomic.Int64
	e.g.TestHook = func(string) { phases.Add(1) }
	const addr = "198.51.100.7"
	var done []chan *httptest.ResponseRecorder
	for i := range 4 {
		done = append(done, post(h, addr, "text/plain", "a", strconv.Itoa(i)))
		waitFor(t, "body at the backend", func() bool { return int(b.entered.Load()) == i+1 })
	}
	before := phases.Load()
	w := answerOf(t, post(h, addr, "text/plain", "a", "over"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the share: %d", w.Code)
	}
	if ra, _ := strconv.Atoi(w.Header().Get("Retry-After")); ra < 5 || ra > 8 {
		t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	var p blockpage.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Code != bodylimit.CodeWaitingShare {
		t.Fatalf("problem: %v %+v", err, p)
	}
	if phases.Load() != before {
		t.Fatal("a refused client caused WAF work")
	}
	if got := counterOf(t, e.g.Metrics.BodiesAborted.WithLabelValues(bodylimit.AbortWaiting)); got != 1 {
		t.Fatalf("aborted waiting %v", got)
	}
	if got := counterOf(t, e.g.Metrics.HardLimits.WithLabelValues(bodylimit.CodeWaitingShare)); got != 1 {
		t.Fatalf("hard limit %v", got)
	}
	if n := e.incidents(t); n != 0 {
		t.Fatalf("%d incidents", n)
	}
	// A request without a body is not touched.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = net.JoinHostPort(addr, "40000")
	got := make(chan int, 1)
	go func() { rec := httptest.NewRecorder(); h.ServeHTTP(rec, r); got <- rec.Code }()
	// Another client waits as well, within its share.
	done = append(done, post(h, "192.0.2.9", "text/plain", "a", "other"))
	waitFor(t, "other client at the backend", func() bool { return b.entered.Load() == 6 })
	b.answer()
	for _, d := range done {
		if w := <-d; w.Code != http.StatusOK {
			t.Fatalf("within the share: %d", w.Code)
		}
	}
	if code := <-got; code != http.StatusOK {
		t.Fatalf("GET: %d", code)
	}
	if w := <-post(h, addr, "text/plain", "a", "after"); w.Code != http.StatusOK {
		t.Fatalf("after the backend answered: %d", w.Code)
	}
}

// The limit of a network adds up its clients, and the gateway limit all of them.
func TestWaitingNetworkAndGateway(t *testing.T) {
	e, b, h := waitEnv(t)
	s := e.g.Settings()
	s.Body.MaxWaitingBytesPerNetwork = 2 * bodylimit.WaitingOverheadBytes
	s.Body.MaxWaitingBytes = 3 * bodylimit.WaitingOverheadBytes
	e.g.SetSettings(s)
	var done []chan *httptest.ResponseRecorder
	for i, addr := range []string{"198.51.100.7", "198.51.100.8", "192.0.2.9"} {
		done = append(done, post(h, addr, "text/plain", "a", addr))
		waitFor(t, "body at the backend", func() bool { return int(b.entered.Load()) == i+1 })
	}
	w := answerOf(t, post(h, "198.51.100.9", "text/plain", "a", "net"))
	var p blockpage.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); w.Code != http.StatusTooManyRequests || err != nil || p.Code != bodylimit.CodeWaitingShare {
		t.Fatalf("network: %d %v %+v", w.Code, err, p)
	}
	if w := answerOf(t, post(h, "203.0.113.5", "text/plain", "a", "gw")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("gateway: %d", w.Code)
	}
	b.answer()
	for _, d := range done {
		<-d
	}
}

// Legitimate traffic: several hundred posts of one office wait for a slow app,
// each within the default share. Between them large uploads wait on disk.
func TestOfficeBehindOneAddressWaits(t *testing.T) {
	e, b, h := waitEnv(t)
	var done []chan *httptest.ResponseRecorder
	const posts = 400
	for i := range posts {
		done = append(done, post(h, "198.51.100.7", "application/x-www-form-urlencoded", "a=1&b=2", strconv.Itoa(i)))
		if i%8 == 7 {
			// Bodies being read have their own limit: stay under it.
			waitFor(t, "bodies at the backend", func() bool { return int(b.entered.Load()) == i+1 })
		}
	}
	upload, ct := uploadBody(t, 5<<20)
	for i := range 8 {
		done = append(done, post(h, "198.51.100.7", ct, upload, "up"+strconv.Itoa(i)))
	}
	waitFor(t, "everything at the backend", func() bool { return b.entered.Load() == posts+8 })
	b.answer()
	for i, d := range done {
		if w := <-d; w.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if e.hits.Load() != 0 {
		t.Fatal("wrong backend")
	}
}

// A body that cannot be spooled is our disk's fault: 503, no incident, and the
// backend never sees a part of it.
func TestSpoolFailureIsBusy(t *testing.T) {
	e, b, h := waitEnv(t)
	body := strings.Repeat("x", int(bodylimit.WaitingMemoryBodyBytes)+1)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "gone"))
	b.answer()
	w := <-post(h, "198.51.100.7", "text/plain", body, "x")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", w.Code)
	}
	if b.entered.Load() != 0 {
		t.Fatal("the backend got a request")
	}
	if n := e.incidents(t); n != 0 {
		t.Fatalf("%d incidents", n)
	}
	if e.g.bodies.held.Load() != 0 {
		t.Fatalf("held bytes left: %d", e.g.bodies.held.Load())
	}
}

func TestWaitingBodyBothWays(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	limit := int(bodylimit.WaitingMemoryBodyBytes)
	for _, size := range []int{0, 1, limit, limit + 1, 3 * limit} {
		src := strings.Repeat("z", size)
		wb, err := newWaitingBody(strings.NewReader(src), int64(size))
		if err != nil {
			t.Fatal(err)
		}
		if (wb.file == nil) != bodylimit.WaitsInMemory(int64(size)) {
			t.Fatalf("size %d: file %v", size, wb.file)
		}
		got, err := io.ReadAll(wb)
		if err != nil || string(got) != src {
			t.Fatalf("size %d: %d bytes, %v", size, len(got), err)
		}
		wb.remove()
	}
	if f := spoolFiles(t); len(f) != 0 {
		t.Fatalf("temp files left: %v", f)
	}
	if _, err := newWaitingBody(strings.NewReader("short"), 6); err == nil {
		t.Fatal("a short body in memory passed")
	}
	if _, err := newWaitingBody(strings.NewReader("short"), int64(limit)+1); err == nil {
		t.Fatal("a short body on disk passed")
	}
	if f := spoolFiles(t); len(f) != 0 {
		t.Fatalf("temp file of a failed copy left: %v", f)
	}
}

// The transport may read after the handler returned: a removed body ends, it
// does not fail, and the end of a request can never panic a late reader.
func TestRemovedBodyEnds(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	wb, err := newWaitingBody(strings.NewReader(strings.Repeat("z", 1<<20)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	wb.remove()
	if n, err := wb.Read(make([]byte, 16)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("%d %v", n, err)
	}
	wb.remove() // twice is harmless
}

// Waiting bytes of an address without a client key still count for the gateway.
func TestWaitWithoutClient(t *testing.T) {
	var l bodyLimiter
	w := l.wait(netip.Addr{}, 10, nil)
	if l.waiting != bodylimit.Waiting(10) || len(l.waitClients) != 0 {
		t.Fatalf("%d %v", l.waiting, l.waitClients)
	}
	w.end()
	w.end()
	if l.waiting != 0 {
		t.Fatalf("after end: %d", l.waiting)
	}
}

// The errors of a shared address keep their answer in the waiting page path.
func TestWaitShareOnSharedAddressIsBusy(t *testing.T) {
	if waf.ErrBodyWaitShareBusy.Status != http.StatusServiceUnavailable || waf.ErrBodyWaitShare.Status != http.StatusTooManyRequests {
		t.Fatal("status")
	}
	ri := &reqInfo{limit: waf.ErrBodyWaitShareBusy}
	if overloadReason(ri) == "" {
		t.Fatal("no waiting page for a shared address")
	}
}
