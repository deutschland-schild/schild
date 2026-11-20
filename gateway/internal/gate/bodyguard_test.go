package gate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/contract/vectors"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// openBody is a request whose body stays open until close.
type openBody struct {
	w    *io.PipeWriter
	done chan struct{}
	rec  *httptest.ResponseRecorder
}

func (o *openBody) close() {
	_ = o.w.Close()
	<-o.done
}

// startBody sends a request with an open body of unknown length.
func startBody(h http.Handler, addr, ctype string) *openBody {
	pr, pw := io.Pipe()
	r := httptest.NewRequest("POST", "/upload", pr)
	r.RemoteAddr = net.JoinHostPort(addr, "40000")
	r.Header.Set("Content-Type", ctype)
	r.ContentLength = -1
	o := &openBody{w: pw, done: make(chan struct{}), rec: httptest.NewRecorder()}
	go func() {
		defer close(o.done)
		h.ServeHTTP(o.rec, r)
	}()
	return o
}

func sendBody(h http.Handler, addr, accept string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/upload", strings.NewReader("a=1"))
	r.RemoteAddr = net.JoinHostPort(addr, "40001")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accept != "" {
		r.Header.Set("Accept", accept)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func bodyEnv(t *testing.T, mode string) (*tenv, http.Handler) {
	t.Helper()
	e := newEnv(t, mode)
	e.g.Metrics = metrics.New()
	return e, e.g.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.hits.Add(1); _, _ = io.Copy(io.Discard, r.Body) }))
}

func counterOf(t *testing.T, c interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue() + m.GetGauge().GetValue()
}

func (e *tenv) inFlight() int {
	e.g.bodies.mu.Lock()
	defer e.g.bodies.mu.Unlock()
	return e.g.bodies.inFlight
}

func (e *tenv) waitBodies(t *testing.T, n int) {
	t.Helper()
	waitFor(t, "bodies being read", func() bool { return e.inFlight() == n })
}

func (e *tenv) incidents(t *testing.T) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e.g.FlushIncidents(ctx) // the incident writer stores what is queued
	n, err := e.st.CountIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	return int(n)
}

// A client over its share gets a 429 before any WAF work, in observe mode too,
// while another client goes on; a finished body frees its place.
func TestBodyClientShare(t *testing.T) {
	e, h := bodyEnv(t, decide.ModeObserve)
	var phases atomic.Int64
	e.g.TestHook = func(string) { phases.Add(1) }
	var open []*openBody
	for range bodylimit.DefaultMaxPerClient {
		open = append(open, startBody(h, "198.51.100.7", "text/plain"))
	}
	e.waitBodies(t, bodylimit.DefaultMaxPerClient)
	// A body counts from its admission, before its phase 1 runs; each open body
	// runs exactly that one phase and then waits for its bytes. Counted from
	// there, any further phase is the refused request's.
	waitFor(t, "phase 1 of the open bodies", func() bool { return phases.Load() == bodylimit.DefaultMaxPerClient })
	before := phases.Load()

	w := sendBody(h, "198.51.100.7", "")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the share: %d", w.Code)
	}
	if ra, _ := strconv.Atoi(w.Header().Get("Retry-After")); ra < 5 || ra > 8 {
		t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	var p blockpage.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Code != bodylimit.CodeClientShare || w.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("problem: %v %+v %q", err, p, w.Header().Get("Content-Type"))
	}
	if w.Header().Get("X-Schild-Incident") != "" || p.Incident != "" {
		t.Fatal("a refused body showed an incident")
	}
	if phases.Load() != before {
		t.Fatal("a refused client caused WAF work")
	}
	if page := sendBody(h, "198.51.100.7", "text/html"); page.Code != http.StatusTooManyRequests || !strings.HasPrefix(page.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("browser: %d %q", page.Code, page.Header().Get("Content-Type"))
	}
	if w := sendBody(h, "192.0.2.9", ""); w.Code != http.StatusOK {
		t.Fatalf("another client: %d", w.Code)
	}
	if e.hits.Load() != 1 {
		t.Fatalf("backend hits %d", e.hits.Load())
	}
	open[0].close()
	e.waitBodies(t, bodylimit.DefaultMaxPerClient-1)
	if w := sendBody(h, "198.51.100.7", ""); w.Code != http.StatusOK {
		t.Fatalf("after a body ended: %d", w.Code)
	}
	for _, o := range open[1:] {
		o.close()
	}
	e.waitBodies(t, 0)
	if e.g.bodies.clients != nil && len(e.g.bodies.clients)+len(e.g.bodies.networks) != 0 {
		t.Fatalf("counts left: %v %v", e.g.bodies.clients, e.g.bodies.networks)
	}
	if got := counterOf(t, e.g.Metrics.BodiesAborted.WithLabelValues(bodylimit.AbortShare)); got != 2 {
		t.Fatalf("aborted share %v", got)
	}
	if got := counterOf(t, e.g.Metrics.HardLimits.WithLabelValues(bodylimit.CodeClientShare)); got != 2 {
		t.Fatalf("hard limit %v", got)
	}
	if n := e.incidents(t); n != 0 {
		t.Fatalf("%d incidents", n)
	}
}

func TestBodyNetworkShare(t *testing.T) {
	e, h := bodyEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.Body.MaxPerClient, s.Body.MaxPerNetwork = 1, 3
	e.g.SetSettings(s)
	var open []*openBody
	for i := range 3 {
		open = append(open, startBody(h, fmt.Sprintf("198.51.100.%d", i+1), "text/plain"))
	}
	e.waitBodies(t, 3)
	if w := sendBody(h, "198.51.100.200", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("same /24: %d", w.Code)
	}
	if w := sendBody(h, "198.51.101.1", ""); w.Code != http.StatusOK {
		t.Fatalf("next /24: %d", w.Code)
	}
	v6 := startBody(h, "2001:db8:1:1::1", "text/plain")
	e.waitBodies(t, 4)
	if w := sendBody(h, "2001:db8:1:1::2", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("same /64: %d", w.Code)
	}
	v6.close()
	for _, o := range open {
		o.close()
	}
}

// A shared address never gets a 429 (D29), and four times the place.
func TestBodySharedAddress(t *testing.T) {
	e, h := bodyEnv(t, decide.ModeObserve)
	m, err := monitoring.New(monitoring.Config{StoragePath: t.TempDir(), Log: quiet}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	e.g.Monitor = m
	s := e.g.Settings()
	s.Body.MaxPerClient, s.Body.MaxPerNetwork = 1, 4
	e.g.SetSettings(s)
	var open []*openBody
	for range bodylimit.SharedFactor {
		open = append(open, startBody(h, "100.64.0.5", "text/plain"))
	}
	e.waitBodies(t, bodylimit.SharedFactor)
	w := sendBody(h, "100.64.0.5", "")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Schild-Waiting") != "1" {
		t.Fatalf("shared address: %d %v", w.Code, w.Header())
	}
	page := sendBody(h, "100.64.0.5", "text/html")
	if page.Code != http.StatusServiceUnavailable || page.Header().Get("Content-Language") == "" {
		t.Fatalf("shared address, browser: %d %v", page.Code, page.Header())
	}
	c := liveCounters(t, m)
	if c.FailClosedBy.BodyBusy != 2 || c.WaitingPageShown != 1 || c.RejectedLimit != 0 || !c.Check() {
		t.Fatalf("counters %+v", c)
	}
	for _, o := range open {
		o.close()
	}
	if got := counterOf(t, e.g.Metrics.HardLimits.WithLabelValues(bodylimit.CodeClientShare)); got != 2 {
		t.Fatalf("hard limit %v", got)
	}
}

func TestBodyGatewayFull(t *testing.T) {
	e, h := bodyEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.Body.MaxInFlight = 2
	s.Body.MaxPerClient, s.Body.MaxPerNetwork = 1, 1
	e.g.SetSettings(s)
	a, b := startBody(h, "198.51.100.1", "text/plain"), startBody(h, "192.0.2.1", "text/plain")
	e.waitBodies(t, 2)
	w := sendBody(h, "203.0.113.1", "")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("X-Schild-Incident") != "" {
		t.Fatalf("full gateway: %d %v", w.Code, w.Header())
	}
	// A client over its share gets its own answer whatever else is full.
	if w := sendBody(h, "198.51.100.1", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("over its share on a full gateway: %d", w.Code)
	}
	// A request without a body is not touched.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.1:1"
	get := httptest.NewRecorder()
	h.ServeHTTP(get, r)
	if get.Code != http.StatusOK {
		t.Fatalf("GET: %d", get.Code)
	}
	a.close()
	b.close()
	if got := counterOf(t, e.g.Metrics.BodiesAborted.WithLabelValues(bodylimit.AbortBusy)); got != 1 {
		t.Fatalf("aborted busy %v", got)
	}
	if n := e.incidents(t); n != 0 {
		t.Fatalf("%d incidents", n)
	}
}

// The limits hold for no_block, as every hard limit; a bypass_waf body is
// never read by the gate and takes no place.
func TestBodyLimitsAndAllowlist(t *testing.T) {
	e, h := bodyEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.Body.MaxPerClient, s.Body.MaxPerNetwork = 1, 1
	e.g.SetSettings(s)
	e.g.Allow.Set([]store.AllowEntry{{ID: "a", IP: "198.51.100.7", Label: "me", Level: allowlist.NoBlock, Expires: "never"}, {ID: "b", IP: "192.0.2.7", Label: "me", Level: allowlist.BypassWAF, Expires: "never"}})
	o := startBody(h, "198.51.100.7", "text/plain")
	e.waitBodies(t, 1)
	if w := sendBody(h, "198.51.100.7", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("no_block: %d", w.Code)
	}
	o.close()
	by := startBody(h, "192.0.2.7", "text/plain")
	time.Sleep(20 * time.Millisecond)
	if e.inFlight() != 0 {
		t.Fatal("a bypass_waf body took a place")
	}
	by.close()
}

// Held bytes stay until the request ended, after the read ended. A multipart
// body counts once by then: its second copy went with the transaction (D44).
func TestBodyHeldBytesUntilRequestEnds(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	e.g.Metrics = metrics.New()
	s := e.g.Settings()
	s.Limits.Body = 8 << 20
	s.Limits.Raw = 4 << 20
	e.g.SetSettings(s)
	entered, release := make(chan struct{}), make(chan struct{})
	h := e.g.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	var b strings.Builder
	mw := multipart.NewWriter(&b)
	f, _ := mw.CreateFormFile("file", "a.bin")
	_, _ = f.Write(make([]byte, 2<<20))
	_ = mw.Close()
	body := b.String()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := httptest.NewRequest("POST", "/upload", strings.NewReader(body))
		r.RemoteAddr = "198.51.100.7:1"
		r.Header.Set("Content-Type", mw.FormDataContentType())
		h.ServeHTTP(httptest.NewRecorder(), r)
	}()
	<-entered
	if e.inFlight() != 0 {
		t.Fatal("a finished body still counts as being read")
	}
	want := int64(len(body))
	if got := e.g.bodies.held.Load(); got != want {
		t.Fatalf("held %d while the backend reads, want %d", got, want)
	}
	if got := counterOf(t, e.g.Metrics.BodyBytesInFlight); int64(got) != want {
		t.Fatalf("gauge %v", got)
	}
	// Held bytes at the limit refuse new bodies.
	s.Body.MaxInFlightBytes = want
	e.g.SetSettings(s)
	if w := sendBody(e.g.Handler(http.NotFoundHandler()), "192.0.2.9", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("held bytes full: %d", w.Code)
	}
	close(release)
	<-done
	waitFor(t, "held bytes released", func() bool { return e.g.bodies.held.Load() == 0 })
	if got := counterOf(t, e.g.Metrics.BodyBytesInFlight); got != 0 {
		t.Fatalf("gauge after the end %v", got)
	}
}

// Declared lengths are not reserved: a length nobody sends costs nothing.
func TestBodyDeclaredLengthCostsNothing(t *testing.T) {
	e, h := bodyEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.Body.MaxInFlightBytes = 1 << 10
	s.Limits.Body, s.Limits.Raw = 60<<10, 60<<10
	e.g.SetSettings(s)
	pr, pw := io.Pipe()
	r := httptest.NewRequest("POST", "/upload", pr)
	r.RemoteAddr = "198.51.100.7:1"
	r.Header.Set("Content-Type", "text/plain")
	r.ContentLength = 50 << 10
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(httptest.NewRecorder(), r) }()
	e.waitBodies(t, 1)
	if got := e.g.bodies.held.Load(); got != 0 {
		t.Fatalf("held %d for bytes nobody sent", got)
	}
	_ = pw.Close()
	<-done
}

// A body that crosses the byte limit while it is read ends with the answer of
// a full gateway, its bytes released, without an incident.
func TestBodyCrossingHeldBytes(t *testing.T) {
	e, h := bodyEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.Body.MaxInFlightBytes = 1 << 10
	e.g.SetSettings(s)
	r := httptest.NewRequest("POST", "/upload", strings.NewReader(strings.Repeat("a", 4<<10)))
	r.RemoteAddr = "198.51.100.7:1"
	r.Header.Set("Content-Type", "text/plain")
	r.ContentLength = -1
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Schild-Waiting") != "1" {
		t.Fatalf("crossing: %d %v", w.Code, w.Header())
	}
	if e.hits.Load() != 0 {
		t.Fatal("the body reached the backend")
	}
	waitFor(t, "held bytes released", func() bool { return e.g.bodies.held.Load() == 0 })
	if got := counterOf(t, e.g.Metrics.BodiesAborted.WithLabelValues(bodylimit.AbortBusy)); got != 1 {
		t.Fatalf("aborted busy %v", got)
	}
	if n := e.incidents(t); n != 0 {
		t.Fatalf("%d incidents", n)
	}
}

// A request holds one admission however often it is evaluated (D33): the
// second evaluation of an admitted body passes a full gateway.
func TestBodyOneAdmissionPerRequest(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.Body.MaxInFlight = 1
	e.g.SetSettings(s)
	other := startBody(e.g.Handler(http.NotFoundHandler()), "192.0.2.9", "text/plain")
	defer other.close()
	e.waitBodies(t, 1)

	st := NewRecheck()
	st.noteBodyAdmitted()
	r := httptest.NewRequest("POST", "/upload", strings.NewReader("a=1"))
	r.RemoteAddr = "198.51.100.7:1"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var hits atomic.Int64
	w := httptest.NewRecorder()
	e.g.ServeChecked(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), st)
	if w.Code != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("re-check of an admitted body: %d, %d hits", w.Code, hits.Load())
	}
}

// rawRequest writes head and body on a new connection and returns it.
func rawRequest(t *testing.T, srv *httptest.Server, head, body string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := io.WriteString(c, head+body); err != nil {
		t.Fatal(err)
	}
	return c
}

const uploadHead = "POST /upload HTTP/1.1\r\nHost: shop.example\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/plain\r\n"

// A client that leaves costs no incident, no event and no body_read_error.
func TestBodyClientGone(t *testing.T) {
	for name, head := range map[string]string{
		"length":  uploadHead + "Content-Length: 1000\r\n\r\n",
		"chunked": uploadHead + "Transfer-Encoding: chunked\r\n\r\n5\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, decide.ModeObserve)
			e.g.Metrics = metrics.New()
			c := rawRequest(t, e.srv, head, "hello")
			time.Sleep(20 * time.Millisecond)
			_ = c.Close()
			gone := e.g.Metrics.BodiesAborted.WithLabelValues(bodylimit.AbortClientGone)
			waitFor(t, "client_gone", func() bool { return counterOf(t, gone) == 1 })
			if got := counterOf(t, e.g.Metrics.HardLimits.WithLabelValues("body_read_error")); got != 0 {
				t.Fatalf("body_read_error %v", got)
			}
			if n := e.incidents(t); n != 0 {
				t.Fatalf("%d incidents", n)
			}
			if rows := e.events(t, store.EventFilter{}); len(rows) != 0 {
				t.Fatalf("%d events", len(rows))
			}
		})
	}
}

// HTTP/2: a stream reset by the client is client_gone too.
func TestBodyClientGoneHTTP2(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	e.g.Metrics = metrics.New()
	srv := httptest.NewUnstartedServer(e.g.Handler(http.NotFoundHandler()))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/upload", pr)
	req.Header.Set("Content-Type", "text/plain")
	tr := srv.Client().Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{RootCAs: tr.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := srv.Client().Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	_, _ = pw.Write([]byte("hello"))
	e.waitBodies(t, 1)
	cancel()
	<-done
	_ = pw.Close()
	gone := e.g.Metrics.BodiesAborted.WithLabelValues(bodylimit.AbortClientGone)
	waitFor(t, "client_gone", func() bool { return counterOf(t, gone) == 1 })
	if got := counterOf(t, e.g.Metrics.HardLimits.WithLabelValues("body_read_error")); got != 0 {
		t.Fatalf("body_read_error %v", got)
	}
}

// Every other read error stays body_read_error.
func TestBodyBrokenChunkStaysReadError(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	e.g.Metrics = metrics.New()
	c := rawRequest(t, e.srv, uploadHead+"Transfer-Encoding: chunked\r\n\r\n", "zz\r\nhello\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), " 400 ") {
		t.Fatalf("answer %q", b)
	}
	if got := counterOf(t, e.g.Metrics.HardLimits.WithLabelValues("body_read_error")); got != 1 {
		t.Fatalf("body_read_error %v", got)
	}
}

// A read deadline is the server ending a stalled body: the client is there, and
// counts like one that left. A broken body stays an error.
func TestReadEnd(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	if e := readEnd(r, os.ErrDeadlineExceeded); e != bodylimit.ReadEndTimeout {
		t.Fatal(e)
	}
	if e := readEnd(r, fmt.Errorf("read: %w", os.ErrDeadlineExceeded)); e != bodylimit.ReadEndTimeout {
		t.Fatal(e)
	}
	if e := readEnd(r, errors.New("invalid byte in chunk length")); e != bodylimit.ReadEndError {
		t.Fatal(e)
	}
	for _, err := range []error{io.ErrUnexpectedEOF, syscall.ECONNRESET, net.ErrClosed} {
		if e := readEnd(r, err); e != bodylimit.ReadEndClientLeft {
			t.Fatalf("%v: %s", err, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := readEnd(r.WithContext(ctx), errors.New("stream closed")); e != bodylimit.ReadEndClientLeft {
		t.Fatal(e)
	}
}

// A refused request is drained for at most 2 s, however slowly it sends.
func TestDrainIsBounded(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	head := "POST /upload HTTP/1.1\r\nHost: shop.example\r\nContent-Type: text/plain\r\nContent-Length: 1000000\r\n\r\n"
	start := time.Now()
	c := rawRequest(t, e.srv, head, "a")
	_ = c.SetReadDeadline(time.Now().Add(6 * time.Second))
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
				_, _ = c.Write([]byte("a"))
			}
		}
	}()
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), " 413 ") {
		t.Fatalf("answer %q %v", buf[:n], err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("answered after %v", d)
	}
}

// The meter gives what bodylimit.Rate gives, on every rate vector.
func TestRateMeterVectors(t *testing.T) {
	files, err := vectors.Files("../../../contracts/vectors/body-limits/valid")
	if err != nil || len(files) == 0 {
		t.Fatalf("vectors: %v (%d)", err, len(files))
	}
	n := 0
	for _, f := range files {
		v, err := vectors.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		var in struct {
			Op       string              `json:"op"`
			Arrivals []bodylimit.Arrival `json:"arrivals"`
			EndMS    int64               `json:"end_ms"`
		}
		if err := json.Unmarshal(v.InputDecoded, &in); err != nil {
			t.Fatal(err)
		}
		if in.Op != "rate" {
			continue
		}
		n++
		var windows []int64
		var firstBelow *int
		i := 0
		m := &rateMeter{sample: func(rate int64, first bool) {
			windows = append(windows, rate)
			if first {
				j := i
				firstBelow = &j
			}
			i++
		}}
		for _, a := range in.Arrivals {
			if a.TMS <= in.EndMS {
				m.add(a.TMS, a.Bytes)
			}
		}
		m.close(in.EndMS)
		want := bodylimit.Rate(in.Arrivals, in.EndMS)
		if fmt.Sprint(windows) != fmt.Sprint(want.Windows) && len(windows)+len(want.Windows) != 0 {
			t.Fatalf("%s: windows %v, want %v", f, windows, want.Windows)
		}
		if (firstBelow == nil) != (want.FirstBelow == nil) || (firstBelow != nil && *firstBelow != *want.FirstBelow) {
			t.Fatalf("%s: first below %v, want %v", f, firstBelow, want.FirstBelow)
		}
	}
	if n == 0 {
		t.Fatal("no rate vector ran")
	}
}

// A body that sends nothing shows up while it is open, and counts once. No
// sample after its end, none for the partial window.
func TestRateMeterStall(t *testing.T) {
	var rates []int64
	below := 0
	m := &rateMeter{sample: func(rate int64, first bool) {
		rates = append(rates, rate)
		if first {
			below++
		}
	}}
	m.add(100, 300<<10)
	if !m.tick(31_000) || !m.tick(61_000) || !m.tick(91_000) {
		t.Fatal("open body reported closed")
	}
	if fmt.Sprint(rates) != "[10240 0 0]" || below != 1 {
		t.Fatalf("rates %v below %d", rates, below)
	}
	m.close(100_000)
	if m.tick(200_000) {
		t.Fatal("closed body reported open")
	}
	if len(rates) != 3 {
		t.Fatalf("samples after the end: %v", rates)
	}
}

// Text fields of a multipart form are expensive like any text, file parts are
// not, and the text gets the budget of a text body.
func TestMultipartTextIsHeavy(t *testing.T) {
	l := DefaultEvalLimits()
	text := Shape{Body: waf.BodyInfo{Bytes: 400 << 10, Args: 1, Files: true, Text: 400 << 10}}
	file := Shape{Body: waf.BodyInfo{Bytes: 400 << 10, Args: 1, Files: true}}
	if !l.Estimate(text).Heavy || l.Estimate(file).Heavy {
		t.Fatalf("text heavy %v, file heavy %v", l.Estimate(text).Heavy, l.Estimate(file).Heavy)
	}
	if bodyBudget(l, time.Second, text) <= time.Second || bodyBudget(l, time.Second, file) != time.Second {
		t.Fatal("budget")
	}
}

// The limits also act when the body comes over a real connection with the
// metrics of a finished read.
func TestBodyReadMetrics(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	e.g.Metrics = metrics.New()
	if code, _ := e.send("POST", "/contact", "application/x-www-form-urlencoded", "a=1"); code != 200 {
		t.Fatalf("status %d", code)
	}
	var m dto.Metric
	if err := e.g.Metrics.BodyReadSeconds.Write(&m); err != nil {
		t.Fatal(err)
	}
	if m.GetHistogram().GetSampleCount() != 1 {
		t.Fatalf("read seconds samples %d", m.GetHistogram().GetSampleCount())
	}
	if e.inFlight() != 0 || e.g.bodies.held.Load() != 0 {
		t.Fatalf("left: %d bodies, %d bytes", e.inFlight(), e.g.bodies.held.Load())
	}
}
