package gate

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/stats"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

func requestEnv(t *testing.T, mode string, lim bodylimit.RequestLimits) (*tenv, *slowBackend, http.Handler) {
	t.Helper()
	e := newEnv(t, mode)
	e.g.Metrics = metrics.New()
	s := e.g.Settings()
	s.Requests = lim
	e.g.SetSettings(s)
	b := &slowBackend{open: make(chan struct{})}
	t.Cleanup(b.answer)
	return e, b, e.g.Handler(b)
}

// get sends one request without a body and leaves its answer on done.
func get(h http.Handler, addr string, header ...string) chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("GET", "/produkte", nil)
		r.RemoteAddr = net.JoinHostPort(addr, "40000")
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
		for i := 0; i+1 < len(header); i += 2 {
			r.Header.Set(header[i], header[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		done <- w
	}()
	return done
}

func (e *tenv) requests() int {
	e.g.bodies.mu.Lock()
	defer e.g.bodies.mu.Unlock()
	return e.g.bodies.requests
}

// hold starts n waiting requests of addr.
func hold(t *testing.T, e *tenv, b *slowBackend, h http.Handler, addr string, n int) []chan *httptest.ResponseRecorder {
	t.Helper()
	start := b.entered.Load()
	out := make([]chan *httptest.ResponseRecorder, n)
	for i := range out {
		out[i] = get(h, addr)
	}
	waitFor(t, "requests at the backend", func() bool { return b.entered.Load() == start+int64(n) })
	return out
}

// The finding of the measurement: requests without a body had no limit at all.
// A client at its share gets a 429 with Retry-After before any WAF work, in
// observe too, without an incident, while everybody else goes on. An ended
// request frees its place and the gauge follows.
func TestRequestClientShare(t *testing.T) {
	e, b, h := requestEnv(t, decide.ModeObserve, bodylimit.RequestLimits{MaxPerClient: 3, MaxPerNetwork: 10, Max: 100})
	var phases atomic.Int64
	running := hold(t, e, b, h, "198.51.100.7", 3)
	e.g.TestHook = func(string) { phases.Add(1) }
	if got := counterOf(t, e.g.Metrics.RequestsWaiting); got != 3 {
		t.Fatalf("gauge %v", got)
	}

	w := answerOf(t, get(h, "198.51.100.7"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the share: %d", w.Code)
	}
	if ra, _ := strconv.Atoi(w.Header().Get("Retry-After")); ra < 5 || ra > 8 {
		t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	if !strings.Contains(w.Body.String(), bodylimit.CodeRequestShare) {
		t.Fatalf("no code: %s", w.Body)
	}
	if phases.Load() != 0 {
		t.Fatal("WAF work for a refused request")
	}
	if got := counterOf(t, e.g.Metrics.HardLimits.WithLabelValues(bodylimit.CodeRequestShare)); got != 1 {
		t.Fatalf("counter %v", got)
	}
	if n := e.incidents(t); n != 0 {
		t.Fatalf("%d incidents", n)
	}

	other := get(h, "203.0.113.9")
	waitFor(t, "another client", func() bool { return b.entered.Load() == 4 })
	b.answer()
	for _, c := range append(running, other) {
		if w := answerOf(t, c); w.Code != http.StatusOK {
			t.Fatalf("admitted request: %d", w.Code)
		}
	}
	if e.requests() != 0 || counterOf(t, e.g.Metrics.RequestsWaiting) != 0 {
		t.Fatalf("left over: %d", e.requests())
	}
	if w := answerOf(t, get(h, "198.51.100.7")); w.Code != http.StatusOK {
		t.Fatalf("freed place: %d", w.Code)
	}
	e.g.bodies.mu.Lock()
	defer e.g.bodies.mu.Unlock()
	if len(e.g.bodies.reqClients) != 0 || len(e.g.bodies.reqNetworks) != 0 {
		t.Fatal("the maps must not keep ended clients")
	}
}

func TestRequestNetworkAndGateway(t *testing.T) {
	e, b, h := requestEnv(t, decide.ModeObserve, bodylimit.RequestLimits{MaxPerClient: 2, MaxPerNetwork: 3, Max: 4})
	hold(t, e, b, h, "198.51.100.1", 2)
	hold(t, e, b, h, "198.51.100.2", 1)
	if w := answerOf(t, get(h, "198.51.100.3")); w.Code != http.StatusTooManyRequests {
		t.Fatalf("network: %d", w.Code)
	}
	hold(t, e, b, h, "203.0.113.1", 1)
	w := answerOf(t, get(h, "192.0.2.1"))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Schild-Waiting") != "1" {
		t.Fatalf("gateway: %d %v", w.Code, w.Header())
	}
	nav := answerOf(t, get(h, "192.0.2.1", "Accept", "text/html", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document"))
	if nav.Code != http.StatusServiceUnavailable || !strings.Contains(nav.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("waiting page: %d %v", nav.Code, nav.Header())
	}
	if n := e.incidents(t); n != 0 {
		t.Fatalf("%d incidents", n)
	}
}

// cgnat counts four times and never sees a 429 (D29): over its share it gets the
// waiting page, with the marker for everything else.
func TestRequestSharedAddress(t *testing.T) {
	e, b, h := requestEnv(t, decide.ModeObserve, bodylimit.RequestLimits{MaxPerClient: 1, MaxPerNetwork: 2, Max: 100})
	hold(t, e, b, h, "100.64.1.1", bodylimit.SharedFactor)
	w := answerOf(t, get(h, "100.64.1.1"))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Schild-Waiting") != "1" {
		t.Fatalf("shared address: %d", w.Code)
	}
	if got := counterOf(t, e.g.Metrics.HardLimits.WithLabelValues(bodylimit.CodeRequestShare)); got != 1 {
		t.Fatalf("counter %v", got)
	}
	nav := answerOf(t, get(h, "100.64.1.1", "Accept", "text/html", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document"))
	if nav.Code != http.StatusServiceUnavailable || !strings.Contains(nav.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("waiting page: %d", nav.Code)
	}
}

// The limit holds in every mode and for the allowlist: it protects memory.
func TestRequestLimitEveryMode(t *testing.T) {
	for _, mode := range []string{decide.ModeObserve, decide.ModeAutoblock} {
		t.Run(mode, func(t *testing.T) {
			e, b, h := requestEnv(t, mode, bodylimit.RequestLimits{MaxPerClient: 1, MaxPerNetwork: 10, Max: 100})
			hold(t, e, b, h, "198.51.100.7", 1)
			if w := answerOf(t, get(h, "198.51.100.7")); w.Code != http.StatusTooManyRequests {
				t.Fatalf("%d", w.Code)
			}
		})
	}
	t.Run("allowlist", func(t *testing.T) {
		e, b, h := requestEnv(t, decide.ModeObserve, bodylimit.RequestLimits{MaxPerClient: 1, MaxPerNetwork: 10, Max: 100})
		e.g.Allow.Set([]store.AllowEntry{{ID: "a", IP: "198.51.100.7", Label: "me", Level: allowlist.BypassWAF, Expires: "never"}})
		hold(t, e, b, h, "198.51.100.7", 1)
		if w := answerOf(t, get(h, "198.51.100.7")); w.Code != http.StatusTooManyRequests {
			t.Fatalf("%d", w.Code)
		}
	})
}

// A page of 100 assets over one HTTP/2 connection, an office of ten doing that at
// once: every default fits. Bodies count too, a POST does not get past the count.
func TestRequestDefaultsFitAnOffice(t *testing.T) {
	e, b, h := requestEnv(t, decide.ModeObserve, bodylimit.RequestLimits{})
	s := e.g.Settings()
	if s.Requests.MaxPerClient != bodylimit.DefaultMaxWaitingPerClient || s.Requests.Max != bodylimit.FallbackWaitingRequests {
		t.Fatalf("defaults %+v", s.Requests)
	}
	// 1000 evaluations at once on a busy machine wait longer than the queue of
	// the WAF allows, and with the CRS under -race each one can run past
	// eval_timeout; those 503s are not what this test is about. Every request
	// still takes the whole path (admission, phases, slots), on rules without
	// the CRS (a fresh engine: the shared CRS instance stays open).
	e.g.SetEvalLimits(EvalLimits{QueueWait: time.Minute})
	s.EvalTimeout = time.Minute
	e.g.SetSettings(s)
	light, err := waf.Build(waf.Config{})
	if err != nil {
		t.Fatal(err)
	}
	e.g.Engine = &waf.Engine{}
	e.g.Engine.Swap(light)
	hold(t, e, b, h, "198.51.100.7", 1000)
	body := post(h, "198.51.100.7", "application/json", `{"a":1}`, "x")
	waitFor(t, "the body at the backend", func() bool { return b.entered.Load() == 1001 })
	if e.requests() != 1001 {
		t.Fatalf("a request with a body counts too: %d", e.requests())
	}
	b.answer()
	answerOf(t, body)
}

// One request counts once, however many schild handlers it passes: a nested
// evaluation holds no place of its own, so a share of 1 is enough for it. A
// following evaluation (handle_errors) finds the place of the first one free.
func TestRequestRecheckCountsOnce(t *testing.T) {
	e, _, _ := requestEnv(t, decide.ModeObserve, bodylimit.RequestLimits{MaxPerClient: 1, MaxPerNetwork: 1, Max: 1})
	var during, following, inner atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := NewRecheck()
		e.g.ServeChecked(w, r, http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
			r2.URL.Path = "/inner"
			r2.RequestURI = "/inner"
			e.g.ServeChecked(w2, r2, http.HandlerFunc(func(w3 http.ResponseWriter, _ *http.Request) {
				inner.Add(1)
				during.Store(int64(e.requests()))
				w3.WriteHeader(http.StatusOK)
			}), st)
		}), st)
		if e.requests() != 0 {
			t.Errorf("after the outer evaluation: %d", e.requests())
		}
		e.g.ServeChecked(w, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			inner.Add(1)
			following.Store(int64(e.requests()))
		}), st)
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/outer")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if inner.Load() != 2 || during.Load() != 1 || following.Load() != 1 {
		t.Fatalf("evaluations %d, counted %d and %d", inner.Load(), during.Load(), following.Load())
	}
	if e.requests() != 0 {
		t.Fatalf("left over: %d", e.requests())
	}
}

// A panic below the gate gives the place back.
func TestRequestPanicEndsTheCount(t *testing.T) {
	e, _, _ := requestEnv(t, decide.ModeObserve, bodylimit.RequestLimits{})
	h := e.g.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	func() {
		defer func() { _ = recover() }()
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "198.51.100.7:40000"
		h.ServeHTTP(httptest.NewRecorder(), r)
	}()
	if e.requests() != 0 {
		t.Fatalf("left over: %d", e.requests())
	}
}

// Memory pressure: the first level stops bodies, the second every request, each
// in observe, without an incident; the end of the pressure ends the refusals.
func TestMemoryPressure(t *testing.T) {
	e, h := bodyEnv(t, decide.ModeObserve)
	e.g.SetMemoryPressure(bodylimit.PressureBodies)
	w := sendBody(h, "198.51.100.7", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("body at level 1: %d", w.Code)
	}
	if w.Header().Get("Connection") != "close" {
		t.Fatal("a refused body keeps its connection under pressure")
	}
	if w := answerOf(t, get(h, "198.51.100.7")); w.Code != http.StatusOK {
		t.Fatalf("GET at level 1: %d", w.Code)
	}
	e.g.SetMemoryPressure(bodylimit.PressureRequests)
	if w := answerOf(t, get(h, "198.51.100.7")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET at level 2: %d", w.Code)
	}
	if got := counterOf(t, e.g.Metrics.MemoryPressure); got != bodylimit.PressureRequests {
		t.Fatalf("gauge %v", got)
	}
	e.g.SetMemoryPressure(bodylimit.PressureNone)
	if w := sendBody(h, "198.51.100.7", ""); w.Code != http.StatusOK {
		t.Fatalf("no pressure: %d", w.Code)
	}
	if n := e.incidents(t); n != 0 {
		t.Fatalf("%d incidents", n)
	}
}

// A large body, also one of unknown length, meets its own limit; small bodies go
// on past it. That limit is what bounds the read phase of bodies around 1 MB.
func TestLargeBodiesInFlight(t *testing.T) {
	e, h := bodyEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.Body.MaxLargeInFlight = 2
	e.g.SetSettings(s)
	a, b := startBody(h, "198.51.100.1", "text/plain"), startBody(h, "192.0.2.1", "text/plain")
	e.waitBodies(t, 2)
	c := startBody(h, "203.0.113.1", "text/plain")
	select {
	case <-c.done:
	case <-time.After(10 * time.Second):
		t.Fatal("a third large body was admitted")
	}
	if c.rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("third: %d", c.rec.Code)
	}
	if w := sendBody(h, "203.0.113.1", ""); w.Code != http.StatusOK {
		t.Fatalf("a small body: %d", w.Code)
	}
	a.close()
	b.close()
	e.g.bodies.mu.Lock()
	defer e.g.bodies.mu.Unlock()
	if e.g.bodies.largeBodies != 0 {
		t.Fatalf("left over: %d", e.g.bodies.largeBodies)
	}
}

// A stall that ends in a read timeout of the server is no attack (E10): no
// incident, no event, no block, in every mode. The finding of the measurement
// was an incident in observe. The client is still there and reads the status.
func TestBodyStallIsNoIncident(t *testing.T) {
	for _, mode := range []string{decide.ModeObserve, decide.ModeAutoblock} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t, mode)
			e.g.Metrics = metrics.New()
			srv := httptest.NewUnstartedServer(e.g.Handler(http.NotFoundHandler()))
			srv.Config.ReadTimeout = 150 * time.Millisecond
			srv.Start()
			defer srv.Close()
			c := rawRequest(t, srv, uploadHead+"Content-Length: 1000\r\n\r\n", "hello")
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			b, _ := io.ReadAll(c)
			if !strings.Contains(string(b), " 400 ") {
				t.Fatalf("answer %q", b)
			}
			gone := e.g.Metrics.BodiesAborted.WithLabelValues(bodylimit.AbortClientGone)
			waitFor(t, "client_gone", func() bool { return counterOf(t, gone) == 1 })
			if got := counterOf(t, e.g.Metrics.HardLimits.WithLabelValues(bodylimit.CodeBodyRead)); got != 0 {
				t.Fatalf("body_read_error %v", got)
			}
			if n := e.incidents(t); n != 0 {
				t.Fatalf("%d incidents", n)
			}
			if n := e.g.Counters.Rolling.Sum(stats.Incidents, time.Hour, time.Now()); n != 0 {
				t.Fatalf("rolling incidents %d", n)
			}
			if rows := e.events(t, store.EventFilter{}); len(rows) != 0 {
				t.Fatalf("%d events", len(rows))
			}
			// D46: nobody blocked it, and the counters say so.
			waitFor(t, "client_gone outcome", func() bool {
				return counterOf(t, e.g.Metrics.Requests.WithLabelValues(bodylimit.OutcomeClientGone)) == 1
			})
			if got := counterOf(t, e.g.Metrics.Requests.WithLabelValues(decide.Blocked)); got != 0 {
				t.Fatalf("blocked %v", got)
			}
			if n := e.g.Counters.Rolling.Sum(stats.Blocked, time.Hour, time.Now()); n != 0 {
				t.Fatalf("rolling blocked %d", n)
			}
		})
	}
}

// Under pressure a refused body loses its connection with the answer: the client
// reads the 503, and the socket does not wait half closed for a sender that goes
// on sending.
func TestRefusedBodyClosesUnderPressure(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	e.g.Metrics = metrics.New()
	e.g.SetMemoryPressure(bodylimit.PressureBodies)
	c := rawRequest(t, e.srv, uploadHead+"Content-Length: 1000000\r\n\r\n", "hello")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), " 503 ") {
		t.Fatalf("answer %q", b)
	}
	// A half-closed socket would take these bytes for another 500 ms.
	for time.Since(start) < 400*time.Millisecond {
		if _, err := c.Write(make([]byte, 1024)); err != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the socket still takes bytes after the answer")
}

func TestRefusalOf(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
		want   *waf.LimitError
	}{
		{429, bodylimit.CodeClientShare, waf.ErrBodyShare}, {503, bodylimit.CodeClientShare, waf.ErrBodyShareBusy},
		{429, bodylimit.CodeWaitingShare, waf.ErrBodyWaitShare}, {503, bodylimit.CodeWaitingShare, waf.ErrBodyWaitShareBusy},
		{429, bodylimit.CodeRequestShare, waf.ErrRequestShare}, {503, bodylimit.CodeRequestShare, waf.ErrRequestShareBusy},
		{503, bodylimit.CodeRequestBusy, waf.ErrRequestBusy}, {503, bodylimit.CodeBusy, waf.ErrBodyBusy},
	} {
		got := refusalOf(c.status, c.code)
		if got != c.want || got.Status != c.status || got.Code != c.code {
			t.Fatalf("%s", fmt.Sprint(c.status, c.code, got))
		}
	}
}
