package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/geo"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

var (
	crsOnce sync.Once
	crsInst *waf.Instance
)

func crsInstance(t testing.TB) *waf.Instance {
	crsOnce.Do(func() {
		var err error
		crsInst, err = waf.Build(waf.Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
		if err != nil {
			panic(err)
		}
	})
	return crsInst
}

type tenv struct {
	g        *Gate
	st       *store.Store
	ev       *eventlog.Log
	srv      *httptest.Server
	backend  *httptest.Server
	hits     atomic.Int64
	lastBody atomic.Value
	cancel   context.CancelFunc
}

func newEnv(t *testing.T, mode string) *tenv {
	t.Helper()
	e := &tenv{}
	e.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(b)
		e.lastBody.Store(hex.EncodeToString(sum[:]))
		w.Header().Set("X-Body-Len", fmt.Sprint(len(b)))
		_, _ = io.WriteString(w, "backend ok")
	}))
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	e.st = st
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.ev = eventlog.New(st, "test-node", nil, quiet)
	e.ev.Validate = true
	go e.ev.Run(ctx)
	res, _ := clientip.New([]string{"127.0.0.1/32", "::1/128"}, nil)
	g := New(Settings{Mode: mode, Limits: waf.Limits{Body: 64 << 10, Args: 100, JSONDepth: 16}, EvalTimeout: time.Second, Resolver: res, EventsPerSecond: 1000})
	g.Engine = &waf.Engine{}
	g.Engine.Swap(crsInstance(t))
	g.Allow = allowlist.New()
	gp := filepath.Join(t.TempDir(), "geo.mmdb")
	_ = geo.WriteFixture(gp)
	g.Geo, _ = geo.Open(gp)
	g.Events = e.ev
	g.Counters = NewCounters()
	g.Log = quiet
	g.SetReady(true)
	go g.RunIncidents(ctx, st)
	e.g = g
	target := e.backend.URL
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// minimal forwarder for the unit test (Caddy reverse_proxy in production)
		req, _ := http.NewRequest(r.Method, target+r.URL.RequestURI(), r.Body)
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
	e.srv = httptest.NewServer(g.Handler(proxy))
	t.Cleanup(func() {
		e.srv.Close()
		e.backend.Close()
		cancel()
		st.Close()
	})
	return e
}

func (e *tenv) do(t *testing.T, method, path, ctype, body string, hdr map[string]string) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Host = "shop.example"
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	req.Header.Set("Accept", "text/html")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Header.Set("X-Test-Body", string(b))
	return resp
}

func (e *tenv) events(t *testing.T, f store.EventFilter) []*store.EventRow {
	t.Helper()
	e.ev.Flush(context.Background())
	rows, _, err := e.st.ListEvents(context.Background(), f, 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

const sqli = "/?id=1%27%20OR%20%271%27%3D%271%27--"

// wouldBlockReasons returns the stored would_block_reason of every event
// (in store order, "" when absent).
func wouldBlockReasons(t *testing.T, rows []*store.EventRow) []string {
	t.Helper()
	var out []string
	for _, r := range rows {
		var b struct {
			Data events.Request `json:"data"`
		}
		if err := json.Unmarshal(r.Body, &b); err != nil {
			t.Fatal(err)
		}
		if b.Data.WouldBlockReason != "" && b.Data.Outcome != decide.WouldBlock {
			t.Fatalf("would_block_reason %q with outcome %s", b.Data.WouldBlockReason, b.Data.Outcome)
		}
		out = append(out, b.Data.WouldBlockReason)
	}
	return out
}

func TestModesAndBlockPage(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	if r := e.do(t, "GET", "/blog/hello", "", "", nil); r.StatusCode != 200 || e.hits.Load() != 1 {
		t.Fatalf("clean request: %d", r.StatusCode)
	}
	r := e.do(t, "GET", sqli, "", "", nil)
	if r.StatusCode != 403 || e.hits.Load() != 1 {
		t.Fatalf("sqli: %d, backend hits %d", r.StatusCode, e.hits.Load())
	}
	inc := r.Header.Get("X-Schild-Incident")
	if inc == "" || !strings.Contains(r.Header.Get("X-Test-Body"), inc) || !strings.Contains(r.Header.Get("X-Test-Body"), "Vorfallnummer") {
		t.Fatal("block page without incident")
	}
	blocked := e.events(t, store.EventFilter{Type: events.RequestBlocked})
	if len(blocked) != 1 || blocked[0].Incident != inc || blocked[0].IP != "127.0.0.1" {
		t.Fatalf("%+v", blocked)
	}
	time.Sleep(50 * time.Millisecond)
	if in, err := e.st.GetIncident(context.Background(), inc); err != nil || in.Status != "blocked" {
		t.Fatalf("incident not stored: %v", err)
	}
	// Observe: same request passes, would_block.
	e.g.SetSettings(func() Settings { s := e.g.Settings(); s.Mode = decide.ModeObserve; return s }())
	if r := e.do(t, "GET", sqli, "", "", nil); r.StatusCode != 200 || e.hits.Load() != 2 {
		t.Fatalf("observe must pass: %d", r.StatusCode)
	}
	wb := e.events(t, store.EventFilter{Outcome: decide.WouldBlock})
	if len(wb) != 1 {
		t.Fatalf("would_block events %d", len(wb))
	}
	if got := wouldBlockReasons(t, wb); got[0] != decide.ReasonGatewayObserve {
		t.Fatalf("would_block_reason %v", got)
	}
	// Only would_block events carry a reason.
	wouldBlockReasons(t, e.events(t, store.EventFilter{}))
	// API clients get RFC 9457.
	e.g.SetSettings(func() Settings { s := e.g.Settings(); s.Mode = decide.ModeAutoblock; return s }())
	r = e.do(t, "GET", sqli, "", "", map[string]string{"Accept": "application/json"})
	if r.StatusCode != 403 || r.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("problem json: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
}

func TestTimeoutNeverPasses(t *testing.T) {
	wallClock(t)
	for _, phase := range []string{"headers", "body"} {
		t.Run(phase, func(t *testing.T) {
			e := newEnv(t, decide.ModeObserve)
			s := e.g.Settings()
			s.EvalTimeout = 50 * time.Millisecond
			e.g.SetSettings(s)
			e.g.SetWaitingPage(false) // the answer before D37; waiting_test.go covers D37
			e.g.TestHook = func(p string) {
				if p == phase {
					time.Sleep(300 * time.Millisecond)
				}
			}
			start := time.Now()
			r := e.do(t, "POST", "/contact", "application/x-www-form-urlencoded", "a=1&b=2", nil)
			if r.StatusCode != 503 || e.hits.Load() != 0 {
				t.Fatalf("timeout: status %d, backend hits %d", r.StatusCode, e.hits.Load())
			}
			if d := time.Since(start); d > 250*time.Millisecond {
				t.Fatalf("503 took %s, must answer at the timeout", d)
			}
			if r.Header.Get("Retry-After") == "" || r.Header.Get("X-Schild-Incident") == "" {
				t.Fatal("503 without Retry-After/incident")
			}
			time.Sleep(400 * time.Millisecond) // the abandoned evaluation finishes and closes its transaction
		})
	}
}

func TestPanicFailsClosed(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	e.g.TestHook = func(p string) { panic("boom") }
	if r := e.do(t, "GET", "/", "", "", nil); r.StatusCode != 503 || e.hits.Load() != 0 {
		t.Fatalf("panic must fail closed: %d", r.StatusCode)
	}
}

func TestHardLimitsInEveryMode(t *testing.T) {
	for _, mode := range []string{decide.ModeObserve, decide.ModeAutoblock} {
		e := newEnv(t, mode)
		s := e.g.Settings()
		s.EvalTimeout = 60 * time.Second // CRS on a 60 KiB form field is slow under -race
		e.g.SetSettings(s)
		cases := []struct {
			name, ctype, body string
			hdr               map[string]string
			want              int
		}{
			{"too large", "text/plain", strings.Repeat("a", 70<<10), nil, 413},
			{"deep json", "application/json", strings.Repeat("[", 20) + strings.Repeat("]", 20), nil, 400},
			{"broken json", "application/json", `{"a":`, nil, 400},
			{"gzip body", "application/json", `{"a":1}`, map[string]string{"Content-Encoding": "gzip"}, 415},
			{"too many args", "application/x-www-form-urlencoded", strings.Repeat("a=1&", 150), nil, 400},
		}
		for _, c := range cases {
			if r := e.do(t, "POST", "/upload", c.ctype, c.body, c.hdr); r.StatusCode != c.want {
				t.Errorf("%s/%s: got %d want %d", mode, c.name, r.StatusCode, c.want)
			}
		}
		if e.hits.Load() != 0 {
			t.Fatalf("%s: %d uninspected requests reached the backend", mode, e.hits.Load())
		}
		// Within limits the body arrives intact.
		body := "data=" + strings.Repeat("x", 60<<10)
		r := e.do(t, "POST", "/upload", "application/x-www-form-urlencoded", body, nil)
		sum := sha256.Sum256([]byte(body))
		if r.StatusCode != 200 || e.lastBody.Load() != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s: body not forwarded intact (%d)", mode, r.StatusCode)
		}
	}
}

func TestAllowlist(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	e.g.Allow.Set([]store.AllowEntry{{ID: "a", IP: "127.0.0.1", Label: "me", Level: allowlist.NoBlock, Expires: "never"}})
	if r := e.do(t, "GET", sqli, "", "", nil); r.StatusCode != 200 {
		t.Fatalf("no_block: %d", r.StatusCode)
	}
	if wb := wouldBlockReasons(t, e.events(t, store.EventFilter{Outcome: decide.WouldBlock})); len(wb) != 1 || wb[0] != decide.ReasonAllowlist {
		t.Fatalf("would_block_reason %v", wb)
	}
	e.g.Allow.Set([]store.AllowEntry{{ID: "a", IP: "127.0.0.1", Label: "me", Level: allowlist.BypassWAF, Expires: "never"}})
	if r := e.do(t, "POST", "/x", "text/plain", strings.Repeat("a", 70<<10), nil); r.StatusCode != 200 {
		t.Fatalf("bypass_waf: %d", r.StatusCode)
	}
}

func TestExceptionAfterUnblock(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	if r := e.do(t, "GET", sqli, "", "", nil); r.StatusCode != 403 {
		t.Fatal(r.StatusCode)
	}
	e.g.Exceptions.Add(netip.MustParseAddr("127.0.0.1"), []string{"crs"}, time.Now().Add(time.Hour))
	if r := e.do(t, "GET", sqli, "", "", nil); r.StatusCode != 200 {
		t.Fatalf("excepted: %d", r.StatusCode)
	}
}

func TestRedaction(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	secrets := []string{"hunter2hunter2", "max@example.org", "Bearer-abc123SECRET", "sessioncookievalue42", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIz"}
	e.do(t, "POST", "/login?pwd=hunter2hunter2&email=max%40example.org&jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIz&q=%3Cscript%3Ealert(1)%3C/script%3E",
		"application/x-www-form-urlencoded", "password=bodysecret99&x=1",
		map[string]string{"Authorization": "Bearer-abc123SECRET", "Cookie": "sid=sessioncookievalue42"})
	rows := e.events(t, store.EventFilter{})
	if len(rows) == 0 {
		t.Fatal("no event")
	}
	for _, r := range rows {
		for _, s := range append(secrets, "bodysecret99") {
			if strings.Contains(string(r.Body), s) || strings.Contains(r.Path, s) {
				t.Errorf("secret %q stored: %s", s, r.Body)
			}
		}
	}
}

// TestAtomicSwapUnderLoad swaps the WAF instance continuously while clients
// send requests: no request may fail or be dropped (B07).
func TestAtomicSwapUnderLoad(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	// 16 clients on a slow scheduler (-race, few CPUs) can wait longer than the
	// queue allows or run past eval_timeout: a 503 by design that says nothing
	// about the swaps. Without both, any failed request is the swap's.
	e.g.SetEvalLimits(EvalLimits{QueueWait: time.Minute})
	s := e.g.Settings()
	s.EvalTimeout = time.Minute
	e.g.SetSettings(s)
	var instances []*waf.Instance
	for i := 0; i < 3; i++ {
		var local strings.Builder
		for j := 0; j < 50*i; j++ {
			id := 1000100 + j
			fmt.Fprintf(&local, "SecRule ARGS:p%d \"@contains needle%d\" \"id:%d,phase:2,deny,severity:CRITICAL,msg:'probe',t:none\"\n", j, j, id)
		}
		inst, err := waf.Build(waf.Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5, LocalRules: local.String()})
		if err != nil {
			t.Fatal(err)
		}
		instances = append(instances, inst)
	}
	stop := make(chan struct{})
	var swaps atomic.Int64
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			e.g.Engine.Swap(instances[i%len(instances)])
			swaps.Add(1)
			time.Sleep(time.Millisecond)
		}
	}()
	var wg sync.WaitGroup
	var fails, total atomic.Int64
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				resp, err := client.Get(e.srv.URL + "/page?i=" + fmt.Sprint(i))
				total.Add(1)
				if err != nil {
					fails.Add(1)
					continue
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					fails.Add(1)
					t.Logf("request %d: %d %.200s", i, resp.StatusCode, b)
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	if fails.Load() != 0 || e.hits.Load() != total.Load() {
		t.Fatalf("%d of %d requests failed during %d swaps (backend saw %d)", fails.Load(), total.Load(), swaps.Load(), e.hits.Load())
	}
	t.Logf("%d requests, %d swaps, 0 failures", total.Load(), swaps.Load())
}

func TestHealthPaths(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	if r := e.do(t, "GET", ReadyPath, "", "", nil); r.StatusCode != 200 || e.hits.Load() != 0 {
		t.Fatal(r.StatusCode)
	}
	e.g.SetReady(false)
	if r := e.do(t, "GET", ReadyPath, "", "", nil); r.StatusCode != 503 {
		t.Fatal(r.StatusCode)
	}
}

// BenchmarkGateOverhead measures the request overhead of the gate with CRS
// (B01-style): clean GET through the full handler with an in-process backend.
func BenchmarkGateOverhead(b *testing.B) {
	for _, withGate := range []bool{false, true} {
		name := "without"
		if withGate {
			name = "with"
		}
		b.Run(name, func(b *testing.B) {
			res, _ := clientip.New([]string{"127.0.0.1/32"}, nil)
			g := New(Settings{Mode: decide.ModeAutoblock, EvalTimeout: time.Second, Resolver: res})
			g.Engine = &waf.Engine{}
			g.Engine.Swap(crsInstance(b))
			g.Allow = allowlist.New()
			g.Counters = NewCounters()
			backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
			var h http.Handler = backend
			if withGate {
				h = g.Handler(backend)
			}
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req := httptest.NewRequest("GET", "/blog/2026/10/hello-world/?page=2", nil)
					req.RemoteAddr = "203.0.113.7:4444"
					req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
					req.Header.Set("Accept", "text/html")
					w := httptest.NewRecorder()
					h.ServeHTTP(w, req)
				}
			})
		})
	}
}

// A trusted proxy's X-Request-Id becomes the local event's request_id (join
// with the proxy's logs and the test lab's ground truth); malformed ids and
// ids from untrusted peers are ignored.
func TestRequestIDFromTrustedProxy(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	e.do(t, "GET", "/a?x=1", "", "", map[string]string{"X-Request-Id": "0123456789abcdef0123456789abcdef"})
	e.do(t, "GET", "/b?x=1", "", "", map[string]string{"X-Request-Id": "bad id with spaces"})
	untrusted, _ := clientip.New([]string{"192.0.2.0/24"}, nil)
	set := *e.g.settings.Load()
	set.Resolver = untrusted
	e.g.settings.Store(&set)
	e.do(t, "GET", "/c?x=1", "", "", map[string]string{"X-Request-Id": "fedcba9876543210fedcba9876543210"})
	e.ev.Flush(context.Background())
	got := map[string]string{}
	for _, r := range e.events(t, store.EventFilter{}) {
		var ev struct {
			ID   string `json:"id"`
			Data struct {
				RequestID string `json:"request_id"`
			} `json:"data"`
		}
		_ = json.Unmarshal(r.Body, &ev)
		if ev.Data.RequestID == ev.ID {
			got[r.Path] = "event-id"
		} else {
			got[r.Path] = ev.Data.RequestID
		}
	}
	if got["/a"] != "0123456789abcdef0123456789abcdef" || got["/b"] != "event-id" || got["/c"] != "event-id" {
		t.Fatalf("request ids %v", got)
	}
}
