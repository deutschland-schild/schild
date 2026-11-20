package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/vectors"
	"github.com/deutschland-schild/schild/contract/waitingpage"
	"github.com/deutschland-schild/schild/gateway/internal/blockpage"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// D37 (MVP-23 step 1): the waiting-page vectors through the real gate. Each
// valid vector's request is built with its headers, method and host and
// sent to a gate that is overloaded in the vector's way: every evaluation
// slot held (waf_busy), every evaluation over its budget (waf_timeout), no
// WAF yet (not_ready). The vector's website and jitter draw are injected;
// the answer on the wire must be the vector's result. The reason panic is
// answered by the Caddy adapter, not the gate (caddymod TestPanicRecovered
// checks it keeps the block page).

type wpInput struct {
	Enabled    bool              `json:"enabled"`
	Reason     string            `json:"fail_closed"`
	Headers    map[string]string `json:"headers"`
	Host       string            `json:"host"`
	JitterDraw uint32            `json:"jitter_draw"`
	Method     string            `json:"method"`
	Website    string            `json:"website"`
}

var wpHeaderNames = map[string]string{"accept": "Accept", "accept_language": "Accept-Language", "sec_fetch_dest": "Sec-Fetch-Dest",
	"sec_fetch_mode": "Sec-Fetch-Mode", "x_requested_with": "X-Requested-With"}

// overloaded is a gate env that answers every request with one fail-closed
// reason.
type overloaded struct {
	e       *tenv
	h       http.Handler
	website atomic.Value
	draw    atomic.Uint32
	hits    atomic.Int64
	release func()
}

func newOverloaded(t *testing.T, reason string) *overloaded {
	o := &overloaded{e: newEnv(t, decide.ModeObserve)}
	g := o.e.g
	o.website.Store("")
	g.siteID = func(string) string { return o.website.Load().(string) }
	g.jitter = o.draw.Load
	o.h = g.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { o.hits.Add(1) }))
	o.release = func() {}
	switch reason {
	case waitingpage.ReasonWAFBusy:
		s := g.Settings()
		s.EvalTimeout = time.Minute
		g.SetSettings(s)
		g.SetEvalLimits(EvalLimits{MaxConcurrent: 1, QueueWait: time.Millisecond})
		h := newHolder("headers")
		g.TestHook = h.hook
		done := make(chan struct{})
		go func() {
			defer close(done)
			o.h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/held", nil))
		}()
		<-h.entered
		var once sync.Once
		o.release = func() { once.Do(func() { close(h.release); <-done }) }
		t.Cleanup(o.release)
	case waitingpage.ReasonWAFTimeout:
		s := g.Settings()
		s.EvalTimeout = 5 * time.Millisecond
		g.SetSettings(s)
		g.TestHook = func(p string) {
			if p == "headers" {
				time.Sleep(30 * time.Millisecond)
			}
		}
		t.Cleanup(func() { time.Sleep(60 * time.Millisecond) }) // abandoned evaluations finish
	case waitingpage.ReasonNotReady:
		g.Engine = &waf.Engine{}
	case waitingpage.ReasonBodyBusy:
		s := g.Settings()
		s.Body.MaxInFlight = 1
		g.SetSettings(s)
		adm, _ := g.bodies.admit(s.Body, netip.MustParseAddr("203.0.113.200"), "", 1, 0, nil)
		o.release = adm.end
		t.Cleanup(adm.end)
	}
	return o
}

func (o *overloaded) do(in wpInput) *httptest.ResponseRecorder {
	o.e.g.SetWaitingPage(in.Enabled)
	o.website.Store(in.Website)
	o.draw.Store(in.JitterDraw)
	var body io.Reader
	if in.Method == "POST" || in.Method == "PUT" {
		body = strings.NewReader("name=Kim&message=Hallo")
	}
	r := httptest.NewRequest(in.Method, "/kontakt", body)
	r.Host = in.Host
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range in.Headers {
		r.Header.Set(wpHeaderNames[k], v)
	}
	w := httptest.NewRecorder()
	o.h.ServeHTTP(w, r)
	return w
}

func TestWaitingPageVectorsThroughGate(t *testing.T) {
	files, err := vectors.Files("../../../contracts/vectors/waiting-page/valid")
	if err != nil || len(files) == 0 {
		t.Fatalf("vectors: %v (%d)", err, len(files))
	}
	envs := map[string]*overloaded{}
	n := 0
	for _, f := range files {
		v, err := vectors.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		var in wpInput
		if err := json.Unmarshal(v.InputDecoded, &in); err != nil {
			t.Fatal(err)
		}
		var want waitingpage.Result
		if err := json.Unmarshal(v.Expect.Result, &want); err != nil {
			t.Fatal(err)
		}
		if in.Reason == waitingpage.ReasonPanic {
			continue // answered by the Caddy adapter (caddymod TestPanicRecovered)
		}
		o := envs[in.Reason]
		if o == nil {
			o = newOverloaded(t, in.Reason)
			envs[in.Reason] = o
		}
		t.Run(filepath.Base(f), func(t *testing.T) {
			w := o.do(in)
			checkAnswer(t, in, want, w)
			if o.hits.Load() != 0 {
				t.Fatal("an overloaded request reached the backend")
			}
		})
		n++
	}
	if n < 50 {
		t.Fatalf("only %d vectors ran", n)
	}
}

func checkAnswer(t *testing.T, in wpInput, want waitingpage.Result, w *httptest.ResponseRecorder) {
	t.Helper()
	h := w.Header()
	body := w.Body.String()
	if w.Code != http.StatusServiceUnavailable || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d, Cache-Control %q", w.Code, h.Get("Cache-Control"))
	}
	// D37 amendment: the marker exactly on waiting page and problem.
	if got := h.Values(waitingpage.MarkerHeader); want.Marker != (len(got) == 1 && got[0] == waitingpage.MarkerValue) || (!want.Marker && len(got) != 0) {
		t.Fatalf("marker %v, want %v", got, want.Marker)
	}
	switch want.Answer {
	case waitingpage.AnswerUnchanged:
		// body_busy writes no incident (D41), so it shows no number either.
		if h.Get("Retry-After") != "5" || (h.Get("X-Schild-Incident") == "") != (in.Reason == waitingpage.ReasonBodyBusy) || h.Get("Content-Language") != "" {
			t.Fatalf("unchanged: %v", h)
		}
		r := httptest.NewRequest(in.Method, "/", nil)
		for k, v := range in.Headers {
			r.Header.Set(wpHeaderNames[k], v)
		}
		if json := blockpage.WantsJSON(r); json != (h.Get("Content-Type") == "application/problem+json") {
			t.Fatalf("unchanged: Content-Type %q, block page wants JSON %v", h.Get("Content-Type"), json)
		}
	case waitingpage.AnswerProblem:
		if h.Get("Content-Type") != "application/problem+json" || h.Get("Retry-After") != strconv.Itoa(*want.RetryAfter) {
			t.Fatalf("problem: %v", h)
		}
		if !*want.Body {
			if body != "" {
				t.Fatal("HEAD with a body")
			}
			return
		}
		var p blockpage.Problem
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || want.ProblemCode == nil || p.Code != *want.ProblemCode ||
			p.Type != "https://schild.invalid/problems/"+waitingpage.ProblemCode || p.Status != 503 || p.RetryAfter != *want.RetryAfter {
			t.Fatalf("problem body: %v %+v", err, p)
		}
	case waitingpage.AnswerWaitingPage:
		if h.Get("Content-Type") != "text/html; charset=utf-8" || h.Get("Content-Language") != *want.Language ||
			h.Get("Retry-After") != strconv.Itoa(*want.RetryAfter) || h.Get("Content-Security-Policy") != waitingpage.CSP ||
			h.Get("X-Schild-Incident") != "" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" ||
			!strings.Contains(h.Get("Vary"), "Sec-Fetch-Mode") {
			t.Fatalf("waiting page headers: %v", h)
		}
		if !*want.Body {
			if body != "" {
				t.Fatal("HEAD with a body")
			}
			return
		}
		if len(body) > waitingpage.MaxPageBytes || !strings.Contains(body, `<html lang="`+*want.Language+`">`) {
			t.Fatalf("page: %d bytes, lang", len(body))
		}
		tx := waitingpage.Texts[*want.Language]
		refresh := strings.Contains(body, `http-equiv="refresh"`)
		if want.Refresh != nil {
			if !strings.Contains(body, `<meta http-equiv="refresh" content="`+strconv.Itoa(*want.Refresh)+`">`) ||
				!strings.Contains(body, "<b>"+strconv.Itoa(*want.Refresh)+"</b>") {
				t.Fatal("reload variant without the matching refresh and countdown")
			}
		} else if refresh || !strings.Contains(body, strings.ReplaceAll(tx.NextForm, "'", "&#39;")) {
			t.Fatal("form variant with a refresh or without the form copy")
		}
		if want.SiteName != nil {
			if !strings.Contains(body, "<strong>"+*want.SiteName+"</strong>") {
				t.Fatalf("site name %q missing", *want.SiteName)
			}
		} else if !strings.Contains(body, strings.ReplaceAll(tx.LeadNoSite, "'", "&#39;")) || strings.Contains(body, "<strong>") {
			t.Fatal("generic wording missing")
		}
		if strings.Contains(body, "<b>x</b>") {
			t.Fatal("markup of the host on the page")
		}
	default:
		t.Fatalf("unknown answer %q", want.Answer)
	}
}

// D37 amendment: a Schild-Waiting header from the backend never reaches the
// client, whether the backend sets the status, only writes, or flushes
// first; a schild that re-checks the request further down the chain keeps
// the marker of its own waiting page.
func TestBackendCannotFakeWaitingMarker(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	for name, write := range map[string]func(http.ResponseWriter){
		"status": func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) },
		"write":  func(w http.ResponseWriter) { _, _ = io.WriteString(w, "hi") },
		"flush":  func(w http.ResponseWriter) { w.(http.Flusher).Flush() },
	} {
		h := e.g.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(waitingpage.MarkerHeader, waitingpage.MarkerValue)
			w.Header().Set("X-App", "1")
			write(w)
		}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/kontakt", nil))
		if w.Header().Get("X-App") != "1" {
			t.Fatalf("%s: backend response not forwarded: %d %v", name, w.Code, w.Header())
		}
		if v := w.Header().Values(waitingpage.MarkerHeader); len(v) != 0 {
			t.Fatalf("%s: backend marker reached the client: %v", name, v)
		}
	}

	// A re-check: the outer gate forwards to an overloaded inner gate whose
	// waiting page passes through the outer gate's writer.
	o := newOverloaded(t, waitingpage.ReasonWAFBusy)
	o.e.g.SetWaitingPage(true)
	outer := e.g.Handler(o.h)
	r := httptest.NewRequest("GET", "/kontakt", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	w := httptest.NewRecorder()
	outer.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Content-Language") == "" || w.Header().Get(waitingpage.MarkerHeader) != waitingpage.MarkerValue {
		t.Fatalf("re-check waiting page lost its marker: %d %v", w.Code, w.Header())
	}
}

// Serving the waiting page under load: while every evaluation slot is held,
// a burst of browser navigations is answered with the waiting page without
// a single WAF evaluation (no further hook call, no slot taken), without an
// incident in the store, and counted as waf_busy with the waiting-page
// overlay; an API request in the same state gets problem details with an
// incident as before.
func TestWaitingPageUnderLoadSkipsWAF(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	g := e.g
	m, err := monitoring.New(monitoring.Config{StoragePath: t.TempDir(), Log: quiet}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	g.Monitor = m
	s := g.Settings()
	s.EvalTimeout = time.Minute
	g.SetSettings(s)
	g.SetEvalLimits(EvalLimits{MaxConcurrent: 2, QueueWait: time.Millisecond})
	h := newHolder("headers")
	var phases atomic.Int64
	g.TestHook = func(p string) { phases.Add(1); h.hook(p) }
	var hits atomic.Int64
	handler := g.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/held", nil))
		}()
	}
	<-h.entered
	<-h.entered
	held := phases.Load()

	const burst = 200
	var pages atomic.Int64
	var bwg sync.WaitGroup
	for range burst {
		bwg.Add(1)
		go func() {
			defer bwg.Done()
			r := httptest.NewRequest("GET", "/", nil)
			r.Host = "shop.example"
			r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
			r.Header.Set("Sec-Fetch-Dest", "document")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code == 503 && w.Header().Get("Content-Language") == "de" && w.Header().Get("X-Schild-Incident") == "" {
				pages.Add(1)
			}
		}()
	}
	bwg.Wait()
	api := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/items", nil)
	r.Header.Set("Accept", "application/json")
	handler.ServeHTTP(api, r)
	if pages.Load() != burst {
		t.Fatalf("%d of %d got the waiting page", pages.Load(), burst)
	}
	if api.Code != 503 || api.Header().Get("Content-Type") != "application/problem+json" || api.Header().Get("X-Schild-Incident") == "" {
		t.Fatalf("API under load: %d %v", api.Code, api.Header())
	}
	if phases.Load() != held {
		t.Fatalf("the WAF ran for overloaded requests: %d phases, %d held", phases.Load(), held)
	}
	if st := g.EvalStats(); st.InFlight != 2 || st.Busy != burst+1 {
		t.Fatalf("eval stats %+v", st)
	}
	c := liveCounters(t, m)
	if c.FailClosedBy.WAFBusy != burst+1 || c.WaitingPageShown != burst || !c.Check() {
		t.Fatalf("counters: busy %d waiting %d check %v", c.FailClosedBy.WAFBusy, c.WaitingPageShown, c.Check())
	}
	close(h.release)
	wg.Wait()
	if hits.Load() != 2 {
		t.Fatalf("backend hits %d, want the 2 held requests", hits.Load())
	}
	n := e.incidents(t)
	if n != 1 {
		t.Fatalf("incidents stored: %d, want only the API request's", n)
	}
}
