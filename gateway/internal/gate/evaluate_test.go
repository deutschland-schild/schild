package gate

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// MVP-19 measurement, finding 1, at small scale: the WAF work of the gate is
// bounded. All tests hold evaluations with hooks that block on channels, so
// nothing depends on how fast the machine is; the only timers are the queue
// wait and the budget, and every assertion waits for an explicit signal.

// send is a goroutine-safe request (no t.Fatal off the test goroutine).
func (e *tenv) send(method, path, ctype, body string) (int, http.Header) {
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header
}

// holder blocks evaluations in a phase until released and tracks how many
// run at once.
type holder struct {
	phase   string
	entered chan string
	release chan struct{}
	running atomic.Int64
	maxSeen atomic.Int64
}

func newHolder(phase string) *holder {
	return &holder{phase: phase, entered: make(chan string, 256), release: make(chan struct{})}
}

func (h *holder) hook(p string) {
	n := h.running.Add(1)
	defer h.running.Add(-1)
	for {
		m := h.maxSeen.Load()
		if n <= m || h.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	if p != h.phase {
		return
	}
	h.entered <- p
	<-h.release
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// wallClock marks a test whose budgets are a few milliseconds of real time.
// The race detector slows everything several times, so the budgets run out
// before the test gets to its point: such a test runs without it only.
func wallClock(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("millisecond budgets do not hold under the race detector")
	}
}

// patient gives every evaluation time and a long wait for a slot: for tests
// of something else that send many requests at once, where a slow machine
// would otherwise answer 503 as it should under load.
func (e *tenv) patient() {
	s := e.g.Settings()
	s.EvalTimeout = time.Minute
	e.g.SetSettings(s)
	e.g.SetEvalLimits(EvalLimits{QueueWait: time.Minute})
}

func TestEvalSaturatedAnswers503AtOnce(t *testing.T) {
	wallClock(t)
	e := newEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.EvalTimeout = time.Minute // the budget is not what stops these
	e.g.SetSettings(s)
	e.g.SetEvalLimits(EvalLimits{MaxConcurrent: 2, QueueWait: 20 * time.Millisecond})
	e.g.SetWaitingPage(false) // the answer before D37 (block page with incident); waiting_test.go covers D37
	h := newHolder("headers")
	e.g.TestHook = h.hook

	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); c, _ := e.send("GET", "/held", "", ""); codes <- c }()
	}
	<-h.entered
	<-h.entered
	if st := e.g.EvalStats(); st.InFlight != 2 {
		t.Fatalf("in flight %d, want 2", st.InFlight)
	}
	// Both slots taken: the next request waits the queue wait, then 503.
	code, hdr := e.send("GET", "/third", "", "")
	if code != 503 || hdr.Get("Retry-After") == "" || hdr.Get("X-Schild-Incident") == "" {
		t.Fatalf("saturated: %d (Retry-After %q)", code, hdr.Get("Retry-After"))
	}
	if e.hits.Load() != 0 || e.g.EvalStats().Busy != 1 {
		t.Fatalf("busy request reached the backend or was not counted: hits %d busy %d", e.hits.Load(), e.g.EvalStats().Busy)
	}
	close(h.release)
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 200 {
			t.Fatalf("held request: %d", c)
		}
	}
	if e.g.EvalStats().InFlight != 0 {
		t.Fatal("slots not released")
	}
	rows := e.events(t, store.EventFilter{})
	found := false
	for _, r := range rows {
		if r.Summary == "hard limit waf_busy" {
			found = true
		}
	}
	if !found {
		t.Fatal("no event with hard limit waf_busy")
	}
}

func TestEvalQueueWaitsForAFreeSlot(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	e.g.SetEvalLimits(EvalLimits{MaxConcurrent: 1, QueueWait: time.Minute})
	h := newHolder("headers")
	e.g.TestHook = h.hook
	first := make(chan int, 1)
	go func() { c, _ := e.send("GET", "/first", "", ""); first <- c }()
	<-h.entered
	second := make(chan int, 1)
	go func() { c, _ := e.send("GET", "/second", "", ""); second <- c }()
	waitFor(t, "second request queued", func() bool { return e.g.EvalStats().Waiting == 1 })
	h.release <- struct{}{} // first finishes, second takes its slot
	<-h.entered
	close(h.release)
	if a, b := <-first, <-second; a != 200 || b != 200 {
		t.Fatalf("queued requests: %d %d", a, b)
	}
}

// A timed-out evaluation is cancelled, answered 503 at once, and keeps its
// slot until it has really stopped: abandoned work never exceeds the slots.
func TestEvalTimeoutCancelsAndHoldsSlotUntilStopped(t *testing.T) {
	wallClock(t)
	e := newEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.EvalTimeout = 20 * time.Millisecond
	e.g.SetSettings(s)
	e.g.SetEvalLimits(EvalLimits{MaxConcurrent: 1, QueueWait: 10 * time.Millisecond})
	h := newHolder("body")
	e.g.TestHook = h.hook

	code, hdr := e.send("POST", "/contact", "application/x-www-form-urlencoded", "msg="+strings.Repeat("<script>alert(1)</script>", 50))
	if code != 503 || hdr.Get("Retry-After") == "" {
		t.Fatalf("timeout: %d", code)
	}
	<-h.entered
	// The abandoned evaluation still holds the only slot.
	if st := e.g.EvalStats(); st.InFlight != 1 {
		t.Fatalf("in flight %d, want 1 while the timed-out evaluation runs", st.InFlight)
	}
	if code, _ := e.send("GET", "/", "", ""); code != 503 {
		t.Fatalf("slot of a timed-out evaluation was given away: %d", code)
	}
	// Released, the evaluation reaches Coraza with the cancel set and stops
	// at its first rule instead of evaluating the whole body.
	close(h.release)
	waitFor(t, "cancelled evaluation to stop", func() bool {
		st := e.g.EvalStats()
		return st.InFlight == 0 && st.Cancelled == 1
	})
	if code, _ := e.send("GET", "/", "", ""); code != 200 {
		t.Fatalf("after the stop: %d", code)
	}
	if e.hits.Load() != 1 {
		t.Fatalf("backend hits %d, want 1", e.hits.Load())
	}
}

// The measurement scenario in small: a flood of large bodies plus ordinary
// requests. Large bodies get at most the heavy slots, the rest answer 503 at
// once, ordinary requests still pass, nothing runs beyond the slots and
// nothing reaches the backend uninspected.
func TestEvalLargeBodyFloodKeepsOrdinaryRequestsAnswered(t *testing.T) {
	wallClock(t)
	e := newEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.EvalTimeout = time.Minute
	s.Body.MaxPerClient, s.Body.MaxPerNetwork = 1000, 1000 // this flood is about the slots, not D41
	e.g.SetSettings(s)
	e.g.SetEvalLimits(EvalLimits{MaxConcurrent: 4, MaxHeavy: 2, HeavyBody: 4 << 10, QueueWait: 20 * time.Millisecond})
	h := newHolder("body")
	// Hold the first two body evaluations (the flood requests that got the
	// heavy slots); later ones (ordinary GETs) pass through.
	var bodies atomic.Int64
	e.g.TestHook = func(p string) {
		if p == "body" && bodies.Add(1) > 2 {
			p = "passthrough"
		}
		h.hook(p)
	}
	large := "msg=" + strings.Repeat("<img src=x onerror=alert(1)> union select ", 1000) // ~42 KiB, heavy

	const flood = 12
	var wg sync.WaitGroup
	var ok200, busy503, other atomic.Int64
	for range flood {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch c, _ := e.send("POST", "/contact", "application/x-www-form-urlencoded", large); c {
			case 200:
				ok200.Add(1)
			case 503:
				busy503.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	<-h.entered
	<-h.entered
	// Every flood request beyond the two heavy slots is answered without waiting for them.
	waitFor(t, "flood beyond the heavy slots answered", func() bool { return busy503.Load() == flood-2 })
	// Ordinary requests still get their slots while the heavy ones are held.
	for i := range 5 {
		if c, _ := e.send("GET", "/page", "", ""); c != 200 {
			t.Fatalf("ordinary request %d during the flood: %d", i, c)
		}
	}
	close(h.release)
	wg.Wait()
	if ok200.Load() != 2 || other.Load() != 0 {
		t.Fatalf("flood: %d passed, %d busy, %d other", ok200.Load(), busy503.Load(), other.Load())
	}
	if h.maxSeen.Load() > 4 {
		t.Fatalf("ran beyond the slots: %d evaluations at once (max 4)", h.maxSeen.Load())
	}
	if e.hits.Load() != 2+5 {
		t.Fatalf("backend hits %d, want 7", e.hits.Load())
	}
	if e.g.EvalStats().InFlight != 0 {
		t.Fatal("slots not released")
	}
}

// Bodies over the hard limit are rejected while they stream in, before phase
// 2 and without a heavy slot, also without a declared length.
func TestOverLimitBodyRejectedBeforeEvaluation(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	var bodyPhase atomic.Int64
	e.g.TestHook = func(p string) {
		if p == "body" {
			bodyPhase.Add(1)
		}
	}
	pr, pw := io.Pipe()
	go func() {
		chunk := []byte(strings.Repeat("a", 8<<10))
		for range 64 { // 512 KiB, limit is 64 KiB
			if _, err := pw.Write(chunk); err != nil {
				return
			}
		}
		_ = pw.Close()
	}()
	req, _ := http.NewRequest("POST", e.srv.URL+"/upload", pr)
	req.Host = "shop.example"
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = -1 // chunked, no declared size
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 413 {
			t.Fatalf("chunked over-limit body: %d", resp.StatusCode)
		}
	}
	_ = pr.Close()
	if bodyPhase.Load() != 0 || e.hits.Load() != 0 {
		t.Fatalf("over-limit body was evaluated (%d) or forwarded (%d)", bodyPhase.Load(), e.hits.Load())
	}
	if e.g.EvalStats().InFlight != 0 {
		t.Fatal("slot leaked")
	}
}

func TestDefaultEvalLimits(t *testing.T) {
	l := DefaultEvalLimits()
	if l.MaxConcurrent < 2 || l.MaxHeavy < 1 || l.MaxHeavy > l.MaxConcurrent || l.QueueWait != DefaultQueueWait || l.HeavyBody != DefaultHeavyBody {
		t.Fatalf("defaults: %+v", l)
	}
	if l := (EvalLimits{MaxConcurrent: 3, MaxHeavy: 9}).norm(); l.MaxHeavy != 1 {
		t.Fatalf("heavy slots above the expensive cap: %+v", l)
	}
}

// Reserved evaluation slots (D31 amendment 2026-10-29): whatever MaxHeavy
// asks for, expensive evaluations get at most config.ExpensiveEvalSlots(n)
// of n slots, and under a flood of expensive evaluations the reserved
// slots still admit cheap ones.
func TestReservedEvalSlots(t *testing.T) {
	for n := 1; n <= 40; n++ {
		want := min(config.ExpensiveEvalSlots(n), n)
		for _, asked := range []int{0, 1, n / 2, n, 2 * n, 1024} {
			l := (EvalLimits{MaxConcurrent: n, MaxHeavy: asked}).norm()
			if l.MaxHeavy > want || asked <= 0 && l.MaxHeavy != want || asked > 0 && l.MaxHeavy != min(asked, want) {
				t.Fatalf("n %d asked %d: heavy %d, want <= %d", n, asked, l.MaxHeavy, want)
			}
		}
	}
	for _, n := range []int{2, 3, 4, 7, 16} {
		p := newEvalPool(EvalLimits{MaxConcurrent: n, MaxHeavy: n, PerClient: n, MemBudget: 1 << 40, QueueWait: time.Millisecond})
		var rel []func()
		heavy := 0
		for {
			r, ok := p.acquire(Cost{Heavy: true, Mem: 1})
			if !ok {
				break
			}
			rel = append(rel, r)
			heavy++
		}
		if heavy != config.ExpensiveEvalSlots(n) {
			t.Fatalf("n %d: %d expensive evaluations admitted, want %d", n, heavy, config.ExpensiveEvalSlots(n))
		}
		for range config.ReservedEvalSlots(n) {
			r, ok := p.acquire(Cost{Mem: 1})
			if !ok {
				t.Fatalf("n %d: reserved slot not free for a cheap evaluation", n)
			}
			rel = append(rel, r)
		}
		for _, r := range rel {
			r()
		}
	}
}
