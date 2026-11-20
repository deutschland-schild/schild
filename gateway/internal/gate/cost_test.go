package gate

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// MVP-19 re-measurement, findings 2-4, at small scale. Evaluations are held
// with hooks that block on channels; no assertion depends on machine speed.

// sendFrom is send with a visitor address (X-Forwarded-For from the trusted
// loopback proxy) and extra headers.
func (e *tenv) sendFrom(ip, method, path, ctype, body string, hdr map[string]string) int {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Host = "shop.example"
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Forwarded-For", ip)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// manyArgs is a GET query like the re-measurement's (n short arguments of
// harmless text).
func manyArgs(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("f%d=lorem+ipsum+%d", i, i)
	}
	return strings.Join(parts, "&")
}

func form(n int) string {
	return "message=" + strings.Repeat("Sehr+geehrte+Damen+und+Herren+", n/30+1)[:n]
}

// The cost classes: ordinary Laravel, WordPress and Livewire requests are
// cheap; the re-measurement's attack shapes are expensive.
func TestEstimateClasses(t *testing.T) {
	l := DefaultEvalLimits()
	q := func(s string) Shape { return Shape{QueryArgs: waf.QueryArgs(s), QueryBytes: len(s)} }
	cheap := map[string]Shape{
		"GET /":                          {},
		"GET with a few args":            q("page=2&sort=name&q=schuhe"),
		"Laravel login":                  {Cookies: 3, Body: waf.BodyInfo{Bytes: 120, Args: 4}},
		"Livewire update (8 KiB JSON)":   {Cookies: 4, Body: waf.BodyInfo{Bytes: 8 << 10, Args: 40}},
		"WordPress comment":              {Cookies: 10, Body: waf.BodyInfo{Bytes: 2 << 10, Args: 8}},
		"5 MB multipart upload, 3 parts": {Body: waf.BodyInfo{Bytes: 5 << 20, Args: 3, Files: true}},
		"GET with a 1 KiB path":          {TargetBytes: 1 << 10},
	}
	for name, s := range cheap {
		if c := l.Estimate(s); c.Heavy {
			t.Errorf("%s: expensive (%+v)", name, c)
		}
	}
	heavy := map[string]Shape{
		"GET with 990 args":         q(manyArgs(990)),
		"GET with 100 args":         q(manyArgs(100)),
		"GET with a 6 KiB query":    q("q=" + strings.Repeat("a", 6<<10)),
		"126 KB form, one argument": {Body: waf.BodyInfo{Bytes: 126 << 10, Args: 1}},
		"JSON with 990 keys":        {Body: waf.BodyInfo{Bytes: 123 << 10, Args: 1980}},
		"multipart with 200 parts":  {Body: waf.BodyInfo{Bytes: 40 << 10, Args: 200, Files: true}},
		// Security audit 2026-11-05: CRS reads path and Host like the query.
		"GET with a 6 KiB path": {TargetBytes: 6 << 10},
		"GET with a 6 KiB Host": {TargetBytes: 6 << 10},
	}
	for name, s := range heavy {
		if c := l.Estimate(s); !c.Heavy {
			t.Errorf("%s: cheap (%+v)", name, c)
		}
	}
	// Memory grows with the arguments.
	if a, b := l.Estimate(q(manyArgs(990))).Mem, l.Estimate(q(manyArgs(100))).Mem; a < 9*b/2 || a < 64<<20 {
		t.Errorf("memory estimate: 990 args %d, 100 args %d", a, b)
	}
}

// Hard request-shape limits before any rule, every mode, never passed.
func TestRequestShapeLimits(t *testing.T) {
	e := newEnv(t, decide.ModeObserve)
	var evaluated atomic.Int64
	e.g.TestHook = func(p string) {
		if p == "headers" {
			evaluated.Add(1)
		}
	}
	many := map[string]string{}
	for i := range 101 {
		many[fmt.Sprintf("X-H%d", i)] = "1"
	}
	cookies := make([]string, 151)
	for i := range cookies {
		cookies[i] = fmt.Sprintf("c%d=1", i)
	}
	cases := []struct {
		name, path string
		hdr        map[string]string
		code       string
		status     int
	}{
		{"query over 32 KiB", "/s?q=" + strings.Repeat("a", 33<<10), nil, "query_too_long", 400},
		{"request target over 40 KiB", "/" + strings.Repeat("schuhe/", 6<<10) + "?q=1", nil, "uri_too_long", 414},
		{"more than 100 headers", "/", many, "too_many_headers", 400},
		{"headers over 64 KiB", "/", map[string]string{"X-Big": strings.Repeat("a", 65<<10)}, "headers_too_large", 400},
		{"Host and headers over 64 KiB", "/", map[string]string{"Host": strings.Repeat("a", 40<<10) + ".example", "X-Big": strings.Repeat("a", 30<<10)}, "headers_too_large", 400},
		{"more than 150 cookies", "/", map[string]string{"Cookie": strings.Join(cookies, "; ")}, "too_many_cookies", 400},
	}
	for _, tc := range cases {
		if c := e.sendFrom("203.0.113.9", "GET", tc.path, "", "", tc.hdr); c != tc.status {
			t.Errorf("%s: %d, want %d", tc.name, c, tc.status)
		}
	}
	if evaluated.Load() != 0 || e.hits.Load() != 0 {
		t.Fatalf("over-limit request evaluated (%d) or forwarded (%d)", evaluated.Load(), e.hits.Load())
	}
	rows := e.events(t, store.EventFilter{})
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.Summary] = true
	}
	for _, tc := range cases {
		if !seen["hard limit "+tc.code] {
			t.Errorf("no event with hard limit %s (%v)", tc.code, seen)
		}
	}
	// A browser-like request with a long but ordinary query, 30 headers and 40 cookies passes.
	hdr := map[string]string{"Cookie": strings.Join(cookies[:40], "; ")}
	for i := range 25 {
		hdr[fmt.Sprintf("X-H%d", i)] = "1"
	}
	if c := e.sendFrom("203.0.113.9", "GET", "/shop?"+manyArgs(60), "", "", hdr); c != 200 {
		t.Fatalf("ordinary request: %d", c)
	}
}

// The re-measurement's flood in small: many-argument GETs (cheap per byte,
// expensive per evaluation) from many clients plus ordinary GETs from others.
// The expensive ones share the heavy slots; ordinary GETs keep being answered.
func TestManyArgsFloodKeepsOrdinaryGETsAnswered(t *testing.T) {
	wallClock(t)
	e := newEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.EvalTimeout = time.Minute
	s.Limits.Args = 1000
	e.g.SetSettings(s)
	e.g.SetEvalLimits(EvalLimits{MaxConcurrent: 4, MaxHeavy: 2, QueueWait: 20 * time.Millisecond})
	h := newHolder("body")
	var bodies atomic.Int64
	e.g.TestHook = func(p string) {
		if p == "body" && bodies.Add(1) > 2 {
			p = "passthrough" // hold the two flood requests that got the heavy slots
		}
		h.hook(p)
	}
	const flood = 10
	var wg sync.WaitGroup
	var busy, passed atomic.Int64
	for i := range flood {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch e.sendFrom(fmt.Sprintf("198.51.100.%d", 10+i), "GET", "/search?"+manyArgs(300), "", "", nil) {
			case 503:
				busy.Add(1)
			case 200:
				passed.Add(1)
			}
		}()
	}
	<-h.entered
	<-h.entered
	waitFor(t, "flood beyond the heavy slots answered", func() bool { return busy.Load() == flood-2 })
	for i := range 6 {
		if c := e.sendFrom(fmt.Sprintf("203.0.113.%d", 20+i), "GET", "/page?id=7", "", "", nil); c != 200 {
			t.Fatalf("ordinary GET %d during the flood: %d", i, c)
		}
	}
	close(h.release)
	wg.Wait()
	if passed.Load() != 2 || e.hits.Load() != 2+6 {
		t.Fatalf("passed %d, backend hits %d", passed.Load(), e.hits.Load())
	}
	if st := e.g.EvalStats(); st.InFlight != 0 || st.MemInUse != 0 {
		t.Fatalf("not released: %+v", st)
	}
}

// Security audit 2026-11-05: a long path costs CRS time like a long query
// but counted as cheap, so one client held every slot, the reserved ones
// too, and other visitors got 503. A long request target is expensive now:
// the client gets its share and ordinary GETs keep being answered.
func TestLongPathFloodKeepsOrdinaryGETsAnswered(t *testing.T) {
	wallClock(t)
	e := newEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.EvalTimeout = time.Minute
	e.g.SetSettings(s)
	e.g.SetEvalLimits(EvalLimits{MaxConcurrent: 4, MaxHeavy: 2, PerClient: 2, QueueWait: 20 * time.Millisecond})
	h := newHolder("headers")
	var headers atomic.Int64
	e.g.TestHook = func(p string) {
		if p == "headers" && headers.Add(1) > 2 {
			p = "passthrough" // hold the two long paths that got a slot
		}
		h.hook(p)
	}
	path := "/kategorie/" + strings.Repeat("schuhe-herren/", 600) // 8 KiB, under the hard limit
	const flood = 6
	var wg sync.WaitGroup
	var busy atomic.Int64
	for range flood {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.sendFrom("198.51.100.7", "GET", path, "", "", nil) == 503 {
				busy.Add(1)
			}
		}()
	}
	<-h.entered
	<-h.entered
	waitFor(t, "long paths beyond the client's share answered", func() bool { return busy.Load() == flood-2 })
	for i := range 6 {
		if c := e.sendFrom(fmt.Sprintf("203.0.113.%d", 20+i), "GET", "/page?id=7", "", "", nil); c != 200 {
			t.Fatalf("ordinary GET %d during the flood: %d", i, c)
		}
	}
	close(h.release)
	wg.Wait()
	if e.hits.Load() != 2+6 {
		t.Fatalf("backend hits %d", e.hits.Load())
	}
}

// Rotating /64s inside one /48 does not collect a share per /64 (security
// review 2.3); another /48 and a shared address class are not affected.
func TestIPv6NetShare(t *testing.T) {
	p := newEvalPool(EvalLimits{MaxConcurrent: 64, MaxHeavy: 32, PerClient: 2, QueueWait: time.Millisecond})
	limit := config.NetEvalShare(32)
	var rel []func()
	defer func() {
		for _, r := range rel {
			r()
		}
	}()
	addr := func(net, i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("2001:db8:%x:%x::1", net, i)) }
	heavy := func(a netip.Addr, shared bool) Cost {
		return Cost{Heavy: true, Mem: 1 << 20, Client: clientKey(a), Net: netKey(a), Shared: shared}
	}
	for i := range limit {
		r, ok := p.acquire(heavy(addr(1, i), false))
		if !ok {
			t.Fatalf("evaluation %d refused", i)
		}
		rel = append(rel, r)
	}
	if _, ok := p.acquire(heavy(addr(1, limit), false)); ok {
		t.Fatal("a further /64 of the same /48 got past the /48 share")
	}
	if r, ok := p.acquire(heavy(addr(2, 0), false)); !ok {
		t.Fatal("another /48 refused")
	} else {
		rel = append(rel, r)
	}
	if r, ok := p.acquire(heavy(addr(1, limit+1), true)); !ok {
		t.Fatal("mobile address under the /48 refused")
	} else {
		rel = append(rel, r)
	}
	if netKey(netip.MustParseAddr("203.0.113.7")) != "" {
		t.Fatal("IPv4 has no /48 key")
	}
}

// D43, MVP-26 finding 3: the /48 cap binds with the limits the gateway really
// derives from its slot count, where one /48 used to fill every expensive
// slot, and leaves the other half to everybody else. No PerClient by hand.
func TestIPv6NetShareBindsAtRealSlotCounts(t *testing.T) {
	addr := func(net, i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("2001:db8:%x:%x::1", net, i)) }
	heavy := func(a netip.Addr, shared bool) Cost {
		return Cost{Heavy: true, Mem: 1 << 10, Client: clientKey(a), Net: netKey(a), Shared: shared}
	}
	for _, slots := range []int{2, 3, 4, 8, 12, 16, 18, 24, 32, 64, 128, 1024} {
		t.Run(fmt.Sprint(slots), func(t *testing.T) {
			lim := EvalLimits{MaxConcurrent: slots, QueueWait: time.Millisecond}.norm()
			p := newEvalPool(lim)
			var rel []func()
			defer func() {
				for _, r := range rel {
					r()
				}
			}()
			got := 0
			for i := range lim.MaxHeavy + 8 {
				if r, ok := p.acquire(heavy(addr(1, i), false)); ok {
					rel = append(rel, r)
					got++
				}
			}
			want := config.NetEvalShare(lim.MaxHeavy)
			if got != want {
				t.Fatalf("MaxHeavy %d: one /48 got %d expensive evaluations, want %d", lim.MaxHeavy, got, want)
			}
			if lim.MaxHeavy > 1 && got >= lim.MaxHeavy {
				t.Fatalf("one /48 holds every one of the %d expensive slots", lim.MaxHeavy)
			}
			// Every other /48 together gets the rest.
			for i := range lim.MaxHeavy - got {
				r, ok := p.acquire(heavy(addr(2+i, 0), false))
				if !ok {
					t.Fatalf("another /48 refused with %d of %d expensive slots taken", got+i, lim.MaxHeavy)
				}
				rel = append(rel, r)
			}
		})
	}
}

// D43: the exemption stays observable: a carrier's /48 is not capped, one
// mobile address has its own share and many of them fill the expensive slots.
func TestIPv6NetShareExemptsShared(t *testing.T) {
	lim := EvalLimits{MaxConcurrent: 12, QueueWait: time.Millisecond}.norm()
	p := newEvalPool(lim)
	var rel []func()
	defer func() {
		for _, r := range rel {
			r()
		}
	}()
	for i := range lim.MaxHeavy {
		a := netip.MustParseAddr(fmt.Sprintf("2001:db8:1:%x::1", i))
		r, ok := p.acquire(Cost{Heavy: true, Mem: 1 << 10, Client: clientKey(a), Net: netKey(a), Shared: true})
		if !ok {
			t.Fatalf("mobile client %d of %d refused", i, lim.MaxHeavy)
		}
		rel = append(rel, r)
	}
}

// D43: an honest network: several normal clients in one /48 are not hit. Cheap
// requests never touch the share, however many at once, and expensive ones
// that do not overlap never meet it.
func TestIPv6NetShareLeavesAnHonestNetworkAlone(t *testing.T) {
	for _, slots := range []int{4, 8, 12} {
		lim := EvalLimits{MaxConcurrent: slots, QueueWait: 50 * time.Millisecond}.norm()
		p := newEvalPool(lim)
		cost := func(i int, heavy bool) Cost {
			a := netip.MustParseAddr(fmt.Sprintf("2001:db8:1:%x::1", i))
			return Cost{Heavy: heavy, Mem: 1 << 10, Client: clientKey(a), Net: netKey(a)}
		}
		var rel []func()
		for i := range slots {
			r, ok := p.acquire(cost(i, false))
			if !ok {
				t.Fatalf("%d slots: cheap request %d refused", slots, i)
			}
			rel = append(rel, r)
		}
		for _, r := range rel {
			r()
		}
		for i := range 40 {
			r, ok := p.acquire(cost(i, true))
			if !ok {
				t.Fatalf("%d slots: expensive request %d of a quiet /48 refused", slots, i)
			}
			r()
		}
		// As many at once as the share: an office saving a few large forms.
		rel = rel[:0]
		for i := range config.NetEvalShare(lim.MaxHeavy) {
			r, ok := p.acquire(cost(i, true))
			if !ok {
				t.Fatalf("%d slots: overlapping expensive request %d refused", slots, i)
			}
			rel = append(rel, r)
		}
		for _, r := range rel {
			r()
		}
		if p.busy.Load() != 0 {
			t.Fatalf("%d slots: %d refused", slots, p.busy.Load())
		}
	}
}

// One client cannot hold more than its share of the expensive slots; a
// cgnat or mobile address (many people) gets SharedFactor times as much.
func TestPerClientShare(t *testing.T) {
	p := newEvalPool(EvalLimits{MaxConcurrent: 32, MaxHeavy: 12, PerClient: 2, QueueWait: time.Millisecond})
	heavy := func(client string, shared bool) Cost {
		return Cost{Heavy: true, Mem: 1 << 20, Client: client, Shared: shared}
	}
	var rel []func()
	for range 2 {
		r, ok := p.acquire(heavy("198.51.100.7", false))
		if !ok {
			t.Fatal("first two expensive evaluations of a client refused")
		}
		rel = append(rel, r)
	}
	if _, ok := p.acquire(heavy("198.51.100.7", false)); ok {
		t.Fatal("third expensive evaluation of one client admitted")
	}
	if p.clientBusy.Load() != 1 {
		t.Fatalf("client busy %d", p.clientBusy.Load())
	}
	// Other clients and cheap requests of the same client are not affected.
	if r, ok := p.acquire(heavy("198.51.100.8", false)); !ok {
		t.Fatal("another client refused")
	} else {
		rel = append(rel, r)
	}
	if r, ok := p.acquire(Cost{Mem: 1 << 20, Client: "198.51.100.7"}); !ok {
		t.Fatal("cheap request of the client refused")
	} else {
		rel = append(rel, r)
	}
	n := 0
	for {
		r, ok := p.acquire(heavy("100.64.12.34", true))
		if !ok {
			break
		}
		rel = append(rel, r)
		n++
	}
	if n != 2*SharedFactor {
		t.Fatalf("cgnat address got %d expensive evaluations, want %d", n, 2*SharedFactor)
	}
	for _, r := range rel {
		r()
	}
	if r, ok := p.acquire(heavy("198.51.100.7", false)); !ok {
		t.Fatal("share not released")
	} else {
		r()
	}
	if len(p.clients) != 0 || p.inFlight.Load() != 0 {
		t.Fatalf("leak: clients %v in flight %d", p.clients, p.inFlight.Load())
	}
}

// The memory budget bounds expensive evaluations whatever the slot count.
func TestMemoryBudgetBoundsExpensiveEvaluations(t *testing.T) {
	p := newEvalPool(EvalLimits{MaxConcurrent: 64, MaxHeavy: 32, PerClient: 64, MemBudget: 100 << 20, QueueWait: time.Millisecond})
	c := Cost{Heavy: true, Mem: 30 << 20}
	var rel []func()
	for range 3 {
		r, ok := p.acquire(c)
		if !ok {
			t.Fatal("within the budget refused")
		}
		rel = append(rel, r)
	}
	if _, ok := p.acquire(c); ok {
		t.Fatal("over the memory budget admitted")
	}
	if p.memInUse.Load() != 90<<20 {
		t.Fatalf("mem in use %d", p.memInUse.Load())
	}
	// Cheap evaluations do not count against the budget.
	if r, ok := p.acquire(Cost{Mem: 4 << 20}); !ok {
		t.Fatal("cheap evaluation refused while the budget is used")
	} else {
		r()
	}
	// One evaluation larger than the whole budget runs alone.
	for _, r := range rel {
		r()
	}
	big, ok := p.acquire(Cost{Heavy: true, Mem: 500 << 20})
	if !ok {
		t.Fatal("evaluation larger than the budget refused when alone")
	}
	if _, ok := p.acquire(c); ok {
		t.Fatal("admitted next to an evaluation that uses the whole budget")
	}
	big()
	if p.memInUse.Load() != 0 {
		t.Fatalf("mem in use %d after release", p.memInUse.Load())
	}
}

// Memory under a many-argument flood at small scale: with a budget for two
// evaluations, a flood of 12 holds at most two transactions at their peak
// (all transformed values cached), and the live heap grows by about two
// evaluations, not twelve.
func TestManyArgsFloodMemoryBound(t *testing.T) {
	wallClock(t)
	e := newEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.EvalTimeout = time.Minute
	s.Limits.Args = 1000
	e.g.SetSettings(s)
	query := manyArgs(400)
	cost := e.g.EvalLimits().Estimate(Shape{QueryArgs: waf.QueryArgs(query), QueryBytes: len(query)})
	e.g.SetEvalLimits(EvalLimits{MaxConcurrent: 16, MaxHeavy: 8, PerClient: 16, MemBudget: 2*cost.Mem + cost.Mem/2, QueueWait: 20 * time.Millisecond})
	// Hold after phase 2, when the transaction holds the most.
	h := newHolder("body-done")
	e.g.TestHook = h.hook
	// One unheld evaluation first, so pools and caches exist before the baseline.
	go func() { <-h.entered; h.release <- struct{}{} }()
	if c := e.sendFrom("198.51.100.1", "GET", "/search?"+query, "", "", nil); c != 200 {
		t.Fatalf("warm-up: %d", c)
	}
	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	const flood = 12
	var wg sync.WaitGroup
	var busy atomic.Int64
	for i := range flood {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.sendFrom(fmt.Sprintf("198.51.100.%d", 10+i), "GET", "/search?"+query, "", "", nil) == 503 {
				busy.Add(1)
			}
		}()
	}
	<-h.entered
	<-h.entered
	waitFor(t, "flood beyond the memory budget answered", func() bool { return busy.Load() == flood-2 })
	st := e.g.EvalStats()
	if st.HeavyInFlight != 2 || st.MemInUse > e.g.EvalLimits().MemBudget {
		t.Fatalf("held %d, mem %d of %d", st.HeavyInFlight, st.MemInUse, e.g.EvalLimits().MemBudget)
	}
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	grown := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	if grown > 2*cost.Mem {
		t.Fatalf("live heap grew by %d MiB with 2 evaluations held, estimate %d MiB each", grown>>20, cost.Mem>>20)
	}
	t.Logf("live heap +%d MiB with 2 of %d held (estimate %d MiB each)", grown>>20, flood, cost.Mem>>20)
	close(h.release)
	wg.Wait()
	if st := e.g.EvalStats(); st.InFlight != 0 || st.MemInUse != 0 {
		t.Fatalf("not released: %+v", st)
	}
}

// MVP-19 re-measurement, finding 4: a text body gets an allowance on top of
// eval_timeout, so a large harmless form is inspected instead of answered
// 503 every time; capped at MaxBudget.
func TestBodyBudget(t *testing.T) {
	l := EvalLimits{BodyAllowance: 4 * time.Millisecond, MaxBudget: 10 * time.Second}.norm()
	base := time.Second
	cases := []struct {
		s    Shape
		want time.Duration
	}{
		{Shape{}, base},
		{Shape{QueryArgs: 990, QueryBytes: 60 << 10}, base},
		{Shape{Body: waf.BodyInfo{Bytes: 388 << 10, Args: 1}}, base + 388*4*time.Millisecond},
		{Shape{Body: waf.BodyInfo{Bytes: 5 << 20, Args: 3, Files: true}}, base},
		{Shape{Body: waf.BodyInfo{Bytes: 13 << 20, Args: 1}}, 10 * time.Second},
	}
	for _, tc := range cases {
		if got := bodyBudget(l, base, tc.s); got != tc.want {
			t.Errorf("%+v: %v, want %v", tc.s, got, tc.want)
		}
	}
	if got := bodyBudget(l, 20*time.Second, Shape{Body: waf.BodyInfo{Bytes: 1 << 10}}); got != 20*time.Second {
		t.Errorf("never below eval_timeout: %v", got)
	}
}

func TestLargeFormWithinBodyAllowance(t *testing.T) {
	wallClock(t)
	e := newEnv(t, decide.ModeObserve)
	s := e.g.Settings()
	s.EvalTimeout = 20 * time.Millisecond
	e.g.SetSettings(s)
	e.g.SetEvalLimits(EvalLimits{MaxConcurrent: 2, BodyAllowance: time.Second, QueueWait: time.Second})
	h := newHolder("body")
	e.g.TestHook = h.hook
	code := make(chan int, 1)
	go func() {
		code <- e.sendFrom("198.51.100.5", "POST", "/contact", "application/x-www-form-urlencoded", form(40<<10), nil)
	}()
	<-h.entered
	time.Sleep(100 * time.Millisecond) // well past eval_timeout, far below the allowance (40 s)
	close(h.release)
	if c := <-code; c != 200 {
		t.Fatalf("large form: %d, want 200", c)
	}
	if e.hits.Load() != 1 {
		t.Fatalf("backend hits %d", e.hits.Load())
	}
}
