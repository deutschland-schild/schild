package gate

import (
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cc "github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
	"github.com/deutschland-schild/schild/gateway/internal/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// D57 (MVP-29): crawler control in the gate.

const (
	uaGPTBot    = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"
	uaGooglebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	uaFirefox   = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
	// googleIP is inside the shipped Googlebot ranges, otherIP outside.
	googleIP = "66.249.66.1"
	otherIP  = "203.0.113.50"
)

// crawlerClock is inside the 30 days of the shipped range snapshot, so the
// impersonator tests do not depend on the day they run.
var crawlerClock = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// crawlerEnv is a gate in mode with a monitor and the crawler policy p on
// shop.example (nil: no policy at all).
func crawlerEnv(t *testing.T, mode string, p *cc.Policy) (*tenv, *crawlers.Control, *monitoring.Monitor) {
	t.Helper()
	e := newEnv(t, mode)
	e.g.siteID = func(string) string { return "shop.example" }
	eng, err := bots.New(config.Bots{}, func() time.Time { return crawlerClock })
	if err != nil {
		t.Fatal(err)
	}
	m, err := monitoring.New(monitoring.Config{StoragePath: t.TempDir(), Log: quiet}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	m.UseBots(eng)
	e.g.Monitor = m
	c := crawlers.New(eng, time.Now())
	if p != nil {
		st := crawlers.NewState()
		st.Entries["shop.example"] = &crawlers.Entry{Policy: *p, Actor: cc.ActorDashboard}
		if unk := c.Set(st); len(unk) > 0 {
			t.Fatalf("unknown bots %v", unk)
		}
	}
	e.g.Crawlers = c
	return e, c, m
}

func crawlerReq(e *tenv, t *testing.T, ua, ip string) *http.Response {
	t.Helper()
	return e.do(t, "GET", "/blog/hallo", "", "", map[string]string{"User-Agent": ua, "X-Forwarded-For": ip})
}

func blockTraining() *cc.Policy {
	return &cc.Policy{Categories: map[string]string{"ai_training": cc.Block}}
}

func TestCrawlerBlockedInAutoblock(t *testing.T) {
	e, c, m := crawlerEnv(t, decide.ModeAutoblock, blockTraining())
	r := crawlerReq(e, t, uaGPTBot, otherIP)
	if r.StatusCode != 403 || r.Header.Get("X-Test-Body") != crawlerBody || r.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("gptbot: %d %q %v", r.StatusCode, r.Header.Get("X-Test-Body"), r.Header)
	}
	if n := e.hits.Load(); n != 0 {
		t.Fatalf("%d requests reached the app", n)
	}
	// Browsers and other categories pass.
	for _, ua := range []string{uaFirefox, uaGooglebot, "", "curl/8.5.0", "Mozilla/5.0 (compatible; UnknownCrawler/1.0)"} {
		if r := crawlerReq(e, t, ua, otherIP); r.StatusCode != 200 {
			t.Fatalf("%q: %d", ua, r.StatusCode)
		}
	}
	cnt := liveCounters(t, m)
	if cnt.BlockedCrawler != 1 || cnt.Stopped != 1 || cnt.Detections != 0 || cnt.WouldBlock != 0 || !cnt.Check() {
		t.Fatalf("counters: %+v", cnt)
	}
	got := c.Counts("shop.example")
	if len(got) != 1 || got[0].Bot != c.Engine().ID("gptbot") || got[0].Blocked != 1 || got[0].WouldBlock != 0 {
		t.Fatalf("crawler counts: %+v", got)
	}
	// No incident for a blocked crawler.
	e.g.FlushIncidents(t.Context())
	n, err := e.st.CountIncidents(t.Context(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour), "")
	if err != nil || n != 0 {
		t.Fatalf("%d incidents (%v)", n, err)
	}
}

func TestCrawlerObserveOnlyRecords(t *testing.T) {
	e, c, m := crawlerEnv(t, decide.ModeObserve, blockTraining())
	for i := 0; i < 3; i++ {
		if r := crawlerReq(e, t, uaGPTBot, otherIP); r.StatusCode != 200 {
			t.Fatalf("observe: %d", r.StatusCode)
		}
	}
	if n := e.hits.Load(); n != 3 {
		t.Fatalf("%d requests reached the app", n)
	}
	cnt := liveCounters(t, m)
	if cnt.WouldBlock != 3 || cnt.Forwarded != 3 || cnt.BlockedCrawler != 0 || cnt.Detections != 0 || !cnt.Check() {
		t.Fatalf("counters: %+v", cnt)
	}
	if got := c.Counts("shop.example"); len(got) != 1 || got[0].WouldBlock != 3 || got[0].Blocked != 0 {
		t.Fatalf("crawler counts: %+v", got)
	}
}

func TestCrawlerAllowlistedOnlyRecords(t *testing.T) {
	e, c, _ := crawlerEnv(t, decide.ModeAutoblock, blockTraining())
	e.g.Allow.Set([]store.AllowEntry{{ID: "a", IP: otherIP, Label: "büro", Level: allowlist.NoBlock, Expires: "never"}})
	if r := crawlerReq(e, t, uaGPTBot, otherIP); r.StatusCode != 200 {
		t.Fatalf("allowlisted: %d", r.StatusCode)
	}
	if got := c.Counts("shop.example"); len(got) != 1 || got[0].WouldBlock != 1 {
		t.Fatalf("crawler counts: %+v", got)
	}
}

func TestCrawlerImpersonators(t *testing.T) {
	e, _, _ := crawlerEnv(t, decide.ModeAutoblock, &cc.Policy{Bots: map[string]string{"googlebot": cc.Allow}, Impersonators: cc.Block})
	if r := crawlerReq(e, t, uaGooglebot, otherIP); r.StatusCode != 403 {
		t.Fatalf("impersonator: %d", r.StatusCode)
	}
	if r := crawlerReq(e, t, uaGooglebot, googleIP); r.StatusCode != 200 {
		t.Fatalf("real googlebot: %d", r.StatusCode)
	}
	// A browser is no crawler, also with impersonators block.
	if r := crawlerReq(e, t, uaFirefox, otherIP); r.StatusCode != 200 {
		t.Fatalf("browser: %d", r.StatusCode)
	}
}

func TestCrawlerOverridePrecedence(t *testing.T) {
	e, _, _ := crawlerEnv(t, decide.ModeAutoblock, &cc.Policy{Categories: map[string]string{"ai_training": cc.Block, "search_engine": cc.Allow},
		Bots: map[string]string{"gptbot": cc.Allow, "googlebot": cc.Block}})
	if r := crawlerReq(e, t, uaGPTBot, otherIP); r.StatusCode != 200 {
		t.Fatalf("gptbot allowed by its own rule: %d", r.StatusCode)
	}
	if r := crawlerReq(e, t, "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", otherIP); r.StatusCode != 403 {
		t.Fatalf("claudebot by its category: %d", r.StatusCode)
	}
	if r := crawlerReq(e, t, uaGooglebot, googleIP); r.StatusCode != 403 {
		t.Fatalf("googlebot blocked by its own rule: %d", r.StatusCode)
	}
}

// A website without a policy, or with one that only allows, behaves exactly
// as before: same answers, same counters, same events.
func TestCrawlerDefaultUnchanged(t *testing.T) {
	run := func(p *cc.Policy, with bool) (codes []int, events int, cnt string) {
		e, _, m := crawlerEnv(t, decide.ModeAutoblock, p)
		if !with {
			e.g.Crawlers = nil
		}
		for _, ua := range []string{uaGPTBot, uaGooglebot, uaFirefox, "", "curl/8.5.0"} {
			codes = append(codes, crawlerReq(e, t, ua, otherIP).StatusCode)
			codes = append(codes, e.do(t, "GET", "/blog/hallo"+sqli[1:], "", "", map[string]string{"User-Agent": ua}).StatusCode)
		}
		c := liveCounters(t, m)
		c.BytesIn, c.BytesOut = 0, 0
		return codes, len(e.events(t, store.EventFilter{})), stringOf(c)
	}
	baseCodes, baseEvents, baseCnt := run(nil, false)
	for _, p := range []*cc.Policy{nil, {}, {Categories: map[string]string{"ai_training": cc.Allow}, Bots: map[string]string{"gptbot": cc.Allow}, Impersonators: cc.Allow}} {
		codes, events, cnt := run(p, true)
		if stringOf(codes) != stringOf(baseCodes) || events != baseEvents || cnt != baseCnt {
			t.Fatalf("policy %+v changed the gate:\n%v %d %s\n%v %d %s", p, codes, events, cnt, baseCodes, baseEvents, baseCnt)
		}
	}
}

// A crawler that would only be blocked writes no event of its own: it is
// sampled like an unremarkable request, so a crawler cannot fill the store.
func TestCrawlerWouldBlockSampled(t *testing.T) {
	e, _, _ := crawlerEnv(t, decide.ModeObserve, blockTraining())
	e.g.SetSettings(Settings{Mode: decide.ModeObserve, Limits: e.g.Settings().Limits, EvalTimeout: time.Second, Resolver: e.g.Settings().Resolver,
		EventsPerSecond: -1, SampleRate: 1e-9})
	for i := 0; i < 20; i++ {
		crawlerReq(e, t, uaGPTBot, otherIP)
	}
	for _, ev := range e.events(t, store.EventFilter{}) {
		if ev.Outcome == decide.WouldBlock {
			t.Fatalf("crawler would_block wrote an event: %+v", ev)
		}
	}
}

// With monitoring off the gate takes the bot id from crawler control.
func TestCrawlerWithoutMonitor(t *testing.T) {
	e, c, _ := crawlerEnv(t, decide.ModeAutoblock, &cc.Policy{Categories: map[string]string{"ai_training": cc.Block}, Impersonators: cc.Block})
	e.g.Monitor = nil
	if r := crawlerReq(e, t, uaGPTBot, otherIP); r.StatusCode != 403 {
		t.Fatalf("gptbot: %d", r.StatusCode)
	}
	if r := crawlerReq(e, t, uaGooglebot, otherIP); r.StatusCode != 403 {
		t.Fatalf("impersonator: %d", r.StatusCode)
	}
	if r := crawlerReq(e, t, uaGooglebot, googleIP); r.StatusCode != 200 {
		t.Fatalf("googlebot: %d", r.StatusCode)
	}
	if r := crawlerReq(e, t, uaFirefox, otherIP); r.StatusCode != 200 {
		t.Fatalf("browser: %d", r.StatusCode)
	}
	a := netip.MustParseAddr(otherIP)
	c.BotID(uaGPTBot)
	if n := testing.AllocsPerRun(200, func() { _ = c.Lookup("shop.example").Rule(c.BotID(uaGPTBot), a) }); n != 0 {
		t.Fatalf("%.1f allocations", n)
	}
}

func TestCrawlerHeadNoBody(t *testing.T) {
	e, _, _ := crawlerEnv(t, decide.ModeAutoblock, blockTraining())
	r := e.do(t, "HEAD", "/", "", "", map[string]string{"User-Agent": uaGPTBot, "X-Forwarded-For": otherIP})
	if r.StatusCode != 403 || r.Header.Get("X-Test-Body") != "" {
		t.Fatalf("HEAD: %d %q", r.StatusCode, r.Header.Get("X-Test-Body"))
	}
}

// The request path: Lookup, BotID and Rule do not allocate.
func TestCrawlerHotPathNoAlloc(t *testing.T) {
	_, c, m := crawlerEnv(t, decide.ModeAutoblock, &cc.Policy{Categories: map[string]string{"ai_training": cc.Block}, Impersonators: cc.Block})
	a := netip.MustParseAddr(otherIP)
	for _, ua := range []string{uaGPTBot, uaGooglebot, uaFirefox} {
		m.BotID(ua) // fill the UA cache
		n := testing.AllocsPerRun(200, func() {
			t := c.Lookup("shop.example")
			_ = t.Rule(m.BotID(ua), a)
			_ = c.Lookup("other.example")
		})
		if n != 0 {
			t.Fatalf("%q: %.1f allocations", ua, n)
		}
	}
}

// BenchmarkCrawlerCheck is the work crawlerStop adds to a request of a
// website with a policy: the table lookup, the bot id from the UA cache and
// the rule (with the impersonator check).
func BenchmarkCrawlerCheck(b *testing.B) {
	eng, err := bots.New(config.Bots{}, func() time.Time { return crawlerClock })
	if err != nil {
		b.Fatal(err)
	}
	m, err := monitoring.New(monitoring.Config{StoragePath: b.TempDir(), Log: quiet}, time.Now())
	if err != nil {
		b.Fatal(err)
	}
	defer m.Close()
	m.UseBots(eng)
	c := crawlers.New(eng, time.Now())
	st := crawlers.NewState()
	for _, w := range []string{"shop.example", "blog.example", "verein.example"} {
		st.Entries[w] = &crawlers.Entry{Policy: cc.Policy{Categories: map[string]string{"ai_training": cc.Block}, Impersonators: cc.Block}}
	}
	c.Set(st)
	a := netip.MustParseAddr(otherIP)
	for _, tc := range []struct{ name, ua string }{{"browser", uaFirefox}, {"gptbot", uaGPTBot}, {"googlebot", uaGooglebot}} {
		m.BotID(tc.ua)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if t := c.Lookup("shop.example"); t != nil {
					_ = t.Rule(m.BotID(tc.ua), a)
				}
			}
		})
	}
	// monitoring.enabled false: the bot id comes from the cache of crawler
	// control (measurement 1, finding 2).
	for _, tc := range []struct{ name, ua string }{{"browser", uaFirefox}, {"gptbot", uaGPTBot}, {"googlebot", uaGooglebot}} {
		c.BotID(tc.ua)
		b.Run("no-monitor-"+tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if t := c.Lookup("shop.example"); t != nil {
					_ = t.Rule(c.BotID(tc.ua), a)
				}
			}
		})
	}
	b.Run("no-policy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if t := c.Lookup("other.example"); t != nil {
				_ = t.Rule(m.BotID(uaFirefox), a)
			}
		}
	})
}

func stringOf(v any) string { return fmt.Sprint(v) }
