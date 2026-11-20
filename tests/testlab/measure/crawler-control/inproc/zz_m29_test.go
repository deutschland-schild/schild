//go:build spec29measure

// TEST ONLY: MVP-29 measurement, in-process. Copied into a scratch copy of client/internal/gate (never into the product
// tree) and run with -tags spec29measure. Measures what crawler control adds to a whole gate request (Serve with a
// trivial next handler), allocations per request with and without a policy, the UA-cache miss path, the gate without
// a monitor (monitoring.enabled false), and policy swaps under concurrent requests (run with -race).
package gate

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cc "github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
	"github.com/deutschland-schild/schild/gateway/internal/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
)

var m29Next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

func m29Req(ua, ip string) *http.Request {
	r := httptest.NewRequest("GET", "http://shop.example/blog/hallo", nil)
	r.Host = "shop.example"
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("X-Forwarded-For", ip)
	return r
}

func m29Serve(g *Gate, ua, ip string) int {
	w := httptest.NewRecorder()
	g.Serve(w, m29Req(ua, ip), m29Next)
	return w.Code
}

type m29Variant struct {
	name, ua, ip string
	setup        func(e *tenv, c *crawlers.Control)
}

func m29Policy(c *crawlers.Control, site string) {
	st := crawlers.NewState()
	st.Entries[site] = &crawlers.Entry{Policy: cc.Policy{Categories: map[string]string{"ai_training": cc.Block}, Impersonators: cc.Block}}
	c.Set(st)
}

func m29Variants() []m29Variant {
	off := func(e *tenv, c *crawlers.Control) { e.g.Crawlers = nil }
	empty := func(e *tenv, c *crawlers.Control) { c.Set(crawlers.NewState()) }
	other := func(e *tenv, c *crawlers.Control) { m29Policy(c, "other.example") }
	on := func(e *tenv, c *crawlers.Control) { m29Policy(c, "shop.example") }
	return []m29Variant{
		{"browser/feature-off", uaFirefox, otherIP, off},
		{"browser/no-policy", uaFirefox, otherIP, empty},
		{"browser/policy-other-site", uaFirefox, otherIP, other},
		{"browser/policy", uaFirefox, otherIP, on},
		{"googlebot-verified/feature-off", uaGooglebot, googleIP, off},
		{"googlebot-verified/policy", uaGooglebot, googleIP, on},
		{"gptbot/feature-off(passes)", uaGPTBot, otherIP, off},
		{"gptbot/policy(blocked)", uaGPTBot, otherIP, on},
	}
}

// TestM29Allocs: allocations of one whole gate request per variant.
func TestM29Allocs(t *testing.T) {
	for _, v := range m29Variants() {
		e, c, m := crawlerEnv(t, decide.ModeAutoblock, nil)
		v.setup(e, c)
		m.BotID(v.ua)
		for i := 0; i < 50; i++ {
			m29Serve(e.g, v.ua, v.ip)
		}
		n := testing.AllocsPerRun(2000, func() { m29Serve(e.g, v.ua, v.ip) })
		fmt.Printf("ALLOCS\t%s\t%.2f\tstatus %d\n", v.name, n, m29Serve(e.g, v.ua, v.ip))
	}
}

// TestM29Cost: ns per whole gate request per variant, interleaved rounds (M29_ROUNDS, default 8).
func TestM29Cost(t *testing.T) {
	rounds := 8
	if s := os.Getenv("M29_ROUNDS"); s != "" {
		rounds, _ = strconv.Atoi(s)
	}
	vs := m29Variants()
	envs := make([]*tenv, len(vs))
	for i, v := range vs {
		e, c, m := crawlerEnv(t, decide.ModeAutoblock, nil)
		v.setup(e, c)
		m.BotID(v.ua)
		envs[i] = e
	}
	res := map[string][]float64{}
	for r := 0; r < rounds; r++ {
		for i, v := range vs {
			g := envs[i].g
			b := testing.Benchmark(func(b *testing.B) {
				for j := 0; j < b.N; j++ {
					m29Serve(g, v.ua, v.ip)
				}
			})
			res[v.name] = append(res[v.name], float64(b.NsPerOp()))
		}
	}
	for _, v := range vs {
		x := res[v.name]
		sort.Float64s(x)
		mean, sd := m29Stats(x)
		fmt.Printf("COST\t%s\tmedian %.0f ns\tmean %.0f ns\tsd %.0f ns\tmin %.0f\tmax %.0f\tn %d\n", v.name, x[len(x)/2], mean, sd, x[0], x[len(x)-1], len(x))
	}
}

func m29Stats(x []float64) (float64, float64) {
	var s, q float64
	for _, v := range x {
		s += v
	}
	m := s / float64(len(x))
	for _, v := range x {
		q += (v - m) * (v - m)
	}
	return m, math.Sqrt(q / float64(len(x)-1))
}

// BenchmarkM29BotIDMiss: the check crawlerStop makes on a website with a policy when the user agent is not in the UA
// cache (65536 distinct agents cycled through 4096 slots), when it is, and without a monitor (monitoring.enabled
// false: the shipped catalogue is scanned every time).
func BenchmarkM29BotIDMiss(b *testing.B) {
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
	m29Policy(c, "shop.example")
	uas := make([]string, 65536)
	for i := range uas {
		uas[i] = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131." + strconv.Itoa(i)
	}
	long := make([]string, 16384)
	for i := range long {
		long[i] = uaGPTBot + " pad" + strconv.Itoa(i) + " " + strings.Repeat("x", 300)
	}
	a := netip.MustParseAddr(otherIP)
	b.Run("miss-browser", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if t := c.Lookup("shop.example"); t != nil {
				_ = t.Rule(m.BotID(uas[i&65535]), a)
			}
		}
	})
	b.Run("miss-gptbot-400B", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if t := c.Lookup("shop.example"); t != nil {
				_ = t.Rule(m.BotID(long[i%len(long)]), a)
			}
		}
	})
	b.Run("hit-browser", func(b *testing.B) {
		m.BotID(uaFirefox)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if t := c.Lookup("shop.example"); t != nil {
				_ = t.Rule(m.BotID(uaFirefox), a)
			}
		}
	})
	b.Run("no-monitor-browser", func(b *testing.B) {
		var nm *monitoring.Monitor
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if t := c.Lookup("shop.example"); t != nil {
				_ = t.Rule(nm.BotID(uaFirefox), a)
			}
		}
	})
}

// TestM29NoMonitor: a gate without a monitor (monitoring.enabled false) still applies the policy, with the shipped
// catalogue. Allocations of the check then.
func TestM29NoMonitor(t *testing.T) {
	e, c, _ := crawlerEnv(t, decide.ModeAutoblock, nil)
	m29Policy(c, "shop.example")
	e.g.Monitor = nil
	for _, x := range []struct{ ua, ip string }{{uaGPTBot, otherIP}, {uaFirefox, otherIP}, {uaGooglebot, otherIP}, {uaGooglebot, googleIP}} {
		code := m29Serve(e.g, x.ua, x.ip)
		n := testing.AllocsPerRun(500, func() {
			_ = c.Lookup("shop.example").Rule(e.g.Monitor.BotID(x.ua), netip.MustParseAddr(x.ip))
		})
		fmt.Printf("NOMONITOR\t%q from %s\tstatus %d\tcheck allocs %.1f\n", x.ua[:30], x.ip, code, n)
	}
}

// TestM29SwapUnderLoad: requests on 8 goroutines while the policy flips 20,000 times; a browser is never blocked and
// GPTBot is always answered by one of the two policies. Run with -race.
func TestM29SwapUnderLoad(t *testing.T) {
	e, c, _ := crawlerEnv(t, decide.ModeAutoblock, nil)
	on := crawlers.NewState()
	on.Entries["shop.example"] = &crawlers.Entry{Policy: cc.Policy{Categories: map[string]string{"ai_training": cc.Block}}}
	off := crawlers.NewState()
	var stop atomic.Bool
	var browserBlocked, gptBlocked, gptPassed, other atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				if i%2 == 0 {
					if m29Serve(e.g, uaFirefox, otherIP) == 403 {
						browserBlocked.Add(1)
					}
					continue
				}
				switch m29Serve(e.g, uaGPTBot, otherIP) {
				case 403:
					gptBlocked.Add(1)
				case 200:
					gptPassed.Add(1)
				default:
					other.Add(1)
				}
			}
		}(w)
	}
	for i := 0; i < 20000; i++ {
		if i%2 == 0 {
			c.Set(on)
		} else {
			c.Set(off)
		}
	}
	stop.Store(true)
	wg.Wait()
	fmt.Printf("SWAP\tflips 20000\tbrowser blocked %d\tgptbot blocked %d passed %d other %d\n", browserBlocked.Load(), gptBlocked.Load(), gptPassed.Load(), other.Load())
	if browserBlocked.Load() != 0 || other.Load() != 0 {
		t.Fatal("browser blocked or unexpected status under swaps")
	}
}

// TestM29AllocsPaired: one gate, events off (no background writer), the crawler control switched between nil, no
// policy for this website and a policy for it, interleaved six times, so drift and background work hit every variant.
func TestM29AllocsPaired(t *testing.T) {
	e, c, m := crawlerEnv(t, decide.ModeAutoblock, nil)
	e.g.Events = nil
	type v struct {
		name, ua, ip string
		set          func()
	}
	off := func() { e.g.Crawlers = nil }
	none := func() { e.g.Crawlers = c; c.Set(crawlers.NewState()) }
	other := func() { e.g.Crawlers = c; m29Policy(c, "other.example") }
	on := func() { e.g.Crawlers = c; m29Policy(c, "shop.example") }
	vs := []v{{"browser/feature-off", uaFirefox, otherIP, off}, {"browser/no-policy", uaFirefox, otherIP, none},
		{"browser/policy-other-site", uaFirefox, otherIP, other}, {"browser/policy", uaFirefox, otherIP, on},
		{"googlebot-verified/feature-off", uaGooglebot, googleIP, off}, {"googlebot-verified/policy", uaGooglebot, googleIP, on}}
	res := map[string][]float64{}
	for r := 0; r < 6; r++ {
		for _, x := range vs {
			x.set()
			m.BotID(x.ua)
			for i := 0; i < 20; i++ {
				m29Serve(e.g, x.ua, x.ip)
			}
			res[x.name] = append(res[x.name], testing.AllocsPerRun(3000, func() { m29Serve(e.g, x.ua, x.ip) }))
		}
	}
	for _, x := range vs {
		fmt.Printf("ALLOCSPAIRED\t%s\t%v\n", x.name, res[x.name])
	}
}
