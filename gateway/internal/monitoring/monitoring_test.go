package monitoring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/schema"
)

// ---------------------------------------------------------------- contract schemas

const apiDoc = "../../../contracts/api/client-dashboard.openapi.yaml"

var (
	compOnce sync.Once
	comp     *jsonschema.Compiler
	compErr  error
)

func validate(t *testing.T, name string, body []byte) {
	t.Helper()
	compOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		for rel, b := range schema.Files() {
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				compErr = err
				return
			}
			if err := c.AddResource(schema.BaseURL+rel, doc); err != nil {
				compErr = err
				return
			}
		}
		b, err := os.ReadFile(apiDoc)
		if err != nil {
			compErr = err
			return
		}
		j, err := config.YAMLToJSON(b)
		if err != nil {
			compErr = err
			return
		}
		doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(j))
		compErr = c.AddResource(schema.BaseURL+"api/client-dashboard.openapi.yaml", doc)
		comp = c
	})
	if compErr != nil {
		t.Skipf("contracts not available: %v", compErr)
	}
	s, err := comp.Compile(schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/" + name)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("%s: not JSON: %s", name, body)
	}
	if err := s.Validate(v); err != nil {
		b := string(body)
		if len(b) > 2000 {
			b = b[:2000]
		}
		t.Errorf("%s does not match the contract: %v\n%s", name, err, b)
	}
}

// ---------------------------------------------------------------- classification

func TestClassifyUA(t *testing.T) {
	cases := []struct {
		ua                      string
		class, br, os, dev, bot int
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36", uaBrowser, brChrome, osWindows, devDesktop, botLikelyBrowser},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", uaBrowser, brSafari, osIOS, devMobile, botLikelyBrowser},
		{"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121 Mobile Safari/537.36", uaBrowser, brSamsung, osAndroid, devMobile, botLikelyBrowser},
		{"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130 Safari/537.36 Edg/130.0", uaBrowser, brEdge, osWindows, devDesktop, botLikelyBrowser},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", uaBotUnverified, brNone, osNone, devUnknown, botSearch},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", uaBotUnverified, brNone, osNone, devUnknown, botAITraining},
		{"Mozilla/5.0 (compatible; Applebot-Extended/0.1)", uaBotUnverified, brNone, osNone, devUnknown, botAITraining},
		{"curl/8.5.0", uaTool, brNone, osNone, devUnknown, botTool},
		{"sqlmap/1.8#stable (https://sqlmap.org)", uaTool, brNone, osNone, devUnknown, botScanner},
		{"", uaNone, brNone, osNone, devUnknown, botLikelyAutomated},
		{"SomeCrawler/1.0", uaBotUnverified, brNone, osNone, devUnknown, botLikelyAutomated},
		{"weird-client", uaOther, brNone, osNone, devUnknown, botLikelyAutomated},
	}
	for _, c := range cases {
		got := classifyUA(c.ua)
		want := uaInfo{c.class, c.br, c.os, c.dev, c.bot, got.id} // the entry itself: TestClassifyUAMatchesReference
		if got != want || (got.id != 0) != (c.bot < botLikelyAutomated) {
			t.Errorf("%q: got %+v, want %+v", c.ua, got, want)
		}
	}
}

func TestReferrerKey(t *testing.T) {
	cases := []struct{ ref, host, key, label string }{
		{"", "verein.example", "_direct", ""},
		{"https://www.google.com/search?q=x", "verein.example", "google.com", ""},
		{"https://news.bbc.co.uk/a", "verein.example", "bbc.co.uk", ""},
		{"https://chatgpt.com/c/123", "verein.example", "ai:chatgpt", "ChatGPT"},
		{"https://www.perplexity.ai/", "verein.example", "ai:perplexity", "Perplexity"},
		{"https://verein.example/kontakt", "verein.example:443", "_intern", ""},
		{"https://www.verein.example/", "verein.example", "_intern", ""},
		{"http://203.0.113.7/x", "verein.example", "_other", ""},
		{"http://[2001:db8::1]/", "verein.example", "_other", ""},
		{"not a url", "verein.example", "_other", ""},
		{"http://localhost:8080/", "verein.example", "_other", ""},
		{"https://User@WWW.Example.ORG:8443/p", "verein.example", "example.org", ""},
	}
	for _, c := range cases {
		var d domainCache
		d.init()
		k, l := referrerKey(c.ref, c.host, d.registrable, nil)
		if k != c.key || l != c.label {
			t.Errorf("%q: got %q %q, want %q %q", c.ref, k, l, c.key, c.label)
		}
		if !cm.ValidReferrerKey(k) {
			t.Errorf("%q: %q is not a ReferrerKey", c.ref, k)
		}
	}
}

func TestSketches(t *testing.T) {
	var h hll
	for i := 0; i < 20000; i++ {
		h.add(splitmix(uint64(i)))
	}
	if e := h.estimate(); e < 19000 || e > 21000 {
		t.Errorf("hll estimate %d for 20000", e)
	}
	tt := newTopTable(4)
	for i, k := range []string{"/a", "/a", "/a", "/b", "/b", "/c", "/d"} {
		tt.add(k, "", 1, 0, 0, int64(i%2), 0)
	}
	tt.add("/e", "", 1, 0, 0, 0, 0) // evicts the smallest (count 1) and inherits it
	top := tt.top(10, true)
	if top[0].Key != "/a" || top[0].Requests != 3 || top[0].Error != 0 {
		t.Errorf("top %+v", top)
	}
	for _, e := range top {
		if e.Key == "/e" && (e.Requests != 2 || e.Error != 1) {
			t.Errorf("evicted entry %+v", e)
		}
	}
	f := newSeenFilter(100)
	if f.seen(42) || !f.seen(42) {
		t.Error("seen filter: first sight must be new, second not")
	}
	f.rotate(108)
	if f.seen(42) {
		t.Error("seen filter must forget after seven days")
	}
}

// The monitor moves the seen filter on with the UTC day: a client seen
// once is new again after seven days.
func TestSeenFilterRotatesWithTick(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	m := newTestMonitor(t, now)
	if m.rec.seen.seen(42) {
		t.Fatal("first sight must be new")
	}
	for d := 1; d <= 8; d++ {
		m.Tick(now.Add(time.Duration(d) * 24 * time.Hour))
	}
	if got, want := m.rec.seen.cur.Load(), now.Add(8*24*time.Hour).Unix()/86400; got != want {
		t.Fatalf("seen filter at day %d, want %d", got, want)
	}
	if m.rec.seen.seen(42) {
		t.Error("a client seen eight days ago must be new again")
	}
}

// Snapshots before the first host sample sample on the caller's goroutine;
// concurrent callers must not share the sampler's state unguarded (-race).
func TestSnapshotConcurrentFirstSample(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	m := newTestMonitor(t, now)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.Snapshot(now)
		}()
	}
	wg.Wait()
}

func splitmix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// ---------------------------------------------------------------- request path

func newReq(path, ua, ref string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://verein.example"+path, nil)
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Referer", ref)
	r.Header.Set("Sec-Fetch-Dest", "document")
	return r
}

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"

func TestRecordDoesNotAllocate(t *testing.T) {
	rc := newRecorder(time.Now())
	r := newReq("/blog/my-post", chromeUA, "https://www.google.com/search")
	q := Req{R: r, Class: Forwarded, Status: 200, Timed: true, Total: 3 * time.Millisecond, UpstreamDur: 2 * time.Millisecond,
		Client: netip.MustParseAddr("192.0.2.10"), Country: "DE", ASN: 3320, ASOrg: "Deutsche Telekom", NetClass: "residential"}
	for i := 0; i < len(rc.shards)*2; i++ {
		rc.record(&q) // warm every shard's top tables
	}
	if n := testing.AllocsPerRun(1000, func() { rc.record(&q) }); n != 0 {
		t.Errorf("Record allocates %.1f times per request", n)
	}
}

// ---------------------------------------------------------------- monitor

func newTestMonitor(t *testing.T, now time.Time) *Monitor {
	t.Helper()
	m, err := New(Config{StoragePath: t.TempDir(), Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
		Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: now, Version: "test"},
		Internals: func(bool) Internals {
			return Internals{EventQueueUsed: 3, EventQueueCapacity: 8192, EvalSlotsUsed: 1, EvalSlotsMax: 16, StoreBytes: 1 << 20, StoreMaxBytes: 500 << 20}
		},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// traffic records a known mix: per call 10 forwarded (2 would_block), 3 WAF
// blocks, 1 rate limit, 1 hard limit, 1 waf_busy.
func traffic(m *Monitor) {
	ip := netip.MustParseAddr("198.51.100.4")
	for i := 0; i < 10; i++ {
		q := Req{R: newReq(fmt.Sprintf("/termine/%d", i), chromeUA, ""), Class: Forwarded, Status: 200, Timed: true, Total: 40 * time.Millisecond,
			UpstreamDur: 39 * time.Millisecond, Client: ip, Country: "DE", ASN: 3320, ASOrg: "Deutsche Telekom", NetClass: "residential", BytesOut: 1000}
		if i < 2 {
			q.WouldBlock, q.Detection, q.Rules = true, true, []string{"942100"}
		}
		m.Record(&q)
	}
	for i := 0; i < 3; i++ {
		m.Record(&Req{R: newReq("/wp-login.php", "sqlmap/1.8", ""), Class: BlockedWAF, Status: 403, Detection: true, Rules: []string{"913100", "930120"},
			Client: netip.MustParseAddr("203.0.113.9"), Country: "NL", ASN: 24940, ASOrg: "Hetzner Online", NetClass: "hosting", Timed: true, Total: time.Millisecond})
	}
	m.Record(&Req{R: newReq("/api/x", "curl/8", ""), Class: RateLimited, Status: 429, Country: "US", NetClass: "hosting"})
	m.Record(&Req{R: newReq("/upload", "curl/8", ""), Class: RejectedLimit, Status: 413, Country: "US", NetClass: "hosting"})
	m.Record(&Req{R: newReq("/", chromeUA, ""), Class: FailBusy, Status: 503, Country: "DE", NetClass: "residential"})
}

func TestMonitorCountsExactlyAndServesTheContract(t *testing.T) {
	now := time.Now().UTC().Truncate(10 * time.Minute).Add(-30 * time.Minute)
	m := newTestMonitor(t, now.Add(-time.Second))
	m.Sample(now.Add(-5 * time.Second))
	// 20 minutes of seconds, traffic in every 10th second.
	for s := 1; s <= 1200; s++ {
		at := now.Add(time.Duration(s) * time.Second)
		m.flushWrites()
		if s%10 == 1 {
			traffic(m)
		}
		if s%10 == 5 {
			m.Sample(at)
		}
		m.Tick(at)
	}
	m.flushWrites()
	end := now.Add(1200 * time.Second)

	// Every bucket keeps the invariants; the 1 min buckets add up exactly.
	page, err := m.Buckets("1m", now, "", 500, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 20 {
		t.Fatalf("got %d minute buckets, want 20", len(page.Items))
	}
	var sum cm.TrafficCounters
	for _, b := range page.Items {
		if !b.Traffic.Check() {
			t.Errorf("invariants broken in %s: %+v", b.T, b.Traffic)
		}
		sum.Add(&b.Traffic)
	}
	// 120 traffic calls of 16 requests each.
	if sum.Requests != 120*16 || sum.Forwarded != 1200 || sum.BlockedWAF != 360 || sum.RateLimited != 120 || sum.RejectedLimit != 120 ||
		sum.FailClosedBy.WAFBusy != 120 || sum.WouldBlock != 240 || sum.Detections != 600 || sum.PageViews != 1200 {
		t.Errorf("counters differ from ground truth: %+v", sum)
	}
	body, _ := json.Marshal(page)
	validate(t, "MetricBucketPage", body)

	h := http.NewServeMux()
	m.Routes(func(p string, f http.HandlerFunc) { h.HandleFunc(p, f) }, "/api/v0")
	get := func(path string) (int, []byte) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		return rr.Code, rr.Body.Bytes()
	}
	from := now.Format(time.RFC3339)
	to := end.Format(time.RFC3339)
	for _, c := range []struct{ path, schema string }{
		{"/api/v0/monitoring/now", "MonitoringNow"},
		{"/api/v0/monitoring/server", "ServerSnapshot"},
		{"/api/v0/monitoring/catalogue", "MetricCatalogue"},
		{"/api/v0/monitoring/series?metric=traffic.requests&metric=traffic.latency_total:p95&metric=traffic.clients_unique&metric=server.cpu_usage:max&metric=server.disk_used_ratio&from=" + from + "&to=" + to, "SeriesResult"},
		{"/api/v0/monitoring/traffic/breakdown?by=path&from=" + from + "&to=" + to, "TrafficBreakdown"},
		{"/api/v0/monitoring/traffic/breakdown?by=rule&from=" + from + "&to=" + to, "TrafficBreakdown"},
		{"/api/v0/monitoring/traffic/breakdown?by=country&from=" + from + "&to=" + to, "TrafficBreakdown"},
		{"/api/v0/monitoring/traffic/breakdown?by=bot_category&from=" + from + "&to=" + to, "TrafficBreakdown"},
		{"/api/v0/monitoring/traffic/breakdown?by=status_class&from=" + from + "&to=" + to, "TrafficBreakdown"},
		{"/api/v0/monitoring/traffic/breakdown?by=site&from=" + from + "&to=" + to, "TrafficBreakdown"},
		{"/api/v0/monitoring/buckets?resolution=10s&from=" + from + "&limit=5", "MetricBucketPage"},
	} {
		code, b := get(c.path)
		if code != 200 {
			t.Errorf("%s: %d %s", c.path, code, b)
			continue
		}
		validate(t, c.schema, b)
		if bytes.Contains(b, []byte("198.51.100.4")) || bytes.Contains(b, []byte("203.0.113.9")) || bytes.Contains(b, []byte("198.51.100.")) {
			t.Errorf("%s: an address leaked: %s", c.path, b)
		}
	}
	var bd TrafficBreakdown
	_, b := get("/api/v0/monitoring/traffic/breakdown?by=rule&from=" + from + "&to=" + to)
	_ = json.Unmarshal(b, &bd)
	counts := map[string]int64{}
	for _, it := range bd.Items {
		counts[it.Key] = it.Requests
	}
	if counts["942100"] != 240 || counts["913100"] != 360 || counts["930120"] != 360 {
		t.Errorf("rule detections %+v", counts)
	}
	_, b = get("/api/v0/monitoring/traffic/breakdown?by=path&from=" + from + "&to=" + to)
	_ = json.Unmarshal(b, &bd)
	for _, it := range bd.Items {
		if it.Key == "/wp-login.php" && (it.Requests != 360 || it.Detections != 360 || it.Stopped != 360) {
			t.Errorf("wp-login %+v", it)
		}
		if it.Key == "/termine/{n}" && it.Requests != 1200 {
			t.Errorf("template %+v", it)
		}
	}
	if code, b := get("/api/v0/monitoring/series?metric=traffic.requests&resolution=10s&from=" + now.Add(-6*time.Hour).Format(time.RFC3339) + "&to=" + to); code != 400 || !strings.Contains(string(b), "too_many_points") {
		t.Errorf("too_many_points: %d %s", code, b)
	}
	if code, b := get("/api/v0/monitoring/series?metric=traffic.latency_total:sum"); code != 400 || !strings.Contains(string(b), `"invalid"`) {
		t.Errorf("bad stat: %d %s", code, b)
	}
	if code, _ := get("/api/v0/monitoring/now?site=other"); code != 400 {
		t.Errorf("unknown site: %d", code)
	}
	// Nothing derived from an address in metrics.db.
	raw, _ := os.ReadFile(filepath.Join(m.cfg.StoragePath, "metrics.db"))
	if bytes.Contains(raw, []byte("198.51.100")) || bytes.Contains(raw, []byte("203.0.113")) {
		t.Error("metrics.db contains an address")
	}
}

func TestMonitoringOffAnswers409(t *testing.T) {
	var m *Monitor
	h := http.NewServeMux()
	m.Routes(func(p string, f http.HandlerFunc) { h.HandleFunc(p, f) }, "/agent/v0")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/agent/v0/monitoring/now", nil))
	if rr.Code != 409 || !strings.Contains(rr.Body.String(), "monitoring_off") {
		t.Errorf("got %d %s", rr.Code, rr.Body)
	}
}

func TestStreamReplaysAndLimitsSubscribers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	m := newTestMonitor(t, now)
	for s := 1; s <= 5; s++ {
		traffic(m)
		m.Tick(now.Add(time.Duration(s) * time.Second))
	}
	_, replay, cancel, ok := m.Subscribe(now.Unix() + 2)
	if !ok || len(replay) != 2 {
		t.Fatalf("replay %d ticks, ok %v", len(replay), ok)
	}
	cancel()
	var tick cm.LiveTick
	_ = json.Unmarshal(replay[0], &tick)
	if tick.Traffic.Requests != 16 || !tick.Traffic.Check() {
		t.Errorf("tick %+v", tick.Traffic)
	}
	validate(t, "LiveTick", replay[0])
	if TickID(replay[0]) != fmt.Sprint(now.Unix()+3) {
		t.Errorf("tick id %s", TickID(replay[0]))
	}
	var cancels []func()
	for i := 0; i < cm.MaxStreamSubscribers; i++ {
		_, _, c, ok := m.Subscribe(0)
		if !ok {
			t.Fatal("subscriber refused below the limit")
		}
		cancels = append(cancels, c)
	}
	if _, _, _, ok := m.Subscribe(0); ok {
		t.Error("17th subscriber accepted")
	}
	for _, c := range cancels {
		c()
	}
}

func TestHintsHoldAndClear(t *testing.T) {
	st := newHintState()
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i <= 30; i++ {
		st.set(t0.Add(time.Duration(i)*10*time.Second), true, hintHold, cm.HintCPUHigh, "warning", "", 0.95, 0.9)
	}
	if l := st.list(t0.Add(300 * time.Second)); len(l) != 1 || l[0].Since != ts(t0) {
		t.Fatalf("cpu_high after 5 min: %+v", l)
	}
	st.set(t0.Add(310*time.Second), false, hintHold, cm.HintCPUHigh, "warning", "", 0.2, 0.9)
	if l := st.list(t0.Add(500 * time.Second)); len(l) != 1 {
		t.Error("hint cleared before 5 min without the condition")
	}
	if l := st.list(t0.Add(700 * time.Second)); len(l) != 0 {
		t.Error("hint not cleared after 5 min without the condition")
	}
	st.set(t0, true, 0, cm.HintDiskFullSoon, "notice", "/var/lib/docker", 0.91, 0.9)
	l := st.list(t0)
	if len(l) != 1 || l[0].Object != "/var/lib/docker" {
		t.Errorf("disk hint %+v", l)
	}
}
