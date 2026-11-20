package monitoring

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

func testSites(t *testing.T) *sites.Registry {
	t.Helper()
	v := sites.NewView(websites.Input{Mode: websites.ModeIngress, Blocks: []websites.Block{
		{Addresses: []string{"shop.example.org", "www.shop.example.org"}, Schild: true},
		{Addresses: []string{"verein.example"}, Schild: true},
		{Addresses: []string{"legacy.example.org"}, Proxies: true},
	}, UnprotectedSites: []string{"legacy.example.org"}})
	if v.Err != nil {
		t.Fatal(v.Err)
	}
	return sites.NewRegistry(v)
}

func siteReq(host, path string) *http.Request {
	r := newReq(path, chromeUA, "")
	r.Host = host
	return r
}

func TestRecordPerSiteDoesNotAllocate(t *testing.T) {
	rc := newRecorder(time.Now())
	rc.sites = testSites(t)
	q := Req{R: siteReq("www.shop.example.org", "/warenkorb"), Class: Forwarded, Status: 200, Timed: true, Total: 3 * time.Millisecond,
		Client: netip.MustParseAddr("192.0.2.10"), Country: "DE", ASN: 3320, ASOrg: "Deutsche Telekom", NetClass: "residential"}
	for i := 0; i < len(rc.shards)*2; i++ {
		rc.record(&q)
	}
	if n := testing.AllocsPerRun(1000, func() { rc.record(&q) }); n != 0 {
		t.Errorf("Record with a website allocates %.1f times per request", n)
	}
}

// siteTraffic records per call 6 requests of shop (1 WAF block, 1 would
// block) and 2 of verein.
func siteTrafficMix(m *Monitor) {
	for i := 0; i < 4; i++ {
		m.Record(&Req{R: siteReq("shop.example.org", "/produkt/"+fmt.Sprint(i)), Class: Forwarded, Status: 200, Timed: true, Total: 20 * time.Millisecond,
			UpstreamDur: 15 * time.Millisecond, Client: netip.MustParseAddr("198.51.100.4"), Country: "DE", ASN: 3320, NetClass: "residential"})
	}
	m.Record(&Req{R: siteReq("www.shop.example.org", "/suche"), Class: Forwarded, WouldBlock: true, Detection: true, Rules: []string{"942100"}, Status: 200,
		Timed: true, Total: 20 * time.Millisecond, Client: netip.MustParseAddr("198.51.100.5"), Country: "FR", NetClass: "residential"})
	m.Record(&Req{R: siteReq("shop.example.org:443", "/wp-login.php"), Class: BlockedWAF, Detection: true, Rules: []string{"930120"}, Status: 403,
		Timed: true, Total: time.Millisecond, Client: netip.MustParseAddr("203.0.113.9"), Country: "NL", ASN: 24940, NetClass: "hosting"})
	for i := 0; i < 2; i++ {
		m.Record(&Req{R: siteReq("verein.example", "/termine"), Class: Forwarded, Status: 500, Timed: true, Total: 300 * time.Millisecond,
			UpstreamDur: 299 * time.Millisecond, Client: netip.MustParseAddr("198.51.100.6"), Country: "DE", NetClass: "residential"})
	}
}

func TestMonitorPerWebsite(t *testing.T) {
	now := time.Now().UTC().Truncate(10 * time.Minute).Add(-30 * time.Minute)
	m, err := New(Config{StoragePath: t.TempDir(), Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
		Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: now, Version: "test"}, Sites: testSites(t)}, now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.Sample(now.Add(-5 * time.Second))
	for s := 1; s <= 1200; s++ {
		at := now.Add(time.Duration(s) * time.Second)
		m.flushWrites()
		if s%10 == 1 {
			siteTrafficMix(m)
		}
		m.Tick(at)
	}
	m.flushWrites()
	end := now.Add(1200 * time.Second)

	// Every bucket lists both websites with traffic; the 10 min buckets
	// carry their top lists and day estimates. Day visitors of shop are 2:
	// the client whose only request the WAF blocked is no visitor (D36
	// amendment).
	page, err := m.Buckets("10m", now, "", 10, end)
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("%v %d buckets", err, len(page.Items))
	}
	for _, b := range page.Items {
		if len(b.Sites) != 2 || b.Sites[0].Site != "shop.example.org" || b.Sites[1].Site != "verein.example" {
			t.Fatalf("sites %+v", b.Sites)
		}
		shop := b.Sites[0]
		if shop.Traffic.Requests != 60*6 || shop.Traffic.BlockedWAF != 60 || shop.Traffic.WouldBlock != 60 || shop.Latency == nil || shop.Clients == nil ||
			shop.Clients.UniqueDay == nil || *shop.Clients.UniqueDay != 2 || shop.Clients.Bots == nil || *shop.Clients.Bots != 0 || shop.Top == nil || len(shop.Top.Path) != 3 {
			t.Fatalf("shop %+v day %v paths %d", shop, *shop.Clients.UniqueDay, len(shop.Top.Path))
		}
		if b.Sites[1].Traffic.Requests+shop.Traffic.Requests != b.Traffic.Requests || b.Clients.UniqueDay == nil {
			t.Fatalf("site sum %d + %d != %d", shop.Traffic.Requests, b.Sites[1].Traffic.Requests, b.Traffic.Requests)
		}
	}
	body, _ := json.Marshal(page)
	validate(t, "MetricBucketPage", body)
	p1, _ := m.Buckets("1m", now, "", 2, end)
	if p1.Items[0].Sites[0].Top != nil || p1.Items[0].Sites[0].Latency == nil {
		t.Fatalf("1 min ring: per-website top lists only in the 10 min ring: %+v", p1.Items[0].Sites[0])
	}

	h := http.NewServeMux()
	m.Routes(func(p string, f http.HandlerFunc) { h.HandleFunc(p, f) }, "/api/v0")
	get := func(path string, q url.Values) (int, []byte) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil))
		return rr.Code, rr.Body.Bytes()
	}
	rng := url.Values{"from": {now.Format(time.RFC3339)}, "to": {end.Format(time.RFC3339)}}
	with := func(kv ...string) url.Values {
		q := url.Values{}
		for k, v := range rng {
			q[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			q.Add(kv[i], kv[i+1])
		}
		return q
	}
	var sr cm.SeriesResult
	code, b := get("/api/v0/monitoring/series", with("metric", "traffic.requests:sum", "metric", "traffic.latency_total:p95", "site", "shop.example.org"))
	if code != 200 {
		t.Fatalf("site series: %d %s", code, b)
	}
	validate(t, "SeriesResult", b)
	_ = json.Unmarshal(b, &sr)
	var total float64
	for _, v := range sr.Series[0].Values {
		if v != nil {
			total += *v
		}
	}
	if total != 120*6 || sr.Site != "shop.example.org" {
		t.Fatalf("shop requests %v", total)
	}
	// One filter from the per-website top lists of the 10 min ring.
	code, b = get("/api/v0/monitoring/series", with("metric", "traffic.requests:sum", "site", "shop.example.org", "filter", "path:/wp-login.php"))
	if code != 200 {
		t.Fatalf("filtered series: %d %s", code, b)
	}
	validate(t, "SeriesResult", b)
	_ = json.Unmarshal(b, &sr)
	total = 0
	for _, v := range sr.Series[0].Values {
		if v != nil {
			total += *v
		}
	}
	if sr.Resolution != cm.Res10m || total != 120 || sr.Source != "rings" || len(sr.Filters) != 1 || sr.Series[0].Exact {
		t.Fatalf("filtered: %s %v %+v", sr.Resolution, total, sr)
	}
	for _, c := range []url.Values{
		with("metric", "traffic.requests", "filter", "path:/a", "filter", "country:DE"),
		with("metric", "traffic.latency_total:p95", "filter", "country:DE"),
		with("metric", "traffic.requests", "filter", "ip:192.0.2.10"),      // D64: the request ring only
		with("metric", "traffic.requests", "filter", "user_agent:bingbot"), // D64
	} {
		if code, b := get("/api/v0/monitoring/series", c); code != 409 {
			t.Errorf("%v: %d %s", c, code, b)
		}
	}
	if code, _ := get("/api/v0/monitoring/series", with("metric", "traffic.requests", "site", "nope.example")); code != 400 {
		t.Errorf("unknown site: %d", code)
	}
	// Breakdown of one website and by website.
	var bd TrafficBreakdown
	code, b = get("/api/v0/monitoring/traffic/breakdown", with("by", "path", "site", "shop.example.org"))
	if code != 200 {
		t.Fatalf("breakdown: %d %s", code, b)
	}
	validate(t, "TrafficBreakdown", b)
	_ = json.Unmarshal(b, &bd)
	if bd.Total.Requests != 120*6 || bd.Resolution != "10m" || len(bd.Items) != 3 {
		t.Fatalf("shop breakdown %+v", bd)
	}
	_, b = get("/api/v0/monitoring/traffic/breakdown", with("by", "site"))
	_ = json.Unmarshal(b, &bd)
	if len(bd.Items) != 2 || bd.Items[0].Key != "shop.example.org" || bd.Items[0].Requests != 120*6 {
		t.Fatalf("by site %+v", bd.Items)
	}
	if code, _ := get("/api/v0/monitoring/traffic/breakdown", with("by", "path", "filter", "country:DE")); code != 409 {
		t.Errorf("breakdown under a filter: %d", code)
	}
	for _, by := range []string{"ip", "user_agent"} { // D65: the request ring only
		if code, _ := get("/api/v0/monitoring/traffic/breakdown", with("by", by)); code != 409 {
			t.Errorf("by %s without the ring: %d", by, code)
		}
	}
	// An unprotected website has no numbers.
	_, b = get("/api/v0/monitoring/traffic/breakdown", with("by", "path", "site", "legacy.example.org"))
	_ = json.Unmarshal(b, &bd)
	if bd.Total.Requests != 0 || len(bd.Items) != 0 {
		t.Fatalf("unprotected: %+v", bd)
	}
	// Now and the status window of one website.
	code, b = get("/api/v0/monitoring/now", url.Values{"site": {"verein.example"}})
	if code != 200 {
		t.Fatalf("now: %d %s", code, b)
	}
	validate(t, "MonitoringNow", b)
	n := m.Site(m.view().SlotOf("verein.example"), end)
	if !n.HasData || n.Now == nil || n.Now.RequestsPerS != 0.2 || n.Window.Requests != 60 || n.Window.Status5xx != 60 {
		t.Fatalf("verein numbers %+v %+v", n.Now, n.Window)
	}
	req, stopped, _, vis := m.Recent(m.view().SlotOf("shop.example.org"), 5*time.Minute, end)
	if req != 30*6 || stopped != 30 || vis == nil || *vis != 2 { // the blocked client is no visitor
		t.Fatalf("recent: %d %d %v", req, stopped, vis)
	}
}

func TestSeriesMergesAndMarksPartial(t *testing.T) {
	end := time.Now().UTC().Truncate(10 * time.Minute)
	m := newTestMonitor(t, end.Add(-14*24*time.Hour))
	ring := m.rings[2]
	for i := 0; i < 2016; i += 7 {
		start := end.Add(-time.Duration(i+1) * ring.Step)
		b := cm.MetricBucket{T: ts(start), Resolution: ring.Resolution, StepS: 600, Traffic: cm.TrafficCounters{Requests: 600}, Sites: []cm.SiteTraffic{},
			Latency: cm.BucketLatency{Total: emptyHist(), Overhead: emptyHist(), Upstream: emptyHist()}}
		if err := m.store.put(ring, start, &b); err != nil {
			t.Fatal(err)
		}
	}
	res, err := m.Series(SeriesQuery{Metrics: []string{"traffic.requests:rate", "traffic.requests:sum"}, From: end.Add(-14 * 24 * time.Hour), To: end.Add(5 * time.Minute)}, end.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if res.BucketsPerPoint != 3 || res.StepS != 1800 || res.Points > cm.MaxPoints || len(res.Partial) != res.Points || !res.Partial[len(res.Partial)-1] {
		t.Fatalf("plan: %d per point, step %d, %d points, partial %d", res.BucketsPerPoint, res.StepS, res.Points, len(res.Partial))
	}
	body, _ := json.Marshal(res)
	validate(t, "SeriesResult", body)
	for i, v := range res.Series[0].Values {
		if v != nil && *v != 1 {
			t.Fatalf("point %d: rate %v, want 1/s over the buckets present", i, *v)
		}
	}
	if _, err := m.Series(SeriesQuery{Metrics: []string{"traffic.requests"}, From: end.Add(-14 * 24 * time.Hour), To: end, Resolution: "10m"}, end); !errors.Is(err, cm.ErrTooManyPoints) {
		t.Fatalf("explicit resolution never merges: %v", err)
	}
}

// TestStoppedOfClassFailClosed (D36 fix round 2, re-measurement B 3.3 a):
// fail_closed is never part of stopped, so it changes neither class.
func TestStoppedOfClassFailClosed(t *testing.T) {
	tc := &cm.TrafficCounters{Requests: 1200, Stopped: 511, FailClosed: 342}
	if got := stoppedOfClass(tc, "4xx"); got != 511 {
		t.Fatalf("4xx %d, want 511", got)
	}
	for _, c := range []string{"1xx", "2xx", "3xx", "5xx"} {
		if got := stoppedOfClass(tc, c); got != 0 {
			t.Fatalf("%s %d, want 0", c, got)
		}
	}
}
