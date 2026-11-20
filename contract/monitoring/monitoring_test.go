package monitoring

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/schema"
)

const apiDoc = "../../contracts/api/client-dashboard.openapi.yaml"

func openAPI(t *testing.T) (map[string]any, *jsonschema.Compiler) {
	t.Helper()
	b, err := os.ReadFile(apiDoc)
	if err != nil {
		t.Skipf("contracts/api not present: %v", err)
	}
	j, err := config.YAMLToJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(j, &d); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	for rel, f := range schema.Files() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(f))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource(schema.BaseURL+rel, doc); err != nil {
			t.Fatal(err)
		}
	}
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(j))
	if err := c.AddResource(schema.BaseURL+"api/client-dashboard.openapi.yaml", doc); err != nil {
		t.Fatal(err)
	}
	return d, c
}

func comp(d map[string]any, name string) map[string]any {
	return d["components"].(map[string]any)["schemas"].(map[string]any)[name].(map[string]any)
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// TestCatalogueMatchesOpenAPI: the Go catalogue and the MetricId enum list
// the same ids in the same order; units, kinds, scopes and the query
// pattern agree.
func TestCatalogueMatchesOpenAPI(t *testing.T) {
	d, _ := openAPI(t)
	enum := strs(comp(d, "MetricId")["enum"])
	var ids []string
	for _, m := range Catalogue {
		ids = append(ids, m.ID)
	}
	if !reflect.DeepEqual(enum, ids) {
		t.Fatalf("MetricId enum and Catalogue differ:\nopenapi %v\ngo      %v", enum, ids)
	}
	units := map[string]bool{}
	for _, u := range strs(comp(d, "MetricUnit")["enum"]) {
		units[u] = true
	}
	scopes := map[string]bool{}
	for _, s := range strs(comp(d, "MetricScope")["enum"]) {
		scopes[s] = true
	}
	pat := regexp.MustCompile(comp(d, "MetricQuery")["pattern"].(string))
	for _, m := range Catalogue {
		if !units[m.Unit] || !scopes[m.Scope] {
			t.Errorf("%s: unit %q or scope %q not in the OpenAPI enums", m.ID, m.Unit, m.Scope)
		}
		if m.Exact == (m.ErrorBound > 0) {
			t.Errorf("%s: exact metrics have no error bound, estimates have one", m.ID)
		}
		if (m.Kind == Histogram || m.Kind == Estimate) && m.Exact {
			t.Errorf("%s: histograms and estimates are never exact", m.ID)
		}
		if (m.Scope == "traffic") != m.SiteAware {
			t.Errorf("%s: exactly the traffic metrics are site aware", m.ID)
		}
		for _, st := range m.Kind.Stats() {
			if q := m.ID + ":" + string(st); !pat.MatchString(q) {
				t.Errorf("query %q does not match MetricQuery", q)
			}
		}
	}
	nonTraffic := 0
	for _, m := range Catalogue {
		if m.Scope != "traffic" {
			nonTraffic++
		}
	}
	if nonTraffic > 64 {
		t.Errorf("MetricValues allows 64 ids per map, catalogue has %d non-traffic metrics", nonTraffic)
	}
}

// TestDimensionsMatchOpenAPI: the fixed value sets of the breakdown
// dimensions equal the OpenAPI enums (addendum 2026-10-29), the top lists
// of MetricBucket fit them, and every AI assistant key is a ReferrerKey.
func TestDimensionsMatchOpenAPI(t *testing.T) {
	d, _ := openAPI(t)
	for name, want := range map[string][]string{"BreakdownDimension": append(append([]string{}, Dimensions...), RingFilterDimensions...), "UAClass": UAClasses, "BrowserFamily": BrowserFamilies,
		"OSFamily": OSFamilies, "DeviceClass": DeviceClasses, "BotCategory": BotCategories, "RequestOutcome": RequestOutcomes} {
		if got := strs(comp(d, name)["enum"]); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: openapi %v, go %v", name, got, want)
		}
	}
	top := comp(d, "MetricBucket")["properties"].(map[string]any)["top"].(map[string]any)["properties"].(map[string]any)
	for dim, n := range map[string]int{"path": TopK, "asn": TopK, "referrer": TopK, "rule": TopK, "ua_class": len(UAClasses), "browser": len(BrowserFamilies),
		"os": len(OSFamilies), "device": len(DeviceClasses), "bot_category": len(BotCategories)} {
		if got := top[dim].(map[string]any)["maxItems"].(float64); int(got) != n {
			t.Errorf("top.%s maxItems %v, want %d", dim, got, n)
		}
	}
	pat := regexp.MustCompile(comp(d, "ReferrerKey")["pattern"].(string))
	seen := map[string]bool{}
	for _, a := range AIAssistants {
		k := ReferrerAI + a.ID
		if seen[k] || !pat.MatchString(k) || !ValidReferrerKey(k) || a.Name == "" || len(a.Hosts) == 0 {
			t.Errorf("AI assistant %+v", a)
		}
		seen[k] = true
		for _, h := range a.Hosts {
			if got, _, ok := AIAssistantOf("WWW." + strings.ToUpper(h) + "."); !ok || got != k {
				t.Errorf("%s: %q %v", h, got, ok)
			}
		}
	}
	for _, k := range []string{"_direct", "_intern", "_other", "ai:chatgpt", "google.com", "example.co.uk", "xn--mnchen-3ya.de", "1und1.de", "example.xn--p1ai"} {
		if !pat.MatchString(k) || !ValidReferrerKey(k) {
			t.Errorf("%s rejected", k)
		}
	}
	for _, k := range []string{"", "_none", "localhost", "Google.com", "google.com/search", "google.com:443", "203.0.113.7", "198.51.100.7x", "2001:db8::1", "ai:", "-a.com", "a..com"} {
		if pat.MatchString(k) || ValidReferrerKey(k) {
			t.Errorf("%s accepted", k)
		}
	}
	for _, h := range []string{"openai.com", "google.com", "notclaude.ai", "chatgpt.com.example.org"} {
		if k, _, ok := AIAssistantOf(h); ok {
			t.Errorf("%s grouped as %s", h, k)
		}
	}
}

func TestParseQuery(t *testing.T) {
	for in, want := range map[string]Stat{"traffic.requests": Rate, "traffic.requests:sum": Sum, "server.cpu_usage": Avg, "server.cpu_usage:max": Max,
		"traffic.latency_total": P95, "traffic.latency_overhead:p99": P99, "traffic.clients_unique": Value} {
		q, err := ParseQuery(in)
		if err != nil || q.Stat != want {
			t.Errorf("%s: %v %v", in, q.Stat, err)
		}
	}
	for _, in := range []string{"traffic.requests:p95", "server.cpu_usage:rate", "traffic.ip", "traffic.latency_total:avg", "traffic.clients_new:sum", ""} {
		if _, err := ParseQuery(in); err == nil {
			t.Errorf("%s: accepted", in)
		}
	}
}

func TestRings(t *testing.T) {
	rs := Rings(config.DefaultKeepTenSecondsHours, config.DefaultKeepMinuteHours, config.DefaultKeepTenMinuteDays)
	if rs[0].Slots() != 2160 || rs[1].Slots() != 2880 || rs[2].Slots() != 2016 {
		t.Fatalf("slots %d %d %d", rs[0].Slots(), rs[1].Slots(), rs[2].Slots())
	}
	if max := Rings(24, 168, 90); max[0].Slots() != 8640 || max[1].Slots() != 10080 || max[2].Slots() != 12960 {
		t.Fatal("max slots (RingInfo.slots maximum 12960)")
	}
	r := rs[1]
	now := time.Date(2026, 10, 28, 12, 0, 30, 0, time.UTC)
	if got := r.Start(now); !got.Equal(time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)) {
		t.Fatal(got)
	}
	// Slots of consecutive buckets are consecutive modulo the ring.
	if (r.Slot(now.Add(time.Minute))-r.Slot(now)+r.Slots())%r.Slots() != 1 {
		t.Fatal("slot step")
	}
	if r.Slot(now) != r.Slot(now.Add(-48*time.Hour)) {
		t.Fatal("a bucket 48 h ago shares the slot (overwritten)")
	}
	// At most two contiguous ranges, together exactly the buckets asked for.
	for _, back := range []time.Duration{0, time.Minute, 3 * time.Hour, 47 * time.Hour, 48 * time.Hour} {
		from := r.Start(now.Add(-back))
		rg := r.SlotRanges(from, r.Start(now))
		var n int64
		for _, x := range rg {
			n += x[1] - x[0] + 1
		}
		want := int64(back/time.Minute) + 1
		if want > r.Slots() {
			want = r.Slots()
		}
		if len(rg) > 2 || n != want {
			t.Errorf("back %v: ranges %v (%d slots, want %d)", back, rg, n, want)
		}
	}
	if r.Oldest(now).After(now.Add(-47 * time.Hour)) {
		t.Fatal("oldest")
	}
}

func TestChoose(t *testing.T) {
	rs := Rings(6, 48, 14)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		back  time.Duration
		res   string
		want  Resolution
		pts   int
		error error
	}{
		{time.Hour, "auto", Res10s, 360, nil},
		{6 * time.Hour, "", Res1m, 360, nil}, // 10 s covers 6 h minus one bucket only
		{24 * time.Hour, "auto", Res10m, 144, nil},
		{14 * 24 * time.Hour, "auto", Res10m, 2016, ErrTooManyPoints},
		{6 * 24 * time.Hour, "auto", Res10m, 864, nil},
		{time.Hour, "1m", Res1m, 60, nil},
		{24 * time.Hour, "10s", Res10s, 8640, ErrTooManyPoints},
	} {
		r, _, n, err := Choose(rs, c.res, now.Add(-c.back), now, now)
		if r.Resolution != c.want || n != c.pts || !errors.Is(err, c.error) {
			t.Errorf("%v %s: got %s %d %v, want %s %d %v", c.back, c.res, r.Resolution, n, err, c.want, c.pts, c.error)
		}
	}
	if _, _, _, err := Choose(rs, "auto", now, now, now); err == nil {
		t.Error("empty range accepted")
	}
}

func TestHistogram(t *testing.T) {
	if BucketOf(0.01) != 0 || BucketOf(0.05) != 0 || BucketOf(0.0626) != 2 || BucketOf(1e9) != HistogramBuckets-1 {
		t.Fatal(BucketOf(0.0626))
	}
	for i := 0; i < HistogramBuckets-1; i++ {
		b := BucketBound(i)
		if BucketOf(b) != i || BucketOf(b*1.0001) != i+1 {
			t.Errorf("bucket %d bound %v: %d %d", i, b, BucketOf(b), BucketOf(b*1.0001))
		}
	}
	if b := BucketBound(HistogramBuckets - 2); b < 13000 || b > 15000 {
		t.Fatalf("last finite bound %v", b)
	}
	q, ok := Quantile(map[int]int64{10: 95, 30: 5}, 0.95)
	if !ok || q != BucketBound(10) {
		t.Fatal(q)
	}
	if _, ok := Quantile(nil, 0.5); ok {
		t.Fatal("empty")
	}
}

func f(v float64) *float64 { return &v }
func i64(v int64) *int64   { return &v }

func traffic() TrafficCounters {
	return TrafficCounters{Requests: 1000, Forwarded: 960, Stopped: 38, BlockedWAF: 20, BlockedBehaviour: 5, RateLimited: 10, RejectedLimit: 3,
		FailClosed: 2, FailClosedBy: FailClosedBy{WAFBusy: 2}, WouldBlock: 4, PageViews: 310, Detections: 23, Status: StatusClasses{S2xx: 900, S3xx: 40, S4xx: 52, S5xx: 8},
		UpstreamErrors: 1, UpstreamTimeouts: 1, BytesIn: 12000, BytesOut: 48000000}
}

// TestCheckAddendum: the page view and detection invariants of the
// 2026-10-29 addendum.
func TestCheckAddendum(t *testing.T) {
	for _, c := range []struct {
		name string
		f    func(*TrafficCounters)
		ok   bool
	}{
		{"base", func(*TrafficCounters) {}, true},
		{"detections only enforced", func(t *TrafficCounters) { t.Detections = t.BlockedWAF }, true},
		{"detections incl. every would_block", func(t *TrafficCounters) { t.Detections = t.BlockedWAF + t.WouldBlock }, true},
		{"detections below blocked_waf", func(t *TrafficCounters) { t.Detections = t.BlockedWAF - 1 }, false},
		{"detections above blocked_waf + would_block", func(t *TrafficCounters) { t.Detections = t.BlockedWAF + t.WouldBlock + 1 }, false},
		{"page views above 2xx", func(t *TrafficCounters) { t.PageViews = t.Status.S2xx + 1 }, false},
		{"waiting page within busy + timeout", func(t *TrafficCounters) { t.WaitingPageShown = t.FailClosedBy.WAFBusy + t.FailClosedBy.WAFTimeout }, true},
		{"waiting page above busy + timeout", func(t *TrafficCounters) { t.WaitingPageShown = t.FailClosedBy.WAFBusy + t.FailClosedBy.WAFTimeout + 1 }, false},
		{"body_busy counts in fail_closed (D41)", func(t *TrafficCounters) {
			t.FailClosed, t.Requests, t.FailClosedBy.BodyBusy, t.WaitingPageShown = t.FailClosed+3, t.Requests+3, 3, 3
			t.Status.S5xx += 3
		}, true},
		{"body_busy outside fail_closed (D41)", func(t *TrafficCounters) { t.FailClosedBy.BodyBusy = 1 }, false},
	} {
		tr := traffic()
		c.f(&tr)
		if tr.Check() != c.ok {
			t.Errorf("%s: Check %v", c.name, !c.ok)
		}
	}
}

// TestWireTypes: Go values encode to documents the OpenAPI schemas accept,
// and decode back without unknown fields.
func TestWireTypes(t *testing.T) {
	_, c := openAPI(t)
	tr := traffic()
	if !tr.Check() {
		t.Fatal("example counters break the invariants")
	}
	sum := tr
	sum.Add(&tr)
	if !sum.Check() || sum.Requests != 2000 {
		t.Fatal("Add")
	}
	rs := Rings(6, 48, 14)
	hist := LatencyHistogram{Scheme: HistogramScheme, Counts: map[string]int64{"20": 700, "31": 250, "57": 3}}
	cursor := "b1m.1761652800"
	bucket := MetricBucket{T: "2026-10-28T12:00:00Z", Resolution: Res1m, StepS: 60, Traffic: tr,
		Latency: BucketLatency{Total: hist, Overhead: LatencyHistogram{Scheme: HistogramScheme, Counts: map[string]int64{"12": 960}}, Upstream: hist},
		Clients: BucketClients{Unique: i64(212), New: i64(37)},
		Top: &BucketTop{Path: []TopEntry{{Key: "/wp-login.php", Requests: 120, Stopped: 30, Detections: 18, Error: 2}, {Key: "/blog/{slug}/", Requests: 300}},
			ASN:         []TopEntry{{Key: "64496", Label: "Example Telekom", Requests: 500}},
			Country:     []TopEntry{{Key: "DE", Requests: 800, Stopped: 10}, {Key: "ZZ", Requests: 5}},
			UAClass:     []TopEntry{{Key: "browser", Requests: 700}, {Key: "bot_unverified", Requests: 50, Stopped: 3}},
			Referrer:    []TopEntry{{Key: ReferrerDirect, Requests: 400}, {Key: ReferrerIntern, Requests: 350}, {Key: "ai:chatgpt", Label: "ChatGPT", Requests: 12}, {Key: "example.org", Requests: 9, Error: 1}},
			Browser:     []TopEntry{{Key: "chrome", Requests: 500}, {Key: "safari", Requests: 180}, {Key: "none", Requests: 120, Stopped: 20}},
			OS:          []TopEntry{{Key: "android", Requests: 300}, {Key: "windows", Requests: 260}},
			Device:      []TopEntry{{Key: "mobile", Requests: 420}, {Key: "desktop", Requests: 330}, {Key: "unknown", Requests: 120}},
			BotCategory: []TopEntry{{Key: "likely_browser", Requests: 760}, {Key: "ai_training", Requests: 40}, {Key: "likely_automated", Requests: 30, Stopped: 12}},
			Rule:        []TopEntry{{Key: "942100", Requests: 9, Stopped: 8, WouldBlock: 1}, {Key: "930120", Requests: 6, Stopped: 6}}},
		Sites: []SiteTraffic{{Site: "verein", Traffic: tr}, {Site: OtherSite, Traffic: TrafficCounters{}}},
		Values: MetricValues{Counters: map[string]float64{"server.tcp_listen_drops": 0, "schild.events_dropped": 0},
			Gauges: map[string]GaugeStats{"server.cpu_usage": {Avg: 0.21, Min: 0.12, Max: 0.4}, "process.rss": {Avg: 9.1e7, Min: 9e7, Max: 9.3e7}}},
		Objects: []ObjectValues{{Object: "/var/lib/schild", Kind: "mount", Values: MetricValues{Gauges: map[string]GaugeStats{"server.disk_used_ratio": {Avg: 0.62, Min: 0.62, Max: 0.62}}}},
			{Object: "eth0", Kind: "interface", Values: MetricValues{Counters: map[string]float64{"server.net_rx_bytes": 1.2e9}}}}}
	none := MetricBucket{T: "2026-10-28T12:00:10Z", Resolution: Res10s, StepS: 10, Partial: true,
		Latency: BucketLatency{Total: LatencyHistogram{HistogramScheme, map[string]int64{}}, Overhead: LatencyHistogram{HistogramScheme, map[string]int64{}}, Upstream: LatencyHistogram{HistogramScheme, map[string]int64{}}},
		Sites:   []SiteTraffic{}}
	cpu, cores := 0.21, 4
	srv := &ServerNow{SampledAt: "2026-10-28T12:00:00Z", Scope: "host", CPUUsage: &cpu, Cores: &cores, Load1: f(0.8), MemoryUsedRatio: f(0.55),
		MemoryAvailableBytes: i64(3 << 30), SwapUsedBytes: i64(0), Disk: &DiskNow{Mount: "/", UsedRatio: 0.71}, NetRxBytesPerS: f(1.5e6), NetTxBytesPerS: f(9e6)}
	for _, c0 := range []struct {
		name  string
		v     any
		proto any
	}{
		{"MetricBucket", bucket, MetricBucket{}},
		{"MetricBucket", none, MetricBucket{}},
		{"MetricBucketPage", MetricBucketPage{Resolution: Res1m, Items: []MetricBucket{bucket}, NextCursor: &cursor}, MetricBucketPage{}},
		{"MetricBucketPage", MetricBucketPage{Resolution: Res10m, Items: []MetricBucket{}}, MetricBucketPage{}},
		{"SeriesResult", SeriesResult{From: "2026-10-28T11:00:00Z", To: "2026-10-28T12:00:00Z", Resolution: Res10s, StepS: 10, Points: 3,
			Series: []MetricSeries{{Metric: "traffic.requests", Stat: Rate, Kind: Counter, Unit: "requests", Exact: true, Values: []*float64{f(12.5), nil, f(14)}},
				{Metric: "traffic.latency_total", Stat: P95, Kind: Histogram, Unit: "ms", ErrorBound: LatencyErrorBound, Values: []*float64{f(7.45), f(9.31), nil}},
				{Metric: "server.disk_used_ratio", Stat: Max, Kind: Gauge, Unit: "ratio", Exact: true, Object: "/", Values: []*float64{f(0.7), f(0.7), f(0.71)}}},
			Restarts: []string{"2026-10-28T11:20:00Z"}}, SeriesResult{}},
		{"LiveTick", LiveTick{T: "2026-10-28T12:00:01Z", Traffic: tr}, LiveTick{}},
		{"LiveTick", LiveTick{T: "2026-10-28T12:00:10Z", Traffic: tr, LatencyTotalP95MS: f(12.1), Sites: []LiveSite{{Site: "verein", Requests: 9, Stopped: 1}},
			Schild: &LiveSchild{EventQueueFill: 0.01, EvalSlotsUsed: 1, EvalSlotsMax: 4}, Server: srv}, LiveTick{}},
		{"ServerNow", ServerNow{SampledAt: "2026-10-28T12:00:00Z", Scope: "process"}, ServerNow{}},
		{"HealthHint", HealthHint{Code: HintDiskFullSoon, Level: "notice", Since: "2026-10-28T09:00:00Z", Value: f(0.93), Threshold: f(0.9), Object: "/var/lib/docker"}, HealthHint{}},
		{"MetricCatalogue", NewCatalogue(rs), MetricCatalogue{}},
	} {
		sch, err := c.Compile(schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/" + c0.name)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(c0.v)
		if err != nil {
			t.Fatal(err)
		}
		inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err := sch.Validate(inst); err != nil {
			t.Errorf("%s: %v\n%s", c0.name, err, b)
			continue
		}
		v := reflect.New(reflect.TypeOf(c0.proto)).Interface()
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Errorf("%s: %v", c0.name, err)
		}
	}
}

// TestNoAddressFields: no monitoring schema has a property that could carry
// an address or a client key (aggregates only, D33).
func TestNoAddressFields(t *testing.T) {
	d, _ := openAPI(t)
	forbidden := regexp.MustCompile(`(?i)^(ip|ips|client_ip|ip_key|ip_hash|client_key|address|cidr|remote_addr)$`)
	for _, name := range []string{"MetricBucket", "MetricBucketPage", "SeriesResult", "MetricSeries", "LiveTick", "TrafficCounters", "TopEntry", "TrafficBreakdown",
		"MonitoringNow", "TrafficNow", "ServerNow", "ServerSnapshot", "InterfaceSnapshot", "MountSnapshot", "TCPSnapshot", "HealthHint", "MetricValues"} {
		var walk func(v any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				if p, ok := x["properties"].(map[string]any); ok {
					for k := range p {
						if forbidden.MatchString(k) {
							t.Errorf("%s: property %s", name, k)
						}
					}
				}
				for _, y := range x {
					walk(y)
				}
			case []any:
				for _, y := range x {
					walk(y)
				}
			}
		}
		walk(comp(d, name))
	}
}
