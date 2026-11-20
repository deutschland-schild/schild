package monitoring

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// heavyBucket is a worst-case bucket of the given ring: every top list
// full with long keys, 16 mounts and 16 interfaces with values.
func heavyBucket(start time.Time, res cm.Resolution, step int, seed int) cm.MetricBucket {
	tc := cm.TrafficCounters{Requests: 6000, Forwarded: 5900, Stopped: 100, BlockedWAF: 60, RateLimited: 40, Detections: 80, WouldBlock: 20,
		PageViews: 3000, Status: cm.StatusClasses{S2xx: 5500, S3xx: 300, S4xx: 200}, BytesIn: 1 << 20, BytesOut: 1 << 26}
	h := cm.LatencyHistogram{Scheme: cm.HistogramScheme, Counts: map[string]int64{}}
	for i := 10; i < 40; i++ {
		h.Counts[fmt.Sprint(i)] = int64(i * 7)
	}
	u, n := int64(900), int64(100)
	vals := cm.MetricValues{Counters: map[string]float64{}, Gauges: map[string]cm.GaugeStats{}}
	for _, id := range []string{"server.cpu_usage", "server.cpu_iowait", "server.cpu_steal", "server.load1", "server.memory_used", "server.swap_used",
		"server.tcp_established", "server.tcp_syn_recv", "server.tcp_time_wait", "server.tcp_close_wait", "server.conntrack_used_ratio",
		"server.files_open_ratio", "process.cpu_usage", "process.rss", "process.heap", "process.goroutines", "container.cpu_usage"} {
		vals.Gauges[id] = cm.GaugeStats{Avg: 0.42, Min: 0.1, Max: 0.9}
	}
	vals.Counters["server.tcp_listen_drops"] = 1
	vals.Counters["server.tcp_retransmits"] = 30
	var objs []cm.ObjectValues
	for i := 0; i < 16; i++ {
		objs = append(objs, cm.ObjectValues{Object: fmt.Sprintf("/mnt/volume-%02d", i), Kind: "mount", Values: cm.MetricValues{Gauges: map[string]cm.GaugeStats{"server.disk_used_ratio": {Avg: 0.5, Min: 0.5, Max: 0.5}},
			Counters: map[string]float64{"server.disk_read_bytes": 1e6, "server.disk_write_bytes": 2e6}}})
		objs = append(objs, cm.ObjectValues{Object: fmt.Sprintf("eth%d", i), Kind: "interface", Values: cm.MetricValues{
			Counters: map[string]float64{"server.net_rx_bytes": 1e7, "server.net_tx_bytes": 2e7, "server.net_errors": 0, "server.net_drops": 0}}})
	}
	b := cm.MetricBucket{T: ts(start), Resolution: res, StepS: step, Traffic: tc, Latency: cm.BucketLatency{Total: h, Overhead: h, Upstream: h},
		Clients: cm.BucketClients{Unique: &u, New: &n}, Sites: []cm.SiteTraffic{}, Values: vals, Objects: objs}
	if res == cm.Res10s {
		return b
	}
	list := func(prefix string, k int, long int) []cm.TopEntry {
		out := make([]cm.TopEntry, k)
		for i := range out {
			out[i] = cm.TopEntry{Key: fmt.Sprintf("%s%d-%d%s", prefix, i, seed%97, strings.Repeat("x", long)), Label: "", Requests: int64(1000 - i*10), Stopped: int64(i), WouldBlock: 1, Error: int64(i)}
		}
		return out
	}
	b.Top = &cm.BucketTop{Path: list("/p/", cm.TopK, 200), ASN: list("", cm.TopK, 0), Referrer: list("ref", cm.TopK, 30), Rule: list("9421", cm.TopK, 0),
		Country: list("C", 60, 0), NetClass: list("n", 11, 0), UAClass: list("u", 6, 0), Method: list("m", 10, 0), Browser: list("b", 9, 0),
		OS: list("o", 8, 0), Device: list("d", 5, 0), BotCategory: list("bc", 13, 0)}
	for i := range b.Top.ASN {
		b.Top.ASN[i].Key = fmt.Sprint(64512 + i)
		b.Top.ASN[i].Label = "Some Hosting Provider GmbH " + strings.Repeat("y", 40)
	}
	return b
}

// filledMonitor writes full 1 min (1000 points) and 10 min (14 days) rings.
func filledMonitor(tb testing.TB, end time.Time) *Monitor {
	tb.Helper()
	m, err := New(Config{StoragePath: tb.TempDir(), Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14}}, end)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = m.Close() })
	for i := 1; i <= 1000; i++ {
		start := end.Add(-time.Duration(i) * time.Minute)
		b := heavyBucket(start, cm.Res1m, 60, i)
		if err := m.store.put(m.rings[1], start, &b); err != nil {
			tb.Fatal(err)
		}
	}
	for i := 1; i <= 2016; i++ {
		start := end.Add(-time.Duration(i) * 10 * time.Minute)
		b := heavyBucket(start, cm.Res10m, 600, i)
		if err := m.store.put(m.rings[2], start, &b); err != nil {
			tb.Fatal(err)
		}
	}
	return m
}

var series16 = []string{"traffic.requests:rate", "traffic.forwarded:rate", "traffic.stopped:rate", "traffic.fail_closed:rate", "traffic.would_block:rate",
	"traffic.latency_total:p50", "traffic.latency_total:p95", "traffic.latency_total:p99", "traffic.latency_overhead:p95", "traffic.latency_upstream:p95",
	"traffic.bytes_in:rate", "traffic.bytes_out:rate", "traffic.clients_unique", "server.cpu_usage:avg", "server.memory_used:max", "server.disk_used_ratio:max"}

// queryMetricSeries, 16 metrics x 1000 points of the 1 min ring (spec:
// p95 < 100 ms) and getTrafficBreakdown over 14 days (spec: p95 < 300 ms).
// Run: go test -run - -bench Query ./internal/monitoring
func BenchmarkQuerySeries16x1000(b *testing.B) {
	end := time.Now().UTC().Truncate(10 * time.Minute)
	m := filledMonitor(b, end)
	q := SeriesQuery{Metrics: series16, From: end.Add(-1000 * time.Minute), To: end, Resolution: "1m"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := m.Series(q, end)
		if err != nil || res.Points != 1000 {
			b.Fatal(err, res.Points)
		}
	}
}

// A coarse guard against the decoding cost of storage layout 1 (0.6-1 s
// for the series, 1.1 s per breakdown on the builder's machine): the bounds
// are several times the spec budget, so a slow CI machine passes, layout 1
// does not. The real numbers come from the benchmarks above and the
// independent measurement.
func TestQueryLatencyGuard(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing guard")
	}
	end := time.Now().UTC().Truncate(10 * time.Minute)
	m := filledMonitor(t, end)
	best := func(f func()) time.Duration {
		d := time.Hour
		for i := 0; i < 3; i++ {
			t0 := time.Now()
			f()
			d = min(d, time.Since(t0))
		}
		return d
	}
	series := best(func() {
		if _, err := m.Series(SeriesQuery{Metrics: series16, From: end.Add(-1000 * time.Minute), To: end, Resolution: "1m"}, end); err != nil {
			t.Fatal(err)
		}
	})
	breakdown := best(func() {
		if _, err := m.Breakdown("path", end.Add(-14*24*time.Hour), end, "", nil, 20, end); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("series 16x1000 %v, breakdown 14 d %v", series, breakdown)
	if series > 300*time.Millisecond || breakdown > 600*time.Millisecond {
		t.Errorf("queries too slow: series %v (spec < 100 ms), breakdown %v (spec < 300 ms)", series, breakdown)
	}
}

func BenchmarkQueryBreakdown14d(b *testing.B) {
	end := time.Now().UTC().Truncate(10 * time.Minute)
	m := filledMonitor(b, end)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, by := range []string{"path", "country"} {
			bd, err := m.Breakdown(by, end.Add(-14*24*time.Hour), end, "", nil, 20, end)
			if err != nil || len(bd.Items) == 0 {
				b.Fatal(err)
			}
		}
	}
}
