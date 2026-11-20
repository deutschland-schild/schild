// Package monitoring is the v0.4 (MVP-21, D33) contract of the traffic and
// server monitoring: the fixed metric catalogue, the three rings and their
// slot arithmetic, the latency histogram scheme, the series query syntax and
// the wire types of the client dashboard API (and of the MVP-20 export, which
// streams MetricBucket). The schemas live in
// contracts/api/client-dashboard.openapi.yaml; tests keep both in step.
//
// Nothing in here carries an IP address, a client key or a hash of one.
package monitoring

// Kind of a metric.
type Kind string

const (
	Counter   Kind = "counter"
	Gauge     Kind = "gauge"
	Histogram Kind = "histogram"
	Estimate  Kind = "estimate"
)

// Stat selects what a series shows.
type Stat string

const (
	Rate  Stat = "rate"
	Sum   Stat = "sum"
	Avg   Stat = "avg"
	Min   Stat = "min"
	Max   Stat = "max"
	P50   Stat = "p50"
	P95   Stat = "p95"
	P99   Stat = "p99"
	Value Stat = "value"
)

// Stats returns the stats a kind allows; the first one is the default.
func (k Kind) Stats() []Stat {
	switch k {
	case Counter:
		return []Stat{Rate, Sum}
	case Gauge:
		return []Stat{Avg, Min, Max}
	case Histogram:
		return []Stat{P95, P50, P99}
	case Estimate:
		return []Stat{Value}
	}
	return nil
}

// Metric describes one metric id.
type Metric struct {
	ID         string
	Kind       Kind
	Unit       string // requests | bytes | ms | ratio | count | packets | segments | clients
	Scope      string // traffic | host | container | process | schild
	Exact      bool
	ErrorBound float64 // relative, estimates only
	PerObject  string  // none | mount | device | interface
	SiteAware  bool
}

// Error bounds of the estimates (spec MVP-21, "exactness").
const (
	// LatencyErrorBound: a quantile reports its bucket's upper bound, at most
	// 25 % above the true value (growth factor 1.25); documented as 0.25.
	LatencyErrorBound = 0.25
	// ClientsErrorBound: HyperLogLog with precision 10 (1.04/sqrt(1024)).
	ClientsErrorBound = 0.033
)

func tc(id string, unit string) Metric {
	return Metric{ID: "traffic." + id, Kind: Counter, Unit: unit, Scope: "traffic", Exact: true, PerObject: "none", SiteAware: true}
}
func g(id, unit, scope string) Metric {
	return Metric{ID: id, Kind: Gauge, Unit: unit, Scope: scope, Exact: true, PerObject: "none"}
}
func c(id, unit, scope string) Metric {
	return Metric{ID: id, Kind: Counter, Unit: unit, Scope: scope, Exact: true, PerObject: "none"}
}
func per(m Metric, obj string) Metric { m.PerObject = obj; return m }

// Catalogue is the fixed list of metrics, in the order of the OpenAPI enum
// MetricId. Adding a metric is a contract change.
var Catalogue = []Metric{
	tc("requests", "requests"),
	tc("forwarded", "requests"),
	tc("stopped", "requests"),
	tc("blocked_waf", "requests"),
	tc("blocked_behaviour", "requests"),
	tc("rate_limited", "requests"),
	tc("rejected_limit", "requests"),
	tc("challenged", "requests"),
	tc("fail_closed", "requests"),
	tc("fail_closed_waf_busy", "requests"),
	tc("fail_closed_waf_timeout", "requests"),
	tc("would_block", "requests"),
	tc("would_rate_limit", "requests"),
	tc("page_views", "requests"),         // addendum 2026-10-29
	tc("detections", "requests"),         // addendum 2026-10-29
	tc("waiting_page_shown", "requests"), // D37 (MVP-23 step 1)
	tc("blocked_crawler", "requests"),    // D57 (MVP-29)
	tc("status_1xx", "requests"),
	tc("status_2xx", "requests"),
	tc("status_3xx", "requests"),
	tc("status_4xx", "requests"),
	tc("status_5xx", "requests"),
	tc("upstream_errors", "requests"),
	tc("upstream_timeouts", "requests"),
	tc("bytes_in", "bytes"),
	tc("bytes_out", "bytes"),
	{ID: "traffic.latency_total", Kind: Histogram, Unit: "ms", Scope: "traffic", ErrorBound: LatencyErrorBound, PerObject: "none", SiteAware: true},
	{ID: "traffic.latency_overhead", Kind: Histogram, Unit: "ms", Scope: "traffic", ErrorBound: LatencyErrorBound, PerObject: "none", SiteAware: true},
	{ID: "traffic.latency_upstream", Kind: Histogram, Unit: "ms", Scope: "traffic", ErrorBound: LatencyErrorBound, PerObject: "none", SiteAware: true},
	// Visitors (D36 amendment 2026-10-29): clients with a browser request
	// schild forwarded (Visitor); bots are in BucketClients.Bots.
	{ID: "traffic.clients_unique", Kind: Estimate, Unit: "clients", Scope: "traffic", ErrorBound: ClientsErrorBound, PerObject: "none", SiteAware: true},
	{ID: "traffic.clients_new", Kind: Estimate, Unit: "clients", Scope: "traffic", ErrorBound: ClientsErrorBound, PerObject: "none", SiteAware: true},
	g("server.cpu_usage", "ratio", "host"),
	g("server.cpu_iowait", "ratio", "host"),
	g("server.cpu_steal", "ratio", "host"),
	g("server.load1", "count", "host"),
	g("server.load5", "count", "host"),
	g("server.load15", "count", "host"),
	g("server.memory_used", "bytes", "host"),
	g("server.memory_available", "bytes", "host"),
	g("server.swap_used", "bytes", "host"),
	per(g("server.disk_used", "bytes", "host"), "mount"),
	per(g("server.disk_used_ratio", "ratio", "host"), "mount"),
	per(g("server.disk_inodes_used_ratio", "ratio", "host"), "mount"),
	per(c("server.disk_read_bytes", "bytes", "host"), "device"),
	per(c("server.disk_write_bytes", "bytes", "host"), "device"),
	per(g("server.disk_busy", "ratio", "host"), "device"),
	per(c("server.net_rx_bytes", "bytes", "host"), "interface"),
	per(c("server.net_tx_bytes", "bytes", "host"), "interface"),
	per(c("server.net_errors", "packets", "host"), "interface"),
	per(c("server.net_drops", "packets", "host"), "interface"),
	g("server.tcp_established", "count", "host"),
	g("server.tcp_syn_recv", "count", "host"),
	g("server.tcp_time_wait", "count", "host"),
	g("server.tcp_close_wait", "count", "host"),
	c("server.tcp_listen_drops", "count", "host"),
	c("server.tcp_retransmits", "segments", "host"),
	g("server.conntrack_used_ratio", "ratio", "host"),
	g("server.files_open_ratio", "ratio", "host"),
	g("container.cpu_usage", "ratio", "container"),
	g("container.cpu_throttled", "ratio", "container"),
	g("container.memory_used", "bytes", "container"),
	g("process.cpu_usage", "ratio", "process"),
	g("process.rss", "bytes", "process"),
	g("process.heap", "bytes", "process"),
	g("process.goroutines", "count", "process"),
	g("process.gc_pause_p99", "ms", "process"),
	g("process.open_files", "count", "process"),
	g("schild.event_queue_fill", "ratio", "schild"),
	c("schild.events_dropped", "count", "schild"),
	g("schild.eval_slots_used", "ratio", "schild"),
	g("schild.store_bytes", "bytes", "schild"),
	g("schild.sampler_ms", "ms", "schild"),
}

var byID = func() map[string]Metric {
	m := make(map[string]Metric, len(Catalogue))
	for _, x := range Catalogue {
		m[x.ID] = x
	}
	return m
}()

// Lookup returns the metric with id.
func Lookup(id string) (Metric, bool) {
	m, ok := byID[id]
	return m, ok
}

// PromWaitingPageShown (D37, MVP-23 step 1) is the Prometheus counter of
// TrafficCounters.WaitingPageShown on the metrics port, a cumulative total
// since start without labels. It is not a class of schild_http_requests_total,
// whose classes add up to all requests: the waiting page is part of the
// fail_closed_waf_busy and fail_closed_waf_timeout classes.
const PromWaitingPageShown = "schild_http_waiting_page_shown_total"

// Limits of one series query (MetricCatalogue.max_points, max_series).
const (
	MaxPoints = 1000
	MaxSeries = 16
	// MaxSites is the number of sites with their own traffic series; the
	// rest is summed as OtherSite.
	MaxSites  = 32
	OtherSite = "_other"
	// MaxBreakdownBuckets (v0.5, D36): getTrafficBreakdown reads the 1 min
	// ring when it covers from and the range has at most MaxPoints of its
	// buckets, else the 10 min ring with at most this many buckets (14 days
	// at the default keep); a longer range answers 400 invalid (pointer
	// #/query/from).
	MaxBreakdownBuckets = 2016
	// LiveRingSeconds: seconds of LiveTick kept in memory for Last-Event-ID.
	LiveRingSeconds = 300
	// MaxStreamSubscribers of streamMonitoring; more answer 429.
	MaxStreamSubscribers = 16
	// SampleInterval of the host sampler in seconds.
	SampleInterval = 10
)
