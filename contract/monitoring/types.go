package monitoring

// Wire types of the client dashboard API (contracts v0.4, MVP-21). The
// gateway serves them and the MVP-20 export streams MetricBucket unchanged.
// Field names and optionality follow the OpenAPI schemas of the same name.

// StatusClasses counts the status sent to the client.
type StatusClasses struct {
	S1xx int64 `json:"s1xx"`
	S2xx int64 `json:"s2xx"`
	S3xx int64 `json:"s3xx"`
	S4xx int64 `json:"s4xx"`
	S5xx int64 `json:"s5xx"`
}

// FailClosedBy splits the fail-closed 503s of schild by cause.
type FailClosedBy struct {
	WAFTimeout int64 `json:"waf_timeout"`
	WAFBusy    int64 `json:"waf_busy"`
	NotReady   int64 `json:"not_ready"`
	Panic      int64 `json:"panic"`
	// BodyBusy (v0.5, D41; optional): refused by the body limits with a 503.
	BodyBusy int64 `json:"body_busy,omitempty"`
}

// TrafficCounters are the exact counts of one interval. Invariants:
// Requests = Forwarded + Stopped + FailClosed and Stopped = BlockedWAF +
// BlockedBehaviour + RateLimited + RejectedLimit + Challenged (+
// BlockedCrawler since D57); since the
// 2026-10-29 addendum also PageViews <= Forwarded, PageViews <= Status.S2xx
// and BlockedWAF <= Detections <= BlockedWAF + WouldBlock, since D37
// WaitingPageShown <= FailClosedBy.WAFBusy + FailClosedBy.WAFTimeout, since
// the D33 amendment of 2026-10-29 Rechecked <= Requests (Check).
type TrafficCounters struct {
	Requests         int64        `json:"requests"`
	Forwarded        int64        `json:"forwarded"`
	Stopped          int64        `json:"stopped"`
	BlockedWAF       int64        `json:"blocked_waf"`
	BlockedBehaviour int64        `json:"blocked_behaviour"`
	RateLimited      int64        `json:"rate_limited"`
	RejectedLimit    int64        `json:"rejected_limit"`
	Challenged       int64        `json:"challenged"`
	FailClosed       int64        `json:"fail_closed"`
	FailClosedBy     FailClosedBy `json:"fail_closed_by"`
	WouldBlock       int64        `json:"would_block"`
	WouldRateLimit   int64        `json:"would_rate_limit"`
	// PageViews (addendum 2026-10-29): forwarded GET, 2xx, a document
	// request (Sec-Fetch-Dest document, or Accept naming text/html), bot
	// category likely_browser.
	PageViews int64 `json:"page_views"`
	// Detections (addendum 2026-10-29): the WAF reached its blocking
	// decision, enforced (BlockedWAF) or observed (part of WouldBlock).
	Detections int64 `json:"detections"`
	// WaitingPageShown (D37, MVP-23 step 1; optional, absent = 0): an
	// overlay of the fail-closed 503s, those answered with the waiting page
	// (contract/waitingpage); at most FailClosedBy.WAFBusy + WAFTimeout.
	WaitingPageShown int64 `json:"waiting_page_shown,omitempty"`
	// Rechecked (D33 amendment 2026-10-29; optional, absent = 0): an
	// overlay, requests schild evaluated more than once (e.g. again in
	// handle_errors); each still counts once in Requests and in one class
	// (Recheck). At most Requests.
	Rechecked int64 `json:"rechecked,omitempty"`
	// BlockedCrawler (D57, MVP-29; optional, absent = 0): 403 from the
	// crawler policy of a website. Part of Stopped.
	BlockedCrawler   int64         `json:"blocked_crawler,omitempty"`
	Status           StatusClasses `json:"status"`
	UpstreamErrors   int64         `json:"upstream_errors"`
	UpstreamTimeouts int64         `json:"upstream_timeouts"`
	BytesIn          int64         `json:"bytes_in"`
	BytesOut         int64         `json:"bytes_out"`
}

// Check reports whether the invariants hold.
func (t *TrafficCounters) Check() bool {
	f := t.FailClosedBy
	s := t.Status
	return t.Requests == t.Forwarded+t.Stopped+t.FailClosed &&
		t.Stopped == t.BlockedWAF+t.BlockedBehaviour+t.RateLimited+t.RejectedLimit+t.Challenged+t.BlockedCrawler &&
		t.FailClosed == f.WAFTimeout+f.WAFBusy+f.NotReady+f.Panic+f.BodyBusy &&
		t.Requests == s.S1xx+s.S2xx+s.S3xx+s.S4xx+s.S5xx &&
		t.PageViews <= t.Forwarded && t.PageViews <= s.S2xx &&
		t.BlockedWAF <= t.Detections && t.Detections <= t.BlockedWAF+t.WouldBlock &&
		t.WaitingPageShown <= f.WAFBusy+f.WAFTimeout+f.BodyBusy &&
		t.Rechecked >= 0 && t.Rechecked <= t.Requests
}

// Add adds o to t (merging buckets).
func (t *TrafficCounters) Add(o *TrafficCounters) {
	t.Requests += o.Requests
	t.Forwarded += o.Forwarded
	t.Stopped += o.Stopped
	t.BlockedWAF += o.BlockedWAF
	t.BlockedBehaviour += o.BlockedBehaviour
	t.RateLimited += o.RateLimited
	t.RejectedLimit += o.RejectedLimit
	t.Challenged += o.Challenged
	t.FailClosed += o.FailClosed
	t.FailClosedBy.WAFTimeout += o.FailClosedBy.WAFTimeout
	t.FailClosedBy.WAFBusy += o.FailClosedBy.WAFBusy
	t.FailClosedBy.NotReady += o.FailClosedBy.NotReady
	t.FailClosedBy.Panic += o.FailClosedBy.Panic
	t.FailClosedBy.BodyBusy += o.FailClosedBy.BodyBusy
	t.WouldBlock += o.WouldBlock
	t.WouldRateLimit += o.WouldRateLimit
	t.PageViews += o.PageViews
	t.Detections += o.Detections
	t.WaitingPageShown += o.WaitingPageShown
	t.Rechecked += o.Rechecked
	t.BlockedCrawler += o.BlockedCrawler
	t.Status.S1xx += o.Status.S1xx
	t.Status.S2xx += o.Status.S2xx
	t.Status.S3xx += o.Status.S3xx
	t.Status.S4xx += o.Status.S4xx
	t.Status.S5xx += o.Status.S5xx
	t.UpstreamErrors += o.UpstreamErrors
	t.UpstreamTimeouts += o.UpstreamTimeouts
	t.BytesIn += o.BytesIn
	t.BytesOut += o.BytesOut
}

// LatencyHistogram is sparse: bucket index (decimal string) -> count.
type LatencyHistogram struct {
	Scheme string           `json:"scheme"` // HistogramScheme
	Counts map[string]int64 `json:"counts"`
}

// TopEntry is one entry of a top list. For the rule list Requests counts
// the detections in which the rule matched.
type TopEntry struct {
	Key        string `json:"key"`
	Label      string `json:"label,omitempty"`
	Requests   int64  `json:"requests"`
	Stopped    int64  `json:"stopped"`
	WouldBlock int64  `json:"would_block"`
	// Detections on a path template (path list only; absent = 0).
	Detections int64 `json:"detections,omitempty"`
	Error      int64 `json:"error"`
}

// GaugeStats of the 10 s samples in a bucket.
type GaugeStats struct {
	Avg float64 `json:"avg"`
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// MetricValues of server, container, process and schild metrics by id.
type MetricValues struct {
	Counters map[string]float64    `json:"counters,omitempty"`
	Gauges   map[string]GaugeStats `json:"gauges,omitempty"`
}

// BucketLatency are the three histograms of a bucket.
type BucketLatency struct {
	Total    LatencyHistogram `json:"total"`
	Overhead LatencyHistogram `json:"overhead"`
	Upstream LatencyHistogram `json:"upstream"`
}

// BucketClients are per-bucket estimates (nil = unknown). UniqueDay (v0.5,
// D36): distinct clients since 00:00 UTC up to the end of the bucket.
// D36 amendment (2026-10-29): Unique, New and UniqueDay count visitors only
// (Visitor: browser requests schild forwarded); Bots counts the clients of
// every other request (BotClient), "Bot-Clients".
type BucketClients struct {
	Unique    *int64 `json:"unique"`
	New       *int64 `json:"new"`
	UniqueDay *int64 `json:"unique_day,omitempty"`
	Bots      *int64 `json:"bots,omitempty"`
}

// BucketTop are the top lists (1 min and 10 min rings only).
type BucketTop struct {
	Path     []TopEntry `json:"path,omitempty"`
	ASN      []TopEntry `json:"asn,omitempty"`
	Country  []TopEntry `json:"country,omitempty"`
	NetClass []TopEntry `json:"net_class,omitempty"`
	UAClass  []TopEntry `json:"ua_class,omitempty"`
	Method   []TopEntry `json:"method,omitempty"`
	// Addendum 2026-10-29 (MVP-22 MVP-21 addendum).
	Referrer    []TopEntry `json:"referrer,omitempty"` // space-saving, K = TopK
	Browser     []TopEntry `json:"browser,omitempty"`
	OS          []TopEntry `json:"os,omitempty"`
	Device      []TopEntry `json:"device,omitempty"`
	BotCategory []TopEntry `json:"bot_category,omitempty"`
	Rule        []TopEntry `json:"rule,omitempty"` // space-saving, K = TopK
}

// SiteTraffic is the traffic of one website (D36) or OtherSite. Since v0.5
// it carries the website's own latency histograms (per-website p95 and the
// MVP-20 merge across gateways); buckets written before have none.
type SiteTraffic struct {
	Site    string          `json:"site"`
	Traffic TrafficCounters `json:"traffic"`
	Latency *BucketLatency  `json:"latency,omitempty"`
	// Clients and Top (v0.5, D36 website overview): per-website estimates
	// and, in the 10 min ring only, per-website top lists (SiteTopK).
	Clients *BucketClients `json:"clients,omitempty"`
	Top     *BucketTop     `json:"top,omitempty"`
}

// SiteTopK is the size of the per-website space-saving lists (path, asn,
// country, referrer, rule) in MetricBucket.sites[].top (v0.5, D36).
const SiteTopK = 16

// ObjectValues are the values of one mount, device or interface.
type ObjectValues struct {
	Object string       `json:"object"`
	Kind   string       `json:"kind"` // mount | device | interface
	Values MetricValues `json:"values"`
}

// Gap kinds of a partial bucket or window (KpiValue.gap_kind,
// TrafficBreakdown.gap_kind, MetricBucket.gap_kind; initiator 2026-10-29):
// GapRestart, only orderly stops (every request schild answered is
// counted); GapLost, a hard stop, a skipped sample or a failed write (some
// answered requests may be missing). GapLost wins.
const (
	GapRestart = "restart"
	GapLost    = "lost"
)

// CheckpointIntervalS: the running 10 min bucket (gateway-wide and per
// website, top lists included) is written to its slot every 60 s as a
// checkpoint (partial, GapLost) and resumed from after a start inside the
// same bucket, so a hard stop loses at most one minute of the 10 min ring.
const CheckpointIntervalS = 60

// MetricBucket is one row of a ring and the unit of the MVP-20 export.
type MetricBucket struct {
	T          string     `json:"t"`
	Resolution Resolution `json:"resolution"`
	StepS      int        `json:"step_s"`
	Partial    bool       `json:"partial"`
	// GapKind (initiator 2026-10-29 evening): only with Partial, GapRestart
	// or GapLost; a minute checkpoint of a running 10 min bucket is written
	// with GapLost until the bucket is complete (CheckpointInterval).
	GapKind string          `json:"gap_kind,omitempty"`
	Traffic TrafficCounters `json:"traffic"`
	Latency BucketLatency   `json:"latency"`
	Clients BucketClients   `json:"clients"`
	Top     *BucketTop      `json:"top,omitempty"`
	Sites   []SiteTraffic   `json:"sites"`
	Values  MetricValues    `json:"values"`
	Objects []ObjectValues  `json:"objects,omitempty"`
}

// MetricBucketPage is the answer of listMetricBuckets.
type MetricBucketPage struct {
	Resolution Resolution     `json:"resolution"`
	Items      []MetricBucket `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

// MetricSeries is one series of a SeriesResult; nil values are gaps.
type MetricSeries struct {
	Metric     string     `json:"metric"`
	Stat       Stat       `json:"stat"`
	Kind       Kind       `json:"kind"`
	Unit       string     `json:"unit"`
	Exact      bool       `json:"exact"`
	ErrorBound float64    `json:"error_bound,omitempty"`
	Object     string     `json:"object,omitempty"`
	Values     []*float64 `json:"values"`
}

// SeriesResult is the answer of queryMetricSeries.
type SeriesResult struct {
	From       string     `json:"from"`
	To         string     `json:"to"`
	Resolution Resolution `json:"resolution"`
	StepS      int        `json:"step_s"`
	// BucketsPerPoint (v0.5, D36): ring buckets merged into one point
	// (MergeFactors); absent = 1.
	BucketsPerPoint int            `json:"buckets_per_point,omitempty"`
	Points          int            `json:"points"`
	Site            string         `json:"site,omitempty"`
	Series          []MetricSeries `json:"series"`
	Restarts        []string       `json:"restarts"`
	// v0.5 (D36): one flag per point (absent: none partial), the filters
	// applied and where a filtered series came from (rings | requests).
	Partial []bool   `json:"partial,omitempty"`
	Filters []string `json:"filters,omitempty"`
	Source  string   `json:"source,omitempty"`
	// Cluster: in a group of gateways, the nodes the answer adds up.
	Cluster *ClusterScope `json:"cluster,omitempty"`
}

// ClusterScope says which nodes of a group of gateways an answer covers
// (contracts/cluster.md section 9a); absent on a single gateway.
type ClusterScope struct {
	// Node is "all" or the id of the one node asked for.
	Node string `json:"node"`
	// Nodes are the nodes whose numbers the answer holds.
	Nodes []ClusterNode `json:"nodes"`
	// PartialNodes are nodes of Nodes whose history ends before the span
	// asked for does: the answer lacks their part from Until on.
	PartialNodes []ClusterPartialNode `json:"partial_nodes"`
	// ClientsAtLeast: the answer adds up several nodes, and its estimates
	// of distinct clients are the largest of the nodes, a lower bound.
	ClientsAtLeast bool `json:"clients_at_least"`
}

// ClusterNode is one node of a ClusterScope.
type ClusterNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Self bool   `json:"self,omitempty"`
}

// ClusterPartialNode is a node whose part of an answer is incomplete.
// Until is the end of what this gateway holds of it; absent: nothing yet.
type ClusterPartialNode struct {
	Node  string  `json:"node"`
	Name  string  `json:"name"`
	Until *string `json:"until,omitempty"`
}

// TrafficNow is the traffic of the last 60 s (MonitoringNow.traffic and,
// v0.5 D36, WebsiteSummary.now).
type TrafficNow struct {
	WindowS              int      `json:"window_s"`
	RequestsPerS         float64  `json:"requests_per_s"`
	RequestsPerS10s      float64  `json:"requests_per_s_10s"`
	StoppedShare         *float64 `json:"stopped_share"`
	WouldBlockShare      *float64 `json:"would_block_share"`
	FailClosed           int64    `json:"fail_closed"`
	UpstreamErrorShare   *float64 `json:"upstream_error_share"`
	LatencyTotalP50MS    *float64 `json:"latency_total_p50_ms"`
	LatencyTotalP95MS    *float64 `json:"latency_total_p95_ms"`
	LatencyOverheadP95MS *float64 `json:"latency_overhead_p95_ms"`
	LatencyUpstreamP95MS *float64 `json:"latency_upstream_p95_ms"`
	BytesInPerS          float64  `json:"bytes_in_per_s"`
	BytesOutPerS         float64  `json:"bytes_out_per_s"`
	// ClientsUnique: visitors in the window (D36 amendment: Visitor).
	ClientsUnique *int64 `json:"clients_unique,omitempty"`
}

// LiveSite is the per-site part of a LiveTick.
type LiveSite struct {
	Site     string `json:"site"`
	Requests int64  `json:"requests"`
	Stopped  int64  `json:"stopped"`
}

// LiveSchild are the internal queues in a LiveTick.
type LiveSchild struct {
	EventQueueFill float64 `json:"event_queue_fill"`
	EvalSlotsUsed  int     `json:"eval_slots_used"`
	EvalSlotsMax   int     `json:"eval_slots_max"`
}

// DiskNow is the fullest mount in ServerNow.
type DiskNow struct {
	Mount     string  `json:"mount"`
	UsedRatio float64 `json:"used_ratio"`
}

// ServerNow is the brief server sample of MonitoringNow and LiveTick.
type ServerNow struct {
	SampledAt            string   `json:"sampled_at"`
	Scope                string   `json:"scope"` // host | container | process
	CPUUsage             *float64 `json:"cpu_usage"`
	Cores                *int     `json:"cores"`
	Load1                *float64 `json:"load1"`
	MemoryUsedRatio      *float64 `json:"memory_used_ratio"`
	MemoryAvailableBytes *int64   `json:"memory_available_bytes"`
	SwapUsedBytes        *int64   `json:"swap_used_bytes"`
	Disk                 *DiskNow `json:"disk"`
	NetRxBytesPerS       *float64 `json:"net_rx_bytes_per_s"`
	NetTxBytesPerS       *float64 `json:"net_tx_bytes_per_s"`
	UptimeS              *int64   `json:"uptime_s,omitempty"`
}

// LiveTick is one `tick` of streamMonitoring.
type LiveTick struct {
	T                    string          `json:"t"`
	Traffic              TrafficCounters `json:"traffic"`
	LatencyTotalP95MS    *float64        `json:"latency_total_p95_ms,omitempty"`
	LatencyOverheadP95MS *float64        `json:"latency_overhead_p95_ms,omitempty"`
	Sites                []LiveSite      `json:"sites,omitempty"`
	Schild               *LiveSchild     `json:"schild,omitempty"`
	Server               *ServerNow      `json:"server,omitempty"`
}

// HealthHint codes (HealthHintCode); the UI renders German text by code.
const (
	HintCPUHigh            = "cpu_high"
	HintCPUThrottled       = "cpu_throttled"
	HintLoadHigh           = "load_high"
	HintMemoryLow          = "memory_low"
	HintSwapActive         = "swap_active"
	HintOOMKill            = "oom_kill"
	HintDiskFullSoon       = "disk_full_soon"
	HintDiskIOBusy         = "disk_io_busy"
	HintNetErrors          = "net_errors"
	HintConntrackHigh      = "conntrack_high"
	HintFDHigh             = "fd_high"
	HintListenDrops        = "listen_drops"
	HintUpstreamErrors     = "upstream_errors"
	HintUpstreamSlow       = "upstream_slow"
	HintFailClosed         = "fail_closed"
	HintWAFSaturated       = "waf_saturated"
	HintEventsDropped      = "events_dropped"
	HintStoreNearCap       = "store_near_cap"
	HintTrafficSpike       = "traffic_spike"
	HintMonitoringDegraded = "monitoring_degraded"
	// v0.5 (D38): storage bounds. store_cap_unreachable and storage_budget
	// mark only the server (websites.ServerOnlyHintCodes, like
	// store_near_cap); disk_fill_projection reaches every website.
	HintStoreCapUnreachable = "store_cap_unreachable"
	HintStorageBudget       = "storage_budget"
	HintDiskFillProjection  = "disk_fill_projection"
	// D108 (contracts/audit.md sections 4 and 6): the audit log. Both mark
	// only the server (websites.ServerOnlyHintCodes).
	HintAuditStuck = "audit_stuck"
	HintAuditSize  = "audit_size"
)

// HealthHint is one plain-language hint.
type HealthHint struct {
	Code      string   `json:"code"`
	Level     string   `json:"level"` // info | notice | warning
	Since     string   `json:"since"`
	Value     *float64 `json:"value,omitempty"`
	Threshold *float64 `json:"threshold,omitempty"`
	// Count is a number of things next to Value, only where the code says
	// so (audit_size: the entries of the last 30 days).
	Count  *int64 `json:"count,omitempty"`
	Object string `json:"object,omitempty"`
	// Site (v0.5, D36): the website of a website-scoped hint (SiteHintCodes);
	// absent for server-wide hints.
	Site string `json:"site,omitempty"`
}

// SiteHintCodes are computed per website from its own counters and carry
// HealthHint.Site (v0.5, D36); every other code is server-wide and reaches
// every website that runs on the server as a short hint.
var SiteHintCodes = map[string]bool{HintUpstreamErrors: true, HintUpstreamSlow: true, HintFailClosed: true, HintTrafficSpike: true}

// MetricInfo is one catalogue entry on the wire.
type MetricInfo struct {
	ID          string  `json:"id"`
	Kind        Kind    `json:"kind"`
	Unit        string  `json:"unit"`
	Scope       string  `json:"scope"`
	Exact       bool    `json:"exact"`
	ErrorBound  float64 `json:"error_bound,omitempty"`
	Stats       []Stat  `json:"stats"`
	DefaultStat Stat    `json:"default_stat"`
	PerObject   string  `json:"per_object"`
	SiteAware   bool    `json:"site_aware"`
	Available   bool    `json:"available"`
	Reason      string  `json:"reason,omitempty"`
}

// Info returns the wire entry of m (available; the server sets Available
// and Reason from what it can read).
func (m Metric) Info() MetricInfo {
	st := m.Kind.Stats()
	return MetricInfo{ID: m.ID, Kind: m.Kind, Unit: m.Unit, Scope: m.Scope, Exact: m.Exact, ErrorBound: m.ErrorBound,
		Stats: st, DefaultStat: st[0], PerObject: m.PerObject, SiteAware: m.SiteAware, Available: true}
}

// RingInfo describes one ring on the wire.
type RingInfo struct {
	Resolution Resolution `json:"resolution"`
	StepS      int        `json:"step_s"`
	KeepS      int64      `json:"keep_s"`
	Slots      int64      `json:"slots"`
	Oldest     *string    `json:"oldest,omitempty"`
}

// Info returns the wire description of r.
func (r Ring) Info() RingInfo {
	return RingInfo{Resolution: r.Resolution, StepS: int(r.Step.Seconds()), KeepS: int64(r.Keep.Seconds()), Slots: r.Slots()}
}

// MetricCatalogue is the answer of getMetricCatalogue.
type MetricCatalogue struct {
	Resolutions []RingInfo   `json:"resolutions"`
	MaxPoints   int          `json:"max_points"`
	MaxSeries   int          `json:"max_series"`
	Metrics     []MetricInfo `json:"metrics"`
}

// NewCatalogue returns the catalogue for the given rings, every metric
// marked available.
func NewCatalogue(rings []Ring) MetricCatalogue {
	c := MetricCatalogue{MaxPoints: MaxPoints, MaxSeries: MaxSeries}
	for _, r := range rings {
		c.Resolutions = append(c.Resolutions, r.Info())
	}
	for _, m := range Catalogue {
		c.Metrics = append(c.Metrics, m.Info())
	}
	return c
}
