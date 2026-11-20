package monitoring

import cm "github.com/deutschland-schild/schild/contract/monitoring"

// Wire types of getServerSnapshot (client-dashboard.openapi.yaml
// ServerSnapshot and its parts). contract/monitoring has the bucket, series
// and now types; the snapshot is served only by the gateway, so its types
// live here. Field names and optionality follow the OpenAPI schemas.

// Environment says what is visible from here.
type Environment struct {
	OSFamily     string `json:"os_family"` // linux | other
	Container    bool   `json:"container"`
	Cgroup       string `json:"cgroup"`        // v2 | v1 | none
	NetNamespace string `json:"net_namespace"` // host | own | unknown
	LXCFS        bool   `json:"lxcfs"`
}

// HostOS is the operating system of the gateway host.
type HostOS struct {
	Source   string  `json:"source"` // host_report | uname
	Name     string  `json:"name"`
	Kernel   string  `json:"kernel"`
	Arch     string  `json:"arch"`
	EOL      *string `json:"eol,omitempty"`
	ReportAt *string `json:"report_at,omitempty"`
}

// CPUSnapshot of the last sample interval.
type CPUSnapshot struct {
	Scope   string    `json:"scope"`
	Cores   int       `json:"cores"`
	Usage   float64   `json:"usage"`
	User    float64   `json:"user"`
	System  float64   `json:"system"`
	IOWait  float64   `json:"iowait"`
	Steal   float64   `json:"steal"`
	PerCore []float64 `json:"per_core,omitempty"`
	Load1   *float64  `json:"load1,omitempty"`
	Load5   *float64  `json:"load5,omitempty"`
	Load15  *float64  `json:"load15,omitempty"`
}

// MemorySnapshot from /proc/meminfo.
type MemorySnapshot struct {
	Scope          string `json:"scope"`
	TotalBytes     int64  `json:"total_bytes"`
	AvailableBytes int64  `json:"available_bytes"`
	UsedBytes      int64  `json:"used_bytes"`
	CachedBytes    int64  `json:"cached_bytes,omitempty"`
	SwapTotalBytes int64  `json:"swap_total_bytes"`
	SwapUsedBytes  int64  `json:"swap_used_bytes"`
	OOMKills24h    *int64 `json:"oom_kills_24h"`
}

// ContainerSnapshot from cgroup v2.
type ContainerSnapshot struct {
	CPULimitCores    *float64 `json:"cpu_limit_cores"`
	CPUUsage         float64  `json:"cpu_usage"`
	CPUThrottled     float64  `json:"cpu_throttled"`
	MemoryUsedBytes  int64    `json:"memory_used_bytes"`
	MemoryLimitBytes *int64   `json:"memory_limit_bytes"`
	OOMKills         int64    `json:"oom_kills"`
}

// MountSnapshot of one shown mount.
type MountSnapshot struct {
	Mount          string   `json:"mount"`
	Device         string   `json:"device,omitempty"`
	FSType         string   `json:"fs_type"`
	SizeBytes      int64    `json:"size_bytes"`
	UsedBytes      int64    `json:"used_bytes"`
	AvailBytes     int64    `json:"avail_bytes"`
	UsedRatio      float64  `json:"used_ratio"`
	InodesTotal    int64    `json:"inodes_total,omitempty"`
	InodesUsed     int64    `json:"inodes_used,omitempty"`
	ReadBytesPerS  *float64 `json:"read_bytes_per_s"`
	WriteBytesPerS *float64 `json:"write_bytes_per_s"`
	ReadsPerS      *float64 `json:"reads_per_s"`
	WritesPerS     *float64 `json:"writes_per_s"`
	Busy           *float64 `json:"busy"`
}

// InterfaceSnapshot of one shown interface.
type InterfaceSnapshot struct {
	Name          string  `json:"name"`
	RxBytesPerS   float64 `json:"rx_bytes_per_s"`
	TxBytesPerS   float64 `json:"tx_bytes_per_s"`
	RxPacketsPerS float64 `json:"rx_packets_per_s"`
	TxPacketsPerS float64 `json:"tx_packets_per_s"`
	ErrorsPerS    float64 `json:"errors_per_s"`
	DropsPerS     float64 `json:"drops_per_s"`
}

// TCPSnapshot: state counts.
type TCPSnapshot struct {
	Source          string   `json:"source"` // netlink | proc | sockstat
	Established     int64    `json:"established"`
	SynSent         int64    `json:"syn_sent"`
	SynRecv         int64    `json:"syn_recv"`
	FinWait         int64    `json:"fin_wait"`
	TimeWait        int64    `json:"time_wait"`
	CloseWait       int64    `json:"close_wait"`
	LastAck         int64    `json:"last_ack"`
	Closing         int64    `json:"closing"`
	Listen          *int64   `json:"listen"` // nil: unknown (sockstat path)
	InUse           *int64   `json:"inuse,omitempty"`
	Orphan          *int64   `json:"orphan,omitempty"`
	ListenDropsPerS *float64 `json:"listen_drops_per_s,omitempty"`
	RetransPerS     *float64 `json:"retransmits_per_s,omitempty"`
}

// Conntrack table use.
type Conntrack struct {
	Count int64 `json:"count"`
	Max   int64 `json:"max"`
}

// Files: system-wide open files.
type Files struct {
	Open int64 `json:"open"`
	Max  int64 `json:"max"`
}

// ProcessSnapshot of the schild process.
type ProcessSnapshot struct {
	StartedAt      string  `json:"started_at"`
	Version        string  `json:"version,omitempty"`
	CPUUsage       float64 `json:"cpu_usage"`
	RSSBytes       int64   `json:"rss_bytes"`
	HeapBytes      int64   `json:"heap_bytes"`
	Goroutines     int64   `json:"goroutines"`
	Threads        int64   `json:"threads"`
	GCPauseP99MS   float64 `json:"gc_pause_p99_ms"`
	OpenFiles      int64   `json:"open_files"`
	OpenFilesLimit int64   `json:"open_files_limit"`
}

// SchildInternals: queues and stores.
type SchildInternals struct {
	EventQueueUsed     int64   `json:"event_queue_used"`
	EventQueueCapacity int64   `json:"event_queue_capacity"`
	EventsDropped1h    int64   `json:"events_dropped_1h"`
	EvalSlotsUsed      int64   `json:"eval_slots_used"`
	EvalSlotsMax       int64   `json:"eval_slots_max"`
	StoreBytes         int64   `json:"store_bytes"`
	StoreMaxBytes      int64   `json:"store_max_bytes"`
	MetricsStoreBytes  int64   `json:"metrics_store_bytes"`
	SamplerMS          float64 `json:"sampler_ms"`
	SamplerBudgetMS    float64 `json:"sampler_budget_ms"`
	// StoreCapUnreachable: the last size-cap pass stopped above the cap
	// (hint store_cap_unreachable, D38); not part of the snapshot JSON.
	StoreCapUnreachable bool `json:"-"`
}

// Unavailable names an area that cannot be read here.
type Unavailable struct {
	Area   string `json:"area"`
	Reason string `json:"reason"`
}

// ServerSnapshot is the answer of getServerSnapshot.
type ServerSnapshot struct {
	GeneratedAt string              `json:"generated_at"`
	SampledAt   *string             `json:"sampled_at"`
	IntervalS   int                 `json:"interval_s"`
	Environment Environment         `json:"environment"`
	OS          *HostOS             `json:"os"`
	UptimeS     *int64              `json:"uptime_s,omitempty"`
	CPU         *CPUSnapshot        `json:"cpu"`
	Memory      *MemorySnapshot     `json:"memory"`
	Container   *ContainerSnapshot  `json:"container"`
	Mounts      []MountSnapshot     `json:"mounts"`
	Interfaces  []InterfaceSnapshot `json:"interfaces"`
	TCP         *TCPSnapshot        `json:"tcp"`
	Conntrack   *Conntrack          `json:"conntrack"`
	Files       *Files              `json:"files"`
	Process     ProcessSnapshot     `json:"process"`
	Schild      SchildInternals     `json:"schild"`
	Unavailable []Unavailable       `json:"unavailable"`
}

// TrafficNow is the traffic part of MonitoringNow (last 60 s and 10 s);
// the same type as WebsiteSummary.now (v0.5, D36).
type TrafficNow = cm.TrafficNow

// SiteNow is one site card of MonitoringNow (MVP-16).
type SiteNow struct {
	Site         string   `json:"site"`
	Label        string   `json:"label,omitempty"`
	RequestsPerS float64  `json:"requests_per_s"`
	StoppedShare *float64 `json:"stopped_share"`
}

// MonitoringNow is the answer of getMonitoringNow.
type MonitoringNow struct {
	GeneratedAt string          `json:"generated_at"`
	StartedAt   string          `json:"started_at"`
	Site        string          `json:"site,omitempty"`
	Traffic     TrafficNow      `json:"traffic"`
	Server      *cm.ServerNow   `json:"server"`
	Hints       []cm.HealthHint `json:"hints"`
	Sites       []SiteNow       `json:"sites,omitempty"`
}

// BreakdownCounts are the totals of a breakdown.
type BreakdownCounts struct {
	Requests   int64 `json:"requests"`
	Stopped    int64 `json:"stopped"`
	WouldBlock int64 `json:"would_block"`
}

// TrafficBreakdown is the answer of getTrafficBreakdown. Exact says how
// the numbers are made (counted vs bounded top list); Partial says the
// window was not fully covered (a partial bucket, a gap or a schild start
// inside it). Source is "rings" (the request ring is not wired yet).
type TrafficBreakdown struct {
	By              string          `json:"by"`
	From            string          `json:"from"`
	To              string          `json:"to"`
	Resolution      string          `json:"resolution"`
	Site            string          `json:"site,omitempty"`
	Exact           bool            `json:"exact"`
	Partial         bool            `json:"partial,omitempty"`
	GapKind         string          `json:"gap_kind,omitempty"`
	Source          string          `json:"source,omitempty"`
	BotVerification *bool           `json:"bot_verification,omitempty"`
	Total           BreakdownCounts `json:"total"`
	Items           []cm.TopEntry   `json:"items"`
	Other           BreakdownCounts `json:"other"`
}
