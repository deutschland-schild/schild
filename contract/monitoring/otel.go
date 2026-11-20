package monitoring

// OpenTelemetry mapping (v0.5, D36; initiator addendum 2026-10-29). The
// metric ids and dimensions of this contract stay as they are (renaming
// would break the built gateway, the dashboards and the rings on disk);
// this fixed table says how each one translates to the OpenTelemetry
// semantic conventions (HTTP and system metrics, semconv 1.2x), so a later
// optional OTLP export is a pure translation without guessing. No OTel
// dependency. Names starting with "schild." have no semantic convention and
// stay in the schild namespace. Tests keep the table complete.

// OTelMetric is the OpenTelemetry form of one metric id.
type OTelMetric struct {
	// Name of the OTel instrument.
	Name string
	// Unit in UCUM as OTel uses it ("s", "By", "1", "{request}", ...).
	Unit string
	// Attrs are fixed attributes that select this metric from the
	// instrument (e.g. the state of a usage metric).
	Attrs map[string]string
	// Scale converts the value (ms -> s: 0.001); 0 means 1.
	Scale float64
}

func om(name, unit string, attrs ...string) OTelMetric {
	m := OTelMetric{Name: name, Unit: unit}
	if len(attrs) > 0 {
		m.Attrs = map[string]string{}
		for i := 0; i+1 < len(attrs); i += 2 {
			m.Attrs[attrs[i]] = attrs[i+1]
		}
	}
	return m
}

func outcome(o string) OTelMetric {
	return om("schild.http.server.requests", "{request}", "schild.outcome", o)
}

// OTelMetrics maps every metric id of Catalogue. The request counts are
// the count of the duration histogram where OTel has one; schild's outcome
// classes are a schild attribute on a counter.
var OTelMetrics = map[string]OTelMetric{
	"traffic.requests":                om("http.server.request.duration", "s"), // histogram count
	"traffic.forwarded":               outcome("forwarded"),
	"traffic.stopped":                 outcome("stopped"),
	"traffic.blocked_waf":             outcome("blocked_waf"),
	"traffic.blocked_behaviour":       outcome("blocked_behaviour"),
	"traffic.rate_limited":            outcome("rate_limited"),
	"traffic.rejected_limit":          outcome("rejected_limit"),
	"traffic.challenged":              outcome("challenged"),
	"traffic.fail_closed":             outcome("fail_closed"),
	"traffic.fail_closed_waf_busy":    om("schild.http.server.requests", "{request}", "schild.outcome", "fail_closed", "error.type", "waf_busy"),
	"traffic.fail_closed_waf_timeout": om("schild.http.server.requests", "{request}", "schild.outcome", "fail_closed", "error.type", "waf_timeout"),
	"traffic.would_block":             outcome("would_block"),
	"traffic.would_rate_limit":        outcome("would_rate_limit"),
	"traffic.page_views":              om("schild.http.server.page_views", "{request}"),
	"traffic.detections":              om("schild.waf.detections", "{request}"),
	"traffic.waiting_page_shown":      om("schild.http.server.waiting_page", "{request}"), // D37
	"traffic.blocked_crawler":         outcome("blocked_crawler"),                         // D57
	// OTel wants the exact status code; the rings keep classes only.
	"traffic.status_1xx":        om("http.server.request.duration", "s", "schild.http.status_class", "1xx"),
	"traffic.status_2xx":        om("http.server.request.duration", "s", "schild.http.status_class", "2xx"),
	"traffic.status_3xx":        om("http.server.request.duration", "s", "schild.http.status_class", "3xx"),
	"traffic.status_4xx":        om("http.server.request.duration", "s", "schild.http.status_class", "4xx"),
	"traffic.status_5xx":        om("http.server.request.duration", "s", "schild.http.status_class", "5xx"),
	"traffic.upstream_errors":   om("http.client.request.duration", "s", "error.type", "connection_failed"),
	"traffic.upstream_timeouts": om("http.client.request.duration", "s", "error.type", "timeout"),
	"traffic.bytes_in":          om("http.server.request.body.size", "By"),
	"traffic.bytes_out":         om("http.server.response.body.size", "By"),
	"traffic.latency_total":     {Name: "http.server.request.duration", Unit: "s", Scale: 0.001},
	"traffic.latency_upstream":  {Name: "http.client.request.duration", Unit: "s", Scale: 0.001}, // schild -> app
	"traffic.latency_overhead":  {Name: "schild.http.server.overhead.duration", Unit: "s", Scale: 0.001},
	"traffic.clients_unique":    om("schild.http.server.clients", "{client}", "schild.clients", "unique"),
	"traffic.clients_new":       om("schild.http.server.clients", "{client}", "schild.clients", "new"),

	"server.cpu_usage":              om("system.cpu.utilization", "1"),
	"server.cpu_iowait":             om("system.cpu.utilization", "1", "cpu.mode", "iowait"),
	"server.cpu_steal":              om("system.cpu.utilization", "1", "cpu.mode", "steal"),
	"server.load1":                  om("system.cpu.load_average.1m", "{thread}"),
	"server.load5":                  om("system.cpu.load_average.5m", "{thread}"),
	"server.load15":                 om("system.cpu.load_average.15m", "{thread}"),
	"server.memory_used":            om("system.memory.usage", "By", "system.memory.state", "used"),
	"server.memory_available":       om("system.linux.memory.available", "By"),
	"server.swap_used":              om("system.paging.usage", "By", "system.paging.state", "used"),
	"server.disk_used":              om("system.filesystem.usage", "By", "system.filesystem.state", "used"),
	"server.disk_used_ratio":        om("system.filesystem.utilization", "1"),
	"server.disk_inodes_used_ratio": om("schild.system.filesystem.inodes.utilization", "1"),
	"server.disk_read_bytes":        om("system.disk.io", "By", "disk.io.direction", "read"),
	"server.disk_write_bytes":       om("system.disk.io", "By", "disk.io.direction", "write"),
	"server.disk_busy":              om("schild.system.disk.busy", "1"), // rate of system.disk.io_time
	"server.net_rx_bytes":           om("system.network.io", "By", "network.io.direction", "receive"),
	"server.net_tx_bytes":           om("system.network.io", "By", "network.io.direction", "transmit"),
	"server.net_errors":             om("system.network.errors", "{error}"),
	"server.net_drops":              om("system.network.dropped", "{packet}"),
	"server.tcp_established":        om("system.network.connections", "{connection}", "network.transport", "tcp", "network.connection.state", "established"),
	"server.tcp_syn_recv":           om("system.network.connections", "{connection}", "network.transport", "tcp", "network.connection.state", "syn_recv"),
	"server.tcp_time_wait":          om("system.network.connections", "{connection}", "network.transport", "tcp", "network.connection.state", "time_wait"),
	"server.tcp_close_wait":         om("system.network.connections", "{connection}", "network.transport", "tcp", "network.connection.state", "close_wait"),
	"server.tcp_listen_drops":       om("schild.system.network.tcp.listen_drops", "{connection}"),
	"server.tcp_retransmits":        om("schild.system.network.tcp.retransmits", "{segment}"),
	"server.conntrack_used_ratio":   om("schild.system.network.conntrack.utilization", "1"),
	"server.files_open_ratio":       om("schild.system.files.utilization", "1"),
	"container.cpu_usage":           om("container.cpu.usage", "{cpu}"),
	"container.cpu_throttled":       om("schild.container.cpu.throttled", "1"),
	"container.memory_used":         om("container.memory.usage", "By"),
	"process.cpu_usage":             om("process.cpu.utilization", "1"),
	"process.rss":                   om("process.memory.usage", "By"),
	"process.heap":                  om("go.memory.used", "By"),
	"process.goroutines":            om("go.goroutine.count", "{goroutine}"),
	"process.gc_pause_p99":          {Name: "schild.go.gc.pause.p99", Unit: "s", Scale: 0.001},
	"process.open_files":            om("process.open_file_descriptor.count", "{file_descriptor}"),
	"schild.event_queue_fill":       om("schild.event_queue.utilization", "1"),
	"schild.events_dropped":         om("schild.events.dropped", "{event}"),
	"schild.eval_slots_used":        om("schild.waf.eval_slots.utilization", "1"),
	"schild.store_bytes":            om("schild.store.size", "By"),
	"schild.sampler_ms":             {Name: "schild.monitoring.sampler.duration", Unit: "s", Scale: 0.001},
}

// OTelAttributes maps the breakdown dimensions, objects and labels of this
// contract to OTel attribute names. site carries the website's first host
// (WebsiteSummary.hosts[0], or the label for _any and default), not the id
// with "_" for a wildcard label.
var OTelAttributes = map[string]string{
	"site":         "server.address",
	"path":         "http.route", // path template, never the raw path
	"method":       "http.request.method",
	"status_class": "schild.http.status_class",
	"country":      "geo.country.iso_code",
	"asn":          "schild.client.asn",
	"net_class":    "schild.client.net_class",
	"ua_class":     "schild.user_agent.class",
	"browser":      "user_agent.name",
	"os":           "user_agent.os.name",
	"device":       "schild.user_agent.device",
	"bot_category": "schild.bot.category",
	"referrer":     "schild.http.referrer.domain",
	"rule":         "schild.waf.rule.id",
	"mount":        "system.filesystem.mountpoint",
	"device_io":    "system.device",
	"interface":    "network.interface.name",
	"node":         "host.name", // resource attribute: node_name of the gateway
}
