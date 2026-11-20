// Package metrics exposes Prometheus metrics (schild_*) on the metrics port.
// Labels never carry visitor data: no IPs, paths or user agents.
package metrics

import (
	"github.com/deutschland-schild/schild/contract/access"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/deutschland-schild/schild/contract/bodylimit"
)

// Metrics of one schild process.
type Metrics struct {
	Reg           *prometheus.Registry
	Requests      *prometheus.CounterVec
	WAFSeconds    prometheus.Histogram
	HardLimits    *prometheus.CounterVec
	EventsWritten prometheus.Counter
	EventsDropped prometheus.Counter
	// IncidentHitsDropped: hits of an aggregated incident lost under load.
	IncidentHitsDropped prometheus.Counter
	RuleSwaps           prometheus.Counter
	RuleSwapSeconds     prometheus.Histogram
	BaselineProtection  prometheus.Gauge
	// Request bodies (D41, contracts/body-limits.md section 6).
	BodiesInFlight    prometheus.Gauge
	BodyBytesInFlight prometheus.Gauge
	BodiesWaiting     prometheus.Gauge
	RequestsWaiting   prometheus.Gauge
	MemoryPressure    prometheus.Gauge
	// D46
	ConnectionsOpen   prometheus.Gauge
	ConnsRefused      *prometheus.CounterVec
	ConnsEvicted      *prometheus.CounterVec
	LocalRulesReloads *prometheus.CounterVec
	// AccessLogins counts logins of the access lock by result (D56).
	AccessLogins       *prometheus.CounterVec
	BodyWaitingBytes   prometheus.Gauge
	BodySpoolBytes     prometheus.Gauge
	BodiesAborted      *prometheus.CounterVec
	BodiesBelowMinRate prometheus.Counter
	BodyReadSeconds    prometheus.Histogram
	BodyRate           prometheus.Histogram
}

// New registers all metrics on a fresh registry.
func New() *Metrics {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	f := func(c prometheus.Collector) { r.MustRegister(c) }
	m := &Metrics{Reg: r}
	m.Requests = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "schild_requests_total", Help: "Requests by outcome."}, []string{"outcome"})
	m.WAFSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "schild_waf_seconds", Help: "Time spent in the WAF per request (overhead).",
		Buckets: []float64{.0001, .00025, .0005, .001, .002, .003, .005, .01, .025, .05, .1, .25, .5, 1}})
	m.HardLimits = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "schild_hard_limit_rejects_total", Help: "Requests rejected by hard limits (never passed uninspected)."}, []string{"code"})
	m.EventsWritten = prometheus.NewCounter(prometheus.CounterOpts{Name: "schild_events_written_total", Help: "Local events written."})
	m.IncidentHitsDropped = prometheus.NewCounter(prometheus.CounterOpts{Name: "schild_incident_hits_dropped_total", Help: "Hits of aggregated incidents dropped: the pending map was full or the row never appeared."})
	m.EventsDropped = prometheus.NewCounter(prometheus.CounterOpts{Name: "schild_events_dropped_total", Help: "Local events dropped because the writer queue was full."})
	m.RuleSwaps = prometheus.NewCounter(prometheus.CounterOpts{Name: "schild_rule_swaps_total", Help: "Atomic WAF rule swaps."})
	m.RuleSwapSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "schild_rule_swap_build_seconds", Help: "Time to build a new WAF instance before the swap.",
		Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}})
	m.BaselineProtection = prometheus.NewGauge(prometheus.GaugeOpts{Name: "schild_baseline_protection_active", Help: "1 when the local WAF with CRS runs (baseline protection)."})
	m.BodiesInFlight = prometheus.NewGauge(prometheus.GaugeOpts{Name: bodylimit.PromBodiesInFlight, Help: "Request bodies being read."})
	m.BodyBytesInFlight = prometheus.NewGauge(prometheus.GaugeOpts{Name: bodylimit.PromBodyBytesInFlight, Help: "Held bytes of request bodies until the request ended, a multipart body counted twice while Coraza holds it."})
	m.BodiesWaiting = prometheus.NewGauge(prometheus.GaugeOpts{Name: bodylimit.PromBodiesWaiting, Help: "Checked request bodies waiting for the backend."})
	m.BodyWaitingBytes = prometheus.NewGauge(prometheus.GaugeOpts{Name: bodylimit.PromBodyWaitingBytes, Help: "Memory held by checked request bodies waiting for the backend, overhead of the request included."})
	m.RequestsWaiting = prometheus.NewGauge(prometheus.GaugeOpts{Name: bodylimit.PromRequestsWaiting, Help: "Requests between their admission and their end, with or without a body."})
	m.MemoryPressure = prometheus.NewGauge(prometheus.GaugeOpts{Name: bodylimit.PromMemoryPressure, Help: "Memory pressure of the container: 0 none, 1 bodies are refused, 2 all requests are refused, -1 no brake is running."})
	m.ConnectionsOpen = prometheus.NewGauge(prometheus.GaugeOpts{Name: bodylimit.PromConnections, Help: "Open connections of the ingress."})
	m.ConnsRefused = prometheus.NewCounterVec(prometheus.CounterOpts{Name: bodylimit.PromConnsRefused, Help: "Connections closed at accept because a limit was full and nothing idle could give way, by scope."}, []string{"scope"})
	m.ConnsEvicted = prometheus.NewCounterVec(prometheus.CounterOpts{Name: bodylimit.PromConnsEvicted, Help: "Idle connections closed to make room for a new one, by scope."}, []string{"scope"})
	m.LocalRulesReloads = prometheus.NewCounterVec(prometheus.CounterOpts{Name: bodylimit.PromLocalRulesReloads, Help: "Reloads of rules.d by result."}, []string{"result"})
	for _, scope := range []string{bodylimit.ScopeClient, bodylimit.ScopeNetwork, bodylimit.ScopeGateway} {
		m.ConnsRefused.WithLabelValues(scope)
		m.ConnsEvicted.WithLabelValues(scope)
	}
	for _, result := range []string{bodylimit.ReloadApplied, bodylimit.ReloadUnchanged, bodylimit.ReloadRefused} {
		m.LocalRulesReloads.WithLabelValues(result)
	}
	m.AccessLogins = prometheus.NewCounterVec(prometheus.CounterOpts{Name: access.PromLogins, Help: "Logins at the access lock by result."}, []string{"result"})
	for _, result := range []string{"ok", "wrong", "locked_out", "busy"} {
		m.AccessLogins.WithLabelValues(result)
	}
	m.BodySpoolBytes = prometheus.NewGauge(prometheus.GaugeOpts{Name: bodylimit.PromBodySpoolBytes, Help: "Size of the temp files of request bodies."})
	m.BodiesAborted = prometheus.NewCounterVec(prometheus.CounterOpts{Name: bodylimit.PromBodiesAborted, Help: "Request bodies refused or ended before they were read, by reason."}, []string{"reason"})
	for _, reason := range []string{bodylimit.AbortTooLarge, bodylimit.AbortShare, bodylimit.AbortBusy, bodylimit.AbortClientGone, bodylimit.AbortTooSlow} {
		m.BodiesAborted.WithLabelValues(reason)
	}
	m.BodiesBelowMinRate = prometheus.NewCounter(prometheus.CounterOpts{Name: bodylimit.PromBodiesBelowMinRate, Help: "Request bodies an enforced minimum rate would have ended."})
	m.BodyReadSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{Name: bodylimit.PromBodyReadSeconds, Help: "Time from the start to the end of reading a request body.", Buckets: bodylimit.ReadSecondsBuckets})
	m.BodyRate = prometheus.NewHistogram(prometheus.HistogramOpts{Name: bodylimit.PromBodyRate, Help: "Receive rate of request bodies over complete windows.", Buckets: bodylimit.RateBuckets})
	for _, c := range []prometheus.Collector{m.BodiesInFlight, m.BodyBytesInFlight, m.BodiesWaiting, m.BodyWaitingBytes, m.RequestsWaiting, m.MemoryPressure, m.BodySpoolBytes, m.BodiesAborted, m.BodiesBelowMinRate, m.BodyReadSeconds, m.BodyRate,
		m.ConnectionsOpen, m.ConnsRefused, m.ConnsEvicted, m.LocalRulesReloads, m.AccessLogins} {
		f(c)
	}
	for _, c := range []prometheus.Collector{m.Requests, m.WAFSeconds, m.HardLimits, m.EventsWritten, m.EventsDropped, m.IncidentHitsDropped,
		m.RuleSwaps, m.RuleSwapSeconds, m.BaselineProtection} {
		f(c)
	}
	return m
}

// Handler serves /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Reg, promhttp.HandlerOpts{})
}
