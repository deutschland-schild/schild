package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// Prometheus on the metrics port gets the same traffic counters and
// histograms (spec MVP-21 api): labels without visitor data, path or
// country. They are cumulative totals since start, kept by the 1 Hz
// aggregation, so the request path does no extra work for them.

var (
	descRequests = prometheus.NewDesc("schild_http_requests_total", "Requests that reached the schild handler, by what schild did.", []string{"class"}, nil)
	descBytes    = prometheus.NewDesc("schild_http_bytes_total", "Request and response body bytes read and written by the gate.", []string{"direction"}, nil)
	descLatency  = prometheus.NewDesc("schild_http_latency_seconds", "Latency by part: total, upstream (the app) and overhead (schild).", []string{"part"}, nil)
	// D37: an overlay of the fail-closed 503s (waf_busy, waf_timeout and,
	// D41, body_busy), not a class of schild_http_requests_total.
	descWaitingPage = prometheus.NewDesc(cm.PromWaitingPageShown, "Fail-closed 503s (waf_busy, waf_timeout, body_busy) answered with the waiting page.", nil, nil)
)

var promClasses = []struct {
	name string
	slot int
}{
	{"forwarded", cForwarded}, {"blocked_waf", cBlockedWAF}, {"blocked_behaviour", cBlockedBehaviour}, {"rate_limited", cRateLimited},
	{"rejected_limit", cRejectedLimit}, {"challenged", cChallenged}, {"fail_closed_waf_timeout", cFCTimeout}, {"fail_closed_waf_busy", cFCBusy},
	{"fail_closed_not_ready", cFCNotReady}, {"fail_closed_panic", cFCPanic}, {"blocked_crawler", cBlockedCrawler},
}

type collector struct{ m *Monitor }

// Collector returns the Prometheus collector of the traffic totals.
func (m *Monitor) Collector() prometheus.Collector { return collector{m} }

func (c collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descRequests
	ch <- descBytes
	ch <- descLatency
	ch <- descWaitingPage
}

func (c collector) Collect(ch chan<- prometheus.Metric) {
	m := c.m
	m.mu.Lock()
	tot := m.total.c
	hist := m.total.hist
	m.mu.Unlock()
	for _, k := range promClasses {
		ch <- prometheus.MustNewConstMetric(descRequests, prometheus.CounterValue, float64(tot[k.slot]), k.name)
	}
	ch <- prometheus.MustNewConstMetric(descBytes, prometheus.CounterValue, float64(tot[cBytesIn]), "in")
	ch <- prometheus.MustNewConstMetric(descBytes, prometheus.CounterValue, float64(tot[cBytesOut]), "out")
	ch <- prometheus.MustNewConstMetric(descWaitingPage, prometheus.CounterValue, float64(tot[cWaitingPage]))
	for part, name := range []string{"total", "overhead", "upstream"} {
		buckets := map[float64]uint64{}
		var cum uint64
		var sum float64
		for i := 0; i < cm.HistogramBuckets-1; i++ {
			cum += uint64(hist[part][i])
			bound := cm.BucketBound(i) / 1000
			buckets[bound] = cum
			sum += float64(hist[part][i]) * bound
		}
		cum += uint64(hist[part][cm.HistogramBuckets-1])
		ch <- prometheus.MustNewConstHistogram(descLatency, cum, sum, buckets, name)
	}
}
