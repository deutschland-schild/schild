package crawlers

import "github.com/prometheus/client_golang/prometheus"

var descRequests = prometheus.NewDesc("schild_crawler_requests_total",
	"Requests a crawler policy blocked or would have blocked (observe mode, allowlisted address), by catalogue bot id.",
	[]string{"bot", "outcome"}, nil)

type collector struct{ c *Control }

// Collector exposes schild_crawler_requests_total{bot,outcome} with
// outcome blocked_crawler or would_block, summed over the websites. Bot ids
// come from the catalogue, never from a request.
func Collector(c *Control) prometheus.Collector { return collector{c} }

func (x collector) Describe(ch chan<- *prometheus.Desc) { ch <- descRequests }

func (x collector) Collect(ch chan<- prometheus.Metric) {
	for _, n := range x.c.Totals() {
		b := x.c.eng.Bot(n.Bot)
		if b == nil {
			continue
		}
		if n.Blocked > 0 {
			ch <- prometheus.MustNewConstMetric(descRequests, prometheus.CounterValue, float64(n.Blocked), b.ID, "blocked_crawler")
		}
		if n.WouldBlock > 0 {
			ch <- prometheus.MustNewConstMetric(descRequests, prometheus.CounterValue, float64(n.WouldBlock), b.ID, "would_block")
		}
	}
}
