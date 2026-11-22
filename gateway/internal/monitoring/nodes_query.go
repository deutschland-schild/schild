package monitoring

import (
	"strconv"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	cr "github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/contract/websites"
)

// The queries of the stored history live on NodeView (nodes.go). On the
// monitor itself they answer for every node this gateway holds history of:
// the whole group, and on a single gateway the gateway.

// Series answers queryMetricSeries for every node.
func (m *Monitor) Series(q SeriesQuery, now time.Time) (cm.SeriesResult, error) {
	return m.all().Series(q, now)
}

// Breakdown answers getTrafficBreakdown for every node.
func (m *Monitor) Breakdown(by string, from, to time.Time, site string, filters []string, top int, now time.Time) (TrafficBreakdown, error) {
	return m.all().Breakdown(by, from, to, site, filters, top, now)
}

// Totals sums the traffic counters of [from, to) for every node.
func (m *Monitor) Totals(site string, from, to, now time.Time) (*cm.TrafficCounters, error) {
	return m.all().Totals(site, from, to, now)
}

// TotalsCovered is Totals with what the rings covered, for every node.
func (m *Monitor) TotalsCovered(site string, from, to, now time.Time) (*cm.TrafficCounters, Coverage, error) {
	return m.all().TotalsCovered(site, from, to, now)
}

// Kpis answers getWebsiteKpis for every node.
func (m *Monitor) Kpis(site string, from, to time.Time, filters []string, now time.Time) (websites.KpiSet, error) {
	return m.all().Kpis(site, from, to, filters, now)
}

// KpisSource names where Kpis reads from, for every node.
func (m *Monitor) KpisSource(filters []string, from, to, now time.Time) string {
	return m.all().KpisSource(filters, from, to, now)
}

// Realtime answers getWebsiteRealtime for every node.
func (m *Monitor) Realtime(site string, now time.Time) (websites.Realtime, error) {
	return m.all().Realtime(site, now)
}

// Strip returns the site-wide strip of [from, to] for every node.
func (m *Monitor) Strip(site string, from, to time.Time) []cr.StripPoint {
	if m == nil {
		return []cr.StripPoint{}
	}
	return m.all().Strip(site, from, to)
}

// nowLag is how far behind the clock the last 60 s of a group end: a 10 s
// bucket of another node arrives within the pull interval after it closed.
const nowLag = 20 * time.Second

// Now answers getMonitoringNow for the nodes of the view. This gateway
// alone answers from memory, as a single gateway does. The group, or one
// other member, answers from the 10 s ring: the last six buckets that
// every node had time to hand over, so the numbers end about 20 s ago.
// Hints and the host sample are those of this gateway and absent for
// another member.
func (v NodeView) Now(site string, now time.Time) (MonitoringNow, error) {
	if !v.Merged() && !v.Foreign() {
		out, err := v.Monitor.Now(site, now)
		if err == nil {
			out.Cluster = v.Scope(now.Add(-time.Minute), now, now)
		}
		return out, err
	}
	sel, err := v.selectSite(site)
	if err != nil {
		return MonitoringNow{}, err
	}
	out := MonitoringNow{GeneratedAt: ts(now), Site: site, Traffic: TrafficNow{WindowS: 60}, Hints: []cm.HealthHint{}}
	if !v.Foreign() {
		local, lerr := v.Monitor.Now(site, now)
		if lerr != nil {
			return MonitoringNow{}, lerr
		}
		out.StartedAt, out.Hints, out.Server = local.StartedAt, local.Hints, local.Server
	}
	ring := v.rings[0]
	last := ring.Start(now.Add(-nowLag)).Add(-ring.Step)
	first := last.Add(-5 * ring.Step)
	out.Cluster = v.Scope(first, last.Add(ring.Step), now)
	if sel.none {
		return out, nil
	}
	parts := readSeries
	parts.only = onlyOf(sel)
	if !sel.whole {
		parts.core = coreSites
	}
	var sum cm.MetricBucket
	sum.Latency = cm.BucketLatency{Total: emptyHist(), Overhead: emptyHist(), Upstream: emptyHist()}
	var newest int64
	n := 0
	_ = v.readNodes(ring, first, last, parts, func(t time.Time, b *cm.MetricBucket) {
		sb := siteBucket(b, sel)
		if sb == nil {
			return
		}
		n++
		if t.Equal(last) {
			newest = sb.Traffic.Requests
		}
		sum.Traffic.Add(&sb.Traffic)
		mergeLatency(&sum.Latency, &sb.Latency)
		maxClients(&sum.Clients, &sb.Clients)
	})
	out.Traffic = trafficNowOf(&sum, newest)
	if n > 0 {
		out.Traffic.ClientsUnique = sum.Clients.Unique
	}
	return out, nil
}

// trafficNowOf is TrafficNow from the sum of the last six 10 s buckets;
// newest are the requests of the last of them.
func trafficNowOf(sum *cm.MetricBucket, newest int64) TrafficNow {
	c := &sum.Traffic
	share := func(a, b int64) *float64 {
		if b == 0 {
			return nil
		}
		x := float64(a) / float64(b)
		return &x
	}
	q := func(h *cm.LatencyHistogram, p float64) *float64 {
		counts := map[int]int64{}
		for k, x := range h.Counts {
			if i, cerr := strconv.Atoi(k); cerr == nil {
				counts[i] = x
			}
		}
		x, ok := cm.Quantile(counts, p)
		if !ok {
			return nil
		}
		return &x
	}
	return TrafficNow{
		WindowS: 60, RequestsPerS: float64(c.Requests) / 60, RequestsPerS10s: float64(newest) / 10,
		StoppedShare: share(c.Stopped, c.Requests), WouldBlockShare: share(c.WouldBlock, c.Requests), FailClosed: c.FailClosed,
		UpstreamErrorShare: share(c.UpstreamErrors+c.UpstreamTimeouts, c.Forwarded),
		LatencyTotalP50MS:  q(&sum.Latency.Total, 0.5), LatencyTotalP95MS: q(&sum.Latency.Total, 0.95),
		LatencyOverheadP95MS: q(&sum.Latency.Overhead, 0.95), LatencyUpstreamP95MS: q(&sum.Latency.Upstream, 0.95),
		BytesInPerS: float64(c.BytesIn) / 60, BytesOutPerS: float64(c.BytesOut) / 60,
	}
}

// GroupSitesNow returns the last 60 s of every website over the nodes of
// the group, by website id, from the 10 s ring (see NodeView.Now for the
// lag); nil on a single gateway, whose numbers come from memory.
func (m *Monitor) GroupSitesNow(now time.Time) map[string]*TrafficNow {
	v := m.all()
	if !v.Merged() {
		return nil
	}
	ring := v.rings[0]
	last := ring.Start(now.Add(-nowLag)).Add(-ring.Step)
	first := last.Add(-5 * ring.Step)
	type acc struct {
		sum    cm.MetricBucket
		newest int64
	}
	sums := map[string]*acc{}
	_ = v.readNodes(ring, first, last, readSeries, func(t time.Time, b *cm.MetricBucket) {
		for i := range b.Sites {
			s := &b.Sites[i]
			a := sums[s.Site]
			if a == nil {
				a = &acc{}
				a.sum.Latency = cm.BucketLatency{Total: emptyHist(), Overhead: emptyHist(), Upstream: emptyHist()}
				sums[s.Site] = a
			}
			if t.Equal(last) {
				a.newest = s.Traffic.Requests
			}
			a.sum.Traffic.Add(&s.Traffic)
			if s.Latency != nil {
				mergeLatency(&a.sum.Latency, s.Latency)
			}
			if s.Clients != nil {
				maxClients(&a.sum.Clients, s.Clients)
			}
		}
	})
	out := make(map[string]*TrafficNow, len(sums))
	for id, a := range sums {
		tn := trafficNowOf(&a.sum, a.newest)
		tn.ClientsUnique = a.sum.Clients.Unique
		out[id] = &tn
	}
	return out
}
