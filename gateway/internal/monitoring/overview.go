package monitoring

import (
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// v0.5 (D36 addendum "Plausible"): the reads behind the website overview -
// counters of a range (getWebsite traffic_24h), the KPI row
// (getWebsiteKpis), Echtzeit (getWebsiteRealtime), restarts and gaps
// (listAnnotations). Primary key range reads of the rings; nothing here
// scans or returns an address.

// Totals sums the counters of a website (or the gateway for "") over
// [from, to) from the 10 min ring, lost 10 min buckets from the 1 min ring
// (readFilled). nil: no numbers for the website.
func (m NodeView) Totals(site string, from, to, now time.Time) (*cm.TrafficCounters, error) {
	tc, _, err := m.TotalsCovered(site, from, to, now)
	return tc, err
}

// Coverage says whether Totals counted the whole range (D36 open items
// 2026-10-29, WebsiteDetail.traffic_24h_partial and _since).
type Coverage struct {
	// Partial: the counters miss a part of the range - a schild start, a
	// gap or a bucket marked partial inside it, or the range begins before
	// the first counted bucket.
	Partial bool
	// Since is the start of the counted window when it begins later than
	// the range: the first bucket after a schild start or the oldest
	// bucket the ring still holds (zero = the whole range).
	Since time.Time
}

// TotalsCovered is Totals with the coverage of the range.
func (m NodeView) TotalsCovered(site string, from, to, now time.Time) (*cm.TrafficCounters, Coverage, error) {
	var out Coverage
	sel, err := m.selectSite(site)
	if err != nil {
		return nil, out, err
	}
	if sel.none {
		return nil, out, nil
	}
	ring := m.rings[2]
	start, end := ring.Start(from), ring.Start(to.Add(-time.Nanosecond))
	first := start
	if o := ring.Oldest(now); start.Before(o) {
		start = o
	}
	parts := readParts{core: coreTraffic}
	if !sel.whole {
		parts.core, parts.only = coreSites, sel.id
	}
	var tc cm.TrafficCounters
	var cov coverage
	err = m.readFilled(start, end, now, parts, true, &cov, func(_ time.Time, b *cm.MetricBucket) {
		if sb := siteBucket(b, sel); sb != nil {
			tc.Add(&sb.Traffic)
		}
	})
	if err != nil {
		return nil, out, err
	}
	out.Partial = m.incomplete(&cov, end)
	switch {
	case cov.n > 0 && cov.first.After(first):
		out.Partial, out.Since = true, cov.first
	case cov.n == 0:
		// Nothing stored in the range yet: counted from schild's start
		// (the bucket it started in) when that is inside the range.
		out.Partial = true
		if s := ring.Start(m.started); s.After(first) {
			out.Since = s
		}
	}
	return &tc, out, nil
}

// kpisRings returns the KPI row of a website over [from, to) from the 10 min
// ring (ranges are rounded to 10 min), lost 10 min buckets from the 1 min
// ring (readFilled). One filter answers requests,
// stopped and would_block from the per-website top lists; the other KPIs
// then need the request ring (unavailable filter_needs_requests). Two or
// more filters, or an ip or user_agent filter (D64): ErrFilterUnavailable.
func (m NodeView) kpisRings(site string, from, to time.Time, filters []string, now time.Time) (websites.KpiSet, error) {
	sel, err := m.selectSite(site)
	if err != nil {
		return websites.KpiSet{}, err
	}
	fs, err := ParseFilters(filters)
	if err != nil {
		return websites.KpiSet{}, err
	}
	if len(fs) > 1 || ringOnly(fs) {
		return websites.KpiSet{}, ErrFilterUnavailable
	}
	none := func(why string) websites.KpiValue { return websites.KpiValue{Unavailable: why} }
	out := websites.KpiSet{Visitors: none("no_data"), PageViews: none("no_data"), Requests: none("no_data"), Stopped: none("no_data"),
		WouldBlock: none("no_data"), LatencyP95MS: none("no_data"), ErrorRate: none("no_data")}
	if sel.none {
		return out, nil
	}
	ring := m.rings[2]
	start, end := ring.Start(from), ring.Start(to.Add(-time.Nanosecond))
	if o := ring.Oldest(now); start.Before(o) {
		start = o
	}
	parts := readSeries
	if len(fs) == 1 {
		parts = readParts{core: coreAll, top: fs[0].Dim != "status_class", dim: fs[0].Dim}
		if !sel.whole {
			parts.site = sel.id
		}
	}
	parts.only = onlyOf(sel)
	if !sel.whole {
		parts.core = coreSites // the website's numbers are in its part
	}
	var tc cm.TrafficCounters
	var hist [cm.HistogramBuckets]int64
	days := map[int64]int64{}     // UTC day -> unique_day of its newest bucket
	dayT := map[int64]time.Time{} // UTC day -> start of that bucket
	n := 0
	var cov coverage
	// Per-website top lists are in the 10 min ring only.
	fine := len(fs) == 0 || sel.whole
	err = m.readFilled(start, end, now, parts, fine, &cov, func(t time.Time, b *cm.MetricBucket) {
		sb := siteBucket(b, sel)
		if sb == nil {
			return
		}
		n++
		if len(fs) == 1 {
			ft, ok := filteredTraffic(sb, fs[0])
			if ok {
				tc.Add(&ft)
			}
			return
		}
		tc.Add(&sb.Traffic)
		for k, v := range sb.Latency.Total.Counts {
			if i := atoiKey(k); i >= 0 && i < len(hist) {
				hist[i] += v
			}
		}
		if p := sb.Clients.UniqueDay; p != nil {
			d := t.Unix() / 86400
			if t.After(dayT[d]) || dayT[d].IsZero() {
				days[d], dayT[d] = *p, t
			}
		}
	})
	if err != nil || n == 0 {
		return out, err
	}
	// A range with a partial or missing bucket (a restart, a skipped write)
	// is partial: the counters then miss the seconds schild was down. Exact
	// only says counted vs estimate (contracts v0.5, D36 fix round 1).
	partial, gap := m.incomplete(&cov, end), m.gapKind(&cov, end)
	val := func(v float64, exact bool) websites.KpiValue {
		return websites.KpiValue{Value: &v, Exact: exact, Partial: partial, GapKind: gap}
	}
	out.Requests, out.Stopped, out.WouldBlock = val(float64(tc.Requests), true), val(float64(tc.Stopped), true), val(float64(tc.WouldBlock), true)
	if len(fs) == 1 {
		exact := !cm.EstimatedDimensions[fs[0].Dim] && (sel.whole || fs[0].Dim != "country")
		out.Requests.Exact, out.Stopped.Exact, out.WouldBlock.Exact = exact, exact, exact
		need := none("filter_needs_requests")
		if fs[0].Dim == "status_class" {
			out.Stopped.Exact = exact && StatusStoppedExact
			out.WouldBlock = need
		}
		out.Visitors, out.PageViews, out.LatencyP95MS, out.ErrorRate = need, need, need, need
		return out, nil
	}
	out.PageViews = val(float64(tc.PageViews), true)
	if tc.Requests > 0 {
		out.ErrorRate = val(float64(tc.Status.S5xx)/float64(tc.Requests), true)
	}
	if p := quantileOf(&hist, 0.95); p != nil {
		out.LatencyP95MS = websites.KpiValue{Value: p, Exact: false, Partial: partial, GapKind: gap, ErrorBound: 0.25}
	}
	if len(days) > 0 {
		var sum int64
		for _, v := range days {
			sum += v
		}
		out.Visitors = val(float64(sum), false)
	}
	return out, nil
}

// Realtime returns Echtzeit of a website: the last 5 minutes from memory
// and 30 one-minute points from the 1 min ring plus the current minute.
func (m NodeView) Realtime(site string, now time.Time) (websites.Realtime, error) {
	sel, err := m.selectSite(site)
	if err != nil {
		return websites.Realtime{}, err
	}
	out := websites.Realtime{Site: site, GeneratedAt: ts(now), Points: []websites.RealtimePoint{}}
	if sel.none {
		return out, nil
	}
	slot := sel.slot
	if v := m.view(); v != nil && slot < 0 {
		slot = v.SlotOf(site)
	}
	// What is in memory is this gateway's: the group and another member
	// take the last five minutes from the minute points below.
	fromRing := m.Merged() || m.Foreign()
	if !fromRing {
		out.Requests5m, out.Stopped5m, out.WouldBlock5m, out.Visitors5m = m.Recent(slot, 5*time.Minute, now)
	}
	ring := m.rings[1]
	cur := ring.Start(now)
	first := cur.Add(-30 * ring.Step)
	pts := map[int64]websites.RealtimePoint{}
	parts := readSeries
	parts.only = onlyOf(sel)
	if !sel.whole {
		parts.core = coreSites
	}
	_ = m.readNodes(ring, first, cur.Add(-ring.Step), parts, func(t time.Time, b *cm.MetricBucket) {
		sb := siteBucket(b, sel)
		if sb == nil {
			return
		}
		pts[t.Unix()] = websites.RealtimePoint{T: ts(t), Requests: sb.Traffic.Requests, Stopped: sb.Traffic.Stopped, WouldBlock: sb.Traffic.WouldBlock,
			Visitors: sb.Clients.Unique, Partial: sb.Partial}
	})
	for t := first; t.Before(cur); t = t.Add(ring.Step) {
		p, ok := pts[t.Unix()]
		if !ok {
			p = websites.RealtimePoint{T: ts(t)}
		}
		out.Points = append(out.Points, p)
	}
	if fromRing {
		for _, p := range out.Points[max(0, len(out.Points)-5):] {
			out.Requests5m += p.Requests
			out.Stopped5m += p.Stopped
			out.WouldBlock5m += p.WouldBlock
			if p.Visitors != nil && (out.Visitors5m == nil || *p.Visitors > *out.Visitors5m) {
				x := *p.Visitors
				out.Visitors5m = &x
			}
		}
	}
	// The minute that runs now (partial).
	p := websites.RealtimePoint{T: ts(cur), Partial: true}
	if m.Foreign() {
		out.Points = append(out.Points, p)
		return out, nil
	}
	m.mu.Lock()
	var s *siteAcc
	if sel.whole && (m.view() == nil || slot < 0) {
		s = &siteAcc{c: m.a1m.c, unique: m.a1m.unique}
	} else if slot >= 0 && slot < sites.Slots {
		s = m.a1m.sites[slot]
	}
	if s.used() {
		p.Requests, p.Stopped, p.WouldBlock = s.c[cRequests], s.c[cStopped], s.c[cWouldBlock]
		v := s.unique.estimate()
		p.Visitors = &v
	}
	m.mu.Unlock()
	out.Points = append(out.Points, p)
	return out, nil
}

// Restarts returns the schild starts in [from, to).
func (m *Monitor) Restarts(from, to time.Time) []time.Time { return m.store.startTimes(from, to) }

// Gap is a stretch of the 10 min ring without buckets between two that
// exist (schild was down or did not write).
type Gap struct{ From, To time.Time }

// Gaps returns the gaps of the 10 min ring in [from, to) (at most max).
func (m *Monitor) Gaps(from, to, now time.Time, max int) []Gap {
	ring := m.rings[2]
	start, end := ring.Start(from), ring.Start(to.Add(-time.Nanosecond))
	if o := ring.Oldest(now); start.Before(o) {
		start = o
	}
	ts := m.store.times(ring, start, end)
	var out []Gap
	for i := 1; i < len(ts) && len(out) < max; i++ {
		if d := ts[i].Sub(ts[i-1]); d > ring.Step {
			out = append(out, Gap{From: ts[i-1].Add(ring.Step), To: ts[i]})
		}
	}
	return out
}
