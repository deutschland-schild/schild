package monitoring

import (
	"context"
	"errors"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	cr "github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// MVP-22: filters the rings cannot combine (two or more filters, a
// breakdown under a filter, visitors or latency under a filter) come from
// the request ring within its window (keep_hours, at most 48 h); outside
// it they stay 409 filter_unavailable (D36).

// ringTimeout bounds one aggregate over the request ring.
const ringTimeout = 30 * time.Second

func dimFilters(fs []Filter) []reqring.DimFilter {
	out := make([]reqring.DimFilter, len(fs))
	for i, f := range fs {
		out[i] = reqring.DimFilter{Dim: f.Dim, Value: f.Value}
	}
	return out
}

// ringFor returns the request ring when it covers [from, to) and the view
// is not one node of a group.
func (m NodeView) ringFor(from, to, now time.Time) *reqring.Ring {
	r := m.cfg.Requests
	// The ring holds the requests of every node without their node: it
	// answers for the group, never for one node of it.
	if r == nil || m.One() || !r.Covers(from, to, now) {
		return nil
	}
	return r
}

// ringSite is the site filter of the ring: none for the whole gateway.
func ringSite(sel siteSel) string {
	if sel.whole {
		return ""
	}
	return sel.id
}

// ringErr maps errors of the ring: a busy ring is unavailable for now.
func ringErr(err error) error {
	if errors.Is(err, reqring.ErrBusy) || errors.Is(err, context.DeadlineExceeded) {
		return ErrRingBusy
	}
	return err
}

// ErrRingBusy: the request ring is busy with another query (429).
var ErrRingBusy = errors.New("request ring busy")

// Kpis returns the KPI row of a website (getWebsiteKpis). The rings answer
// without a filter and with one filter (requests, stopped, would_block from
// the top lists); within the request ring's window it adds what they
// cannot: visitors (distinct visitor keys per day), page views, latency
// and the error rate under a filter, and every value under two or more
// filters.
func (m NodeView) Kpis(site string, from, to time.Time, filters []string, now time.Time) (websites.KpiSet, error) {
	sel, err := m.selectSite(site)
	if err != nil {
		return websites.KpiSet{}, err
	}
	fs, err := ParseFilters(filters)
	if err != nil {
		return websites.KpiSet{}, err
	}
	r := m.ringFor(from, to, now)
	if r == nil || sel.none {
		return m.kpisRings(site, from, to, filters, now)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ringTimeout)
	defer cancel()
	if len(fs) > 1 || ringOnly(fs) {
		k, err := r.Kpis(ctx, ringSite(sel), from, to, dimFilters(fs))
		return k, ringErr(err)
	}
	base, err := m.kpisRings(site, from, to, filters, now)
	if err != nil {
		return base, err
	}
	rk, err := r.Kpis(ctx, ringSite(sel), from, to, dimFilters(fs))
	if err != nil {
		m.log.Debug("request ring kpis", "err", err)
		return base, nil
	}
	if len(fs) == 1 {
		base.Visitors, base.PageViews, base.LatencyP95MS, base.ErrorRate = rk.Visitors, rk.PageViews, rk.LatencyP95MS, rk.ErrorRate
		if fs[0].Dim == "status_class" {
			base.WouldBlock = rk.WouldBlock
		}
		return base, nil
	}
	// Without a filter only the visitors come from the ring (D36: within
	// 48 h distinct visitor keys per day), when it covers the whole range.
	if !rk.Visitors.Partial && rk.Visitors.Value != nil {
		base.Visitors = rk.Visitors
	}
	return base, nil
}

// KpisSource is WebsiteKpis.source: requests when the request ring
// answers a filter (one filter adds visitors, page views, latency and the
// error rate from it; two or more filters take every value from it).
func (m NodeView) KpisSource(filters []string, from, to, now time.Time) string {
	if len(filters) > 0 && m.ringFor(from, to, now) != nil {
		return "requests"
	}
	return "rings"
}

// breakdownRing answers a breakdown under filters from the request ring.
func (m NodeView) breakdownRing(by string, from, to time.Time, site string, sel siteSel, fs []Filter, top int, now time.Time) (TrafficBreakdown, error) {
	r := m.ringFor(from, to, now)
	if r == nil {
		return TrafficBreakdown{}, ErrFilterUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), ringTimeout)
	defer cancel()
	b, err := r.Breakdown(ctx, by, ringSite(sel), from, to, dimFilters(fs), top)
	if err != nil {
		return TrafficBreakdown{}, ringErr(err)
	}
	out := TrafficBreakdown{By: by, From: ts(from), To: ts(to), Resolution: string(cm.Res1m), Site: site, Exact: b.Exact, Partial: b.Partial,
		Source: "requests", Items: b.Items,
		Total: BreakdownCounts{Requests: b.Total[0], Stopped: b.Total[1], WouldBlock: b.Total[2]},
		Other: BreakdownCounts{Requests: b.Other[0], Stopped: b.Other[1], WouldBlock: b.Other[2]}}
	if by == "bot_category" || by == "ua_class" {
		v := m.BotVerification()
		out.BotVerification = &v
	}
	return out, nil
}

// ringMetrics are the counters the request ring answers per step.
var ringMetrics = map[string]func(p *reqring.SeriesPoint) float64{
	"traffic.requests":    func(p *reqring.SeriesPoint) float64 { return p.Requests },
	"traffic.stopped":     func(p *reqring.SeriesPoint) float64 { return p.Stopped },
	"traffic.would_block": func(p *reqring.SeriesPoint) float64 { return p.WouldBlock },
	"traffic.detections":  func(p *reqring.SeriesPoint) float64 { return p.Detections },
	"traffic.page_views":  func(p *reqring.SeriesPoint) float64 { return p.PageViews },
}

// seriesRing answers a series under filters the rings cannot serve: the
// request counters of the ring per point (sum or rate).
func (m NodeView) seriesRing(q SeriesQuery, sel siteSel, fs []Filter, qs []cm.Query, now time.Time) (cm.SeriesResult, error) {
	r := m.ringFor(q.From, q.To, now)
	if r == nil {
		return cm.SeriesResult{}, ErrFilterUnavailable
	}
	for _, p := range qs {
		if ringMetrics[p.Metric.ID] == nil || p.Stat != cm.Sum && p.Stat != cm.Rate {
			return cm.SeriesResult{}, ErrFilterUnavailable
		}
	}
	plan, err := cm.Plan(m.rings, q.Resolution, q.From, q.To, now)
	if err != nil {
		return cm.SeriesResult{}, &ErrInvalid{"from", err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), ringTimeout)
	defer cancel()
	pts, exact, err := r.Series(ctx, ringSite(sel), plan.First, plan.Step, plan.Points, dimFilters(fs))
	if err != nil {
		return cm.SeriesResult{}, ringErr(err)
	}
	n := plan.Points
	end := plan.First.Add(time.Duration(n) * plan.Step)
	res := cm.SeriesResult{From: ts(plan.First), To: ts(end), Resolution: plan.Ring.Resolution, StepS: int(plan.Step.Seconds()), Points: n,
		Site: q.Site, Series: []cm.MetricSeries{}, Restarts: []string{}, Filters: q.Filters, Source: "requests"}
	if plan.Merge > 1 {
		res.BucketsPerPoint = plan.Merge
	}
	covered := r.Oldest()
	partial := make([]bool, n)
	anyPartial := false
	for i := range partial {
		ps := plan.First.Add(time.Duration(i) * plan.Step)
		pe := ps.Add(plan.Step)
		partial[i] = covered.IsZero() || ps.Before(covered) || pe.After(now)
		anyPartial = anyPartial || partial[i]
	}
	if anyPartial {
		res.Partial = partial
	}
	for _, p := range qs {
		info := p.Metric.Info()
		s := cm.MetricSeries{Metric: info.ID, Stat: p.Stat, Kind: info.Kind, Unit: info.Unit, Exact: exact, Values: make([]*float64, n)}
		get := ringMetrics[info.ID]
		for i := range pts {
			if covered.IsZero() || plan.First.Add(time.Duration(i+1)*plan.Step).Before(covered) {
				continue // before the ring: no value
			}
			v := get(&pts[i])
			if p.Stat == cm.Rate {
				v /= plan.Step.Seconds()
			}
			s.Values[i] = &v
		}
		res.Series = append(res.Series, s)
	}
	return res, nil
}

// Strip returns the site-wide strip of [from, to] in 10 s steps from the
// 10 s ring (getRequestContext, at most 61 points; steps without a bucket
// count 0). A website without numbers gives an empty strip.
func (m NodeView) Strip(site string, from, to time.Time) []cr.StripPoint {
	out := []cr.StripPoint{}
	if m.Monitor == nil {
		return out
	}
	sel, err := m.selectSite(site)
	if err != nil || sel.none {
		return out
	}
	ring := m.rings[0]
	first, last := ring.Start(from), ring.Start(to)
	if n := int(last.Sub(first)/ring.Step) + 1; n > 61 {
		first = last.Add(-60 * ring.Step)
	}
	parts := readSeries
	parts.only = onlyOf(sel)
	if !sel.whole {
		parts.core = coreSites
	}
	pts := map[int64]cr.StripPoint{}
	_ = m.readNodes(ring, first, last, parts, func(t time.Time, b *cm.MetricBucket) {
		sb := siteBucket(b, sel)
		if sb == nil {
			return
		}
		tr := sb.Traffic
		pts[t.Unix()] = cr.StripPoint{T: ts(t), Requests: tr.Requests, Stopped: tr.Stopped, WouldBlock: tr.WouldBlock, Detections: tr.Detections}
	})
	for t := first; !t.After(last); t = t.Add(ring.Step) {
		p, ok := pts[t.Unix()]
		if !ok {
			p = cr.StripPoint{T: ts(t)}
		}
		out = append(out, p)
	}
	return out
}
