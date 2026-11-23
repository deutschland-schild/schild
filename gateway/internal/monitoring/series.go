package monitoring

import (
	"errors"
	"sort"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// maxSeries bounds the series of one answer (SeriesResult.series maxItems).
const maxSeries = 128

// Series answers queryMetricSeries. v0.5 (D36): resolution auto over the
// coarsest ring merges buckets per point (cm.Plan, buckets_per_point), a
// rate divides by the seconds a point really covers, partial marks
// incomplete points, site selects one website and one filter is answered
// from the top lists (the per-website lists of the 10 min ring).
func (m NodeView) Series(q SeriesQuery, now time.Time) (cm.SeriesResult, error) {
	sel, err := m.selectSite(q.Site)
	if err != nil {
		return cm.SeriesResult{}, &ErrInvalid{"site", "unknown site"}
	}
	filters, err := ParseFilters(q.Filters)
	if err != nil {
		return cm.SeriesResult{}, err
	}
	if len(q.Metrics) == 0 || len(q.Metrics) > cm.MaxSeries {
		return cm.SeriesResult{}, &ErrInvalid{"metric", "1 to 16 metrics"}
	}
	var qs []cm.Query
	for _, s := range q.Metrics {
		p, err := cm.ParseQuery(s)
		if err != nil {
			return cm.SeriesResult{}, &ErrInvalid{"metric", err.Error()}
		}
		qs = append(qs, p)
	}
	needRing := len(filters) > 1 || ringOnly(filters)
	for _, p := range qs {
		needRing = needRing || len(filters) > 0 && !filterMetric(p.Metric.ID)
	}
	if needRing {
		// MVP-22: the request ring answers within its window.
		return m.seriesRing(q, sel, filters, qs, now)
	}
	rings := m.rings
	if len(filters) == 1 {
		// Top lists: gateway-wide in the 1 min and 10 min rings, per
		// website in the 10 min ring only.
		rings = m.rings[1:]
		if !sel.whole {
			rings = m.rings[2:]
		}
		if q.Resolution != "" && q.Resolution != "auto" && q.Resolution != string(rings[0].Resolution) && (len(rings) == 1 || q.Resolution != string(rings[1].Resolution)) {
			return cm.SeriesResult{}, ErrFilterUnavailable
		}
	}
	plan, err := cm.Plan(rings, q.Resolution, q.From, q.To, now)
	if errors.Is(err, cm.ErrTooManyPoints) {
		return cm.SeriesResult{}, err
	}
	if err != nil {
		return cm.SeriesResult{}, &ErrInvalid{"from", err.Error()}
	}
	ring, n, step := plan.Ring, plan.Points, plan.Step
	first := plan.First
	end := first.Add(time.Duration(n) * step) // end of the last point
	points := make([]*pointAgg, n)
	from := first
	if o := ring.Oldest(now); from.Before(o) {
		from = o
	}
	parts := readSeries
	if len(filters) == 1 {
		parts = readParts{core: coreAll, top: true, dim: filters[0].Dim}
		if !sel.whole {
			parts.site = sel.id
		}
		if filters[0].Dim == "status_class" {
			parts.top = false
		}
	}
	parts.only = onlyOf(sel)
	starts := m.store.startTimes(first, end)
	read := func(fn func(t time.Time, b *cm.MetricBucket, span float64)) error {
		if ring.Resolution != m.rings[2].Resolution {
			return m.readNodes(ring, from, end.Add(-ring.Step), parts, func(t time.Time, b *cm.MetricBucket) {
				fn(t, b, bucketSpan(t, ring.Step, b.Partial, starts))
			})
		}
		// A partial or lost 10 min bucket (a hard kill) from its minutes
		// while the 1 min ring keeps them (evening measurement 2026-10-29
		// 4.3); a website's filtered series needs its top lists, which
		// only the 10 min ring has.
		var cov coverage
		fine := !(len(filters) == 1 && !sel.whole)
		return m.readFilledMerged(from, end.Add(-ring.Step), now, parts, fine, &cov, fn)
	}
	if err := read(func(t time.Time, b *cm.MetricBucket, span float64) {
		i := int(t.Sub(first) / step)
		if i < 0 || i >= n {
			return
		}
		sb := siteBucket(b, sel)
		if sb == nil {
			return
		}
		if len(filters) == 1 {
			tr, ok := filteredTraffic(sb, filters[0])
			if !ok {
				return
			}
			sb = &cm.MetricBucket{T: sb.T, Resolution: sb.Resolution, StepS: sb.StepS, Partial: sb.Partial, Traffic: tr}
		}
		if points[i] == nil {
			points[i] = &pointAgg{}
		}
		points[i].add(sb, span)
	}); err != nil {
		return cm.SeriesResult{}, err
	}
	res := cm.SeriesResult{From: ts(first), To: ts(end), Resolution: ring.Resolution, StepS: int(step.Seconds()), Points: n,
		Site: q.Site, Series: []cm.MetricSeries{}, Restarts: []string{}}
	if plan.Merge > 1 {
		res.BucketsPerPoint = plan.Merge
	}
	for _, t := range starts {
		res.Restarts = append(res.Restarts, ts(t))
	}
	if len(filters) == 1 {
		res.Filters, res.Source = q.Filters, "rings"
	}
	// Partial points: an incomplete bucket in it, or the point that holds
	// the current (unwritten) bucket.
	partial := make([]bool, n)
	anyPartial := false
	cur := ring.Start(now)
	for i := range points {
		ps := first.Add(time.Duration(i) * step)
		partial[i] = (points[i] != nil && points[i].partial) || (!cur.Before(ps) && cur.Before(ps.Add(step)))
		anyPartial = anyPartial || partial[i]
	}
	if anyPartial {
		res.Partial = partial
	}
	buckets := make([]*cm.MetricBucket, n)
	spans := make([]float64, n)
	for i, p := range points {
		if p != nil {
			buckets[i], spans[i] = p.bucket(), p.span
		}
	}
	objectsOf := func(kind string) []string {
		if q.Object != "" {
			return []string{q.Object}
		}
		seen := map[string]bool{}
		var out []string
		for _, b := range buckets {
			if b == nil {
				continue
			}
			for _, o := range b.Objects {
				if o.Kind == kind && !seen[o.Object] {
					seen[o.Object] = true
					out = append(out, o.Object)
				}
			}
		}
		if s := m.last.Load(); s != nil {
			for _, o := range s.objects {
				if o.kind == kind && !seen[o.object] {
					seen[o.object] = true
					out = append(out, o.object)
				}
			}
		}
		sort.Strings(out)
		return out
	}
	// At most maxSeries series: the cap ends both loops.
series:
	for _, p := range qs {
		info := p.Metric.Info()
		objs := []string{""}
		if info.PerObject != "none" {
			objs = objectsOf(info.PerObject)
		}
		for _, o := range objs {
			s := cm.MetricSeries{Metric: info.ID, Stat: p.Stat, Kind: info.Kind, Unit: info.Unit, Exact: info.Exact, ErrorBound: info.ErrorBound, Object: o, Values: make([]*float64, n)}
			if len(filters) == 1 && cm.EstimatedDimensions[filters[0].Dim] || len(filters) == 1 && !sel.whole && filters[0].Dim == "country" {
				s.Exact = false
			}
			if len(filters) == 1 && filters[0].Dim == "status_class" && info.ID != "traffic.requests" {
				s.Exact = false // stopped split by stoppedOfClass, would_block unknown
			}
			for i, b := range buckets {
				if b != nil {
					s.Values[i] = valueOf(b, p, o, spans[i])
				}
			}
			res.Series = append(res.Series, s)
			if len(res.Series) >= maxSeries {
				break series
			}
		}
	}
	return res, nil
}

// bucketSpan is the seconds a bucket covers: a partial bucket after a
// process start only the span from that start to its end (MVP-21
// measurement finding 9).
func bucketSpan(t time.Time, step time.Duration, partial bool, starts []time.Time) float64 {
	span := step.Seconds()
	if !partial {
		return span
	}
	for _, st := range starts {
		if !st.Before(t) && st.Before(t.Add(step)) {
			span = max(1, t.Add(step).Sub(st).Seconds())
		}
	}
	return span
}

// pointAgg merges the buckets of one point: counters and histograms
// summed, gauges avg of averages, min of minima, max of maxima, estimates
// the mean of the bucket values.
type pointAgg struct {
	n       int
	first   *cm.MetricBucket
	traffic cm.TrafficCounters
	hist    [nHist]map[string]int64
	uniq    estAgg
	fresh   estAgg
	day     estAgg
	bots    estAgg
	values  valuesAgg
	objects map[string]*valuesAgg
	order   []string
	kinds   map[string]string
	partial bool
	span    float64
}

type estAgg struct {
	sum int64
	n   int64
}

func (e *estAgg) add(p *int64) {
	if p != nil {
		e.sum += *p
		e.n++
	}
}

func (e *estAgg) value() *int64 {
	if e.n == 0 {
		return nil
	}
	v := (e.sum + e.n/2) / e.n
	return &v
}

type gaugeMerge struct {
	sumAvg, min, max float64
	n                int
}

type valuesAgg struct {
	gauges   map[string]*gaugeMerge
	counters map[string]float64
}

func (v *valuesAgg) add(x *cm.MetricValues) {
	for k, g := range x.Gauges {
		if v.gauges == nil {
			v.gauges = map[string]*gaugeMerge{}
		}
		a := v.gauges[k]
		if a == nil {
			a = &gaugeMerge{min: g.Min, max: g.Max}
			v.gauges[k] = a
		}
		a.sumAvg += g.Avg
		a.min = min(a.min, g.Min)
		a.max = max(a.max, g.Max)
		a.n++
	}
	for k, c := range x.Counters {
		if v.counters == nil {
			v.counters = map[string]float64{}
		}
		v.counters[k] += c
	}
}

func (v *valuesAgg) wire() cm.MetricValues {
	var out cm.MetricValues
	if len(v.gauges) > 0 {
		out.Gauges = map[string]cm.GaugeStats{}
		for k, g := range v.gauges {
			out.Gauges[k] = cm.GaugeStats{Avg: g.sumAvg / float64(g.n), Min: g.min, Max: g.max}
		}
	}
	if len(v.counters) > 0 {
		out.Counters = v.counters
	}
	return out
}

func (p *pointAgg) add(b *cm.MetricBucket, span float64) {
	p.n++
	p.span += span
	p.partial = p.partial || b.Partial
	if p.n == 1 {
		p.first = b
	}
	p.traffic.Add(&b.Traffic)
	for i, h := range []*cm.LatencyHistogram{&b.Latency.Total, &b.Latency.Overhead, &b.Latency.Upstream} {
		for k, v := range h.Counts {
			if p.hist[i] == nil {
				p.hist[i] = map[string]int64{}
			}
			p.hist[i][k] += v
		}
	}
	p.uniq.add(b.Clients.Unique)
	p.fresh.add(b.Clients.New)
	p.day.add(b.Clients.UniqueDay)
	p.bots.add(b.Clients.Bots)
	p.values.add(&b.Values)
	for i := range b.Objects {
		o := &b.Objects[i]
		key := o.Kind + "\x00" + o.Object
		if p.objects == nil {
			p.objects, p.kinds = map[string]*valuesAgg{}, map[string]string{}
		}
		a := p.objects[key]
		if a == nil {
			a = &valuesAgg{}
			p.objects[key] = a
			p.order = append(p.order, key)
			p.kinds[key] = o.Kind
		}
		a.add(&o.Values)
	}
}

// bucket returns the merged bucket (the bucket itself for one).
func (p *pointAgg) bucket() *cm.MetricBucket {
	if p.n == 1 {
		return p.first
	}
	b := &cm.MetricBucket{Traffic: p.traffic, Partial: p.partial}
	for i, h := range []*cm.LatencyHistogram{&b.Latency.Total, &b.Latency.Overhead, &b.Latency.Upstream} {
		h.Scheme, h.Counts = cm.HistogramScheme, p.hist[i]
		if h.Counts == nil {
			h.Counts = map[string]int64{}
		}
	}
	b.Clients = cm.BucketClients{Unique: p.uniq.value(), New: p.fresh.value(), UniqueDay: p.day.value(), Bots: p.bots.value()}
	b.Values = p.values.wire()
	for _, k := range p.order {
		obj := k[len(p.kinds[k])+1:]
		b.Objects = append(b.Objects, cm.ObjectValues{Object: obj, Kind: p.kinds[k], Values: p.objects[k].wire()})
	}
	return b
}
