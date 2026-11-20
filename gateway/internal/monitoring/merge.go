package monitoring

import (
	"sort"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// mergeBucket adds src into dst: two parts of the same bucket written by
// two processes (the part flushed at a graceful shutdown and the part the
// next process collected after its start, D36 fix round 1). Counters and
// histograms add up exactly; estimates of distinct clients add up (an
// upper bound: a client seen by both parts counts twice), unique_day takes
// the larger value; gauges average their averages; top lists merge as
// space-saving summaries. The result is always partial: the process was
// down for a moment inside the bucket.
func mergeBucket(dst, src *cm.MetricBucket) {
	dst.Partial = true
	dst.GapKind = worseGap(dst.GapKind, src.GapKind)
	dst.Traffic.Add(&src.Traffic)
	mergeLatency(&dst.Latency, &src.Latency)
	mergeClients(&dst.Clients, &src.Clients)
	dst.Top = mergeTop(dst.Top, src.Top, cm.TopK, cm.EstimatedDimensions)
	dst.Values = mergeValues(dst.Values, src.Values)
	for _, so := range src.Objects {
		found := false
		for i := range dst.Objects {
			if do := &dst.Objects[i]; do.Kind == so.Kind && do.Object == so.Object {
				do.Values = mergeValues(do.Values, so.Values)
				found = true
				break
			}
		}
		if !found {
			dst.Objects = append(dst.Objects, so)
		}
	}
	for _, ss := range src.Sites {
		i := -1
		for j := range dst.Sites {
			if dst.Sites[j].Site == ss.Site {
				i = j
				break
			}
		}
		if i < 0 {
			dst.Sites = append(dst.Sites, ss)
			continue
		}
		ds := &dst.Sites[i]
		ds.Traffic.Add(&ss.Traffic)
		switch {
		case ds.Latency == nil:
			ds.Latency = ss.Latency
		case ss.Latency != nil:
			mergeLatency(ds.Latency, ss.Latency)
		}
		switch {
		case ds.Clients == nil:
			ds.Clients = ss.Clients
		case ss.Clients != nil:
			mergeClients(ds.Clients, ss.Clients)
		}
		ds.Top = mergeTop(ds.Top, ss.Top, cm.SiteTopK, siteEstimated)
	}
}

// worseGap combines two gap kinds: lost wins over restart, restart over
// unknown ("").
func worseGap(a, b string) string {
	switch {
	case a == cm.GapLost || b == cm.GapLost:
		return cm.GapLost
	case a == cm.GapRestart || b == cm.GapRestart:
		return cm.GapRestart
	}
	return ""
}

// siteEstimated: the per-website lists of path, asn, country, referrer and
// rule are space-saving (D36), the small enums exact.
var siteEstimated = map[string]bool{"path": true, "asn": true, "country": true, "referrer": true, "rule": true}

func mergeLatency(dst, src *cm.BucketLatency) {
	for _, p := range [][2]*cm.LatencyHistogram{{&dst.Total, &src.Total}, {&dst.Overhead, &src.Overhead}, {&dst.Upstream, &src.Upstream}} {
		d, s := p[0], p[1]
		if d.Scheme == "" {
			d.Scheme = s.Scheme
		}
		for k, v := range s.Counts {
			if d.Counts == nil {
				d.Counts = map[string]int64{}
			}
			d.Counts[k] += v
		}
	}
}

func mergeClients(dst, src *cm.BucketClients) {
	add := func(d **int64, s *int64) {
		switch {
		case s == nil:
		case *d == nil:
			v := *s
			*d = &v
		default:
			v := **d + *s
			*d = &v
		}
	}
	add(&dst.Unique, src.Unique)
	add(&dst.New, src.New)
	add(&dst.Bots, src.Bots)
	if s := src.UniqueDay; s != nil && (dst.UniqueDay == nil || *s > *dst.UniqueDay) {
		v := *s
		dst.UniqueDay = &v
	}
}

func mergeValues(dst, src cm.MetricValues) cm.MetricValues {
	var a valuesAgg
	a.add(&dst)
	a.add(&src)
	return a.wire()
}

// mergeTop merges two bucket top lists. A space-saving list that is full
// (k entries) may have counted a key it does not name up to its smallest
// count: a key missing from such a list gets that count added to its
// requests (upper bound) and its error, as the breakdown does across
// buckets. The merged list keeps every key (at most 2k for one merge).
func mergeTop(dst, src *cm.BucketTop, k int, estimated map[string]bool) *cm.BucketTop {
	if src == nil {
		return dst
	}
	if dst == nil {
		return src
	}
	for _, dim := range topDims {
		d, s := topField(dst, dim), topField(src, dim)
		if len(*s) == 0 {
			continue
		}
		*d = mergeEntries(*d, *s, k, estimated[dim])
	}
	return dst
}

func mergeEntries(a, b []cm.TopEntry, k int, estimated bool) []cm.TopEntry {
	minOf := func(l []cm.TopEntry) int64 {
		if !estimated || len(l) < k {
			return 0
		}
		m := l[0].Requests
		for _, e := range l {
			m = min(m, e.Requests)
		}
		return m
	}
	minA, minB := minOf(a), minOf(b)
	idx := map[string]int{}
	out := make([]cm.TopEntry, 0, len(a)+len(b))
	for _, e := range a {
		idx[e.Key] = len(out)
		out = append(out, e)
	}
	inB := map[string]bool{}
	for _, e := range b {
		inB[e.Key] = true
		i, ok := idx[e.Key]
		if !ok {
			e.Requests += minA
			e.Error += minA
			out = append(out, e)
			continue
		}
		x := &out[i]
		x.Requests += e.Requests
		x.Stopped += e.Stopped
		x.WouldBlock += e.WouldBlock
		x.Detections += e.Detections
		x.Error += e.Error
		if x.Label == "" {
			x.Label = e.Label
		}
	}
	for i := range a {
		if !inB[a[i].Key] {
			out[idx[a[i].Key]].Requests += minB
			out[idx[a[i].Key]].Error += minB
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	return out
}

// coverage tracks the buckets one read saw, so a range that misses a part
// is never called exact (D36 fix round 1, finding D.1).
type coverage struct {
	step         time.Duration
	first, last  time.Time
	n            int
	partial, gap bool
	// gap kinds of the partial buckets seen (gap_kind, contracts v0.5):
	// lost, restart, or unknown (partial without a gap kind).
	lost, restart, unknown bool
	// gaps are the missing stretches [from, to) between stored buckets.
	gaps [][2]time.Time
}

func (c *coverage) add(t time.Time, partial bool, kind string) {
	if c.n > 0 && t.Sub(c.last) > c.step {
		c.gap = true
		if len(c.gaps) < 100 {
			c.gaps = append(c.gaps, [2]time.Time{c.last.Add(c.step), t})
		}
	}
	if c.n == 0 {
		c.first = t
	}
	c.last = t
	c.n++
	c.partial = c.partial || partial
	if partial {
		switch kind {
		case cm.GapLost:
			c.lost = true
		case cm.GapRestart:
			c.restart = true
		default:
			c.unknown = true
		}
	}
}

// gapKind is KpiValue.gap_kind and TrafficBreakdown.gap_kind of a range
// that incomplete calls partial (contracts v0.5): lost when a bucket is
// lost-partial, a missing stretch was not ended by a start after an
// orderly shutdown, or a start in the range followed a hard stop; "" when
// a partial bucket has no gap kind or the range is complete; else
// restart.
func (m *Monitor) gapKind(c *coverage, end time.Time) string {
	if !m.incomplete(c, end) {
		return ""
	}
	if c.lost {
		return cm.GapLost
	}
	for _, g := range c.gaps {
		// The start that ended the gap lies in it or in the bucket after it.
		if bad, any := m.store.unorderlyStarts(g[0].Add(-c.step), g[1].Add(c.step-time.Second)); bad || !any {
			return cm.GapLost
		}
	}
	if c.n > 0 {
		if bad, _ := m.store.unorderlyStarts(c.first.Add(time.Second), end.Add(c.step-time.Second)); bad {
			return cm.GapLost
		}
	}
	if c.unknown {
		return ""
	}
	return cm.GapRestart
}

// incomplete reports whether the range up to the bucket starting at end
// misses a part: a partial bucket, a gap between two stored buckets, or a
// schild start after the first stored bucket (a bucket lost in a crash at
// the end of the range shows only as that start).
func (m *Monitor) incomplete(c *coverage, end time.Time) bool {
	if c.partial || c.gap {
		return true
	}
	if c.n == 0 {
		return false
	}
	return len(m.store.startTimes(c.first.Add(time.Second), end.Add(c.step-time.Second))) > 0
}
