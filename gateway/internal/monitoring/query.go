package monitoring

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// DefaultSite is the one implicit site of a gateway without MVP-16 sites.
const DefaultSite = "default"

// ErrUnknownSite: the site filter names no site of this gateway.
var ErrUnknownSite = errors.New("unknown site")

// ---------------------------------------------------------------- now

// Now returns MonitoringNow from memory.
func (m *Monitor) Now(site string, now time.Time) (MonitoringNow, error) {
	sel, err := m.selectSite(site)
	if err != nil {
		return MonitoringNow{}, err
	}
	if !sel.whole {
		return m.siteNow(sel, now), nil
	}
	m.mu.Lock()
	var c [nCounters]int64
	var h [nHist][cm.HistogramBuckets]int64
	var u hll
	var c10 int64
	n := 0
	newest := int64(0)
	for i := 0; i < m.winN; i++ {
		newest = max(newest, m.window[i].sec)
	}
	for i := 0; i < m.winN; i++ {
		w := &m.window[i]
		if w.sec <= newest-60 {
			continue
		}
		n++
		for k, v := range w.c {
			c[k] += v
		}
		for p := range w.hist {
			for k, v := range w.hist[p] {
				h[p][k] += v
			}
		}
		u.merge(&w.unique)
		if w.sec > newest-10 {
			c10 += w.c[cRequests]
		}
	}
	hints := append(m.hints.list(now), m.siteHintList(now, -1)...)
	m.mu.Unlock()
	share := func(a, b int64) *float64 {
		if b == 0 {
			return nil
		}
		v := float64(a) / float64(b)
		return &v
	}
	tn := TrafficNow{
		WindowS: 60, RequestsPerS: float64(c[cRequests]) / 60, RequestsPerS10s: float64(c10) / 10,
		StoppedShare: share(c[cStopped], c[cRequests]), WouldBlockShare: share(c[cWouldBlock], c[cRequests]), FailClosed: c[cFailClosed],
		UpstreamErrorShare: share(c[cUpstreamErrors]+c[cUpstreamTimeouts], c[cForwarded]),
		LatencyTotalP50MS:  quantileOf(&h[hTotal], 0.5), LatencyTotalP95MS: quantileOf(&h[hTotal], 0.95),
		LatencyOverheadP95MS: quantileOf(&h[hOverhead], 0.95), LatencyUpstreamP95MS: quantileOf(&h[hUpstream], 0.95),
		BytesInPerS: float64(c[cBytesIn]) / 60, BytesOutPerS: float64(c[cBytesOut]) / 60,
	}
	if n > 0 {
		e := u.estimate()
		tn.ClientsUnique = &e
	}
	out := MonitoringNow{GeneratedAt: ts(now), StartedAt: ts(m.started), Site: site, Traffic: tn, Hints: hints}
	if s := m.last.Load(); s != nil {
		sn := s.now
		out.Server = &sn
	}
	return out, nil
}

// Snapshot returns the latest full host sample.
func (m *Monitor) Snapshot(now time.Time) ServerSnapshot {
	s := m.last.Load()
	if s == nil {
		m.Sample(now)
		s = m.last.Load()
	}
	snap := s.snap
	snap.GeneratedAt = ts(now)
	return snap
}

// ---------------------------------------------------------------- catalogue

// Catalogue returns every metric with its availability here.
func (m *Monitor) Catalogue(now time.Time) cm.MetricCatalogue {
	c := cm.NewCatalogue(m.rings)
	for i, r := range m.rings {
		if t := m.store.oldest(r, now); t != nil {
			s := ts(*t)
			c.Resolutions[i].Oldest = &s
		}
	}
	s := m.last.Load()
	env := Environment{OSFamily: "other"}
	unav := map[string]string{}
	if s != nil {
		env = s.snap.Environment
		for _, u := range s.snap.Unavailable {
			unav[u.Area] = u.Reason
		}
	}
	area := func(id string) string {
		switch {
		case strings.HasPrefix(id, "server.cpu"):
			return "cpu"
		case strings.HasPrefix(id, "server.load"):
			return "load"
		case strings.HasPrefix(id, "server.memory"), id == "server.swap_used":
			return "memory"
		case id == "server.disk_read_bytes", id == "server.disk_write_bytes", id == "server.disk_busy":
			return "disk_io"
		case strings.HasPrefix(id, "server.disk"):
			return "mounts"
		case strings.HasPrefix(id, "server.net"):
			return "interfaces"
		case strings.HasPrefix(id, "server.tcp"):
			return "tcp"
		case id == "server.conntrack_used_ratio":
			return "conntrack"
		case id == "server.files_open_ratio":
			return "files"
		case strings.HasPrefix(id, "container."):
			return "container"
		}
		return ""
	}
	for i := range c.Metrics {
		mi := &c.Metrics[i]
		a := area(mi.ID)
		if a == "" {
			continue
		}
		if r, ok := unav[a]; ok {
			mi.Available, mi.Reason = false, r
		} else if a == "container" && !env.Container {
			mi.Available, mi.Reason = false, "not_present"
		} else if s == nil {
			mi.Available, mi.Reason = false, "not_present"
		}
	}
	return c
}

// ---------------------------------------------------------------- series

// SeriesQuery is one queryMetricSeries call.
type SeriesQuery struct {
	Metrics    []string
	From, To   time.Time
	Resolution string
	Site       string
	Object     string
	// Filters are `dimension:value` (D36; one is answered from top lists).
	Filters []string
}

// ErrInvalid wraps a query problem (400 invalid, detail = message).
type ErrInvalid struct {
	Param, Msg string
}

func (e *ErrInvalid) Error() string { return e.Msg }

// valueOf extracts one value of a metric from a bucket (nil = no data).
func valueOf(b *cm.MetricBucket, q cm.Query, object string, step float64) *float64 {
	id := q.Metric.ID
	conv := func(v float64) *float64 {
		if q.Stat == cm.Rate {
			v /= step
		}
		return &v
	}
	if field, ok := strings.CutPrefix(id, "traffic."); ok {
		switch q.Metric.Kind {
		case cm.Counter:
			v, ok := trafficField(&b.Traffic, field)
			if !ok {
				return nil
			}
			return conv(float64(v))
		case cm.Histogram:
			var h *cm.LatencyHistogram
			switch field {
			case "latency_total":
				h = &b.Latency.Total
			case "latency_overhead":
				h = &b.Latency.Overhead
			default:
				h = &b.Latency.Upstream
			}
			counts := map[int]int64{}
			for k, v := range h.Counts {
				i, _ := strconv.Atoi(k)
				counts[i] = v
			}
			qv := map[cm.Stat]float64{cm.P50: 0.5, cm.P95: 0.95, cm.P99: 0.99}[q.Stat]
			v, ok := cm.Quantile(counts, qv)
			if !ok {
				return nil
			}
			return &v
		case cm.Estimate:
			p := b.Clients.Unique
			if field == "clients_new" {
				p = b.Clients.New
			}
			if p == nil {
				return nil
			}
			v := float64(*p)
			return &v
		}
		return nil
	}
	vals := &b.Values
	if object != "" {
		vals = nil
		for i := range b.Objects {
			if b.Objects[i].Object == object {
				vals = &b.Objects[i].Values
				break
			}
		}
		if vals == nil {
			return nil
		}
	}
	if q.Metric.Kind == cm.Counter {
		v, ok := vals.Counters[id]
		if !ok {
			return nil
		}
		return conv(v)
	}
	g, ok := vals.Gauges[id]
	if !ok {
		return nil
	}
	switch q.Stat {
	case cm.Min:
		return &g.Min
	case cm.Max:
		return &g.Max
	}
	return &g.Avg
}

func trafficField(t *cm.TrafficCounters, f string) (int64, bool) {
	switch f {
	case "requests":
		return t.Requests, true
	case "forwarded":
		return t.Forwarded, true
	case "stopped":
		return t.Stopped, true
	case "blocked_waf":
		return t.BlockedWAF, true
	case "blocked_behaviour":
		return t.BlockedBehaviour, true
	case "rate_limited":
		return t.RateLimited, true
	case "rejected_limit":
		return t.RejectedLimit, true
	case "challenged":
		return t.Challenged, true
	case "blocked_crawler":
		return t.BlockedCrawler, true
	case "fail_closed":
		return t.FailClosed, true
	case "fail_closed_waf_busy":
		return t.FailClosedBy.WAFBusy, true
	case "fail_closed_waf_timeout":
		return t.FailClosedBy.WAFTimeout, true
	case "waiting_page_shown":
		return t.WaitingPageShown, true
	case "would_block":
		return t.WouldBlock, true
	case "would_rate_limit":
		return t.WouldRateLimit, true
	case "page_views":
		return t.PageViews, true
	case "detections":
		return t.Detections, true
	case "status_1xx":
		return t.Status.S1xx, true
	case "status_2xx":
		return t.Status.S2xx, true
	case "status_3xx":
		return t.Status.S3xx, true
	case "status_4xx":
		return t.Status.S4xx, true
	case "status_5xx":
		return t.Status.S5xx, true
	case "upstream_errors":
		return t.UpstreamErrors, true
	case "upstream_timeouts":
		return t.UpstreamTimeouts, true
	case "bytes_in":
		return t.BytesIn, true
	case "bytes_out":
		return t.BytesOut, true
	}
	return 0, false
}

// ---------------------------------------------------------------- breakdown

// MaxBreakdownBuckets bounds one breakdown: the default 10 min ring (14 d).
const MaxBreakdownBuckets = 2016

type mergedEntry struct {
	e          cm.TopEntry
	presentMin int64
}

// Breakdown answers getTrafficBreakdown.
func (m NodeView) Breakdown(by string, from, to time.Time, site string, filters []string, top int, now time.Time) (TrafficBreakdown, error) {
	sel, err := m.selectSite(site)
	if err != nil {
		return TrafficBreakdown{}, &ErrInvalid{"site", "unknown site"}
	}
	fs, err := ParseFilters(filters)
	if err != nil {
		return TrafficBreakdown{}, err
	}
	valid, ringDim := false, false
	for _, d := range cm.Dimensions {
		valid = valid || d == by
	}
	for _, d := range cm.RingFilterDimensions {
		ringDim = ringDim || d == by
	}
	if !valid && !ringDim {
		return TrafficBreakdown{}, &ErrInvalid{"by", "unknown dimension"}
	}
	if !from.Before(to) {
		return TrafficBreakdown{}, &ErrInvalid{"from", "from must be before to"}
	}
	if len(fs) > 0 || ringDim {
		// Two dimensions at once, and addresses and User-Agents at all
		// (D65), come from the request ring (MVP-22) within its window,
		// else 409 filter_unavailable.
		return m.breakdownRing(by, from, to, site, sel, fs, top, now)
	}
	ring := m.rings[1]
	if from.Before(ring.Oldest(now)) || int(to.Sub(from)/ring.Step) > cm.MaxPoints || !sel.whole {
		// Per-website top lists live in the 10 min ring only (D36).
		ring = m.rings[2]
	}
	if int(to.Sub(from)/ring.Step) > MaxBreakdownBuckets {
		return TrafficBreakdown{}, &ErrInvalid{"from", fmt.Sprintf("at most %d buckets", MaxBreakdownBuckets)}
	}
	start, end := ring.Start(from), ring.Start(to.Add(-time.Nanosecond))
	if o := ring.Oldest(now); start.Before(o) {
		start = o
	}
	merged := map[string]*mergedEntry{}
	var total cm.TrafficCounters
	var missSum int64
	estimated := cm.EstimatedDimensions[by] || (!sel.whole && by == "country")
	listK := cm.TopK
	if !sel.whole {
		listK = cm.SiteTopK
	}
	parts := readBreakdown(by)
	if !sel.whole {
		parts.core = coreSites // the website's counters are in its part
		parts.site = sel.id
	}
	if by == "status_class" || by == "site" {
		parts.top = false // from the counters
	}
	parts.only = onlyOf(sel)
	if by == "site" {
		// One totals row per bucket, not every website's part (evening
		// measurement 2026-10-29 4.2).
		parts = readParts{core: coreTraffic, siteTotals: true}
	}
	if sel.none {
		end = start.Add(-ring.Step) // nothing to read
	}
	v := m.view()
	single := v == nil || v.Protected <= 1
	cov := coverage{step: ring.Step}
	read := func(fn func(t time.Time, b *cm.MetricBucket)) error {
		if ring.Resolution != m.rings[2].Resolution {
			return m.readNodes(ring, start, end, parts, func(t time.Time, b *cm.MetricBucket) {
				cov.add(t, b.Partial, b.GapKind)
				fn(t, b)
			})
		}
		// A partial or lost 10 min bucket (a hard kill) is read from its
		// minutes while the 1 min ring keeps them (evening measurement
		// 2026-10-29 4.3). The 1 min ring has no per-website top lists:
		// a website's list breakdown reads the 10 min bucket as it is
		// (partial).
		fine := sel.whole || by == "site" || by == "status_class"
		return m.readFilledMerged(start, end, now, parts, fine, &cov, func(t time.Time, b *cm.MetricBucket, _ float64) { fn(t, b) })
	}
	err = read(func(t time.Time, b0 *cm.MetricBucket) {
		b := siteBucket(b0, sel)
		if b == nil {
			return
		}
		total.Add(&b.Traffic)
		var list []cm.TopEntry
		switch by {
		case "status_class":
			s := b.Traffic.Status
			list = []cm.TopEntry{{Key: "1xx", Requests: s.S1xx}, {Key: "2xx", Requests: s.S2xx}, {Key: "3xx", Requests: s.S3xx},
				{Key: "4xx", Requests: s.S4xx, Stopped: stoppedOfClass(&b.Traffic, "4xx")}, {Key: "5xx", Requests: s.S5xx, Stopped: stoppedOfClass(&b.Traffic, "5xx")}}
		case "site":
			switch {
			case len(b.Sites) > 0:
				for _, st := range b.Sites {
					list = append(list, cm.TopEntry{Key: st.Site, Requests: st.Traffic.Requests, Stopped: st.Traffic.Stopped, WouldBlock: st.Traffic.WouldBlock})
				}
			case single:
				key := DefaultSite
				if v != nil && len(v.Websites()) > 0 {
					key = v.Websites()[0].ID
				}
				list = []cm.TopEntry{{Key: key, Requests: b.Traffic.Requests, Stopped: b.Traffic.Stopped, WouldBlock: b.Traffic.WouldBlock}}
			}
		default:
			if b.Top != nil {
				list = topList(b.Top, by)
			}
		}
		var min int64
		full := estimated && len(list) >= listK
		if full {
			min = list[0].Requests
			for _, e := range list {
				min = minInt(min, e.Requests)
			}
			missSum += min
		}
		for _, e := range list {
			if e.Requests == 0 && e.Stopped == 0 {
				continue
			}
			x := merged[e.Key]
			if x == nil {
				x = &mergedEntry{e: cm.TopEntry{Key: e.Key, Label: e.Label}}
				merged[e.Key] = x
			}
			x.e.Requests += e.Requests
			x.e.Stopped += e.Stopped
			x.e.WouldBlock += e.WouldBlock
			x.e.Detections += e.Detections
			x.e.Error += e.Error
			if full {
				x.presentMin += min
			}
			if x.e.Label == "" {
				x.e.Label = e.Label
			}
		}
	})
	if err != nil {
		return TrafficBreakdown{}, err
	}
	items := make([]cm.TopEntry, 0, len(merged))
	for _, x := range merged {
		e := x.e
		if estimated {
			// A bucket whose full list does not name this key may have
			// counted it up to the smallest listed count: that is part of
			// the upper bound (requests) and of the overcount (error).
			miss := missSum - x.presentMin
			e.Requests += miss
			e.Error += miss
		} else {
			e.Error = 0
		}
		if by != "path" {
			e.Detections = 0
		}
		items = append(items, e)
	}
	// Rank by the guaranteed count (requests - error), then by the upper
	// bound: a key seen in a few buckets of a long range carries a large
	// error and must not push out keys that are certainly frequent.
	sort.Slice(items, func(i, j int) bool {
		gi, gj := items[i].Requests-items[i].Error, items[j].Requests-items[j].Error
		if gi != gj {
			return gi > gj
		}
		if items[i].Requests != items[j].Requests {
			return items[i].Requests > items[j].Requests
		}
		return items[i].Key < items[j].Key
	})
	tot := BreakdownCounts{Requests: total.Requests, Stopped: total.Stopped, WouldBlock: total.WouldBlock}
	if by == "rule" {
		tot = BreakdownCounts{Requests: total.Detections, Stopped: total.BlockedWAF, WouldBlock: total.Detections - total.BlockedWAF}
	}
	other := tot
	if top <= 0 {
		top = 20
	}
	if len(items) > top {
		items = items[:top]
	}
	for _, e := range items {
		other.Requests -= e.Requests - e.Error
		other.Stopped -= e.Stopped
		other.WouldBlock -= e.WouldBlock
	}
	other.Requests, other.Stopped, other.WouldBlock = max(0, other.Requests), max(0, other.Stopped), max(0, other.WouldBlock)
	out := TrafficBreakdown{By: by, From: ts(from), To: ts(to), Resolution: string(ring.Resolution), Site: site, Exact: !estimated, Partial: m.incomplete(&cov, end), GapKind: m.gapKind(&cov, end), Source: "rings", Total: tot, Items: items, Other: other}
	if by == "bot_category" || by == "ua_class" {
		v := m.BotVerification()
		out.BotVerification = &v
	}
	return out, nil
}

func minInt(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func topList(t *cm.BucketTop, by string) []cm.TopEntry {
	switch by {
	case "path":
		return t.Path
	case "asn":
		return t.ASN
	case "country":
		return t.Country
	case "net_class":
		return t.NetClass
	case "ua_class":
		return t.UAClass
	case "method":
		return t.Method
	case "referrer":
		return t.Referrer
	case "browser":
		return t.Browser
	case "os":
		return t.OS
	case "device":
		return t.Device
	case "bot_category":
		return t.BotCategory
	case "rule":
		return t.Rule
	}
	return nil
}

// ---------------------------------------------------------------- buckets

// Buckets answers listMetricBuckets: oldest first by cursor.
func (m *Monitor) Buckets(res string, from time.Time, cursor string, limit int, now time.Time) (cm.MetricBucketPage, error) {
	var ring cm.Ring
	found := false
	for _, r := range m.rings {
		if string(r.Resolution) == res {
			ring, found = r, true
		}
	}
	if !found {
		return cm.MetricBucketPage{}, &ErrInvalid{"resolution", "10s, 1m or 10m"}
	}
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 500)
	start := from
	if cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(cursor)
		n, err2 := strconv.ParseInt(string(b), 10, 64)
		if err != nil || err2 != nil {
			return cm.MetricBucketPage{}, &ErrInvalid{"cursor", "bad cursor"}
		}
		start = time.Unix(n, 0)
	}
	if o := ring.Oldest(now); start.IsZero() || start.Before(o) {
		start = o
	}
	start = ring.Start(start)
	end := start.Add(time.Duration(limit-1) * ring.Step)
	if cur := ring.Start(now); end.After(cur) {
		end = cur
	}
	page := cm.MetricBucketPage{Resolution: ring.Resolution, Items: []cm.MetricBucket{}}
	if err := m.store.read(ring, start, end, readAll, func(t time.Time, b *cm.MetricBucket) {
		if len(page.Items) < limit {
			page.Items = append(page.Items, *b)
		}
	}); err != nil {
		return page, err
	}
	next := end.Add(ring.Step)
	if !next.After(ring.Start(now)) || len(page.Items) == limit {
		c := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(next.Unix(), 10)))
		page.NextCursor = &c
	}
	return page, nil
}

// ---------------------------------------------------------------- stream

// Subscribe registers a live subscriber; it receives the ticks after
// lastID (at most the last 300 s) first. ok false: too many subscribers.
func (m *Monitor) Subscribe(lastID int64) (ch chan []byte, replay [][]byte, cancel func(), ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.subs) >= cm.MaxStreamSubscribers {
		return nil, nil, nil, false
	}
	ch = make(chan []byte, 8)
	m.subs[ch] = struct{}{}
	if lastID > 0 {
		var es []liveEntry
		for _, e := range m.live {
			if e.data != nil && e.sec > lastID {
				es = append(es, e)
			}
		}
		sort.Slice(es, func(i, j int) bool { return es[i].sec < es[j].sec })
		for _, e := range es {
			replay = append(replay, e.data)
		}
	}
	return ch, replay, func() {
		m.mu.Lock()
		delete(m.subs, ch)
		m.mu.Unlock()
	}, true
}

// TickID returns the Unix second of a serialised tick (its SSE id).
func TickID(data []byte) string {
	i := strings.Index(string(data), `"t":"`)
	if i < 0 {
		return ""
	}
	t, err := time.Parse(time.RFC3339, string(data[i+5:i+25]))
	if err != nil {
		return ""
	}
	return strconv.FormatInt(t.Unix(), 10)
}
