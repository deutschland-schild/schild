package reqring

import (
	"context"
	"math"
	"math/bits"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/pathtpl"
)

// Aggregates over the ring (D36: two or more filters, a breakdown under a
// filter, visitors or latency under a filter within 48 h; MVP-22 alert
// statistics). One scan at a time (the query lock); at most MaxAggRecords
// records are read, a larger range reads every n-th segment and scales
// (Näherungswert). Records of a sampled segment count 2^level times.

// MaxAggRecords bounds the records one aggregate scan reads.
const MaxAggRecords = 3_000_000

type scanInfo struct {
	records  int
	minRate  float64
	strided  bool
	maxLevel uint8
	covered  int64 // the ring's coverage start (ms)
}

// exact: every record of the range was read unsampled.
func (s *scanInfo) exact() bool { return s.minRate == 1 && !s.strided }

// aggScan calls fn for every record in [from, to) with its weight. The
// caller holds the query lock.
func (r *Ring) aggScan(ctx context.Context, from, to int64, fn func(x *Rec, w float64)) (scanInfo, error) {
	r.Flush()
	files := r.snapshot(kindSeg, from, to)
	total := 0
	info := scanInfo{minRate: 1, covered: r.coveredFrom()}
	for i := range files {
		total += files[i].count
		info.maxLevel = max(info.maxLevel, files[i].level)
	}
	stride := 1
	if total > MaxAggRecords {
		stride = (total + MaxAggRecords - 1) / MaxAggRecords
		info.strided = true
	}
	for i := range files {
		if i%stride != 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return info, err
		}
		f := &files[i]
		w := float64(uint64(1)<<f.level) * float64(stride)
		info.minRate = min(info.minRate, f.rate())
		if err := r.load(f, func(_ int, x *Rec) bool {
			if x.T >= from && x.T < to {
				info.records++
				fn(x, w)
			}
			return true
		}); err != nil {
			continue
		}
	}
	return info, nil
}

// ---------------------------------------------------------------- dimension filters

// DimFilter is one `dimension:value` of the click-to-filter (D36).
type DimFilter struct{ Dim, Value string }

// keyer derives breakdown keys of records; it caches path templates of
// raw paths and ASN strings for one scan.
type keyer struct {
	tpl  map[string]string
	asn  map[uint32]string
	addr map[string]netip.Addr // ip filter values (invalid: matches nothing)
}

func newKeyer() *keyer {
	return &keyer{tpl: map[string]string{}, asn: map[uint32]string{}, addr: map[string]netip.Addr{}}
}

var statusKeys = []string{"1xx", "2xx", "3xx", "4xx", "5xx"}

func statusKey(s uint16) string {
	i := int(s/100) - 1
	if i < 0 {
		i = 0
	}
	if i > 4 {
		i = 4
	}
	return statusKeys[i]
}

func (k *keyer) path(x *Rec) string {
	if !x.PathRaw {
		return x.Path
	}
	t, ok := k.tpl[x.Path]
	if !ok {
		t = pathtpl.Template(x.Path)
		if len(k.tpl) < 1<<16 {
			k.tpl[x.Path] = t
		}
	}
	return t
}

// key of a record in a dimension ("" none; rule is handled by the caller).
func (k *keyer) key(dim string, x *Rec) string {
	switch dim {
	case "path":
		return k.path(x)
	case "country":
		return countryOf(x)
	case "asn":
		if x.ASN == 0 {
			return ""
		}
		s, ok := k.asn[x.ASN]
		if !ok {
			s = strconv.FormatUint(uint64(x.ASN), 10)
			k.asn[x.ASN] = s
		}
		return s
	case "net_class":
		return NetClasses[x.NetClass&15]
	case "ua_class":
		return pick(cm.UAClasses, x.UAClass)
	case "method":
		return Methods[x.Method]
	case "status_class":
		return statusKey(x.Status)
	case "site":
		return x.Site
	case "referrer":
		if x.Ref == "" {
			return cm.ReferrerDirect
		}
		return x.Ref
	case "browser":
		return pick(cm.BrowserFamilies, x.Browser)
	case "os":
		return pick(cm.OSFamilies, x.OS)
	case "device":
		return pick(cm.DeviceClasses, x.Device)
	case "bot_category":
		return pick(cm.BotCategories, x.BotCat)
	}
	return ""
}

// uaKey is the user_agent key of a User-Agent: cut at maxUAKey bytes on a
// UTF-8 boundary.
func uaKey(ua string) string {
	if len(ua) <= maxUAKey {
		return ua
	}
	ua = ua[:maxUAKey]
	for len(ua) > 0 && !utf8.RuneStart(ua[len(ua)-1]) {
		ua = ua[:len(ua)-1]
	}
	if len(ua) > 0 && ua[len(ua)-1] >= 0xC0 {
		ua = ua[:len(ua)-1]
	}
	return ua
}

func (k *keyer) match(fs []DimFilter, x *Rec) bool {
	for _, f := range fs {
		if f.Dim == "rule" {
			ok := false
			for i := uint8(0); i < x.NRules; i++ {
				ok = ok || x.Rules[i] == f.Value
			}
			if !ok || !alert(x) {
				return false
			}
			continue
		}
		switch f.Dim {
		case "ip": // D64
			a, ok := k.addr[f.Value]
			if !ok {
				a, _ = netip.ParseAddr(f.Value)
				k.addr[f.Value] = a
			}
			if !a.IsValid() || x.IP != a.Unmap() {
				return false
			}
			continue
		case "user_agent": // D64; lower case, a part of the value like D50
			if !strings.Contains(strings.ToLower(x.UA), f.Value) {
				return false
			}
			continue
		}
		if k.key(f.Dim, x) != f.Value {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- KPIs

// hll is a small HyperLogLog (p = 12) over visitor keys, which are already
// uniformly random.
type hll [1 << 12]uint8

func (h *hll) add(v [8]byte) {
	x := uint64(v[0])<<56 | uint64(v[1])<<48 | uint64(v[2])<<40 | uint64(v[3])<<32 | uint64(v[4])<<24 | uint64(v[5])<<16 | uint64(v[6])<<8 | uint64(v[7])
	i := x >> 52
	rho := uint8(bits.LeadingZeros64(x<<12|1<<11)) + 1
	if rho > h[i] {
		h[i] = rho
	}
}

func (h *hll) estimate() float64 {
	m := float64(len(h))
	sum, zeros := 0.0, 0
	for _, r := range h {
		sum += math.Ldexp(1, -int(r))
		if r == 0 {
			zeros++
		}
	}
	e := 0.7213 / (1 + 1.079/m) * m * m / sum
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros))
	}
	return e
}

// Kpis answers the KPI row of a website from the ring (filters the
// monitoring rings cannot combine). Visitors: distinct visitor keys of
// browser requests schild forwarded, per UTC day, summed (D36; always a
// Näherungswert).
func (r *Ring) Kpis(ctx context.Context, site string, from, to time.Time, fs []DimFilter) (websites.KpiSet, error) {
	if err := r.wait(ctx); err != nil {
		return websites.KpiSet{}, err
	}
	defer r.unlock()
	k := newKeyer()
	var req, stop, would, pv, s5 float64
	var hist [cm.HistogramBuckets]float64
	days := map[int64]*hll{}
	// Consistent sampling: count only visitors every segment of the range
	// keeps (those below the highest level), then scale by 2^level.
	var lv uint8
	for _, f := range r.snapshot(kindSeg, from.UnixMilli(), to.UnixMilli()) {
		lv = max(lv, f.level)
	}
	info, err := r.aggScan(ctx, from.UnixMilli(), to.UnixMilli(), func(x *Rec, w float64) {
		if site != "" && x.Site != site || !k.match(fs, x) {
			return
		}
		req += w
		if stopped(x.Outcome) {
			stop += w
		}
		if x.Outcome == OutWouldBlock {
			would += w
		}
		if x.PageView {
			pv += w
		}
		if x.Status >= 500 {
			s5 += w
		}
		hist[min(int(x.Dur), cm.HistogramBuckets-1)] += w
		if browserFwd(x) && keep(x.Visitor, lv) {
			d := x.T / 86_400_000
			h := days[d]
			if h == nil {
				h = new(hll)
				days[d] = h
			}
			h.add(x.Visitor)
		}
	})
	if err != nil {
		return websites.KpiSet{}, err
	}
	partial := from.UnixMilli() < info.covered || info.covered == 0
	exact := info.exact()
	val := func(v float64, ex bool) websites.KpiValue {
		v = math.Round(v)
		return websites.KpiValue{Value: &v, Exact: ex, Partial: partial}
	}
	out := websites.KpiSet{Requests: val(req, exact), Stopped: val(stop, exact), WouldBlock: val(would, exact), PageViews: val(pv, exact)}
	if req > 0 {
		e := s5 / req
		out.ErrorRate = websites.KpiValue{Value: &e, Exact: exact, Partial: partial}
	} else {
		out.ErrorRate = websites.KpiValue{Unavailable: "no_data"}
	}
	if p, ok := quantile(&hist, 0.95); ok {
		out.LatencyP95MS = websites.KpiValue{Value: &p, Exact: false, Partial: partial, ErrorBound: 0.25}
	} else {
		out.LatencyP95MS = websites.KpiValue{Unavailable: "no_data"}
	}
	var vis float64
	for _, h := range days {
		vis += h.estimate()
	}
	vis *= float64(uint64(1) << lv)
	out.Visitors = val(vis, false)
	return out, nil
}

func quantile(h *[cm.HistogramBuckets]float64, q float64) (float64, bool) {
	var total float64
	for _, n := range h {
		total += n
	}
	if total == 0 {
		return 0, false
	}
	target := math.Ceil(q * total)
	var cum float64
	for i, n := range h {
		cum += n
		if cum >= target {
			return durMS(uint8(i)), true
		}
	}
	return durMS(cm.HistogramBuckets - 2), true
}

// ---------------------------------------------------------------- breakdown

// Breakdown is a breakdown from the ring.
type Breakdown struct {
	Items   []cm.TopEntry
	Total   [3]int64 // requests, stopped, would_block
	Other   [3]int64
	Exact   bool
	Partial bool
}

// aiLabels of the AI assistant referrer keys.
var aiLabels = func() map[string]string {
	m := map[string]string{}
	for _, a := range cm.AIAssistants {
		m[cm.ReferrerAI+a.ID] = a.Name
	}
	return m
}()

// bdDims are the dimensions one breakdown scan fills.
var bdDims = []string{"path", "country", "asn", "net_class", "ua_class", "method", "status_class", "site", "referrer", "browser", "os", "device", "bot_category", "rule"}

type bdAcc struct{ req, stop, would, det float64 }

func (a *bdAcc) add(x *Rec, w float64) {
	a.req += w
	if stopped(x.Outcome) {
		a.stop += w
	}
	if x.Outcome == OutWouldBlock {
		a.would += w
	}
	if alert(x) {
		a.det += w
	}
}

// maxBdKeys bounds the entries of one dimension per scan; the rest is
// "other".
const maxBdKeys = 1 << 14

// maxUAKey bounds a user_agent key (TopEntry.key, FilterExpr value): a cut
// key is a part of the User-Agent, so its filter still matches (D65).
const maxUAKey = 512

// bdEntry is one cached breakdown scan: every dimension under one filter
// set, so the panels of a filtered website view cost one scan.
type bdEntry struct {
	key  string
	at   time.Time
	dims map[string]map[string]*bdAcc
	ips  map[netip.Addr]*bdAcc // by=ip (D65), keyed by address to spare a string per record
	tot  [2]bdAcc              // all, rule (detections)
	info scanInfo
	from int64
}

// bdTTL: a cached breakdown scan answers for this long.
const bdTTL = 30 * time.Second

func bdKey(site string, from, to time.Time, fs []DimFilter) string {
	var b strings.Builder
	b.WriteString(site)
	b.WriteByte(0)
	b.WriteString(strconv.FormatInt(from.UnixMilli(), 10))
	b.WriteByte(0)
	b.WriteString(strconv.FormatInt(to.UnixMilli(), 10))
	for _, f := range fs {
		b.WriteByte(0)
		b.WriteString(f.Dim)
		b.WriteByte(':')
		b.WriteString(f.Value)
	}
	return b.String()
}

// Breakdown answers getTrafficBreakdown under filters from the ring.
func (r *Ring) Breakdown(ctx context.Context, by, site string, from, to time.Time, fs []DimFilter, top int) (Breakdown, error) {
	if top <= 0 {
		top = 20
	}
	e, err := r.breakdownScan(ctx, site, from, to, fs)
	if err != nil {
		return Breakdown{}, err
	}
	m := e.dims[by]
	if by == "ip" {
		m = make(map[string]*bdAcc, len(e.ips))
		for a, acc := range e.ips {
			m[a.String()] = acc
		}
	}
	tot := e.tot[0]
	if by == "rule" {
		tot = e.tot[1]
	}
	out := Breakdown{Exact: e.info.exact(), Partial: e.from < e.info.covered || e.info.covered == 0, Items: []cm.TopEntry{}}
	for key, a := range m {
		it := cm.TopEntry{Key: key, Requests: int64(math.Round(a.req)), Stopped: int64(math.Round(a.stop)), WouldBlock: int64(math.Round(a.would))}
		if by == "rule" {
			it.Requests = int64(math.Round(a.det))
		}
		if by == "path" {
			it.Detections = int64(math.Round(a.det))
		}
		if by == "referrer" {
			it.Label = aiLabels[key]
		}
		out.Items = append(out.Items, it)
	}
	sort.Slice(out.Items, func(i, j int) bool {
		if out.Items[i].Requests != out.Items[j].Requests {
			return out.Items[i].Requests > out.Items[j].Requests
		}
		return out.Items[i].Key < out.Items[j].Key
	})
	out.Total = [3]int64{int64(math.Round(tot.req)), int64(math.Round(tot.stop)), int64(math.Round(tot.would))}
	if len(out.Items) > top {
		out.Items = out.Items[:top]
	}
	out.Other = out.Total
	for _, it := range out.Items {
		out.Other[0] -= it.Requests
		out.Other[1] -= it.Stopped
		out.Other[2] -= it.WouldBlock
	}
	for i := range out.Other {
		out.Other[i] = max(0, out.Other[i])
	}
	return out, nil
}

func (r *Ring) breakdownScan(ctx context.Context, site string, from, to time.Time, fs []DimFilter) (*bdEntry, error) {
	key := bdKey(site, from, to, fs)
	now := time.Now()
	r.bdMu.Lock()
	for _, e := range r.bdCache {
		if e.key == key && now.Sub(e.at) < bdTTL {
			r.bdMu.Unlock()
			return e, nil
		}
	}
	r.bdMu.Unlock()
	if err := r.wait(ctx); err != nil {
		return nil, err
	}
	defer r.unlock()
	// Another panel may have filled the cache while this one waited.
	r.bdMu.Lock()
	for _, e := range r.bdCache {
		if e.key == key && now.Sub(e.at) < bdTTL {
			r.bdMu.Unlock()
			return e, nil
		}
	}
	r.bdMu.Unlock()
	k := newKeyer()
	e := &bdEntry{key: key, at: now, dims: map[string]map[string]*bdAcc{}, ips: map[netip.Addr]*bdAcc{}, from: from.UnixMilli()}
	for _, d := range bdDims {
		e.dims[d] = map[string]*bdAcc{}
	}
	e.dims["user_agent"] = map[string]*bdAcc{}
	add := func(m map[string]*bdAcc, key string, x *Rec, w float64) {
		a := m[key]
		if a == nil {
			if len(m) >= maxBdKeys {
				return // bounded; the rest is "other"
			}
			a = &bdAcc{}
			m[key] = a
		}
		a.add(x, w)
	}
	info, err := r.aggScan(ctx, from.UnixMilli(), to.UnixMilli(), func(x *Rec, w float64) {
		if site != "" && x.Site != site || !k.match(fs, x) {
			return
		}
		t := &e.tot[0]
		t.req += w
		if stopped(x.Outcome) {
			t.stop += w
		}
		if x.Outcome == OutWouldBlock {
			t.would += w
		}
		for _, d := range bdDims[:len(bdDims)-1] {
			if key := k.key(d, x); key != "" {
				add(e.dims[d], key, x, w)
			}
		}
		if x.IP.IsValid() {
			a := e.ips[x.IP]
			if a == nil && len(e.ips) < maxBdKeys {
				a = &bdAcc{}
				e.ips[x.IP] = a
			}
			if a != nil {
				a.add(x, w)
			}
		}
		if x.UA != "" {
			add(e.dims["user_agent"], uaKey(x.UA), x, w)
		}
		if alert(x) {
			rt := &e.tot[1]
			rt.req += w
			if x.Outcome == OutBlockedWAF {
				rt.stop += w
			} else {
				rt.would += w
			}
			for i := uint8(0); i < x.NRules; i++ {
				add(e.dims["rule"], x.Rules[i], x, w)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	e.info = info
	r.bdMu.Lock()
	r.bdCache = append(r.bdCache, e)
	if len(r.bdCache) > 4 {
		r.bdCache = r.bdCache[len(r.bdCache)-4:]
	}
	r.bdMu.Unlock()
	return e, nil
}

// ---------------------------------------------------------------- series

// SeriesPoint counts of one step.
type SeriesPoint struct {
	Requests, Stopped, WouldBlock, Detections, PageViews float64
	N                                                    int
}

// Series answers request counters per step under filters: points[i] covers
// [first + i*step, first + (i+1)*step).
func (r *Ring) Series(ctx context.Context, site string, first time.Time, step time.Duration, n int, fs []DimFilter) ([]SeriesPoint, bool, error) {
	if err := r.wait(ctx); err != nil {
		return nil, false, err
	}
	defer r.unlock()
	k := newKeyer()
	pts := make([]SeriesPoint, n)
	f0, st := first.UnixMilli(), step.Milliseconds()
	info, err := r.aggScan(ctx, f0, f0+int64(n)*st, func(x *Rec, w float64) {
		if site != "" && x.Site != site || !k.match(fs, x) {
			return
		}
		i := int((x.T - f0) / st)
		if i < 0 || i >= n {
			return
		}
		p := &pts[i]
		p.N++
		p.Requests += w
		if stopped(x.Outcome) {
			p.Stopped += w
		}
		if x.Outcome == OutWouldBlock {
			p.WouldBlock += w
		}
		if alert(x) {
			p.Detections += w
		}
		if x.PageView {
			p.PageViews += w
		}
	})
	return pts, info.exact(), err
}

// ---------------------------------------------------------------- alerts

// VisitorStats summarise one visitor within the range of an alert scan.
type VisitorStats struct {
	Requests, Alerts, PageViews, S2xx int
	Browser                           bool
	// AlertRules are the rule sets of its alert requests (at most
	// maxAlertSets; Many: more alert requests than that).
	AlertRules [][3]string
	Many       bool
	W          float64 // sample weight
}

const maxAlertSets = 16

// NormalFor reports whether a visitor otherwise behaved like a normal
// visitor for rule: page views, 2xx answers, a browser, requests without an
// alert, and every alert request of it matched rule (no alert of another
// rule alone).
func (v *VisitorStats) NormalFor(rule string) bool {
	if v.PageViews == 0 || v.S2xx == 0 || !v.Browser || v.Alerts >= v.Requests || v.Many {
		return false
	}
	for _, set := range v.AlertRules {
		if set[0] != rule && set[1] != rule && set[2] != rule {
			return false
		}
	}
	return true
}

// PageStats of one page.
type PageStats struct {
	Site                 string
	Requests, Detections float64
	Blocked, WouldBlock  float64
	Status               [5]float64
	Hist                 [cm.HistogramBuckets]float64
	Rules                map[string]float64
	ObserveFollowedBy2xx float64
	FirstAlert           int64
	AlertVisitors        map[string]map[[8]byte]bool // rule -> visitors
	SampleEvents         map[string][][16]byte       // rule -> up to 5 event ids
	alertFirst           map[string]int64            // rule -> first alert
	_                    struct{}
}

// RuleStats of one rule.
type RuleStats struct {
	Detections, Blocked, WouldBlock float64
	Pages                           map[string]float64 // path -> detections
	Visitors                        map[[8]byte]bool
}

// AlertStats is the result of an alert scan.
type AlertStats struct {
	Pages    map[string]*PageStats // key site + "\x00" + path
	Rules    map[string]*RuleStats
	Visitors map[[8]byte]*VisitorStats
	Exact    bool
	From     int64 // coverage start within the range (ms)
}

// Bounds of an alert scan.
const (
	maxAlertVisitors = 100_000
	maxPages         = 20_000
)

// PageKey joins site and path.
func PageKey(site, path string) string { return site + "\x00" + path }

// SplitPageKey splits a PageKey.
func SplitPageKey(k string) (site, path string) {
	site, path, _ = strings.Cut(k, "\x00")
	return
}

// Alerts scans the range twice: the first pass counts pages and rules and
// finds the visitors with alerts, the second summarises those visitors.
func (r *Ring) Alerts(ctx context.Context, site string, from, to time.Time) (*AlertStats, error) {
	if err := r.wait(ctx); err != nil {
		return nil, err
	}
	defer r.unlock()
	k := newKeyer()
	st := &AlertStats{Pages: map[string]*PageStats{}, Rules: map[string]*RuleStats{}, Visitors: map[[8]byte]*VisitorStats{}}
	f, t := from.UnixMilli(), to.UnixMilli()
	info, err := r.aggScan(ctx, f, t, func(x *Rec, w float64) {
		if site != "" && x.Site != site {
			return
		}
		key := PageKey(x.Site, k.path(x))
		p := st.Pages[key]
		if p == nil {
			if len(st.Pages) >= maxPages {
				return
			}
			p = &PageStats{Site: x.Site, Rules: map[string]float64{}, AlertVisitors: map[string]map[[8]byte]bool{}, SampleEvents: map[string][][16]byte{},
				alertFirst: map[string]int64{}}
			st.Pages[key] = p
		}
		p.Requests += w
		p.Status[min(max(int(x.Status/100)-1, 0), 4)] += w
		p.Hist[min(int(x.Dur), cm.HistogramBuckets-1)] += w
		if !alert(x) {
			return
		}
		p.Detections += w
		if x.Outcome == OutBlockedWAF {
			p.Blocked += w
		} else {
			p.WouldBlock += w
			if x.Status/100 == 2 {
				p.ObserveFollowedBy2xx += w
			}
		}
		if p.FirstAlert == 0 || x.T < p.FirstAlert {
			p.FirstAlert = x.T
		}
		if _, ok := st.Visitors[x.Visitor]; !ok && len(st.Visitors) < maxAlertVisitors {
			st.Visitors[x.Visitor] = &VisitorStats{W: w}
		}
		for i := uint8(0); i < x.NRules; i++ {
			id := x.Rules[i]
			p.Rules[id] += w
			if f, ok := p.alertFirst[id]; !ok || x.T < f {
				p.alertFirst[id] = x.T
			}
			av := p.AlertVisitors[id]
			if av == nil {
				av = map[[8]byte]bool{}
				p.AlertVisitors[id] = av
			}
			if len(av) < maxAlertVisitors {
				av[x.Visitor] = true
			}
			if x.HasEvent && len(p.SampleEvents[id]) < 5 {
				p.SampleEvents[id] = append(p.SampleEvents[id], x.EventID)
			}
			rs := st.Rules[id]
			if rs == nil {
				rs = &RuleStats{Pages: map[string]float64{}, Visitors: map[[8]byte]bool{}}
				st.Rules[id] = rs
			}
			rs.Detections += w
			if x.Outcome == OutBlockedWAF {
				rs.Blocked += w
			} else {
				rs.WouldBlock += w
			}
			rs.Pages[key] += w
			if len(rs.Visitors) < maxAlertVisitors {
				rs.Visitors[x.Visitor] = true
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if len(st.Visitors) > 0 {
		if _, err := r.aggScan(ctx, f, t, func(x *Rec, _ float64) {
			if site != "" && x.Site != site {
				return
			}
			v := st.Visitors[x.Visitor]
			if v == nil {
				return
			}
			v.Requests++
			if x.PageView {
				v.PageViews++
			}
			if x.Status/100 == 2 {
				v.S2xx++
			}
			if browserFwd(x) || int(x.BotCat) == len(cm.BotCategories)-1 && !x.HasBot {
				v.Browser = true
			}
			if alert(x) {
				v.Alerts++
				if len(v.AlertRules) < maxAlertSets {
					var set [3]string
					copy(set[:], x.Rules[:x.NRules])
					v.AlertRules = append(v.AlertRules, set)
				} else {
					v.Many = true
				}
			}
		}); err != nil {
			return nil, err
		}
	}
	st.Exact = info.exact()
	st.From = max(f, info.covered)
	return st, nil
}

// FirstAlertOf returns the first alert time of rule on a page.
func (p *PageStats) FirstAlertOf(rule string) int64 { return p.alertFirst[rule] }

// P95 of a page (upper bucket bound).
func (p *PageStats) P95() (float64, bool) { return quantile(&p.Hist, 0.95) }

// ---------------------------------------------------------------- bots

// BotStats of one catalogue bot.
type BotStats struct {
	Requests, BytesOut float64
	LastSeen           int64
	Verif              [5]float64 // by Entry.Verif
	Disallowed         float64
	Blocked            float64 // D57: blocked_crawler
	WouldBlock         float64 // D57: would_block of the crawler policy alone
	RobotsRead         int64   // last request to /robots.txt (ms; 0 none)
	Category           uint8
}

// BotScan is the result of a bot scan.
type BotScan struct {
	Bots       map[uint16]*BotStats
	Categories map[uint8]*[3]float64 // requests, bytes, distinct bots
	MinRate    float64
}

// Bots scans the range for the bot overview.
func (r *Ring) Bots(ctx context.Context, site string, from, to time.Time) (*BotScan, error) {
	if err := r.wait(ctx); err != nil {
		return nil, err
	}
	defer r.unlock()
	out := &BotScan{Bots: map[uint16]*BotStats{}, Categories: map[uint8]*[3]float64{}}
	seen := map[uint16]bool{}
	info, err := r.aggScan(ctx, from.UnixMilli(), to.UnixMilli(), func(x *Rec, w float64) {
		if site != "" && x.Site != site {
			return
		}
		c := out.Categories[x.BotCat]
		if c == nil {
			c = &[3]float64{}
			out.Categories[x.BotCat] = c
		}
		c[0] += w
		c[1] += w * float64(x.BytesOut)
		if !x.HasBot {
			return
		}
		if !seen[x.Bot] {
			seen[x.Bot] = true
			c[2]++
		}
		b := out.Bots[x.Bot]
		if b == nil {
			b = &BotStats{Category: x.BotCat}
			out.Bots[x.Bot] = b
		}
		b.Requests += w
		b.BytesOut += w * float64(x.BytesOut)
		b.LastSeen = max(b.LastSeen, x.T)
		b.Verif[min(int(x.Verif), 4)] += w
		if x.Disallowed {
			b.Disallowed += w
		}
		switch {
		case x.Outcome == OutBlockedCrawler:
			b.Blocked += w
		case x.Crawler:
			b.WouldBlock += w
		}
		if x.Path == "/robots.txt" && x.Status/100 == 2 {
			b.RobotsRead = max(b.RobotsRead, x.T)
		}
	})
	out.MinRate = info.minRate
	return out, err
}
