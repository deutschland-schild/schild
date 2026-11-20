package monitoring

import (
	"strconv"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// Counter slots of an accumulator (cm.TrafficCounters field by field).
const (
	cRequests = iota
	cForwarded
	cStopped
	cBlockedWAF
	cBlockedBehaviour
	cRateLimited
	cRejectedLimit
	cChallenged
	cFailClosed
	cFCTimeout
	cFCBusy
	cFCNotReady
	cFCPanic
	cWouldBlock
	cWouldRateLimit
	cPageViews
	cDetections
	cS1xx
	cS2xx
	cS3xx
	cS4xx
	cS5xx
	cUpstreamErrors
	cUpstreamTimeouts
	cBytesIn
	cBytesOut
	cWaitingPage    // D37 overlay of cFCBusy, cFCTimeout and cFCBodyBusy
	cRechecked      // D33 amendment overlay of cRequests
	cFCBodyBusy     // D41
	cBlockedCrawler // D57
	nCounters
)

// Histogram parts.
const (
	hTotal = iota
	hOverhead
	hUpstream
	nHist
)

// dimCount counts requests, stopped and would_block of one dimension value.
type dimCount [3]int64

// Fixed-size dimensions (exact breakdowns).
type dims struct {
	country  [nCountries]dimCount
	netClass [11]dimCount
	uaClass  [6]dimCount
	method   [10]dimCount
	status   [5]dimCount
	browser  [9]dimCount
	os       [8]dimCount
	device   [5]dimCount
	bot      [13]dimCount
}

// accum collects one interval. Top lists (path, asn, referrer, rule) are
// only kept where withTop is set (per-second shard accumulators and the
// 1 min and 10 min aggregates).
type accum struct {
	c    [nCounters]int64
	hist [nHist][cm.HistogramBuckets]int64
	dims dims
	// unique and fresh count visitors (D36 amendment), bots the bot clients.
	unique hll
	fresh  hll
	bots   hll
	// asnOrg remembers the AS organisation of top ASNs.
	path, asn, ref, rule *topTable
	withTop              bool
	// sites are the per-website parts (D36); siteTop keeps their top lists.
	sites   [sites.Slots]*siteAcc
	siteTop bool
}

func newAccum(withTop bool, topCap int) *accum {
	a := &accum{withTop: withTop}
	if withTop {
		a.path, a.asn, a.ref, a.rule = newTopTable(topCap), newTopTable(topCap), newTopTable(topCap), newTopTable(topCap)
	}
	return a
}

func (a *accum) reset() {
	a.c = [nCounters]int64{}
	a.hist = [nHist][cm.HistogramBuckets]int64{}
	a.dims = dims{}
	a.unique.reset()
	a.fresh.reset()
	a.bots.reset()
	if a.withTop {
		a.path.reset()
		a.asn.reset()
		a.ref.reset()
		a.rule.reset()
	}
	for _, st := range a.sites {
		if st != nil {
			st.reset()
		}
	}
}

func addDims(dst, src []dimCount) {
	for i := range src {
		dst[i][0] += src[i][0]
		dst[i][1] += src[i][1]
		dst[i][2] += src[i][2]
	}
}

// merge adds o (counters, histograms, dimensions, sketches; top lists when
// both keep them).
func (a *accum) merge(o *accum) {
	for i, v := range o.c {
		a.c[i] += v
	}
	for p := range o.hist {
		for i, v := range o.hist[p] {
			a.hist[p][i] += v
		}
	}
	addDims(a.dims.country[:], o.dims.country[:])
	addDims(a.dims.netClass[:], o.dims.netClass[:])
	addDims(a.dims.uaClass[:], o.dims.uaClass[:])
	addDims(a.dims.method[:], o.dims.method[:])
	addDims(a.dims.status[:], o.dims.status[:])
	addDims(a.dims.browser[:], o.dims.browser[:])
	addDims(a.dims.os[:], o.dims.os[:])
	addDims(a.dims.device[:], o.dims.device[:])
	addDims(a.dims.bot[:], o.dims.bot[:])
	a.unique.merge(&o.unique)
	a.fresh.merge(&o.fresh)
	a.bots.merge(&o.bots)
	if a.withTop && o.withTop {
		a.path.merge(o.path)
		a.asn.merge(o.asn)
		a.ref.merge(o.ref)
		a.rule.merge(o.rule)
	}
	for i, st := range o.sites {
		if st.used() {
			a.siteSlot(i).merge(st)
		}
	}
}

// traffic returns the counters on the wire.
func (a *accum) traffic() cm.TrafficCounters { return trafficOf(&a.c) }

func trafficOf(c *[nCounters]int64) cm.TrafficCounters {
	return cm.TrafficCounters{
		Requests: c[cRequests], Forwarded: c[cForwarded], Stopped: c[cStopped], BlockedWAF: c[cBlockedWAF],
		BlockedBehaviour: c[cBlockedBehaviour], RateLimited: c[cRateLimited], RejectedLimit: c[cRejectedLimit], Challenged: c[cChallenged],
		FailClosed:   c[cFailClosed],
		FailClosedBy: cm.FailClosedBy{WAFTimeout: c[cFCTimeout], WAFBusy: c[cFCBusy], NotReady: c[cFCNotReady], Panic: c[cFCPanic], BodyBusy: c[cFCBodyBusy]},
		WouldBlock:   c[cWouldBlock], WouldRateLimit: c[cWouldRateLimit], PageViews: c[cPageViews], Detections: c[cDetections],
		Status:         cm.StatusClasses{S1xx: c[cS1xx], S2xx: c[cS2xx], S3xx: c[cS3xx], S4xx: c[cS4xx], S5xx: c[cS5xx]},
		UpstreamErrors: c[cUpstreamErrors], UpstreamTimeouts: c[cUpstreamTimeouts], BytesIn: c[cBytesIn], BytesOut: c[cBytesOut],
		WaitingPageShown: c[cWaitingPage], Rechecked: c[cRechecked], BlockedCrawler: c[cBlockedCrawler],
	}
}

func histOf(h *[cm.HistogramBuckets]int64) cm.LatencyHistogram {
	out := cm.LatencyHistogram{Scheme: cm.HistogramScheme, Counts: map[string]int64{}}
	for i, v := range h {
		if v > 0 {
			out.Counts[strconv.Itoa(i)] = v
		}
	}
	return out
}

// quantile of one histogram part in ms (nil without data).
func (a *accum) quantile(part int, q float64) *float64 {
	return quantileOf(&a.hist[part], q)
}

func quantileOf(h *[cm.HistogramBuckets]int64, q float64) *float64 {
	m := map[int]int64{}
	for i, v := range h {
		if v > 0 {
			m[i] = v
		}
	}
	v, ok := cm.Quantile(m, q)
	if !ok {
		return nil
	}
	return &v
}

func dimTop(d []dimCount, key func(int) string) []cm.TopEntry {
	var out []cm.TopEntry
	for i, v := range d {
		if v[0] == 0 {
			continue
		}
		out = append(out, cm.TopEntry{Key: key(i), Requests: v[0], Stopped: v[1], WouldBlock: v[2]})
	}
	return out
}

func listKey(l []string) func(int) string { return func(i int) string { return l[i] } }

// bucket builds the wire bucket of a finished interval.
func (a *accum) bucket(start time.Time, res cm.Resolution, step int, partial bool, values cm.MetricValues, objects []cm.ObjectValues) cm.MetricBucket {
	b := cm.MetricBucket{
		T: ts(start), Resolution: res, StepS: step, Partial: partial, Traffic: a.traffic(),
		Latency: cm.BucketLatency{Total: histOf(&a.hist[hTotal]), Overhead: histOf(&a.hist[hOverhead]), Upstream: histOf(&a.hist[hUpstream])},
		Sites:   []cm.SiteTraffic{}, Values: values, Objects: objects,
	}
	if a.c[cRequests] > 0 || !a.unique.empty() || !a.bots.empty() {
		u, n, bt := a.unique.estimate(), a.fresh.estimate(), a.bots.estimate()
		b.Clients = cm.BucketClients{Unique: &u, New: &n, Bots: &bt}
	}
	if a.withTop {
		d := &a.dims
		b.Top = &cm.BucketTop{
			Path: a.path.top(cm.TopK, true), ASN: a.asn.top(cm.TopK, false), Referrer: a.ref.top(cm.TopK, false), Rule: a.rule.top(cm.TopK, false),
			Country: dimTop(d.country[:], countryCode), NetClass: dimTop(d.netClass[:], listKey(netClasses)), UAClass: dimTop(d.uaClass[:], listKey(cm.UAClasses)),
			Method: dimTop(d.method[:], listKey(methods)), Browser: dimTop(d.browser[:], listKey(cm.BrowserFamilies)), OS: dimTop(d.os[:], listKey(cm.OSFamilies)),
			Device: dimTop(d.device[:], listKey(cm.DeviceClasses)), BotCategory: dimTop(d.bot[:], listKey(cm.BotCategories)),
		}
	}
	return b
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }
