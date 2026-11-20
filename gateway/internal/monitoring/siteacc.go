package monitoring

import (
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// v0.5 (D36): per-website counters, latency histograms, client estimates
// and (10 min ring) top lists. Slot i of an accumulator is the website in
// slot i of the sites view (the first 32 tracked websites; sites.OtherSlot
// sums the rest). A slot is allocated the first time it counts and then
// reset in place, so the request path allocates per slot once per buffer.

// siteAcc collects one website in one interval.
type siteAcc struct {
	c      [nCounters]int64
	hist   [nHist][cm.HistogramBuckets]int64
	unique hll // visitors (D36 amendment)
	fresh  hll
	bots   hll      // bot clients
	top    *siteTop // per-shard and 10 min accumulators only
}

// siteTop are the per-website top lists: path, asn, country, referrer and
// rule space-saving (cm.SiteTopK), the small enums exact.
type siteTop struct {
	netClass [11]dimCount
	uaClass  [6]dimCount
	method   [10]dimCount
	browser  [9]dimCount
	os       [8]dimCount
	device   [5]dimCount
	bot      [13]dimCount

	path, asn, country, ref, rule *topTable
}

func newSiteTop() *siteTop {
	k := 2 * cm.SiteTopK
	return &siteTop{path: newTopTable(k), asn: newTopTable(k), country: newTopTable(k), ref: newTopTable(k), rule: newTopTable(k)}
}

func (t *siteTop) reset() {
	t.netClass, t.uaClass, t.method = [11]dimCount{}, [6]dimCount{}, [10]dimCount{}
	t.browser, t.os, t.device, t.bot = [9]dimCount{}, [8]dimCount{}, [5]dimCount{}, [13]dimCount{}
	t.path.reset()
	t.asn.reset()
	t.country.reset()
	t.ref.reset()
	t.rule.reset()
}

func (t *siteTop) merge(o *siteTop) {
	addDims(t.netClass[:], o.netClass[:])
	addDims(t.uaClass[:], o.uaClass[:])
	addDims(t.method[:], o.method[:])
	addDims(t.browser[:], o.browser[:])
	addDims(t.os[:], o.os[:])
	addDims(t.device[:], o.device[:])
	addDims(t.bot[:], o.bot[:])
	t.path.merge(o.path)
	t.asn.merge(o.asn)
	t.country.merge(o.country)
	t.ref.merge(o.ref)
	t.rule.merge(o.rule)
}

func (t *siteTop) wire() *cm.BucketTop {
	k := cm.SiteTopK
	return &cm.BucketTop{
		Path: t.path.top(k, true), ASN: t.asn.top(k, false), Country: t.country.top(k, false), Referrer: t.ref.top(k, false), Rule: t.rule.top(k, false),
		NetClass: dimTop(t.netClass[:], listKey(netClasses)), UAClass: dimTop(t.uaClass[:], listKey(cm.UAClasses)), Method: dimTop(t.method[:], listKey(methods)),
		Browser: dimTop(t.browser[:], listKey(cm.BrowserFamilies)), OS: dimTop(t.os[:], listKey(cm.OSFamilies)), Device: dimTop(t.device[:], listKey(cm.DeviceClasses)),
		BotCategory: dimTop(t.bot[:], listKey(cm.BotCategories)),
	}
}

func (s *siteAcc) used() bool { return s != nil && s.c[cRequests] > 0 }

func (s *siteAcc) reset() {
	s.c = [nCounters]int64{}
	s.hist = [nHist][cm.HistogramBuckets]int64{}
	s.unique.reset()
	s.fresh.reset()
	s.bots.reset()
	if s.top != nil {
		s.top.reset()
	}
}

func (s *siteAcc) merge(o *siteAcc) {
	for i, v := range o.c {
		s.c[i] += v
	}
	for p := range o.hist {
		for i, v := range o.hist[p] {
			s.hist[p][i] += v
		}
	}
	s.unique.merge(&o.unique)
	s.fresh.merge(&o.fresh)
	s.bots.merge(&o.bots)
	if s.top != nil && o.top != nil {
		s.top.merge(o.top)
	}
}

// siteSlot returns slot i of a, allocating it on first use.
func (a *accum) siteSlot(i int) *siteAcc {
	s := a.sites[i]
	if s == nil {
		s = &siteAcc{}
		if a.siteTop {
			s.top = newSiteTop()
		}
		a.sites[i] = s
	}
	return s
}

// siteBuckets returns the wire traffic of every slot with requests
// (MetricBucket.sites, D36); day are the day-long estimates per slot.
func (a *accum) siteBuckets(v *sites.View, day *[sites.Slots]hll) []cm.SiteTraffic {
	out := []cm.SiteTraffic{}
	if v == nil {
		return out
	}
	for i, s := range a.sites {
		if !s.used() {
			continue
		}
		name := v.SlotName(i)
		if name == "" {
			continue
		}
		st := cm.SiteTraffic{Site: name, Traffic: trafficOf(&s.c)}
		st.Latency = &cm.BucketLatency{Total: histOf(&s.hist[hTotal]), Overhead: histOf(&s.hist[hOverhead]), Upstream: histOf(&s.hist[hUpstream])}
		u, n, bt := s.unique.estimate(), s.fresh.estimate(), s.bots.estimate()
		st.Clients = &cm.BucketClients{Unique: &u, New: &n, Bots: &bt}
		if day != nil {
			d := day[i].estimate()
			st.Clients.UniqueDay = &d
		}
		if a.siteTop && s.top != nil {
			st.Top = s.top.wire()
		}
		out = append(out, st)
	}
	return out
}

// countRequest adds one request to a counter set (the gateway's and its
// website's use the same rules).
func countRequest(c *[nCounters]int64, q *Req, si int, would, det int64, pageView bool) {
	c[cRequests]++
	switch q.Class {
	case Forwarded:
		c[cForwarded]++
	case BlockedWAF:
		c[cStopped]++
		c[cBlockedWAF]++
	case BlockedBehaviour:
		c[cStopped]++
		c[cBlockedBehaviour]++
	case RateLimited:
		c[cStopped]++
		c[cRateLimited]++
	case RejectedLimit:
		c[cStopped]++
		c[cRejectedLimit]++
	case Challenged:
		c[cStopped]++
		c[cChallenged]++
	case BlockedCrawler:
		c[cStopped]++
		c[cBlockedCrawler]++
	case FailTimeout:
		c[cFailClosed]++
		c[cFCTimeout]++
		if q.WaitingPage {
			c[cWaitingPage]++
		}
	case FailBusy:
		c[cFailClosed]++
		c[cFCBusy]++
		if q.WaitingPage {
			c[cWaitingPage]++
		}
	case FailBodyBusy:
		c[cFailClosed]++
		c[cFCBodyBusy]++
		if q.WaitingPage {
			c[cWaitingPage]++
		}
	case FailNotReady:
		c[cFailClosed]++
		c[cFCNotReady]++
	case FailPanic:
		c[cFailClosed]++
		c[cFCPanic]++
	}
	c[cWouldBlock] += would
	if q.WouldRL && q.Class == Forwarded {
		c[cWouldRateLimit]++
	}
	if pageView {
		c[cPageViews]++
	}
	c[cDetections] += det
	c[cS1xx+si]++
	switch q.Upstream {
	case UpstreamError:
		c[cUpstreamErrors]++
	case UpstreamTimeout:
		c[cUpstreamTimeouts]++
	}
	c[cBytesIn] += q.BytesIn
	c[cBytesOut] += q.BytesOut
	if q.Rechecked {
		c[cRechecked]++
	}
}

// histRequest adds the latency of one request.
func histRequest(h *[nHist][cm.HistogramBuckets]int64, q *Req) {
	if !q.Timed {
		return
	}
	total := q.Total
	h[hTotal][cm.BucketOf(ms(total))]++
	if q.Class == Forwarded {
		h[hUpstream][cm.BucketOf(ms(q.UpstreamDur))]++
		total -= q.UpstreamDur
	}
	h[hOverhead][cm.BucketOf(ms(total))]++
}
