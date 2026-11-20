package monitoring

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// ErrFilterUnavailable: the filter combination needs the request ring
// (MVP-22), which this gateway does not keep (409 filter_unavailable, D36).
var ErrFilterUnavailable = errors.New("filter unavailable")

// siteSel is a resolved site filter.
type siteSel struct {
	id    string
	slot  int
	whole bool // the whole traffic of the gateway (no filter, or its only website)
	none  bool // a website without numbers here (unprotected, untracked)
}

// selectSite resolves the site parameter (D36): "" is the whole gateway; a
// website id of this gateway its slot; a gateway with one protected
// website answers it from the whole traffic. Unknown ids: ErrUnknownSite.
func (m *Monitor) selectSite(site string) (siteSel, error) {
	if site == "" {
		return siteSel{whole: true, slot: sites.NoSlot}, nil
	}
	v := m.view()
	if v == nil {
		if site == DefaultSite {
			return siteSel{id: site, whole: true, slot: sites.NoSlot}, nil
		}
		return siteSel{}, ErrUnknownSite
	}
	w, ok := v.Website(site)
	if !ok {
		return siteSel{}, ErrUnknownSite
	}
	sel := siteSel{id: site, slot: v.SlotOf(site)}
	switch {
	case w.Protection == websites.Unprotected:
		sel.none = true
	case v.Protected == 1:
		sel.whole = true
	case sel.slot < 0 || sel.slot == sites.OtherSlot:
		sel.none = true
	}
	return sel, nil
}

// CheckSite reports whether site is empty or a website of this gateway.
func (m *Monitor) CheckSite(site string) error {
	_, err := m.selectSite(site)
	return err
}

// siteBucket returns the part of b that belongs to the selected website:
// its counters, latency and estimates with the server values of b. nil
// for a website without numbers.
func siteBucket(b *cm.MetricBucket, sel siteSel) *cm.MetricBucket {
	if sel.whole {
		return b
	}
	if sel.none {
		return nil
	}
	out := &cm.MetricBucket{T: b.T, Resolution: b.Resolution, StepS: b.StepS, Partial: b.Partial, GapKind: b.GapKind, Values: b.Values, Objects: b.Objects,
		Latency: cm.BucketLatency{Total: emptyHist(), Overhead: emptyHist(), Upstream: emptyHist()}}
	for i := range b.Sites {
		s := &b.Sites[i]
		if s.Site != sel.id {
			continue
		}
		out.Traffic = s.Traffic
		if s.Latency != nil {
			out.Latency = *s.Latency
		}
		if s.Clients != nil {
			out.Clients = *s.Clients
		}
		out.Top = s.Top
		break
	}
	return out
}

// onlyOf is the website a read needs (readParts.only): none for the whole
// gateway, else the selected one.
func onlyOf(sel siteSel) string {
	if sel.whole || sel.none || sel.id == "" {
		return "-"
	}
	return sel.id
}

func emptyHist() cm.LatencyHistogram {
	return cm.LatencyHistogram{Scheme: cm.HistogramScheme, Counts: map[string]int64{}}
}

// Filter is one parsed `dimension:value` (D36 click to filter).
type Filter struct {
	Dim, Value string
}

// ParseFilters parses the filter parameters (at most 4).
func ParseFilters(raw []string) ([]Filter, error) {
	if len(raw) > 4 {
		return nil, &ErrInvalid{"filter", "at most 4 filters"}
	}
	var out []Filter
	for _, r := range raw {
		d, v, ok := strings.Cut(r, ":")
		if !ok || v == "" || len(v) > 512 {
			return nil, &ErrInvalid{"filter", "dimension:value expected"}
		}
		known := false
		for _, x := range cm.Dimensions {
			known = known || (x == d && d != "site")
		}
		for _, x := range cm.RingFilterDimensions {
			known = known || x == d
		}
		if !known {
			return nil, &ErrInvalid{"filter", "unknown dimension " + d}
		}
		for _, c := range v {
			if c < 0x20 || c == 0x7f {
				return nil, &ErrInvalid{"filter", "control character in value"}
			}
		}
		switch d {
		case "ip":
			a, err := netip.ParseAddr(v)
			if err != nil {
				return nil, &ErrInvalid{"filter", "ip: address expected"}
			}
			v = a.Unmap().WithZone("").String()
		case "user_agent":
			v = strings.ToLower(v)
		}
		out = append(out, Filter{d, v})
	}
	return out, nil
}

// ringOnly reports whether a filter needs the request ring whatever the
// number of filters (D64: ip, user_agent).
func ringOnly(fs []Filter) bool {
	for _, f := range fs {
		for _, d := range cm.RingFilterDimensions {
			if f.Dim == d {
				return true
			}
		}
	}
	return false
}

// filterEntry returns the counts of the filter value in a bucket's top
// lists (zero when the value is not listed) and whether the dimension has a
// top list there.
func filterEntry(top *cm.BucketTop, t *cm.TrafficCounters, f Filter) (cm.TopEntry, bool) {
	if f.Dim == "status_class" {
		s := t.Status
		n := map[string]int64{"1xx": s.S1xx, "2xx": s.S2xx, "3xx": s.S3xx, "4xx": s.S4xx, "5xx": s.S5xx}
		v, ok := n[f.Value]
		if !ok {
			return cm.TopEntry{}, true
		}
		return cm.TopEntry{Key: f.Value, Requests: v, Stopped: stoppedOfClass(t, f.Value)}, true
	}
	if top == nil {
		return cm.TopEntry{}, false
	}
	for _, e := range topList(top, f.Dim) {
		if e.Key == f.Value {
			return e, true
		}
	}
	return cm.TopEntry{}, true
}

// stoppedOfClass splits the stopped requests by the status class of
// schild's answer. Every stop (WAF and behaviour blocks 403, rate limits
// 429, request limits 400/413/431) answers a 4xx. fail_closed (503) is
// never counted in stopped (countRequest), so it neither adds to 5xx nor
// comes off 4xx (D36 fix round 2, re-measurement B 3.3 a: 342 fail_closed
// gave 4xx 211 and 5xx 342 for a truth of 511 and 0). The counters do not
// keep the status per stop, so the split stays marked as an estimate
// (StatusStoppedExact).
func stoppedOfClass(t *cm.TrafficCounters, class string) int64 {
	if class == "4xx" {
		return t.Stopped
	}
	return 0
}

// StatusStoppedExact: under a status_class filter, stopped is split by
// stoppedOfClass (an estimate) and would_block is not known (forwarded
// requests get the backend's status).
const StatusStoppedExact = false

// filteredTraffic is the TrafficCounters of a bucket under one filter:
// requests, stopped, would_block and detections only.
func filteredTraffic(b *cm.MetricBucket, f Filter) (cm.TrafficCounters, bool) {
	e, ok := filterEntry(b.Top, &b.Traffic, f)
	if !ok {
		return cm.TrafficCounters{}, false
	}
	det := e.Detections
	if f.Dim == "rule" {
		det = e.Requests
	}
	return cm.TrafficCounters{Requests: e.Requests, Stopped: e.Stopped, WouldBlock: e.WouldBlock, Detections: det}, true
}

// filterMetric reports whether a metric can be answered under a filter
// from the top lists.
func filterMetric(id string) bool {
	switch id {
	case "traffic.requests", "traffic.stopped", "traffic.would_block", "traffic.detections":
		return true
	}
	return false
}

func atoiKey(k string) int {
	i, _ := strconv.Atoi(k)
	return i
}
