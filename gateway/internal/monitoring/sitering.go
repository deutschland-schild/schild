package monitoring

import (
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// v0.5 (D36): the per-website state in memory - the last hour of 10 s
// counters (website hints, status over 5 minutes), the last 5 minutes of
// histograms and client sketches (TrafficNow of a website, realtime), the
// day-long client sketches (unique_day) and the website hints. A slot is
// allocated the first time its website has traffic: at most
// sites.Slots x about 140 KiB.

const (
	siteHourSteps   = 360 // 10 s steps: 1 h
	siteRecentSteps = 30  // 10 s steps: 5 min
)

type siteStep struct {
	sec int64 // start of the 10 s step
	c   [nCounters]int64
}

type siteRecent struct {
	sec    int64
	hist   [nHist][cm.HistogramBuckets]int64
	unique hll
}

type siteRing struct {
	hour   [siteHourSteps]siteStep
	recent [siteRecentSteps]siteRecent
	pos    int // steps written
	hints  *hintState
}

// push stores the 10 s step that starts at sec (mu held).
func (r *siteRing) push(sec int64, s *siteAcc) {
	h := &r.hour[r.pos%siteHourSteps]
	h.sec, h.c = sec, s.c
	rc := &r.recent[r.pos%siteRecentSteps]
	rc.sec, rc.hist, rc.unique = sec, s.hist, s.unique
	r.pos++
}

// sum adds the counters of the steps that start at or after since.
func (r *siteRing) sum(since int64) (c [nCounters]int64, n int) {
	for i := 0; i < min(r.pos, siteHourSteps); i++ {
		h := &r.hour[i]
		if h.sec < since {
			continue
		}
		for k, v := range h.c {
			c[k] += v
		}
		n++
	}
	return
}

// recentSum merges the histograms and sketches of the steps that start at
// or after since.
func (r *siteRing) recentSum(since int64) (h [nHist][cm.HistogramBuckets]int64, u hll, n int) {
	for i := 0; i < min(r.pos, siteRecentSteps); i++ {
		x := &r.recent[i]
		if x.sec < since {
			continue
		}
		for p := range x.hist {
			for k, v := range x.hist[p] {
				h[p][k] += v
			}
		}
		u.merge(&x.unique)
		n++
	}
	return
}

// siteState is the per-website state of the monitor (mu held for every
// access).
type siteState struct {
	rings  [sites.Slots]*siteRing
	day    [sites.Slots]hll
	dayAll hll
	dayNum int64
}

// pushTen stores the finished 10 s accumulator a (ends at now) per slot.
func (m *Monitor) pushTen(now time.Time, a *accum) {
	sec := now.Unix() - 10
	for i, s := range a.sites {
		r := m.site.rings[i]
		if r == nil {
			if !s.used() {
				continue
			}
			r = &siteRing{hints: newHintState()}
			m.site.rings[i] = r
		}
		if s == nil {
			var zero siteAcc
			r.push(sec, &zero)
			continue
		}
		r.push(sec, s)
	}
}

// addDay merges one second into the day-long sketches.
func (m *Monitor) addDay(a *accum) {
	m.site.dayAll.merge(&a.unique)
	for i, s := range a.sites {
		if s.used() {
			m.site.day[i].merge(&s.unique)
		}
	}
}

// rollDay starts the day-long sketches over at a new UTC day (after the
// buckets of the old day are finished) and moves the seven-day filter of
// seen clients on, so "new" means not seen in the last seven days.
func (m *Monitor) rollDay(now time.Time) {
	d := now.Unix() / 86400
	if d == m.site.dayNum {
		return
	}
	m.site.dayNum = d
	m.rec.seen.rotate(d)
	m.site.dayAll.reset()
	for i := range m.site.day {
		m.site.day[i].reset()
	}
}

// view is the current website view (nil without sites).
func (m *Monitor) view() *sites.View {
	if m.cfg.Sites == nil {
		return nil
	}
	return m.cfg.Sites.View()
}

// siteHints evaluates the website-scoped hints of every slot (mu held).
func (m *Monitor) siteHints(now time.Time) {
	v := m.view()
	if v == nil {
		return
	}
	sec := now.Unix()
	for i, r := range m.site.rings {
		if r == nil {
			continue
		}
		name := v.SlotName(i)
		if name == "" || name == websites.OtherSite {
			continue
		}
		r.hints.site = name
		c5, n5 := r.sum(sec - 300)
		h5, _, _ := r.recentSum(sec - 300)
		cH, nH := r.sum(sec - 3600)
		trafficHints(r.hints, now, c5, &h5[hUpstream], n5, cH, nH)
	}
}

// siteHintList returns the hints of one website, or of every website for
// slot NoSlot (mu held).
func (m *Monitor) siteHintList(now time.Time, slot int) []cm.HealthHint {
	var out []cm.HealthHint
	for i, r := range m.site.rings {
		if r == nil || (slot != sites.NoSlot && i != slot) {
			continue
		}
		out = append(out, r.hints.list(now)...)
	}
	return out
}

// SiteNow is the TrafficNow of one website (the last 60 s in 10 s steps),
// its website hints and its counters of the last 5 minutes (status rules).
// ok false: the website is not tracked or has had no traffic since start.
type SiteNumbers struct {
	Now     *TrafficNow
	Window  websites.Traffic
	Hints   []cm.HealthHint
	HasData bool
}

// Site returns the numbers of a website slot at now.
func (m *Monitor) Site(slot int, now time.Time) SiteNumbers {
	if m == nil || slot < 0 || slot >= sites.Slots {
		return SiteNumbers{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.site.rings[slot]
	if r == nil {
		return SiteNumbers{}
	}
	newest := int64(0)
	for i := 0; i < min(r.pos, siteHourSteps); i++ {
		newest = max(newest, r.hour[i].sec)
	}
	c, n := r.sum(newest - 50)
	h, u, _ := r.recentSum(newest - 50)
	last, _ := r.sum(newest)
	tn := trafficNow(&c, &h, n*10, last[cRequests])
	if n > 0 {
		e := u.estimate()
		tn.ClientsUnique = &e
	}
	c5, _ := r.sum(now.Unix() - websites.WindowS)
	out := SiteNumbers{Now: &tn, HasData: true, Hints: r.hints.list(now),
		Window: websites.Traffic{Requests: c5[cRequests], Forwarded: c5[cForwarded], FailClosed: c5[cFailClosed], UpstreamErrors: c5[cUpstreamErrors],
			UpstreamTimeouts: c5[cUpstreamTimeouts], Status5xx: c5[cS5xx]}}
	return out
}

// Recent returns the requests, stopped, would_block and distinct clients of
// a website slot over the last d (at most 5 minutes, 10 s steps).
func (m *Monitor) Recent(slot int, d time.Duration, now time.Time) (req, stopped, would int64, visitors *int64) {
	if m == nil || slot < 0 || slot >= sites.Slots {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.site.rings[slot]
	if r == nil {
		return
	}
	since := now.Unix() - int64(d/time.Second)
	c, _ := r.sum(since)
	_, u, n := r.recentSum(since)
	if n > 0 {
		e := u.estimate()
		visitors = &e
	}
	return c[cRequests], c[cStopped], c[cWouldBlock], visitors
}

// trafficNow builds a TrafficNow from counters over windowS seconds and the
// requests of the last 10 s.
func trafficNow(c *[nCounters]int64, h *[nHist][cm.HistogramBuckets]int64, windowS int, last10 int64) TrafficNow {
	share := func(a, b int64) *float64 {
		if b == 0 {
			return nil
		}
		v := float64(a) / float64(b)
		return &v
	}
	w := float64(max(windowS, 1))
	return TrafficNow{
		WindowS: max(windowS, 1), RequestsPerS: float64(c[cRequests]) / w, RequestsPerS10s: float64(last10) / 10,
		StoppedShare: share(c[cStopped], c[cRequests]), WouldBlockShare: share(c[cWouldBlock], c[cRequests]), FailClosed: c[cFailClosed],
		UpstreamErrorShare: share(c[cUpstreamErrors]+c[cUpstreamTimeouts], c[cForwarded]),
		LatencyTotalP50MS:  quantileOf(&h[hTotal], 0.5), LatencyTotalP95MS: quantileOf(&h[hTotal], 0.95),
		LatencyOverheadP95MS: quantileOf(&h[hOverhead], 0.95), LatencyUpstreamP95MS: quantileOf(&h[hUpstream], 0.95),
		BytesInPerS: float64(c[cBytesIn]) / w, BytesOutPerS: float64(c[cBytesOut]) / w,
	}
}

// siteNow is MonitoringNow of one website: its last 60 s, the server-wide
// hints and its own.
func (m *Monitor) siteNow(sel siteSel, now time.Time) MonitoringNow {
	out := MonitoringNow{GeneratedAt: ts(now), StartedAt: ts(m.started), Site: sel.id, Traffic: TrafficNow{WindowS: 60}}
	if !sel.none {
		if n := m.Site(sel.slot, now); n.Now != nil {
			out.Traffic = *n.Now
		}
	}
	m.mu.Lock()
	out.Hints = m.hints.list(now)
	if !sel.none {
		out.Hints = append(out.Hints, m.siteHintList(now, sel.slot)...)
	}
	m.mu.Unlock()
	if s := m.last.Load(); s != nil {
		sn := s.now
		out.Server = &sn
	}
	return out
}

// ServerHints returns the server-wide hints (HealthHint without site).
func (m *Monitor) ServerHints(now time.Time) []cm.HealthHint {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hints.list(now)
}
