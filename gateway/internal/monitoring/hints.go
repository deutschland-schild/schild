package monitoring

import (
	"sort"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// Health hints (HealthHintCode): fixed thresholds (contracts v0.4; whether
// they become schild.yaml keys is open), levels info, notice, warning. A hint
// clears when its condition is gone for 5 min. Hints never change request
// handling or the baseline protection state.

const (
	hintHold  = 5 * time.Minute
	hintClear = 5 * time.Minute
)

type activeHint struct {
	h        cm.HealthHint
	lastTrue time.Time
}

type hintState struct {
	pending map[string]time.Time // condition true since (for "for 5 min" hints)
	active  map[string]*activeHint
	// site is HealthHint.site of the hints of one website (D36).
	site string
}

func newHintState() *hintState {
	return &hintState{pending: map[string]time.Time{}, active: map[string]*activeHint{}}
}

func f(v float64) *float64 { return &v }

// set notes the condition of one hint at now; hold is how long it must hold.
func (st *hintState) set(now time.Time, cond bool, hold time.Duration, code, level, object string, value, threshold float64) {
	key := code + "\x00" + object
	if !cond {
		delete(st.pending, key)
		return
	}
	since, ok := st.pending[key]
	if !ok {
		since = now
		st.pending[key] = now
	}
	if now.Sub(since) < hold {
		return
	}
	if a, ok := st.active[key]; ok {
		a.lastTrue = now
		a.h.Value, a.h.Threshold, a.h.Level = f(value), f(threshold), level
		return
	}
	st.active[key] = &activeHint{h: cm.HealthHint{Code: code, Level: level, Since: ts(since), Value: f(value), Threshold: f(threshold), Object: object, Site: st.site}, lastTrue: now}
}

func (st *hintState) list(now time.Time) []cm.HealthHint {
	out := []cm.HealthHint{}
	for k, a := range st.active {
		if now.Sub(a.lastTrue) > hintClear {
			delete(st.active, k)
			continue
		}
		out = append(out, a.h)
	}
	rank := map[string]int{"warning": 0, "notice": 1, "info": 2}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Level] != rank[out[j].Level] {
			return rank[out[i].Level] < rank[out[j].Level]
		}
		return out[i].Since < out[j].Since
	})
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// tenSum sums the counters of the 10 s steps newer than since (mu held).
func (m *Monitor) tenSum(since int64) (c [nCounters]int64, up [cm.HistogramBuckets]int64, n int) {
	for i := 0; i < m.tenN; i++ {
		t := &m.tenS[i]
		if t.sec < since {
			continue
		}
		for k, v := range t.c {
			c[k] += v
		}
		for k, v := range t.up {
			up[k] += v
		}
		n++
	}
	return
}

// evaluate runs every 10 s (mu held).
func (st *hintState) evaluate(m *Monitor, now time.Time) {
	sec := now.Unix()
	s := m.last.Load()
	if s != nil && now.Sub(s.at) < 30*time.Second {
		sn := &s.snap
		if c := sn.CPU; c != nil {
			st.set(now, c.Usage >= 0.9, hintHold, cm.HintCPUHigh, "warning", "", c.Usage, 0.9)
			if c.Load5 != nil {
				st.set(now, *c.Load5 > 2*float64(c.Cores), 0, cm.HintLoadHigh, "notice", "", *c.Load5, 2*float64(c.Cores))
			}
		}
		if ct := sn.Container; ct != nil {
			st.set(now, ct.CPUThrottled >= 0.1, hintHold, cm.HintCPUThrottled, "notice", "", ct.CPUThrottled, 0.1)
		}
		if mem := sn.Memory; mem != nil && mem.TotalBytes > 0 {
			free := float64(mem.AvailableBytes) / float64(mem.TotalBytes)
			st.set(now, free < 0.1, 0, cm.HintMemoryLow, "warning", "", free, 0.1)
			if mem.OOMKills24h != nil {
				st.set(now, *mem.OOMKills24h > 0, 0, cm.HintOOMKill, "warning", "", float64(*mem.OOMKills24h), 1)
			}
		}
		if s.swapIn >= 0 {
			st.set(now, s.swapIn > 1<<20, hintHold, cm.HintSwapActive, "notice", "", s.swapIn, 1<<20)
		}
		for _, mt := range sn.Mounts {
			r := mt.UsedRatio
			if mt.InodesTotal > 0 {
				r = max(r, float64(mt.InodesUsed)/float64(mt.InodesTotal))
			}
			level := "notice"
			if r >= 0.95 {
				level = "warning"
			}
			st.set(now, r >= 0.9, 0, cm.HintDiskFullSoon, level, mt.Mount, r, 0.9)
			if mt.Busy != nil && mt.Device != "" {
				st.set(now, *mt.Busy >= 0.9, hintHold, cm.HintDiskIOBusy, "notice", mt.Device, *mt.Busy, 0.9)
			}
		}
		for _, i := range sn.Interfaces {
			pk := i.RxPacketsPerS + i.TxPacketsPerS
			bad := i.ErrorsPerS + i.DropsPerS
			r := 0.0
			if pk > 0 {
				r = bad / pk
			}
			st.set(now, pk > 0 && r >= 0.001, hintHold, cm.HintNetErrors, "notice", i.Name, r, 0.001)
		}
		if c := sn.Conntrack; c != nil && c.Max > 0 {
			r := float64(c.Count) / float64(c.Max)
			st.set(now, r >= 0.8, 0, cm.HintConntrackHigh, "warning", "", r, 0.8)
		}
		fd := 0.0
		if p := sn.Process; p.OpenFilesLimit > 0 {
			fd = float64(p.OpenFiles) / float64(p.OpenFilesLimit)
		}
		if fl := sn.Files; fl != nil && fl.Max > 0 {
			fd = max(fd, float64(fl.Open)/float64(fl.Max))
		}
		st.set(now, fd >= 0.8, 0, cm.HintFDHigh, "warning", "", fd, 0.8)
		if t := sn.TCP; t != nil && t.ListenDropsPerS != nil {
			st.set(now, *t.ListenDropsPerS > 0, 0, cm.HintListenDrops, "notice", "", *t.ListenDropsPerS, 0)
		}
		if si := sn.Schild; si.StoreMaxBytes > 0 {
			r := float64(si.StoreBytes) / float64(si.StoreMaxBytes)
			st.set(now, r >= 0.9, 0, cm.HintStoreNearCap, "notice", "", r, 0.9)
			// D38: the size cap stopped above the cap (every value class
			// at its floor); value = used bytes, threshold = the cap.
			st.set(now, si.StoreCapUnreachable, 0, cm.HintStoreCapUnreachable, "warning", "", float64(si.StoreBytes), float64(si.StoreMaxBytes))
		}
		st.set(now, sn.Schild.EventsDropped1h > 0, 0, cm.HintEventsDropped, "notice", "", float64(sn.Schild.EventsDropped1h), 1)
	}
	// Traffic over the last 5 min and the hour before. With websites (D36)
	// the website-scoped codes are computed per website (siteHints).
	c5, up5, n5 := m.tenSum(sec - 300)
	if n5 > 0 {
		if m.view() == nil {
			cH, _, nH := m.tenSum(sec - 3600)
			trafficHints(st, now, c5, &up5, n5, cH, nH)
		}
		st.set(now, c5[cFCBusy] > 0, 0, cm.HintWAFSaturated, "warning", "", float64(c5[cFCBusy]), 1)
	}
	st.diskHints(m, now)
	m.siteHints(now)
	d := m.degraded.Load()
	st.set(now, d > 0 && sec-d <= 600, 0, cm.HintMonitoringDegraded, "info", "", 1, 0)
}

// trafficHints sets the website-scoped hints (cm.SiteHintCodes) from the
// counters of the last 5 min (n5 10 s steps) and the last hour (nH steps).
func trafficHints(st *hintState, now time.Time, c5 [nCounters]int64, up5 *[cm.HistogramBuckets]int64, n5 int, cH [nCounters]int64, nH int) {
	if n5 == 0 {
		return
	}
	fwd := c5[cForwarded]
	ue := c5[cUpstreamErrors] + c5[cUpstreamTimeouts]
	st.set(now, ue >= 10 && fwd > 0 && float64(ue) >= 0.01*float64(fwd), 0, cm.HintUpstreamErrors, "notice", "", float64(ue), 10)
	if p := quantileOf(up5, 0.95); p != nil {
		st.set(now, *p >= 2000, 0, cm.HintUpstreamSlow, "notice", "", *p, 2000)
	}
	st.set(now, c5[cFailClosed] > 0, 0, cm.HintFailClosed, "warning", "", float64(c5[cFailClosed]), 1)
	prevReq := cH[cRequests] - c5[cRequests]
	prevSteps := nH - n5
	if prevSteps >= 30 {
		rate5 := float64(c5[cRequests]) / float64(n5*10)
		prevRate := float64(prevReq) / float64(prevSteps*10)
		factor := 0.0
		if prevRate > 0 {
			factor = rate5 / prevRate
		}
		st.set(now, rate5 >= 10 && prevRate > 0 && factor >= 5, 0, cm.HintTrafficSpike, "info", "", factor, 5)
	}
}
