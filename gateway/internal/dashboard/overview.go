package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/stats"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Reason codes of the overview (baseline protection).
func (s *Server) reasons(now time.Time) []string {
	var out []string
	if s.Gate == nil || !s.Gate.Ready() {
		out = append(out, "waf_down")
	}
	c := s.Config()
	switch c.Rules.CRS.State {
	case "off":
		out = append(out, "crs_off")
	case "detect":
		out = append(out, "crs_detect")
	}
	if src, built, ok := s.Geo.Status(); !ok || src == "" || now.Sub(built) > 60*24*time.Hour {
		out = append(out, "geo_db_old")
	}
	if s.ProxiesTooBroad {
		out = append(out, "trusted_proxies_too_broad")
	}
	if s.ProxyMissing != nil && s.ProxyMissing(now) {
		out = append(out, "trusted_proxies_missing")
	}
	if s.SettingsDropped != nil && s.SettingsDropped() {
		out = append(out, "dashboard_settings_dropped")
	}
	return out
}

func (s *Server) getOverview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.Overview(r.Context()))
}

// counters24hCoverage: Overview.counters_24h.partial and .since (D36 open
// items). The counters are in memory since schild's start, so a start
// inside the window makes them partial, counted since that start. Events
// dropped inside the window (writer queue full or a failed write) make
// them partial too, as the contract says. Events deleted by the size cap
// leave no signal here yet.
func counters24hCoverage(now, started, lastDrop time.Time) (partial bool, since string) {
	from := now.Add(-24 * time.Hour)
	if !started.IsZero() && started.After(from) {
		partial, since = true, ts(started)
	}
	if !lastDrop.IsZero() && lastDrop.After(from) {
		partial = true
	}
	return partial, since
}

// Overview builds the Overview (also served to agents in getAgentStatus).
func (s *Server) Overview(ctx context.Context) Overview {
	now := s.now()
	c := s.Config()
	codes := s.reasons(now)
	s.mu.Lock()
	current := map[string]bool{}
	for _, code := range codes {
		current[code] = true
		if _, ok := s.reasonsSince[code]; !ok {
			s.reasonsSince[code] = now
		}
	}
	for code := range s.reasonsSince {
		if !current[code] {
			delete(s.reasonsSince, code)
		}
	}
	gs := Baseline{State: "active", Reasons: []Reason{}}
	for _, code := range codes {
		gs.Reasons = append(gs.Reasons, Reason{Code: code, Since: ts(s.reasonsSince[code])})
	}
	s.mu.Unlock()
	switch {
	case current["waf_down"]:
		gs.State = "off"
	case len(codes) > 0:
		gs.State = "degraded"
	}
	ov := Overview{GeneratedAt: ts(now), Profile: c.Profile, Baseline: gs,
		Version: s.Version}
	cnt := s.Gate.Counters
	day := 24 * time.Hour
	ov.Counters24h = Counters{
		Requests: cnt.Rolling.Sum(stats.Requests, day, now), Evaluated: cnt.Rolling.Sum(stats.Evaluated, day, now),
		Blocked: cnt.Rolling.Sum(stats.Blocked, day, now), WouldBlock: cnt.Rolling.Sum(stats.WouldBlock, day, now),
		Incidents: cnt.Rolling.Sum(stats.Incidents, day, now),
	}
	var lastDrop time.Time
	if s.Events != nil {
		lastDrop = s.Events.LastDropped()
	}
	// Rows the size cap deleted inside the window also make the counters
	// partial (D36 open items, D38).
	if s.St != nil {
		if t := s.St.LastCapDeleted(); t.After(lastDrop) {
			lastDrop = t
		}
	}
	ov.Counters24h.Partial, ov.Counters24h.Since = counters24hCoverage(now, s.Started, lastDrop)
	ov.Series24h = &Series24h{
		Requests: cnt.Rolling.Hourly(stats.Requests, now), Blocked: cnt.Rolling.Hourly(stats.Blocked, now),
		WouldBlock: cnt.Rolling.Hourly(stats.WouldBlock, now),
	}
	if p := cnt.Latency.Quantile(0.95, now); !math.IsNaN(p) {
		v := math.Round(p*1000) / 1000
		ov.Counters24h.P95OverheadMS = &v
	}
	ov.Rules = OverviewRules{CRSVersion: s.CRSVersion}
	ov.GeoDB = geoDB(s.Geo.SourceInfo())
	ov.Servers = s.serversSummary(ctx)
	return ov
}

// ---------------------------------------------------------------- SSE

func matches(f store.EventFilter, e *store.EventRow) bool {
	if f.Type != "" && e.Type != f.Type {
		return false
	}
	if f.Country != "" && e.Country != f.Country {
		return false
	}
	if f.ASN != nil && e.ASN != *f.ASN {
		return false
	}
	if f.Path != "" && !strings.HasPrefix(e.Path, f.Path) {
		return false
	}
	if f.Outcome != "" && e.Outcome != f.Outcome {
		return false
	}
	if f.Session != "" && e.Session != f.Session {
		return false
	}
	if f.Site != "" && e.Site != f.Site {
		return false
	}
	if f.Rule != "" {
		found := false
		for _, r := range e.Rules {
			if r == f.Rule {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if f.Q != "" {
		q := f.Q
		if !strings.Contains(e.Path, q) && !strings.Contains(e.UA, q) && !strings.Contains(e.Incident, q) && !strings.Contains(e.Summary, q) {
			return false
		}
	}
	if f.IP != "" {
		if strings.Contains(f.IP, "/") {
			if !ipInPrefix(e.IP, f.IP) {
				return false
			}
		} else if !sameIP(e.IP, f.IP) {
			return false
		}
	}
	return true
}

func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	f := q.eventFilter()
	f.Site = s.siteParam(q)
	if q.failed(w) {
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		s.internal(w, errNoFlush)
		return
	}
	ctx := r.Context()
	var sub *eventlog.Sub
	if s.Events != nil {
		sub = s.Events.Bus().Subscribe()
		defer s.Events.Bus().Unsubscribe(sub)
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	_, _ = w.Write([]byte("retry: 3000\n\n"))
	var sent int64
	if last := r.Header.Get("Last-Event-ID"); last != "" && len(last) <= 64 {
		if e, err := s.St.GetEvent(ctx, last); err == nil {
			// replay what was missed (bounded), then continue live
			rows, err := s.St.EventsAfter(ctx, f, e.Seq, 1000)
			if err == nil {
				for _, row := range rows {
					if !writeEvent(w, row) {
						return
					}
					sent = row.Seq
				}
			}
		}
	}
	if sent == 0 {
		sent = s.St.MaxSeq(ctx)
	}
	fl.Flush()
	every := s.streamCheck
	if every <= 0 {
		every = 15 * time.Second
	}
	keep := time.NewTicker(every)
	defer keep.Stop()
	var ch <-chan *store.EventRow
	if sub != nil {
		ch = sub.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-keep.C:
			// The session was checked once, at the start. A logout, a
			// password change, `schild dashboard reset-password` or its
			// expiry must end an open stream as well, not only new requests.
			if s.currentSession(r) == nil {
				return
			}
			if _, err := w.Write([]byte(": keep-alive\n\n")); err != nil {
				return
			}
			fl.Flush()
		case row, ok := <-ch:
			if !ok {
				return // fell behind: the browser reconnects with Last-Event-ID
			}
			if row.Seq <= sent || !matches(f, row) {
				continue
			}
			if !writeEvent(w, row) {
				return
			}
			sent = row.Seq
			fl.Flush()
		}
	}
}

func writeEvent(w http.ResponseWriter, row *store.EventRow) bool {
	b, err := json.Marshal(summarize(row))
	if err != nil {
		return true
	}
	if _, err := w.Write([]byte("id: " + row.ID + "\ndata: ")); err != nil {
		return false
	}
	if _, err := w.Write(b); err != nil {
		return false
	}
	_, err = w.Write([]byte("\n\n"))
	return err == nil
}

var errNoFlush = errors.New("dashboard: response writer cannot flush")

func ipInPrefix(ip, cidr string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	p, err := netip.ParsePrefix(cidr)
	return err == nil && p.Contains(a.Unmap())
}

func sameIP(a, b string) bool {
	x, err1 := netip.ParseAddr(a)
	y, err2 := netip.ParseAddr(b)
	return err1 == nil && err2 == nil && x.Unmap() == y.Unmap()
}
