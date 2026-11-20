package gate

import (
	"net/http"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// record hands one finished request to the monitor (MVP-21 counting point:
// every request that reached the handler, forwarded or stopped). The
// monitoring.Req lives on this stack frame; nothing here allocates for a
// request without a detection.
func (g *Gate) record(r *http.Request, ri *reqInfo, dur time.Duration, emitted bool) {
	q := monitoring.Req{R: r, Status: ri.status, BytesIn: ri.body.n, BytesOut: ri.sw.bytes, Total: dur, UpstreamDur: ri.upstreamDur,
		Client: ri.client.IP, Country: ri.geo.Country, ASN: ri.geo.ASN, ASOrg: ri.geo.ASOrg, NetClass: ri.geo.NetClass}
	if q.Status == 0 {
		q.Status = http.StatusOK
	}
	q.Class = classOf(ri)
	q.WaitingPage = ri.waiting
	if q.Class == monitoring.Forwarded {
		q.WouldBlock = ri.decision.Outcome == decide.WouldBlock
		q.WouldRL = ri.wouldRL
		q.Upstream = ri.sw.upstream
	}
	// A would_block of the crawler policy alone is no WAF detection (D57).
	q.Detection = q.Class == monitoring.BlockedWAF || q.WouldBlock && !ri.crawlerOnly
	q.Crawler = ri.crawlerOnly || ri.crawler == crawlerBlocked
	if q.Detection && ri.analysis != nil {
		q.Rules = ruleIDs(ri.analysis.Matches)
	}
	// MVP-22 request ring.
	q.Start = ri.start
	if emitted {
		q.EventID = ri.eventID
	}
	if a := ri.analysis; a != nil {
		q.Score = a.Score
		q.NRingRules = topRules(a.Matches, &q.RingRules)
	}
	if ri.decision.Outcome == decide.WouldBlock {
		q.WBReason = ri.decision.WouldBlockReason
	}
	// Pin the visitor's context: a request that drew its own incident, or
	// an alert with an event (observe mode, false positive review).
	q.Pin = emitted && (ri.incident != "" && !ri.joined && !ri.stopped || q.WouldBlock && !ri.crawlerOnly)
	q.Timed = ri.timed
	q.Rechecked = ri.rechecked
	g.Monitor.Record(&q)
}

func classOf(ri *reqInfo) monitoring.Class {
	if l := ri.limit; l != nil {
		switch l {
		case waf.ErrBusy:
			return monitoring.FailBusy
		case waf.ErrBodyBusy, waf.ErrBodyShareBusy, waf.ErrBodyWaitShareBusy, waf.ErrRequestBusy, waf.ErrRequestShareBusy:
			return monitoring.FailBodyBusy
		case waf.ErrTimeout:
			if ri.notReady {
				return monitoring.FailNotReady
			}
			return monitoring.FailTimeout
		}
		return monitoring.RejectedLimit
	}
	if ri.crawler == crawlerBlocked {
		return monitoring.BlockedCrawler
	}
	if ri.stopped {
		src := ""
		if len(ri.decision.Sources) > 0 {
			src = ri.decision.Sources[0]
		}
		switch {
		case ri.status == http.StatusTooManyRequests:
			return monitoring.RateLimited
		case strings.HasPrefix(src, "distributed:shape"):
			return monitoring.BlockedWAF // MVP-18 shape_block counts with the WAF (contract)
		}
		return monitoring.BlockedBehaviour
	}
	if ri.decision.Outcome == decide.Blocked && !ri.forwarded {
		return monitoring.BlockedWAF
	}
	return monitoring.Forwarded
}

// RecordPanic counts a request whose handler panicked and was answered 503
// by the Caddy adapter (fail_closed_by.panic).
func (g *Gate) RecordPanic(r *http.Request) {
	if g.Monitor == nil {
		return
	}
	q := monitoring.Req{R: r, Class: monitoring.FailPanic, Status: http.StatusServiceUnavailable}
	g.Monitor.Record(&q)
}

// topRules keeps up to 3 distinct matched rule ids, highest severity
// first (stable within a severity), for the request ring. Exceptions are
// no findings. Allocates only for the decimal ids of CRS rules.
func topRules(ms []waf.Match, out *[3]string) uint8 {
	n := uint8(0)
	for rank := 0; rank < len(severityOrder) && n < 3; rank++ {
		for i := range ms {
			m := &ms[i]
			if m.Exception || severityRank(m.Severity) != rank {
				continue
			}
			id := m.Key()
			dup := false
			for j := uint8(0); j < n; j++ {
				dup = dup || out[j] == id
			}
			if dup {
				continue
			}
			if len(id) > 32 {
				id = id[:32]
			}
			out[n] = id
			n++
			if n == 3 {
				break
			}
		}
	}
	return n
}

var severityOrder = []string{"critical", "error", "warning", "notice", ""}

func severityRank(s string) int {
	for i, x := range severityOrder {
		if x == s {
			return i
		}
	}
	return len(severityOrder) - 1
}

// ruleIDs lists every distinct rule id of a detection (MVP-21 counts detections
// per rule id; no cut, so the per-rule counts stay exact). A detection
// allocates here; a clean request never gets this far.
func ruleIDs(ms []waf.Match) []string {
	if len(ms) == 0 {
		return nil
	}
	out := make([]string, 0, len(ms))
	seen := make(map[string]struct{}, len(ms))
	for _, m := range ms {
		id := m.Key()
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
