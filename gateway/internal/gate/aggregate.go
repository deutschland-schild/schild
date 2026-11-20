package gate

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// Incident aggregation (v0.5, D38, contracts/storage-bounds.md section 3):
// WAF and request-limit blocks of one client key (IPv4 address, IPv6 /64),
// one rule key (storage.RuleKey) and one UTC minute share one incident. The
// first blocked request of a key draws the number and creates the row;
// every later one shows the same number on its block page, its event
// carries it, and it only adds a hit that the incident writer folds into
// the row in batches (one transaction per flush, not one write per
// request). Behaviour and rate-limit blocks do not pass through here.

// aggFlushInterval is how often the incident writer folds pending hits
// into their rows.
const aggFlushInterval = 500 * time.Millisecond

// aggMaxTries: a hit whose row is still missing after this many flushes
// is dropped (its insert was dropped by a full queue, or the row was
// deleted).
const aggMaxTries = 3

type aggKey struct{ client, rule string }

type aggHits struct {
	store.IncidentHits
	tries int
}

type aggregator struct {
	mu      sync.Mutex
	max     int
	newest  int64 // newest UTC minute seen (unix ms), -1 before the first
	open    map[aggKey]string
	pending map[string]*aggHits
	// dropped counts hits lost because pending was full or their row never
	// appeared; the block page keeps the incident number either way.
	dropped atomic.Int64
}

func newAggregator(max int) *aggregator {
	return &aggregator{max: max, newest: -1, open: map[aggKey]string{}, pending: map[string]*aggHits{}}
}

// assign returns the incident number of a blocked request at tMS (unix
// ms) and whether it joined an open aggregate (then its hit is pending and
// no row must be inserted). A request of a later minute than any before
// closes every open aggregate; a request of an earlier minute, or a new key
// with every slot taken, gets a single-request incident.
func (a *aggregator) assign(k aggKey, tMS int64, draw func() string) (string, bool) {
	minute := tMS - tMS%60000
	a.mu.Lock()
	defer a.mu.Unlock()
	if minute > a.newest {
		clear(a.open)
		a.newest = minute
	}
	if minute == a.newest {
		if id, ok := a.open[k]; ok {
			h := a.pending[id]
			if h == nil {
				// Normally pending empties twice a second; a store that
				// stalls must not cost memory without limit.
				if len(a.pending) >= a.max {
					a.dropped.Add(1)
					return id, true
				}
				h = &aggHits{IncidentHits: store.IncidentHits{Incident: id, FirstMS: tMS, LastMS: tMS}}
				a.pending[id] = h
			}
			h.Count++
			h.FirstMS = min(h.FirstMS, tMS)
			h.LastMS = max(h.LastMS, tMS)
			return id, true
		}
	}
	id := draw()
	if minute == a.newest && len(a.open) < a.max {
		a.open[k] = id
	}
	return id, false
}

// forget closes the aggregate of k when it is incident id (its row was not
// stored, so later requests must not point at it).
func (a *aggregator) forget(k aggKey, id string) {
	a.mu.Lock()
	if a.open[k] == id {
		delete(a.open, k)
	}
	a.mu.Unlock()
}

// take returns the pending hits and how often each was tried before, and
// clears them.
func (a *aggregator) take() ([]store.IncidentHits, map[string]int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.pending) == 0 {
		return nil, nil
	}
	out := make([]store.IncidentHits, 0, len(a.pending))
	tries := make(map[string]int, len(a.pending))
	for id, h := range a.pending {
		out = append(out, h.IncidentHits)
		tries[id] = h.tries
	}
	a.pending = make(map[string]*aggHits, len(out))
	return out, tries
}

// retry puts back the hits whose row did not exist at the last flush
// (usually its insert was still queued); after aggMaxTries flushes they
// are dropped.
func (a *aggregator) retry(missing []store.IncidentHits, tries map[string]int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, m := range missing {
		n := tries[m.Incident] + 1
		if n >= aggMaxTries {
			a.dropped.Add(m.Count)
			continue
		}
		h := a.pending[m.Incident]
		if h == nil {
			if len(a.pending) >= a.max {
				a.dropped.Add(m.Count)
				continue
			}
			a.pending[m.Incident] = &aggHits{IncidentHits: m, tries: n}
			continue
		}
		h.Count += m.Count
		h.FirstMS = min(h.FirstMS, m.FirstMS)
		h.LastMS = max(h.LastMS, m.LastMS)
		h.tries = max(h.tries, n)
	}
}

// blockRuleIDs are the rule ids that caused a WAF block (rules with points
// and every non-CRS rule; a hub rule by its base id and only when it
// blocked).
func blockRuleIDs(a *waf.Analysis) (ids []string) {
	if a == nil {
		return nil
	}
	for _, m := range a.Matches {
		if m.Source == waf.SourceCrowdsec && !m.Counts {
			continue
		}
		if m.Points > 0 || m.Source != "crs" {
			ids = append(ids, m.Key())
		}
	}
	return ids
}

// drawIncident sets the incident number of a request blocked by the WAF or
// a request limit (D38 aggregation). Without a client address the request
// gets its own incident.
func (g *Gate) drawIncident(ri *reqInfo) {
	ck := clientKey(ri.client.IP)
	if ck == "" || g.agg == nil {
		ri.incident = events.NewIncident()
		return
	}
	limit := ""
	var rules []string
	if ri.limit != nil {
		limit = ri.limit.Code
	} else {
		rules = blockRuleIDs(ri.analysis)
	}
	ri.aggKey = aggKey{client: ck, rule: storage.RuleKey(rules, limit)}
	ri.incident, ri.joined = g.agg.assign(ri.aggKey, ri.start.UnixMilli(), events.NewIncident)
}

// flushHits folds the pending hits into their rows (one transaction).
func (g *Gate) flushHits(ctx context.Context, st *store.Store) {
	if g.agg == nil {
		return
	}
	if n := g.agg.dropped.Swap(0); n > 0 {
		if g.Metrics != nil {
			g.Metrics.IncidentHitsDropped.Add(float64(n))
		}
		g.hitErrs.LogAt(g.Log, g.Now(), slog.LevelWarn, "incident hits dropped: their count stays too low", "hits", n)
	}
	hits, tries := g.agg.take()
	if len(hits) == 0 {
		return
	}
	missing, err := st.AddIncidentHits(ctx, hits)
	if err != nil {
		g.hitErrs.LogAt(g.Log, g.Now(), slog.LevelError, "store incident hits", "err", err)
		missing = hits
	}
	g.agg.retry(missing, tries)
}
