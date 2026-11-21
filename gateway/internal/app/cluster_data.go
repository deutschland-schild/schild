package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The group of MVP-27 (D103): what happened is on every node. Every node
// keeps the events, the incidents and the single requests of every node in
// its own store, so every list, search, chart of the requests and the live
// view of its dashboard show the group without a query going from node to
// node, and what a node wrote is still there when the node is gone.
//
//   - Events and incidents are asked for: a node asks every member once a
//     second for what that member wrote itself after a cursor. A node that
//     was away catches up from where it stopped.
//   - Single requests are asked for too: every node keeps the requests it
//     served itself in a bounded log in memory, each with a sequence number,
//     and the others ask once a second for what came after their cursor. A
//     node that was away catches up as far back as that log reaches; what
//     left it before is counted as missed, and the node that served it
//     holds it.
//
// Each node applies its own retention, its size caps and every erasure to
// what it holds, whoever wrote it. The counters of the overview and the
// charts of the server (metrics.db) stay per node.

const (
	askEvents    = "events"
	askIncidents = "incidents"
	askRequests  = "requests"
	// What one answer and one message hold at most.
	dataBatch = 500
	dataScan  = 4000
	// Single requests: one answer holds at most requestsBatch entries and
	// about requestsBytes of their strings, a node asks a member at most
	// requestsRounds times a second, and the log a node answers from holds
	// its newest requestsLog requests within requestsLogBytes.
	requestsBatch    = 2000
	requestsBytes    = 1 << 20
	requestsRounds   = 4
	requestsLog      = 32768
	requestsLogBytes = 24 << 20
	// incidentOverlap: incidents are asked for again this far back, because
	// one that aggregates the requests of a minute still changes.
	incidentOverlap = 2 * time.Minute
)

type eventsQuestion struct {
	After int64 `json:"after"`
}

type eventsAnswer struct {
	// Epoch names the store the cursor counts in: a node that was set up
	// anew starts at 0 again.
	Epoch string            `json:"epoch"`
	Next  int64             `json:"next"`
	Rows  []*store.EventRow `json:"rows"`
}

type incidentsQuestion struct {
	SinceMS int64 `json:"since_ms"`
}

type incidentsAnswer struct {
	Rows []*store.Incident `json:"rows"`
}

type requestsQuestion struct {
	After uint64 `json:"after"`
}

type requestsAnswer struct {
	// Epoch names the run of the answering node the numbers count in: its
	// log lives in memory and starts at 1 with every start.
	Epoch string `json:"epoch"`
	// First is the oldest number the log still holds, Next the cursor for
	// the following question.
	First uint64          `json:"first"`
	Next  uint64          `json:"next"`
	Rows  []reqring.Entry `json:"rows"`
}

type groupData struct {
	a *App
	// requestsEpoch names this run of the node in its answers.
	requestsEpoch string
	// requestsMissed counts requests of other nodes that left their log
	// before this node asked for them.
	requestsMissed atomic.Uint64
}

func (a *App) dataEpoch(ctx context.Context) string {
	at, _ := a.Store.Get(ctx, installedAtKey)
	return a.Cluster.ID() + "@" + string(at)
}

// startGroupData shares events, incidents and requests (cluster.share_data).
func (a *App) startGroupData(ctx context.Context) {
	a.reapplyErasures(ctx, 0) // what was erased while this node was away
	if !a.Config().Cluster.SharesData() {
		return
	}
	g := &groupData{a: a, requestsEpoch: a.Cluster.ID() + "@" + strconv.FormatInt(a.started.UnixNano(), 36)}
	a.groupData = g
	node := a.Cluster
	node.OnAsk(askEvents, func(_ string, body []byte) ([]byte, error) {
		var q eventsQuestion
		if err := json.Unmarshal(body, &q); err != nil {
			return nil, err
		}
		actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rows, next, err := a.Store.EventsOfSource(actx, a.Events.Source(), q.After, dataScan, dataBatch)
		if err != nil {
			return nil, err
		}
		return json.Marshal(eventsAnswer{Epoch: a.dataEpoch(actx), Next: next, Rows: rows})
	})
	node.OnAsk(askIncidents, func(_ string, body []byte) ([]byte, error) {
		var q incidentsQuestion
		if err := json.Unmarshal(body, &q); err != nil {
			return nil, err
		}
		actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rows, err := a.Store.IncidentsOfSource(actx, a.Events.Source(), q.SinceMS, dataBatch)
		if err != nil {
			return nil, err
		}
		return json.Marshal(incidentsAnswer{Rows: rows})
	})
	if a.Requests != nil {
		a.Requests.Tee(requestsLog, requestsLogBytes)
		node.OnAsk(askRequests, func(_ string, body []byte) ([]byte, error) {
			var q requestsQuestion
			if err := json.Unmarshal(body, &q); err != nil {
				return nil, err
			}
			rows, first, next := a.Requests.Served(q.After, requestsBatch, requestsBytes)
			if rows == nil {
				rows = []reqring.Entry{}
			}
			return json.Marshal(requestsAnswer{Epoch: g.requestsEpoch, First: first, Next: next, Rows: rows})
		})
	}
	var round int
	a.goLoop(ctx, "cluster-data", tick(time.Second, func() {
		for _, peer := range node.Reachable() {
			g.pullEvents(ctx, peer)
			g.pullIncidents(ctx, peer)
			g.pullRequests(ctx, peer)
		}
		if round++; round%30 == 0 {
			// An event of an erased address may have come from a node that
			// had not erased yet.
			a.reapplyErasures(ctx, 10*time.Minute)
		}
	}))
}

// pullRequests asks a member for the requests it served after this node's
// cursor. Bounded on both sides: an answer holds at most requestsBatch
// entries, a round asks at most requestsRounds times, and it stops while
// the writer of this node's ring is behind, so a node that returns after an
// outage neither floods a member nor itself. Nothing here is in the request
// path: the ring takes the entries like its own, without blocking.
func (g *groupData) pullRequests(ctx context.Context, peer string) {
	a := g.a
	if a.Requests == nil {
		return
	}
	key := "requests:" + peer
	for round := 0; round < requestsRounds && ctx.Err() == nil; round++ {
		if waiting, room := a.Requests.Backlog(); waiting > room/2 {
			return // the rest comes with a later round
		}
		epoch, cur := g.cursor(key)
		after := uint64(max(cur, 0))
		q, _ := json.Marshal(requestsQuestion{After: after})
		actx, cancel := context.WithTimeout(ctx, 5*time.Second)
		raw, err := a.Cluster.Ask(actx, peer, askRequests, q)
		cancel()
		if err != nil {
			return
		}
		var ans requestsAnswer
		if json.Unmarshal(raw, &ans) != nil || ans.Epoch == "" || len(ans.Epoch) > 128 {
			return
		}
		if ans.Epoch != epoch {
			// Another run of the member than last time: its numbers start anew.
			_ = a.Cluster.SetMark(key, ans.Epoch+":0")
			if after != 0 {
				continue
			}
		}
		if ans.Next < after || ans.Next-after > requestsLog+requestsBatch {
			return // no answer of this version of schild
		}
		if ans.First > after+1 && (after != 0 || epoch == ans.Epoch) {
			// What the member served in between left its log before this node
			// asked. A first question to a run counts nothing: it is the start.
			missed := ans.First - after - 1
			g.requestsMissed.Add(missed)
			ratelog.Warn(a.log, "cluster: requests of another node were gone from its log before this node asked for them; that node holds them", "from", a.Cluster.PeerName(peer), "requests", missed)
		}
		now := time.Now()
		for i := range ans.Rows[:min(len(ans.Rows), requestsBatch)] {
			if e := &ans.Rows[i]; g.takesRequest(e, now) {
				a.Requests.AddForeign(e)
			}
		}
		if ans.Next == after {
			return
		}
		_ = a.Cluster.SetMark(key, ans.Epoch+":"+strconv.FormatUint(ans.Next, 10))
		if len(ans.Rows) < requestsBatch/2 {
			return
		}
	}
}

// Bounds of a request another node hands over: what a member sends is input
// from outside.
const (
	maxForeignHost = 255
	maxForeignPath = 2048
	maxForeignText = 1024
)

// takesRequest reports whether this node stores a request a member served:
// its fields within their bounds, its time within what the ring keeps, and
// its address not erased since (an erased address must not come back with a
// request that was on its way).
func (g *groupData) takesRequest(e *reqring.Entry, now time.Time) bool {
	a := g.a
	if !e.Client.IsValid() || len(e.Host) > maxForeignHost || len(e.RawPath) > maxForeignPath || len(e.Template) > maxForeignPath ||
		len(e.Site) > maxForeignHost || len(e.Referrer) > maxForeignText || len(e.UA) > maxForeignText || len(e.EventID) > 64 {
		return false
	}
	for i := range e.Rules {
		if len(e.Rules[i]) > 64 {
			return false
		}
	}
	t := time.UnixMilli(e.T)
	cfg := a.Config()
	keep := time.Duration(min(cfg.Monitoring.Requests.KeepHours, cfg.Retention.RawIPDays*24)) * time.Hour
	if t.After(now.Add(time.Minute)) || (keep > 0 && now.Sub(t) > keep) {
		return false
	}
	// A minute of margin: the clocks of two nodes differ.
	if at, ok := a.erased.at(e.Client); ok && !t.After(at.Add(time.Minute)) {
		return false
	}
	return true
}

func (g *groupData) cursor(key string) (epoch string, n int64) {
	m := g.a.Cluster.Mark(key)
	i := strings.LastIndexByte(m, ':')
	if i < 0 {
		return "", 0
	}
	n, _ = strconv.ParseInt(m[i+1:], 10, 64)
	return m[:i], n
}

// pullEvents asks a member for the events it wrote after this node's
// cursor, a few batches at most per round.
func (g *groupData) pullEvents(ctx context.Context, peer string) {
	a := g.a
	key := "events:" + peer
	for batch := 0; batch < 4 && ctx.Err() == nil; batch++ {
		epoch, after := g.cursor(key)
		q, _ := json.Marshal(eventsQuestion{After: after})
		raw, err := a.Cluster.Ask(ctx, peer, askEvents, q)
		if err != nil {
			return
		}
		var ans eventsAnswer
		if json.Unmarshal(raw, &ans) != nil || ans.Epoch == "" {
			return
		}
		if ans.Epoch != epoch {
			// Another store than last time: its numbers start anew.
			_ = a.Cluster.SetMark(key, ans.Epoch+":0")
			if after != 0 {
				continue
			}
		}
		own := a.Events.Source()
		rows := ans.Rows[:0]
		for _, r := range ans.Rows[:min(len(ans.Rows), dataBatch)] {
			// What a member hands over is input from outside.
			if r == nil || r.ID == "" || len(r.Body) == 0 || len(r.Body) > 256<<10 || r.Time.IsZero() || len(r.ID) > 64 {
				continue
			}
			if strings.Contains(string(r.Body), `"source":"`+own+`"`) {
				continue // nobody writes this node's events but itself
			}
			r.Seq = 0
			rows = append(rows, r)
		}
		ictx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = a.Events.Ingest(ictx, rows)
		cancel()
		if err != nil {
			ratelog.Warn(a.log, "cluster: events of another node not stored, asked for again", "from", a.Cluster.PeerName(peer), "err", err)
			return
		}
		if ans.Next <= after {
			return
		}
		_ = a.Cluster.SetMark(key, fmt.Sprintf("%s:%d", ans.Epoch, ans.Next))
		if len(ans.Rows) < dataBatch && ans.Next-after < dataScan {
			return
		}
	}
}

func (g *groupData) pullIncidents(ctx context.Context, peer string) {
	a := g.a
	key := "incidents:" + peer
	since, _ := strconv.ParseInt(a.Cluster.Mark(key), 10, 64)
	q, _ := json.Marshal(incidentsQuestion{SinceMS: since})
	raw, err := a.Cluster.Ask(ctx, peer, askIncidents, q)
	if err != nil {
		return
	}
	var ans incidentsAnswer
	if json.Unmarshal(raw, &ans) != nil {
		return
	}
	latest := since
	for _, in := range ans.Rows[:min(len(ans.Rows), dataBatch)] {
		if in == nil || in.Incident == "" || len(in.Incident) > 64 || in.Time.IsZero() {
			continue
		}
		ictx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := a.Store.MergeIncident(ictx, in)
		cancel()
		if err != nil {
			ratelog.Warn(a.log, "cluster: incident of another node not stored, asked for again", "from", a.Cluster.PeerName(peer), "err", err)
			return
		}
		for _, t := range []time.Time{in.Time, in.LastSeen, in.UnblockedAt} {
			if !t.IsZero() && t.UnixMilli() > latest {
				latest = t.UnixMilli()
			}
		}
	}
	if next := latest - incidentOverlap.Milliseconds(); next > since && len(ans.Rows) < dataBatch {
		_ = a.Cluster.SetMark(key, strconv.FormatInt(next, 10))
	} else if len(ans.Rows) >= dataBatch && latest > since {
		_ = a.Cluster.SetMark(key, strconv.FormatInt(latest, 10))
	}
}

// reapplyErasures erases again what the group erased in the last maxAge
// (0: every erasure the node holds): the address of an erased client must
// not come back with data another node handed over late.
func (a *App) reapplyErasures(ctx context.Context, maxAge time.Duration) {
	recs, err := a.Cluster.State(contract.ClassErasure)
	if err != nil {
		return
	}
	now := time.Now()
	for _, rec := range recs {
		if maxAge > 0 && now.Sub(contract.HLCTime(rec.HLC)) > maxAge {
			continue
		}
		a.takeErasure(ctx, rec)
	}
}

// erasedSet is when each address was erased in the group, as far as this
// node holds the erasures (31 days). The requests another node hands over
// are checked against it before they are stored.
type erasedSet struct {
	mu  sync.Mutex
	at_ map[netip.Addr]time.Time
}

// maxErased bounds the set; beyond it the periodic erasure again (every
// 30 s, for ten minutes after an erasure) is what holds.
const maxErased = 100000

func (s *erasedSet) note(ip netip.Addr, at time.Time) {
	ip = ip.Unmap().WithZone("")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.at_ == nil {
		s.at_ = map[netip.Addr]time.Time{}
	}
	if cur, ok := s.at_[ip]; (ok && !at.After(cur)) || (!ok && len(s.at_) >= maxErased) {
		return
	}
	s.at_[ip] = at
}

func (s *erasedSet) at(ip netip.Addr) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.at_[ip.Unmap().WithZone("")]
	return t, ok
}
