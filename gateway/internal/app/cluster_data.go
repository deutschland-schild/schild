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

// The group of MVP-27 (D105): what happened is on every node. Every node
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
	// Single requests: one answer in JSON holds at most requestsBatch
	// entries and about requestsBytes of their strings, and the log a node
	// answers from holds its newest requestsLog requests within
	// requestsLogBytes. A node asks a member again at once while the member
	// has more: four times in any case, then for as long as requestsSpan has
	// not passed, and requestsRounds times at most. What bounds it besides
	// is its own writer (the backlog check, requestsPlace).
	requestsBatch    = 2000
	requestsBytes    = 1 << 20
	requestsRounds   = 64
	requestsSpan     = 800 * time.Millisecond
	requestsLogBytes = 24 << 20
	// In the compact form (cluster_heads.go) an answer holds up to
	// requestsBlockBatch entries and requestsBlockBytes of their strings: a
	// node that is behind catches up in fewer, fuller calls. Less than half
	// of what waits for the writer at most (reqring.ChanSize), so a full
	// answer always fits behind the check of the backlog.
	requestsBlockBatch = 4096
	requestsBlockBytes = 2 << 20
	// requestsPlace is how long a node waits for its own writer before it
	// leaves the rest of an answer for the next call.
	requestsPlace = 2 * time.Second
	// incidentOverlap: incidents are asked for again this far back, because
	// one that aggregates the requests of a minute still changes.
	incidentOverlap = 2 * time.Minute
)

// requestsLog is how many of its newest requests a node holds in memory for
// the others; a cursor further back is answered from its request store on
// disk. A variable for the tests, which make it small.
var requestsLog = 32768

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
	// Enc names the form of the answer the asking node takes besides JSON
	// ("b1", the compact one), Limit how many entries it takes at most. A
	// node of an earlier build sends neither and gets JSON, and a node of an
	// earlier build that is asked ignores both and answers JSON.
	Enc   string `json:"enc,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

type requestsAnswer struct {
	// Epoch names the run of numbers of the answering node: it stays over
	// its restarts (the numbers are kept in its request store) and changes
	// only when that store is new.
	Epoch string `json:"epoch"`
	// First is the lowest number that cannot have left the answering node
	// with a deleted segment, Next the cursor for the following question.
	First uint64          `json:"first"`
	Next  uint64          `json:"next"`
	Rows  []reqring.Entry `json:"rows"`
	// Heads: how far the answering node's own data went (cluster_heads.go).
	Heads *heads `json:"heads,omitempty"`
}

type groupData struct {
	a *App
	// heads: who was told what, and what the others said (cluster_heads.go).
	heads *headsState
	// requestsMissed counts the numbers of requests of other nodes that
	// may have left their request store (retention, the size cap) before
	// this node asked for them. An upper bound: numbers have holes.
	requestsMissed atomic.Uint64
	// What only tests and measurements use, and a release build does not
	// contain (cluster_data_hooks.go, cluster_data_hooks_release.go): a
	// counter of the questions asked, and a switch that makes this node
	// speak as the build before this one did.
	dataHooks
}

func (a *App) dataEpoch(ctx context.Context) string {
	at, _ := a.Store.Get(ctx, installedAtKey)
	return a.Cluster.ID() + "@" + string(at)
}

// startGroupData shares events, incidents and requests: every node of a
// group holds what every node wrote (initiator 2026-11-22, no switch).
func (a *App) startGroupData(ctx context.Context) {
	a.reapplyErasures(ctx, 0) // what was erased while this node was away
	g := &groupData{a: a, heads: newHeadsState(a.started)}
	g.initHooks()
	a.groupData = g
	node := a.Cluster
	// Each answer notes what the asking member has now seen of this node,
	// read before the answer is made: what is written meanwhile is told.
	node.OnAsk(askEvents, func(from string, body []byte) ([]byte, error) {
		var q eventsQuestion
		if err := json.Unmarshal(body, &q); err != nil {
			return nil, err
		}
		actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		gen := a.Store.OwnGen()
		rows, next, err := a.Store.EventsOfSource(actx, a.Events.Source(), q.After, dataScan, dataBatch)
		if err != nil {
			return nil, err
		}
		if len(rows) < dataBatch && next-q.After < dataScan {
			g.noteAsked(from, func(s *peerSeen) { s.events, s.eOK = gen, true })
		}
		return json.Marshal(eventsAnswer{Epoch: a.dataEpoch(actx), Next: next, Rows: rows})
	})
	node.OnAsk(askIncidents, func(from string, body []byte) ([]byte, error) {
		var q incidentsQuestion
		if err := json.Unmarshal(body, &q); err != nil {
			return nil, err
		}
		actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		gen := a.Store.OwnGen()
		rows, err := a.Store.IncidentsOfSource(actx, a.Events.Source(), q.SinceMS, dataBatch)
		if err != nil {
			return nil, err
		}
		if len(rows) < dataBatch {
			g.noteAsked(from, func(s *peerSeen) { s.incidents, s.iOK = gen, true })
		}
		return json.Marshal(incidentsAnswer{Rows: rows})
	})
	if a.Requests != nil {
		a.Requests.Tee(requestsLog, requestsLogBytes)
		node.OnAsk(askRequests, func(from string, body []byte) ([]byte, error) {
			var q requestsQuestion
			if err := json.Unmarshal(body, &q); err != nil {
				return nil, err
			}
			block := q.Enc == encBlock && !g.asBuildBefore()
			limit, size := requestsBatch, requestsBytes
			if block {
				limit, size = requestsBlockBatch, requestsBlockBytes
				if q.Limit > 0 && q.Limit < limit {
					limit = q.Limit
				}
			}
			own := g.ownHeads()
			rows, first, next := a.Requests.Served(q.After, limit, size)
			if rows == nil {
				rows = []reqring.Entry{}
			}
			now := time.Now()
			g.noteAsked(from, func(s *peerSeen) {
				if next+1 >= own.Requests {
					// It holds everything this node had served when it asked.
					s.requests, s.rOK = own.Requests, true
				}
				if len(rows) > 0 {
					// It is fetching: it asks again by itself, and the answer
					// tells it the heads.
					s.expect = now.Add(headsExpect)
				}
			})
			ans := requestsAnswer{Epoch: a.Cluster.ID() + "@" + a.Requests.ServedEpoch(), First: first, Next: next, Rows: rows, Heads: &own}
			if block {
				return encodeRequestsBlock(&ans), nil
			}
			if g.asBuildBefore() {
				ans.Heads = nil
			}
			return json.Marshal(ans)
		})
	}
	node.OnTell(tellHeads, func(from string, body []byte) {
		var hd heads
		if len(body) <= 512 && json.Unmarshal(body, &hd) == nil {
			g.takeHeads(from, hd)
		}
	})
	a.goLoop(ctx, "cluster-heads", tick(headsEvery, func() { g.tellHeadsRound(ctx) }))
	a.goLoop(ctx, "cluster-data", g.pullLoop)
}

// pullRequests asks a member for the requests it served after this node's
// cursor. The member answers from memory or, for a cursor further back,
// from its request store on disk: a node that was away, however long,
// takes everything the member still keeps.
//
// Bounded on both sides: an answer holds at most requestsBlockBatch
// entries, a round asks at most requestsRounds times, and it stops while
// the writer of this node's ring is behind, so a node that returns after an
// outage neither floods a member nor itself. Nothing here is in the request
// path, so it may wait for the writer: what it took of an answer is handed
// over in order, and what did not fit within requestsPlace is asked for
// again, never dropped.
//
// It returns how many requests it took, whether the member had no more,
// the heads the member said with its answer (zero from a member of an
// earlier build), and whether the member answered at all.
func (g *groupData) pullRequests(ctx context.Context, peer string) (got int, drained bool, said heads, ok bool) {
	a := g.a
	if a.Requests == nil {
		return 0, true, heads{}, true
	}
	key := "requests:" + peer
	for round, began := 0, time.Now(); round < requestsRounds && ctx.Err() == nil && (round < 4 || time.Since(began) < requestsSpan); round++ {
		if waiting, room := a.Requests.Backlog(); waiting > room/2 {
			return got, false, said, ok // the rest comes with a later round
		}
		epoch, cur := g.cursor(key)
		after := uint64(max(cur, 0))
		question := requestsQuestion{After: after, Enc: encBlock, Limit: requestsBlockBatch}
		if g.asBuildBefore() {
			question = requestsQuestion{After: after}
		}
		q, _ := json.Marshal(question)
		actx, cancel := context.WithTimeout(ctx, 5*time.Second)
		g.countAsk()
		raw, err := a.Cluster.Ask(actx, peer, askRequests, q)
		cancel()
		if err != nil {
			return got, false, said, ok
		}
		ans, err := decodeRequestsAnswer(raw, requestsBlockBatch)
		if err != nil || ans.Epoch == "" || len(ans.Epoch) > 128 {
			return got, false, said, ok
		}
		ok = true
		if ans.Heads != nil && ans.Heads.Boot != "" && len(ans.Heads.Boot) <= 64 && !g.asBuildBefore() {
			said = *ans.Heads
		}
		if ans.Epoch != epoch {
			// Another request store of the member than last time: its numbers start anew.
			_ = a.Cluster.SetMark(key, ans.Epoch+":0")
			if after != 0 {
				continue
			}
		}
		if ans.Next < after || ans.Next > 1<<62 {
			return got, false, said, false // no answer of this version of schild
		}
		// A number may jump ahead (the member restarted): the cursor follows
		// whatever it says. It is the member's own cursor and bounds nothing
		// but what this node asks that member next.
		if ans.First > after+1 && after != 0 {
			// The member deleted segments (retention, the size cap) that held
			// numbers above this node's cursor. A first question counts
			// nothing: it is the start.
			missed := ans.First - after - 1
			g.requestsMissed.Add(missed)
			ratelog.Warn(a.log, "cluster: requests of another node left its request store before this node asked for them", "from", a.Cluster.PeerName(peer), "numbers", missed)
		}
		now := time.Now()
		nrows := len(ans.Rows)
		take := ans.Rows[:0]
		for i := range ans.Rows {
			if g.takesRequest(&ans.Rows[i], now) {
				take = append(take, ans.Rows[i])
			}
		}
		pctx, cancel := context.WithTimeout(ctx, requestsPlace)
		placed := a.Requests.AddForeignWait(pctx, take)
		cancel()
		got += placed
		if placed < len(take) {
			// The writer did not keep up: go on after the last request that
			// was handed over. Without numbers (a member of an earlier
			// draft) the rest of this answer is lost, as it always was.
			next := ans.Next
			if placed > 0 && take[placed-1].Seq > after {
				next = take[placed-1].Seq
			} else if take[placed].Seq > 0 {
				next = after
			}
			if next != after {
				_ = a.Cluster.SetMark(key, ans.Epoch+":"+strconv.FormatUint(next, 10))
			}
			return got, false, said, ok
		}
		if ans.Next == after {
			return got, true, said, ok
		}
		_ = a.Cluster.SetMark(key, ans.Epoch+":"+strconv.FormatUint(ans.Next, 10))
		// Half an answer of the earlier size or less: the member has no
		// more for now.
		if nrows < requestsBatch/2 {
			return got, true, said, ok
		}
	}
	return got, false, said, ok
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
// cursor, a few batches at most per round. It reports whether the member
// has more after these batches, and whether it answered and all of it was
// stored.
func (g *groupData) pullEvents(ctx context.Context, peer string) (more, ok bool) {
	a := g.a
	key := "events:" + peer
	for batch := 0; batch < 4 && ctx.Err() == nil; batch++ {
		epoch, after := g.cursor(key)
		q, _ := json.Marshal(eventsQuestion{After: after})
		g.countAsk()
		raw, err := a.Cluster.Ask(ctx, peer, askEvents, q)
		if err != nil {
			return false, false
		}
		var ans eventsAnswer
		if json.Unmarshal(raw, &ans) != nil || ans.Epoch == "" {
			return false, false
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
		// Marked as another node's rows: they are no news of this node, so
		// they move nothing the others would ask this node for.
		ictx, cancel := context.WithTimeout(store.Foreign(ctx), 10*time.Second)
		err = a.Events.Ingest(ictx, rows)
		cancel()
		if err != nil {
			ratelog.Warn(a.log, "cluster: events of another node not stored, asked for again", "from", a.Cluster.PeerName(peer), "err", err)
			return false, false
		}
		if ans.Next <= after {
			return false, true
		}
		_ = a.Cluster.SetMark(key, fmt.Sprintf("%s:%d", ans.Epoch, ans.Next))
		if len(ans.Rows) < dataBatch && ans.Next-after < dataScan {
			return false, true
		}
	}
	return true, true
}

// pullIncidents asks a member for the incidents of its own that changed
// since this node's mark. It reports whether the member answered and all of
// it was stored.
func (g *groupData) pullIncidents(ctx context.Context, peer string) bool {
	a := g.a
	key := "incidents:" + peer
	since, _ := strconv.ParseInt(a.Cluster.Mark(key), 10, 64)
	q, _ := json.Marshal(incidentsQuestion{SinceMS: since})
	g.countAsk()
	raw, err := a.Cluster.Ask(ctx, peer, askIncidents, q)
	if err != nil {
		return false
	}
	var ans incidentsAnswer
	if json.Unmarshal(raw, &ans) != nil {
		return false
	}
	latest := since
	for _, in := range ans.Rows[:min(len(ans.Rows), dataBatch)] {
		if in == nil || in.Incident == "" || len(in.Incident) > 64 || in.Time.IsZero() {
			continue
		}
		ictx, cancel := context.WithTimeout(store.Foreign(ctx), 5*time.Second)
		err := a.Store.MergeIncident(ictx, in)
		cancel()
		if err != nil {
			ratelog.Warn(a.log, "cluster: incident of another node not stored, asked for again", "from", a.Cluster.PeerName(peer), "err", err)
			return false
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
	return true
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
