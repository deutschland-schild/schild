package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
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
//   - Single requests are told: every node tells the others the requests it
//     served in the last second. That is the larger stream, and it is not
//     repeated: a node that is away misses the requests of that time on the
//     other nodes; they hold them.
//
// Each node applies its own retention, its size caps and every erasure to
// what it holds, whoever wrote it. The counters of the overview and the
// charts of the server (metrics.db) stay per node.

const (
	askEvents    = "events"
	askIncidents = "incidents"
	tellRequests = "requests"
	// What one answer and one message hold at most.
	dataBatch     = 500
	dataScan      = 4000
	requestsBatch = 4000
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

type groupData struct {
	a *App
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
	g := &groupData{a: a}
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
		a.Requests.Tee(requestsBatch)
		node.OnTell(tellRequests, func(_ string, body []byte) {
			var es []reqring.Entry
			if json.Unmarshal(body, &es) != nil {
				return
			}
			for i := range es[:min(len(es), requestsBatch)] {
				a.Requests.AddForeign(&es[i])
			}
		})
	}
	var round int
	a.goLoop(ctx, "cluster-data", tick(time.Second, func() {
		g.tell(ctx)
		for _, peer := range node.Reachable() {
			g.pullEvents(ctx, peer)
			g.pullIncidents(ctx, peer)
		}
		if round++; round%30 == 0 {
			// An event of an erased address may have come from a node that
			// had not erased yet.
			a.reapplyErasures(ctx, 10*time.Minute)
		}
	}))
}

// tell hands the requests this node served since the last call to the
// other nodes. With nobody to tell they wait (the buffer is bounded): a
// node that just started reaches its peers a moment later.
func (g *groupData) tell(ctx context.Context) {
	a := g.a
	if a.Requests == nil {
		return
	}
	es, _ := a.Requests.TakeTee(len(a.Cluster.Reachable()) == 0 || a.Cluster.Removed())
	// A message holds at most 1 MiB: cut until it fits.
	for len(es) > 0 {
		body, err := json.Marshal(es)
		if err != nil {
			return
		}
		if len(body) < 900<<10 {
			a.Cluster.Tell(ctx, tellRequests, body)
			return
		}
		es = es[:len(es)/2]
	}
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
