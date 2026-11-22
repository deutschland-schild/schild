package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// The counters and charts of a group (MVP-27, D103, contracts/cluster.md
// section 9a). Every gateway keeps the metric buckets of every other
// gateway, so each dashboard shows the sum of the group and any one node,
// also of a node that is gone. Pulled, like the events: every 10 s a
// gateway asks every member it reaches for the buckets after its cursor.
// Nothing here is in the request path, and nothing is decided by it.

const (
	askMetrics = "metrics"
	// metricsEvery is how often a gateway asks; a chart of the group lags
	// by this plus the step of its ring.
	metricsEvery = 10 * time.Second
	// metricsPage bounds the buckets of one answer, metricsRounds the
	// questions per ring and member in one round (a node that returns
	// catches up over several rounds), metricsBucketBytes one bucket, and
	// metricsAnswerBytes what the answering side puts into one answer.
	metricsPage        = 60
	metricsRounds      = 4
	metricsBucketBytes = 512 << 10
	metricsAnswerBytes = 4 << 20
	// metricsFresh is how long after its end a bucket may still change on
	// the node that wrote it (a restart inside the bucket merges two
	// parts), so it is asked for again that long.
	metricsFresh = 30 * time.Second
	// metricsWalk bounds the pages of its own ring a node reads for one
	// answer.
	metricsWalk = 8
)

type metricsQuestion struct {
	Res string `json:"res"`
	// From is the start of the first bucket wanted, unix seconds; 0: the
	// oldest the ring holds.
	From int64 `json:"from"`
}

type metricsAnswer struct {
	Res   string            `json:"res"`
	Items []json.RawMessage `json:"items"`
	// More: the answer does not reach the present; Next is the start (unix
	// seconds) the next question goes on from.
	More bool  `json:"more"`
	Next int64 `json:"next,omitempty"`
}

type groupMetrics struct {
	a *App
	// seen is the hash of the newest buckets stored per member and ring, so
	// a bucket asked for again while it is fresh is written only when it
	// changed.
	mu   sync.Mutex
	seen map[string][sha256.Size]byte
}

// startGroupMetrics answers the members' questions for this node's buckets
// and pulls theirs.
func (a *App) startGroupMetrics(ctx context.Context) {
	if a.Monitor == nil {
		return
	}
	node := a.Cluster
	a.Monitor.SetSelf(node.ID(), node.Name())
	g := &groupMetrics{a: a, seen: map[string][sha256.Size]byte{}}
	a.groupMetrics = g
	g.openNodes()
	node.OnAsk(askMetrics, func(_ string, body []byte) ([]byte, error) {
		var q metricsQuestion
		if err := json.Unmarshal(body, &q); err != nil {
			return nil, err
		}
		var from time.Time
		if q.From > 0 {
			from = time.Unix(q.From, 0)
		}
		// Only what this node measured itself: Buckets reads its own store.
		// A ring is mostly empty on a node that started lately, so the
		// answer walks on until it holds buckets or reaches the present.
		ans := metricsAnswer{Res: q.Res, Items: []json.RawMessage{}}
		now := time.Now()
		cursor, size := "", 0
		for walk := 0; walk < metricsWalk; walk++ {
			page, err := a.Monitor.Buckets(q.Res, from, cursor, 500, now)
			if err != nil {
				return nil, err
			}
			for i := range page.Items {
				raw, merr := json.Marshal(&page.Items[i])
				if merr != nil {
					return nil, merr
				}
				if len(ans.Items) == metricsPage || (size+len(raw) > metricsAnswerBytes && len(ans.Items) > 0) {
					// Cut: the next question starts at this bucket.
					if t, perr := time.Parse(time.RFC3339, page.Items[i].T); perr == nil {
						ans.More, ans.Next = true, t.Unix()
					}
					return json.Marshal(ans)
				}
				size += len(raw)
				ans.Items = append(ans.Items, raw)
			}
			if page.NextCursor == nil {
				return json.Marshal(ans)
			}
			cursor = *page.NextCursor
		}
		// Not at the present yet: the asker goes on from the cursor.
		if raw, derr := base64.RawURLEncoding.DecodeString(cursor); derr == nil {
			if n, perr := strconv.ParseInt(string(raw), 10, 64); perr == nil {
				ans.More, ans.Next = true, n
			}
		}
		return json.Marshal(ans)
	})
	a.goLoop(ctx, "cluster-metrics", tick(metricsEvery, func() { g.round(ctx) }))
}

// round asks every member this node reaches for its new buckets.
func (g *groupMetrics) round(ctx context.Context) {
	node := g.a.Cluster
	if node.Removed() || node.Paused() {
		return
	}
	g.openNodes()
	for _, peer := range node.Reachable() {
		for _, res := range []cm.Resolution{cm.Res10s, cm.Res1m, cm.Res10m} {
			g.pull(ctx, peer, res)
		}
	}
}

// openNodes opens the history of every gateway of the group and drops the
// history of members that were removed.
func (g *groupMetrics) openNodes() {
	st, err := g.a.Cluster.Live()
	if err != nil || st == nil {
		return // keep what is open: a failed read is no removal
	}
	members := map[string]string{}
	for _, m := range st.Members {
		if m.Removed || m.Self || m.Member.Role != contract.RoleGateway {
			continue
		}
		members[m.ID] = m.Member.Name
	}
	g.a.Monitor.OpenNodes(members)
}

func stepOf(res cm.Resolution) time.Duration {
	switch res {
	case cm.Res10s:
		return 10 * time.Second
	case cm.Res1m:
		return time.Minute
	}
	return 10 * time.Minute
}

// pull asks one member for the buckets of one ring after this node's
// cursor and stores them. The cursor is the start of the newest bucket
// stored; buckets that ended within metricsFresh are asked for again.
func (g *groupMetrics) pull(ctx context.Context, peer string, res cm.Resolution) {
	a := g.a
	key := "metrics:" + string(res) + ":" + peer
	step := stepOf(res)
	for round := 0; round < metricsRounds && ctx.Err() == nil; round++ {
		now := time.Now()
		cur, _ := strconv.ParseInt(a.Cluster.Mark(key), 10, 64)
		var from int64
		if cur > 0 {
			from = cur + int64(step/time.Second)
			if fresh := now.Add(-metricsFresh).Truncate(step).Add(-step).Unix(); fresh < from {
				from = fresh
			}
		}
		q, _ := json.Marshal(metricsQuestion{Res: string(res), From: from})
		actx, cancel := context.WithTimeout(ctx, 5*time.Second)
		raw, err := a.Cluster.Ask(actx, peer, askMetrics, q)
		cancel()
		if err != nil {
			return
		}
		var ans metricsAnswer
		if json.Unmarshal(raw, &ans) != nil || ans.Res != string(res) || len(ans.Items) > metricsPage {
			return
		}
		items := make([]cm.MetricBucket, 0, len(ans.Items))
		var newest int64
		for _, it := range ans.Items {
			if len(it) > metricsBucketBytes {
				continue
			}
			var b cm.MetricBucket
			if json.Unmarshal(it, &b) != nil {
				continue
			}
			t, perr := time.Parse(time.RFC3339, b.T)
			if perr != nil {
				continue
			}
			newest = max(newest, t.Unix())
			sum := sha256.Sum256(it)
			sk := key + ":" + b.T
			g.mu.Lock()
			same := g.seen[sk] == sum
			if !same {
				if len(g.seen) > 4096 {
					g.seen = map[string][sha256.Size]byte{}
				}
				g.seen[sk] = sum
			}
			g.mu.Unlock()
			if !same {
				items = append(items, b)
			}
		}
		if len(items) > 0 {
			if _, err := a.Monitor.PutNodeBuckets(peer, a.Cluster.PeerName(peer), res, items, now); err != nil {
				ratelog.Warn(a.log, "cluster: the metric buckets of another node could not be stored", "from", a.Cluster.PeerName(peer), "err", err)
				return
			}
		}
		// The cursor only moves forward, and never past this node's clock: a
		// member whose clock runs ahead must not make this node skip what it
		// writes later. An answer that was cut names where it goes on.
		next := newest
		if ans.More && ans.Next > 0 {
			next = max(next, ans.Next-int64(step/time.Second))
		}
		if limit := now.Add(2 * time.Minute).Unix(); next > cur && next <= limit {
			_ = a.Cluster.SetMark(key, strconv.FormatInt(next, 10))
		} else if ans.More {
			return // no progress: ask again in the next round
		}
		if !ans.More {
			return
		}
	}
}
