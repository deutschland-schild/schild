package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// The audit log in a group (MVP-36, contracts/audit.md section 9): every
// node holds the entries of every node, in its own audit.db. It is shared
// like the events, by asking (cluster_data.go), with one difference: a node
// hands on every entry it holds, also those of other nodes. So a node that
// joins later has the history of a node that is gone, from any member that
// is left.
//
//   - Ask kind `audit`: question `after`, a place in the order the answering
//     node stored its entries; answer `epoch` (the name of its audit.db),
//     `next` and at most auditlog.AskBatch `rows`.
//   - A node keeps a cursor per member and epoch, imports what comes
//     (auditlog.Import checks every entry and never stores an id twice) and
//     asks on while a full answer came.
//   - It asks a member when the member's head `s` moved, and after the
//     safety interval of the events. `s` counts the entries a node writes
//     itself. An entry a node took from a member moves nothing: every member
//     that holds it got it by asking, and a new node starts at 0 anyway.
//
// A change that arrives from another node writes no entry here: nothing in
// this file and nothing that takes a record of the group calls a writer of
// the log. The entry of the change comes from the node it was made on.
//
// A member of a build before this one does not know the kind and answers
// 404. That is no fault: it is asked again after the safety interval, in
// case it was updated, and nothing is logged.

const askAudit = "audit"

// auditAnswerFull: an answer of this size or more was cut by its size, not
// by its number of rows (auditlog.After stops at 4 MiB), so more waits.
const auditAnswerFull = 3 << 20

type auditQuestion struct {
	After int64 `json:"after"`
}

type auditAnswer struct {
	// Epoch names the audit.db the cursor counts in: a node whose file is
	// new starts at 0 again.
	Epoch string            `json:"epoch"`
	Next  int64             `json:"next"`
	Rows  []json.RawMessage `json:"rows"`
}

// auditNews counts how often this node found entries of its own in its
// audit log that were not there before. The count is the part of the head
// `s` that speaks for the audit log.
type auditNews struct {
	mu sync.Mutex
	// head is the place of the newest entry at the last look, known whether
	// there was a look.
	head  int64
	known bool
	n     atomic.Int64
}

// auditNewsCount looks whether the audit log holds new entries of this node
// and returns the count. It reads two rows at most plus the entries stored
// since the last look. A look that is running is not waited for.
func (g *groupData) auditNewsCount() int64 {
	l := g.a.Audit
	s := &g.audit
	if l == nil || g.asBuildBefore() || !s.mu.TryLock() {
		return s.n.Load()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	head, err := l.Head(ctx)
	if err != nil || (s.known && head == s.head) {
		return s.n.Load()
	}
	if !s.known {
		// The first look: what is there was there before this run, and
		// every member asks a node that just started for everything.
		s.head, s.known = head, true
		return s.n.Load()
	}
	// The place went back when the newest entries were deleted by their
	// age. That is said as news too: it costs a question and misses nothing.
	own := head < s.head
	if !own {
		if own, err = l.OwnSince(ctx, s.head); err != nil {
			return s.n.Load()
		}
	}
	s.head = head
	if own {
		return s.n.Add(1)
	}
	return s.n.Load()
}

// startAudit answers the members that ask for the audit log. A node that
// speaks as the build before this one does not know the kind.
func (g *groupData) startAudit() {
	a := g.a
	if a.Audit == nil || g.asBuildBefore() {
		return
	}
	a.Cluster.OnAsk(askAudit, func(from string, body []byte) ([]byte, error) {
		var q auditQuestion
		if err := json.Unmarshal(body, &q); err != nil {
			return nil, err
		}
		actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		epoch, err := a.Audit.Epoch(actx)
		if err != nil {
			return nil, err
		}
		rows, next, err := a.Audit.After(actx, max(q.After, 0))
		if err != nil {
			return nil, err
		}
		if rows == nil {
			rows = []json.RawMessage{}
		}
		return json.Marshal(auditAnswer{Epoch: epoch, Next: next, Rows: rows})
	})
}

// wantsAudit reports whether this node has to ask a member for its audit
// log now. It is called after wants, which notes another run of the member.
func (g *groupData) wantsAudit(peer string, now time.Time) bool {
	if g.a.Audit == nil || g.asBuildBefore() {
		return false
	}
	h := g.heads
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.pullOf(peer)
	late := now.Sub(p.lastA) > safetyOf(peer)
	if p.noAudit {
		// A build without an audit log: asked again now and then, it may be
		// updated.
		return late
	}
	if !p.speaks {
		// No word of the member yet: every second, like the events.
		return true
	}
	return !p.aOK || p.audit != p.told.Store || late
}

// pullAudit asks a member for the entries it stored after this node's
// cursor, a few answers at most per round. It reports whether the member
// has more after these, whether it answered and all of it was stored, and
// whether it does not know the kind.
func (g *groupData) pullAudit(ctx context.Context, peer string) (more, ok, unknown bool) {
	a := g.a
	key := "audit:" + peer
	for batch := 0; batch < 4 && ctx.Err() == nil; batch++ {
		epoch, after := g.cursor(key)
		q, _ := json.Marshal(auditQuestion{After: after})
		g.countAuditAsk()
		actx, cancel := context.WithTimeout(ctx, 10*time.Second)
		raw, err := a.Cluster.Ask(actx, peer, askAudit, q)
		cancel()
		if err != nil {
			var status *cluster.StatusError
			return false, false, errors.As(err, &status) && status.Code == http.StatusNotFound
		}
		var ans auditAnswer
		if json.Unmarshal(raw, &ans) != nil || ans.Epoch == "" || len(ans.Epoch) > 128 || ans.Next < 0 || ans.Next > 1<<62 {
			return false, false, false
		}
		if ans.Epoch != epoch {
			// Another audit.db of the member than last time: its places
			// start anew.
			_ = a.Cluster.SetMark(key, ans.Epoch+":0")
			if after != 0 {
				continue
			}
		}
		// What a member hands over is input from outside: Import checks
		// every entry, skips what is too old here and stores no id twice.
		ictx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err = a.Audit.Import(ictx, ans.Rows[:min(len(ans.Rows), auditlog.AskBatch)])
		cancel()
		if err != nil {
			ratelog.Warn(a.log, "cluster: audit entries of another node not stored, asked for again", "from", a.Cluster.PeerName(peer), "err", err)
			return false, false, false
		}
		if ans.Next <= after {
			return false, true, false
		}
		_ = a.Cluster.SetMark(key, ans.Epoch+":"+strconv.FormatInt(ans.Next, 10))
		if len(ans.Rows) < auditlog.AskBatch && len(raw) < auditAnswerFull {
			return false, true, false
		}
	}
	return true, true, false
}
