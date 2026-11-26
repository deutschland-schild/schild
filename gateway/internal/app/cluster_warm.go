package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// A node that starts takes the running counts of its group before it serves
// (behaviour/warm.go, MVP-27, D105): the per-second counts tell it only what
// the others count from now on, and without what they hold already a client
// one failed login short of a block would start anew on it.
//
// The node asks one member it reaches for the state, page by page, and adds
// it to its own counters; a few seconds later it asks once more and only
// raises what is below, which brings what was counted while the others did
// not tell it yet. Readiness waits for the first pass (inService). It must
// not wait for ever: after warmTries failed tries with a member in reach the
// node serves with what it has, says so in its log and shows the reason
// cluster_counts_not_taken on the overview until a pass succeeds.

const (
	askWarm = "counts_state"
	// warmDeadline bounds one pass over all pages: on one network the state
	// of a full node (some ten megabytes) passes in well under a second;
	// what takes longer is a member in trouble, and the node asks the next.
	warmDeadline = 5 * time.Second
	// warmTries: tries before the node serves without the state.
	warmTries = 3
	// warmAgain is when the second pass follows the first: by then every
	// member that reaches the node tells it its counts.
	warmAgain = 3 * time.Second
	// warmMaxPages bounds the pages of one pass, whatever a member says:
	// more than the steps of the cursor there are not.
	warmMaxPages = 256
	// warmAnswer bounds one page on the wire, below what an Ask may answer.
	warmAnswer = 6 << 20
	// warmMaxBytes bounds the total serialized bytes buffered across all pages
	// of one pass before applying them atomically.
	warmMaxBytes = 64 << 20
)

// warmWait is how long the node waits for a member to ask before it calls
// the handover done with nobody to ask (a var for tests).
var warmWait = 5 * time.Second

// warmRetryNS is how long a node waits between later passes when the initial
// handover failed (cluster_counts_not_taken). Tests may shorten it.
var warmRetryNS atomic.Int64

func init() { warmRetryNS.Store(int64(30 * time.Second)) }

func warmRetry() time.Duration { return time.Duration(warmRetryNS.Load()) }

type warmQuestion struct {
	Cursor int `json:"cursor"`
}

type warmAnswerPage struct {
	// Next is the cursor of the page after this one; below zero: the last.
	Next  int             `json:"next"`
	State *behaviour.Warm `json:"state"`
}

// errWarmUnknown: the member runs a build that does not know the question.
var errWarmUnknown = errors.New("the member does not know the question")

// startWarm answers the question for the running state and takes the state
// of the group once at the start.
func (a *App) startWarm(ctx context.Context) {
	a.Cluster.OnAsk(askWarm, func(_ string, body []byte) ([]byte, error) {
		var q warmQuestion
		if err := json.Unmarshal(body, &q); err != nil {
			return nil, err
		}
		page, next := a.Behaviour.WarmPage(q.Cursor)
		out, err := json.Marshal(warmAnswerPage{Next: next, State: page})
		if err == nil && len(out) > warmAnswer {
			err = errors.New("cluster: a page of the running state is too large")
		}
		return out, err
	})
	a.goLoop(ctx, "cluster-warm", func(ctx context.Context) {
		a.warmStart(ctx)
		<-ctx.Done() // done once per start
	})
}

// warmStart is the handover at the start of a node.
func (a *App) warmStart(ctx context.Context) {
	if a.warmDone.Load() {
		return
	}
	node := a.Cluster
	pause := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
			return true
		}
	}
	// Whom to ask is known when the node is in step. A node that reaches
	// nobody has nobody to ask: readiness has its own rule for it.
	waited := time.Duration(0)
	for !node.Synced() || len(node.Reachable()) == 0 {
		if node.Removed() || node.Alone() || (node.Synced() && waited >= warmWait) {
			a.warmDone.Store(true)
			return
		}
		if !pause(50 * time.Millisecond) {
			return
		}
		if node.Synced() {
			waited += 50 * time.Millisecond
		}
	}
	tries, unknown := 0, 0
	for tries < warmTries {
		peers := node.Reachable()
		if len(peers) == 0 {
			break
		}
		peer := peers[(tries+unknown)%len(peers)]
		err := a.takeWarm(ctx, peer, false)
		if err == nil {
			a.warmDone.Store(true)
			a.log.Info("cluster: took the running counts of the group", "from", node.PeerName(peer))
			if pause(warmAgain) {
				if err := a.takeWarm(ctx, peer, true); err != nil {
					a.log.Warn("cluster: the second look at the running counts of the group failed; the node counts on with what it took", "from", node.PeerName(peer), "err", err)
				}
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errWarmUnknown) {
			// A member of an older build during an update: ask the others,
			// and when none knows the question there is nothing to take.
			if unknown++; unknown >= len(peers) {
				a.warmDone.Store(true)
				a.log.Info("cluster: no member this node reaches hands over running counts (an older build); the node starts counting at zero")
				return
			}
			continue
		}
		tries++
		a.log.Warn("cluster: the running counts of the group were not taken", "from", node.PeerName(peer), "try", tries, "err", err)
		if !pause(250 * time.Millisecond) {
			return
		}
	}
	// Not for ever out of traffic: the node serves and counts from here.
	a.warmFailed.Store(true)
	a.warmDone.Store(true)
	a.log.Error("cluster: this node serves without the running counts of its group; limits and scenarios count on it from zero for the length of their windows")

	// Retry in the background with raise=true so cluster_counts_not_taken
	// ends once a later pass succeeds without double-counting recent traffic.
	retry, unknown := 0, 0
	for a.warmFailed.Load() && !node.Removed() {
		if !pause(warmRetry()) {
			return
		}
		peers := node.Reachable()
		if len(peers) == 0 {
			continue
		}
		peer := peers[(retry+unknown)%len(peers)]
		err := a.takeWarm(ctx, peer, true)
		if err == nil {
			a.log.Info("cluster: took the running counts of the group on a later pass", "from", node.PeerName(peer))
			return
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errWarmUnknown) {
			if unknown++; unknown >= len(peers) {
				a.warmFailed.Store(false)
				a.log.Info("cluster: no member this node reaches hands over running counts (an older build); the node counts on with what it has")
				return
			}
			continue
		}
		unknown = 0
		retry++
		ratelog.Warn(a.log, "cluster: the running counts of the group were not taken on a later pass either; the node tries again", "from", node.PeerName(peer), "err", err)
	}
}

// takeWarm asks one member for its running state and takes every page.
// Pages are buffered until the pass finishes so an aborted pass never leaves
// partial counts that a retry from cursor 0 would add a second time.
// raise: only bring up what is below (the second pass or a later retry).
func (a *App) takeWarm(ctx context.Context, peer string, raise bool) error {
	ctx, cancel := context.WithTimeout(ctx, warmDeadline)
	defer cancel()
	skip := func(k behaviour.Key) bool {
		// An address erased in the group must not come back with the state
		// of a member that had not erased yet.
		at, erased := a.erased.at(k.Addr())
		return erased && k.Bits() == k.Addr().BitLen() && time.Since(at) < 10*time.Minute
	}
	var states []*behaviour.Warm
	totalBytes := 0
	for cursor, pages := 0, 0; cursor >= 0; pages++ {
		if pages >= warmMaxPages {
			return errors.New("the pages do not end")
		}
		q, _ := json.Marshal(warmQuestion{Cursor: cursor})
		raw, err := a.Cluster.Ask(ctx, peer, askWarm, q)
		if err != nil {
			if se := (*cluster.StatusError)(nil); errors.As(err, &se) && se.Code == http.StatusNotFound {
				return errWarmUnknown
			}
			return err
		}
		totalBytes += len(raw)
		if totalBytes > warmMaxBytes {
			return errors.New("the running state is too large")
		}
		var ans warmAnswerPage
		if err := json.Unmarshal(raw, &ans); err != nil {
			return err
		}
		if ans.Next >= 0 && ans.Next <= cursor {
			return errors.New("the cursor does not move on")
		}
		if ans.State != nil {
			states = append(states, ans.State)
		}
		cursor = ans.Next
	}
	for _, st := range states {
		a.Behaviour.ApplyWarm(st, raise, skip)
	}
	a.warmFailed.Store(false)
	return nil
}
