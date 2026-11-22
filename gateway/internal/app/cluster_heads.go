package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/fnv"
	"strconv"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// A group that has nothing to say says nothing (MVP-27, D103). Every node
// keeps the events, incidents and requests of every node by asking each
// member for what came after its cursor. Asked once a second whether or not
// there is anything, that is three calls per member and second, each with a
// query on the answering side: sixteen idle gateways made 720 such calls a
// second for nothing.
//
// So a node says how far its own data went, and the others ask when that
// moved:
//
//   - heads: what a node says about itself. `boot` names this run of the
//     process, `s` is a number that grows with every event or incident the
//     node writes itself (store.OwnGen), `r` the number its next served
//     request gets (Ring.ServedNext). They say that something is new, not
//     what; the cursors of the pulls stay what they were.
//   - A node tells its heads (Tell kind `heads`) to every member that has
//     not asked for what they cover, twice a second at most and again every
//     second until the member asked: a lost word costs a second.
//   - A member that is fetching requests anyway is told nothing: every
//     answer with requests carries the heads, and it asks again by itself
//     while requests keep coming. Under steady traffic that is one call per
//     member and second instead of three.
//   - Whatever was said or lost, a node asks every member again after about
//     half a minute, so nothing can stall for good.
//
// A member of an earlier build says no heads: it is asked every second, as
// before, and it asks this node every second, which costs what it did.

const (
	tellHeads = "heads"
	// headsEvery is how often a node looks whether it has to tell.
	headsEvery = 500 * time.Millisecond
	// headsRepeat is how soon a node tells a member again that has not
	// asked yet.
	headsRepeat = time.Second
	// headsExpect is how long a node waits for the next question of a
	// member that is fetching requests before it tells it again.
	headsExpect = 2500 * time.Millisecond
	// pullSafety is the least time after which a node asks a member again
	// although nothing was said; a share of pullSafetySpread is added per
	// member, so the nodes of a group do not all ask at the same moment.
	pullSafety       = 25 * time.Second
	pullSafetySpread = 10 * time.Second
	// pullWorkers is how many members a node asks at the same time.
	pullWorkers = 4
)

// heads is what a node says about how far its own data went.
type heads struct {
	Boot     string `json:"boot"`
	Store    int64  `json:"s"`
	Requests uint64 `json:"r"`
}

// peerSeen is what this node knows a member has asked for.
type peerSeen struct {
	events, incidents int64
	requests          uint64
	eOK, iOK, rOK     bool
	// expect: the member is fetching requests and asks again by itself
	// until then.
	expect time.Time
	told   time.Time
}

// peerPull is what this node knows of a member it pulls from.
type peerPull struct {
	// told is the newest word of the member, speaks whether it ever said
	// one (a member of an earlier build never does).
	told   heads
	speaks bool
	// boot is the run of the member the fields below belong to.
	boot              string
	events, incidents int64
	requests          uint64
	eOK, iOK, rOK     bool
	// hot: the last answer brought requests, so more are likely.
	hot                 bool
	lastE, lastI, lastR time.Time
}

type headsState struct {
	mu   sync.Mutex
	boot string
	seen map[string]*peerSeen
	pull map[string]*peerPull
	// kicked are the members whose word just arrived; wake tells the pull
	// loop that there are some.
	kicked map[string]bool
	wake   chan struct{}
}

func newHeadsState(started time.Time) *headsState {
	return &headsState{boot: strconv.FormatInt(started.UnixNano(), 36), seen: map[string]*peerSeen{}, pull: map[string]*peerPull{},
		kicked: map[string]bool{}, wake: make(chan struct{}, 1)}
}

func (h *headsState) seenOf(peer string) *peerSeen {
	s := h.seen[peer]
	if s == nil {
		s = &peerSeen{}
		h.seen[peer] = s
	}
	return s
}

func (h *headsState) pullOf(peer string) *peerPull {
	p := h.pull[peer]
	if p == nil {
		p = &peerPull{}
		h.pull[peer] = p
	}
	return p
}

// ownHeads is what this node says of itself right now.
func (g *groupData) ownHeads() heads {
	h := heads{Boot: g.heads.boot, Store: g.a.Store.OwnGen()}
	if g.a.Requests != nil {
		h.Requests = g.a.Requests.ServedNext()
	}
	return h
}

// safetyOf is how long this node lets a member be before it asks it again
// unprompted.
func safetyOf(peer string) time.Duration {
	f := fnv.New32a()
	_, _ = f.Write([]byte(peer))
	return pullSafety + time.Duration(f.Sum32()%1000)*pullSafetySpread/1000
}

// tellHeadsRound tells the members that have not asked for what this node
// holds now.
func (g *groupData) tellHeadsRound(ctx context.Context) {
	node := g.a.Cluster
	if node.Removed() || node.Paused() || g.asBuildBefore() {
		return
	}
	cur := g.ownHeads()
	now := time.Now()
	h := g.heads
	var to []string
	h.mu.Lock()
	for _, peer := range node.Reachable() {
		s := h.seenOf(peer)
		behind := !s.eOK || !s.iOK || s.events != cur.Store || s.incidents != cur.Store || (g.a.Requests != nil && (!s.rOK || s.requests != cur.Requests))
		if !behind || now.Before(s.expect) || now.Sub(s.told) < headsRepeat {
			continue
		}
		s.told = now
		to = append(to, peer)
	}
	// What is kept of a member that is gone goes with it.
	for peer := range h.seen {
		if !node.IsMember(peer) {
			delete(h.seen, peer)
		}
	}
	for peer := range h.pull {
		if !node.IsMember(peer) {
			delete(h.pull, peer)
		}
	}
	h.mu.Unlock()
	if len(to) == 0 {
		return
	}
	body, err := json.Marshal(cur)
	if err != nil {
		return
	}
	node.TellTo(ctx, to, tellHeads, body)
}

// takeHeads keeps the word of a member and wakes the pull loop for it.
func (g *groupData) takeHeads(from string, hd heads) {
	if hd.Boot == "" || len(hd.Boot) > 64 || g.asBuildBefore() {
		return
	}
	h := g.heads
	h.mu.Lock()
	// The mesh takes a word from members only; the maps are bounded all the
	// same.
	if _, ok := h.pull[from]; !ok && len(h.pull) >= 4*clusterMaxGateways {
		h.mu.Unlock()
		return
	}
	p := h.pullOf(from)
	p.told, p.speaks = hd, true
	h.kicked[from] = true
	h.mu.Unlock()
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// wants reports what this node has to ask a member for now.
func (g *groupData) wants(peer string, now time.Time) (events, incidents, requests bool) {
	h := g.heads
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.pullOf(peer)
	if !p.speaks {
		// A member of an earlier build: every second, as before.
		return true, true, true
	}
	if p.boot != p.told.Boot {
		// Another run of the member: its numbers started anew.
		p.boot, p.eOK, p.iOK, p.rOK = p.told.Boot, false, false, false
	}
	safety := safetyOf(peer)
	events = !p.eOK || p.events != p.told.Store || now.Sub(p.lastE) > safety
	incidents = !p.iOK || p.incidents != p.told.Store || now.Sub(p.lastI) > safety
	requests = p.hot || !p.rOK || p.requests != p.told.Requests || now.Sub(p.lastR) > safety
	return
}

// toldOf is the word of a member as of now, to compare after a pull.
func (g *groupData) toldOf(peer string) heads {
	h := g.heads
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pullOf(peer).told
}

// pullPeer asks one member for what it has that this node lacks.
func (g *groupData) pullPeer(ctx context.Context, peer string) {
	now := time.Now()
	wantE, wantI, wantR := g.wants(peer, now)
	h := g.heads
	// Requests first: their answer carries the member's heads, which may
	// say that events and incidents moved too.
	if wantR && g.a.Requests != nil {
		before := g.toldOf(peer)
		got, drained, ansHeads, ok := g.pullRequests(ctx, peer)
		h.mu.Lock()
		p := h.pullOf(peer)
		p.lastR = now
		if ok {
			p.hot = got > 0
			if ansHeads.Boot != "" {
				p.told, p.speaks = ansHeads, true
				before = ansHeads
			} else if p.speaks {
				// It said heads before and answers without them now: the
				// member runs an earlier build again (a rollback). Ask it
				// every second, as that build expects.
				p.speaks = false
			}
			if drained && before.Boot == p.boot {
				p.requests, p.rOK = before.Requests, true
			}
		} else {
			p.hot = false
		}
		h.mu.Unlock()
		wantE2, wantI2, _ := g.wants(peer, now)
		wantE, wantI = wantE || wantE2, wantI || wantI2
	}
	if wantE {
		before := g.toldOf(peer)
		more, ok := g.pullEvents(ctx, peer)
		h.mu.Lock()
		p := h.pullOf(peer)
		p.lastE = now
		if ok && !more && before.Boot == p.boot {
			p.events, p.eOK = before.Store, true
		}
		h.mu.Unlock()
	}
	if wantI {
		before := g.toldOf(peer)
		ok := g.pullIncidents(ctx, peer)
		h.mu.Lock()
		p := h.pullOf(peer)
		p.lastI = now
		if ok && before.Boot == p.boot {
			p.incidents, p.iOK = before.Store, true
		}
		h.mu.Unlock()
	}
}

// pullRound asks the members named (nil: every member this node reaches),
// a few at a time.
func (g *groupData) pullRound(ctx context.Context, only map[string]bool) {
	sem := make(chan struct{}, pullWorkers)
	var wg sync.WaitGroup
	for _, peer := range g.a.Cluster.Reachable() {
		if only != nil && !only[peer] {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(peer string) {
			defer func() {
				// A panic here must not take the process with it; the loop
				// that started the round goes on.
				if p := recover(); p != nil {
					g.a.log.Error("cluster: pull from a member crashed (request handling is not affected)", "panic", p)
				}
				<-sem
				wg.Done()
			}()
			g.pullPeer(ctx, peer)
		}(peer)
	}
	wg.Wait()
}

// pullLoop asks every member once a second for what is due, and a member
// whose word just arrived at once.
func (g *groupData) pullLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	h := g.heads
	var round int
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.pullRound(ctx, nil)
			if round++; round%30 == 0 {
				// An event of an erased address may have come from a node that
				// had not erased yet.
				g.a.reapplyErasures(ctx, 10*time.Minute)
			}
		case <-h.wake:
			h.mu.Lock()
			only := h.kicked
			h.kicked = map[string]bool{}
			h.mu.Unlock()
			if len(only) > 0 {
				g.pullRound(ctx, only)
			}
		}
	}
}

// noteAsked records, on the answering side, what a member has asked for.
func (g *groupData) noteAsked(from string, f func(s *peerSeen)) {
	h := g.heads
	h.mu.Lock()
	if _, ok := h.seen[from]; ok || len(h.seen) < 4*clusterMaxGateways {
		f(h.seenOf(from))
	}
	h.mu.Unlock()
}

// The answer with requests in its compact form (encoding "b1",
// contracts/cluster.md section 9):
//
//	"SRQ1" text(epoch) uvarint(first) uvarint(next) text(boot) uvarint(s) uvarint(r) block
//
// with text and block as in reqring/wire.go. An answer as JSON starts with
// "{" and can never be taken for it.

const (
	encBlock   = "b1"
	blockMagic = "SRQ1"
)

var errAnswer = errors.New("cluster: bad answer")

func appendText(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

// encodeRequestsBlock builds the compact answer.
func encodeRequestsBlock(ans *requestsAnswer) []byte {
	out := make([]byte, 0, 64+len(ans.Rows)*72)
	out = append(out, blockMagic...)
	out = appendText(out, ans.Epoch)
	out = binary.AppendUvarint(out, ans.First)
	out = binary.AppendUvarint(out, ans.Next)
	var hd heads
	if ans.Heads != nil {
		hd = *ans.Heads
	}
	out = appendText(out, hd.Boot)
	out = binary.AppendUvarint(out, uint64(max(hd.Store, 0)))
	out = binary.AppendUvarint(out, hd.Requests)
	return reqring.AppendEntries(out, ans.Rows)
}

// decodeRequestsAnswer reads an answer with requests in either form, at
// most maxRows of them.
func decodeRequestsAnswer(raw []byte, maxRows int) (*requestsAnswer, error) {
	var ans requestsAnswer
	if len(raw) < len(blockMagic) || string(raw[:len(blockMagic)]) != blockMagic {
		if err := json.Unmarshal(raw, &ans); err != nil {
			return nil, err
		}
		if len(ans.Rows) > maxRows {
			ans.Rows = ans.Rows[:maxRows]
		}
		return &ans, nil
	}
	b := raw[len(blockMagic):]
	text := func() (string, bool) {
		n, k := binary.Uvarint(b)
		if k <= 0 || n > 128 || uint64(len(b)-k) < n {
			return "", false
		}
		s := string(b[k : k+int(n)])
		b = b[k+int(n):]
		return s, true
	}
	num := func() (uint64, bool) {
		n, k := binary.Uvarint(b)
		if k <= 0 {
			return 0, false
		}
		b = b[k:]
		return n, true
	}
	var ok [6]bool
	var store uint64
	var hd heads
	ans.Epoch, ok[0] = text()
	ans.First, ok[1] = num()
	ans.Next, ok[2] = num()
	hd.Boot, ok[3] = text()
	store, ok[4] = num()
	hd.Requests, ok[5] = num()
	for _, o := range ok {
		if !o {
			return nil, errAnswer
		}
	}
	if store > 1<<62 {
		return nil, errAnswer
	}
	hd.Store = int64(store)
	if hd.Boot != "" {
		ans.Heads = &hd
	}
	rows, err := reqring.ReadEntries(b, maxRows)
	if err != nil {
		return nil, err
	}
	ans.Rows = rows
	return &ans, nil
}
