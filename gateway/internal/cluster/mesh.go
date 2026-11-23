package cluster

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// The mesh: one listener per node, TLS 1.3 with the node keys, HTTP/2
// inside. Every node asks every other member for what it lacks with a call
// that waits for news (a long poll, as `schild firewall run` asks the
// gateway), so a change reaches a peer at once and one mechanism serves the
// push, the catch-up after an outage and the first sync of a new node.

const (
	pathSync   = "/mesh/v0/sync"
	pathHello  = "/mesh/v0/hello"
	pathLock   = "/mesh/v0/lock"
	pathUnlock = "/mesh/v0/unlock"
	pathTell   = "/mesh/v0/tell"
	pathAsk    = "/mesh/v0/ask"
	// maxBatch bounds the records of one answer.
	maxBatch = 500
	maxBody  = 1 << 20
)

type syncRequest struct {
	Group  string            `json:"group"`
	Vector map[string]uint64 `json:"vector"`
	WaitMS int               `json:"wait_ms"`
}

type syncResponse struct {
	// Vector is how far the answering node is, per origin.
	Vector map[string]uint64 `json:"vector"`
	// Covered is how far this answer brings the asking node, per origin.
	Covered map[string]uint64 `json:"covered"`
	Records []json.RawMessage `json:"records"`
	More    bool              `json:"more"`
	// InStep: the answering node is in step with its group, or was within
	// EntryTombstoneKeep. Only such an answer makes the caller in step
	// (runPeer), so two fresh nodes do not call each other in step with
	// nothing.
	InStep bool `json:"in_step"`
}

// helloRequest is how a node set up by configuration makes itself known:
// its own member record, which carries the admission of the group secret.
type helloRequest struct {
	Record json.RawMessage `json:"record"`
}

// helloResponse is the group and its member list.
type helloResponse struct {
	Group   string            `json:"group"`
	Records []json.RawMessage `json:"records"`
}

func (n *Node) listen() (*http.Server, net.Listener, error) {
	if err := n.Bind(); err != nil {
		return nil, nil, err
	}
	ln := n.takeListener()
	if n.wrapListener != nil {
		ln = n.wrapListener(ln)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+pathSync, n.serveSync)
	mux.HandleFunc("POST "+pathHello, n.serveHello)
	mux.HandleFunc("POST "+pathLock, n.serveLock)
	mux.HandleFunc("POST "+pathUnlock, n.serveUnlock)
	mux.HandleFunc("POST "+pathTell, n.serveTell)
	mux.HandleFunc("POST "+pathAsk, n.serveAsk)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10, HTTP2: meshPings(),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{n.cert},
			// Any certificate may connect; the handlers decide by its key
			// (a member for sync, a member record with the admission of the
			// group secret for hello).
			ClientAuth: tls.RequireAnyClientCert},
		// Handshakes of strangers are no news for the operator's log.
		ErrorLog: slog.NewLogLogger(n.log.Handler(), slog.LevelDebug)}
	return srv, ln, nil
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if err := d.Decode(v); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func (n *Node) serveSync(w http.ResponseWriter, r *http.Request) {
	key, ok := peerKey(r.TLS)
	if !ok {
		http.Error(w, "no key", http.StatusForbidden)
		return
	}
	id, ok := n.activeKey(key, contract.RoleGateway)
	if !ok {
		n.refuse(w, key)
		return
	}
	var req syncRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Group != n.group {
		http.Error(w, "another group", http.StatusForbidden)
		return
	}
	n.seenIn(id, req.Vector[n.id])
	wait := min(time.Duration(req.WaitMS)*time.Millisecond, n.opts.Hold)
	deadline := time.NewTimer(max(wait, 0))
	defer deadline.Stop()
	for {
		news := n.waitNews()
		mine, err := n.vectorNow()
		if err != nil {
			http.Error(w, "store", http.StatusInternalServerError)
			return
		}
		recs, covered, more, err := n.afterOf(r.Context(), mine, req.Vector, maxBatch)
		if err != nil {
			http.Error(w, "store", http.StatusInternalServerError)
			return
		}
		ahead := false
		for o, seq := range covered {
			ahead = ahead || seq > req.Vector[o]
		}
		expired := false
		if !ahead {
			// A command on the host writes into the same file and cannot
			// wake this call itself: watchStore does that for every call
			// that waits, within half a second.
			select {
			case <-r.Context().Done():
				return
			case <-news:
			case <-deadline.C:
				expired = true
			}
			if !expired {
				continue
			}
		}
		vec, _ := n.vectorNow()
		if recs == nil {
			recs = []json.RawMessage{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(syncResponse{Vector: vec, Covered: covered, Records: recs, More: more, InStep: n.inStepAnswer()})
		return
	}
}

// serveHello takes the member record of a node that lets itself in with the
// group secret (cluster.secret_file), and answers with the member list. The
// caller needs no place in the group yet: its record proves it, and the
// answer holds only what every record of it proves by itself. The record is
// checked before anything is stored, and the call touches neither the
// readiness of this node nor what its syncs held back.
func (n *Node) serveHello(w http.ResponseWriter, r *http.Request) {
	key, ok := peerKey(r.TLS)
	if !ok {
		http.Error(w, "no key", http.StatusForbidden)
		return
	}
	var req helloRequest
	if !readJSON(w, r, &req) {
		return
	}
	var rec contract.Record
	id := contract.NodeID(key)
	if len(req.Record) > contract.MaxRecord || json.Unmarshal(req.Record, &rec) != nil || rec.Class != contract.ClassMembers || rec.ID != id || rec.Origin != id || rec.Deleted {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := n.reload(); err != nil {
		http.Error(w, "store", http.StatusInternalServerError)
		return
	}
	// The admission of the group secret, the signature and the clock first:
	// a caller that fails them stores nothing here.
	n.rmu.RLock()
	cerr := n.roster.Check(&rec, n.now())
	n.rmu.RUnlock()
	if cerr != nil {
		n.refuse(w, key)
		return
	}
	if !n.IsMember(id) && n.full() {
		http.Error(w, "the group is full", http.StatusConflict)
		return
	}
	if _, _, err := n.takeRecords([]json.RawMessage{req.Record}, nil, false); err != nil {
		http.Error(w, "store", http.StatusInternalServerError)
		return
	}
	if _, ok := n.activeKey(key, contract.RoleGateway); !ok {
		n.refuse(w, key)
		return
	}
	_, raws, err := n.winners(contract.ClassMembers)
	if err != nil {
		http.Error(w, "store", http.StatusInternalServerError)
		return
	}
	out := helloResponse{Group: n.group}
	for _, raw := range raws {
		out.Records = append(out.Records, raw)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// seek makes this node known at the configured peers it holds no member
// for yet, and takes their member lists. One round at a time; a peer that
// does not answer is asked again with the next round.
func (n *Node) seek(ctx context.Context) {
	if len(n.opts.Peers) == 0 || !n.seeking.CompareAndSwap(false, true) {
		return
	}
	n.rmu.RLock()
	known, gone := map[string]bool{}, map[string]bool{}
	for _, e := range n.roster.Members() {
		if e.Removed {
			gone[e.Member.Address] = true
		} else {
			known[e.Member.Address] = true
		}
	}
	n.rmu.RUnlock()
	now := n.now()
	var todo []string
	for _, p := range n.opts.Peers {
		if known[p] {
			continue
		}
		// The address of a removed member is asked once a minute, not every
		// second: a new node may come up under it.
		if gone[p] {
			if next, ok := n.seekNext[p]; ok && now.Before(next) {
				continue
			}
			n.seekNext[p] = now.Add(seekRemovedEvery)
		}
		todo = append(todo, p)
	}
	if len(todo) == 0 {
		n.seeking.Store(false)
		return
	}
	go func() {
		defer n.seeking.Store(false)
		recs, raws, err := n.winners(contract.ClassMembers)
		if err != nil {
			return
		}
		var own json.RawMessage
		for i, r := range recs {
			if r.ID == n.id && !r.Deleted {
				own = raws[i]
			}
		}
		if own == nil {
			return
		}
		for _, addr := range todo {
			// Any key may answer: what it answers is checked record by
			// record. The key is kept to weigh a 410.
			var mu sync.Mutex
			var answered ed25519.PublicKey
			c := meshClient(n.cert, func(k ed25519.PublicKey) bool {
				mu.Lock()
				answered = k
				mu.Unlock()
				return true
			}, 5*time.Second)
			var resp helloResponse
			err := postJSON(ctx, c, "https://"+addr+pathHello, helloRequest{Record: own}, &resp)
			c.CloseIdleConnections()
			if err != nil {
				mu.Lock()
				k := answered
				mu.Unlock()
				if n.removedBy(err, k) {
					n.noteRemoved()
				}
				n.log.Debug("cluster: configured peer not reached", "peer", addr, "err", err)
				continue
			}
			if resp.Group != n.group {
				n.log.Warn("cluster: a configured peer is in another group (another cluster.secret_file?)", "peer", addr)
				continue
			}
			var rs []json.RawMessage
			for _, raw := range resp.Records {
				rs = append(rs, raw)
			}
			if _, _, err := n.takeRecords(rs, nil, false); err != nil {
				n.log.Warn("cluster: member list of a configured peer not taken", "peer", addr, "err", err)
			}
		}
	}()
}

// meshPings makes both ends of a mesh connection watch it: after a second
// without a frame an HTTP/2 PING goes out, and a connection that does not
// answer within two more is closed. So a node that hangs or whose network
// went away is known as unreachable after about three seconds, without a
// heartbeat of its own and without waiting for a call to time out. The
// nodes keep one long-lived connection each way; this is the monitoring a
// WebSocket would give, with what HTTP/2 already has.
func meshPings() *http.HTTP2Config {
	return &http.HTTP2Config{SendPingTimeout: time.Second, PingTimeout: 2 * time.Second}
}

// client returns an HTTP client that talks to exactly one key: the check of
// the peer's certificate is the comparison of its key.
func meshClient(cert tls.Certificate, accept func(ed25519.PublicKey) bool, timeout time.Duration) *http.Client {
	tr := &http.Transport{ForceAttemptHTTP2: true, MaxIdleConns: 2, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		HTTP2:       meshPings(),
		DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
			// Names and dates of the certificate mean nothing here; the key
			// is compared below.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if k, ok := peerKey(&cs); ok && accept(k) {
					return nil
				}
				return errors.New("cluster: the peer shows another key")
			}}}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// errRemoved: a member answered that this node is no member any more.
var errRemoved = errors.New("this node was removed from the group")

// headerGroup names the group of the node that answers 410: a node that
// moved to another group (a new group secret) may still be known as removed
// to a node of the group before, and that says nothing about the new one.
const headerGroup = "X-Schild-Group"

// removedError is errRemoved with the group the answering node spoke for;
// "" from a node that does not say.
type removedError struct{ group string }

func (e *removedError) Error() string        { return errRemoved.Error() }
func (e *removedError) Is(target error) bool { return target == errRemoved }

// removedHere reports whether err, the answer of a member this node called
// by its key, says that this node was removed from the group it is in now.
// An answer that names no group, or another one, says nothing about it.
func (n *Node) removedHere(err error) bool {
	var re *removedError
	return errors.As(err, &re) && re.group != "" && re.group == n.group
}

// removedBy is removedHere for an answer of a key this node did not choose
// (seek asks an address): it counts only when that key is an active member
// as this node sees it.
func (n *Node) removedBy(err error, key ed25519.PublicKey) bool {
	if len(key) == 0 || !n.removedHere(err) {
		return false
	}
	n.rmu.RLock()
	defer n.rmu.RUnlock()
	_, ok := n.roster.ActiveKey(key)
	return ok
}

// seekRemovedEvery is how often seek asks the address of a removed member.
const seekRemovedEvery = time.Minute

func (n *Node) noteRemoved() {
	if n.removed.CompareAndSwap(false, true) {
		// Kept over a restart: a node that later moves to another group
		// (move.go) takes nothing along from the one it was removed from.
		n.wmu.Lock()
		_, _ = n.db.Exec(`INSERT INTO meta(k, v) VALUES('removed', '1') ON CONFLICT(k) DO UPDATE SET v = excluded.v`)
		n.wmu.Unlock()
		n.log.Warn("cluster: this node was removed from its group. It serves with the state it has and shares nothing. To take it out for good: cluster.enabled false; to bring it back: delete its cluster directory and start schild again")
	}
}

func postJSON(ctx context.Context, c *http.Client, url string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		if resp.StatusCode == http.StatusGone {
			return &removedError{group: resp.Header.Get(headerGroup)}
		}
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxAnswer+contract.MaxRecord+maxBody)).Decode(out)
}

// peer is the outgoing side toward one member.
type peer struct {
	id, name, address string
	cancel            context.CancelFunc
	done              chan struct{}

	key ed25519.PublicKey

	mu     sync.Mutex
	outOK  time.Time
	inOK   time.Time
	err    string
	behind uint64
	// inSeq is how far this peer said it is with the records of this node,
	// in its last call.
	inSeq uint64
	// held: its last answer put records off. fresh: it answered in full as
	// a node that is not in step (newGroup).
	held, fresh bool
	// telling: the kinds of Tell to this peer that are in flight;
	// tellClient keeps its connection.
	telling    map[string]bool
	tellClient *http.Client
	askClient  *http.Client
}

// syncPeers starts a loop for every gateway of the roster and stops the
// loops of members that are gone or moved.
func (n *Node) syncPeers(ctx context.Context) {
	n.rmu.RLock()
	members := n.roster.Members()
	n.rmu.RUnlock()
	want := map[string]contract.Member{}
	for _, e := range members {
		if !e.Removed && e.ID != n.id && e.Member.Role == contract.RoleGateway {
			want[e.ID] = e.Member
		}
	}
	n.pmu.Lock()
	defer n.pmu.Unlock()
	for id, p := range n.peers {
		if m, ok := want[id]; !ok || m.Address != p.address {
			p.cancel()
			delete(n.peers, id)
		}
	}
	for id, m := range want {
		if _, ok := n.peers[id]; ok {
			continue
		}
		key, _ := m.Key()
		pctx, cancel := context.WithCancel(ctx)
		p := &peer{id: id, name: m.Name, address: m.Address, key: key, cancel: cancel, done: make(chan struct{})}
		n.peers[id] = p
		go n.runPeer(pctx, p, key)
	}
}

func (n *Node) stopPeers() {
	n.pmu.Lock()
	ps := make([]*peer, 0, len(n.peers))
	for id, p := range n.peers {
		p.cancel()
		ps = append(ps, p)
		delete(n.peers, id)
	}
	n.pmu.Unlock()
	for _, p := range ps {
		<-p.done
	}
}

func (n *Node) seenIn(id string, own uint64) {
	n.pmu.Lock()
	p := n.peers[id]
	n.pmu.Unlock()
	if p != nil {
		p.mu.Lock()
		p.inOK = n.now()
		if own > p.inSeq {
			p.inSeq = own
		}
		p.mu.Unlock()
	}
}

func (n *Node) runPeer(ctx context.Context, p *peer, key ed25519.PublicKey) {
	defer close(p.done)
	c := meshClient(n.cert, func(k ed25519.PublicKey) bool { return k.Equal(key) }, n.opts.Hold+5*time.Second)
	defer c.CloseIdleConnections()
	backoff := 250 * time.Millisecond
	pause := func(d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}
	// all: what a node that was away too long (Stale) asks this member
	// for until it is in step: everything from the first record on, since
	// it dropped what it held of the shared classes.
	all := map[string]uint64{}
	for ctx.Err() == nil {
		vec, err := n.vectorNow()
		if err != nil {
			if !pause(time.Second) {
				return
			}
			continue
		}
		// A node that is not in step yet asks without waiting: the member
		// answers at once, also when it has nothing new, and the node knows
		// what the group holds. Held, its readiness depended on whether the
		// member happened to write something within the hold. A node whose
		// records this member put off (a clock far behind) waits as usual,
		// so it does not ask in a tight loop.
		synced := n.synced.Load()
		p.mu.Lock()
		wasHeld := p.held
		p.mu.Unlock()
		hold := n.opts.Hold
		if !synced && !wasHeld {
			hold = 0
		}
		ask := vec
		full := !synced && n.stale.Load()
		if full {
			ask = all
		}
		var resp syncResponse
		err = postJSON(ctx, c, "https://"+p.address+pathSync, syncRequest{Group: n.group, Vector: ask, WaitMS: int(hold / time.Millisecond)}, &resp)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if n.removedHere(err) {
				n.noteRemoved()
			}
			p.mu.Lock()
			p.err = err.Error()
			p.mu.Unlock()
			if !pause(backoff) {
				return
			}
			backoff = min(backoff*2, 5*time.Second)
			continue
		}
		backoff = 250 * time.Millisecond
		if full {
			n.retake.Add(1)
		}
		applied, held, err := n.takeRecords(resp.Records, resp.Covered, true)
		if full {
			n.retake.Add(-1)
			for o, seq := range resp.Covered {
				all[o] = max(all[o], seq)
			}
		}
		if err == nil {
			p.mu.Lock()
			p.held = held
			p.mu.Unlock()
		}
		// In step only when nothing was put off, by this member or another:
		// a node whose clock is far behind takes the records of the others a
		// minute late, and must not call itself in step before it holds
		// them. And only by the answer of a member that is in step, or as a
		// node that was in step itself: two fresh nodes do not make each
		// other in step with nothing, unless the whole group is new.
		if err == nil && !resp.More && !held && !n.heldAnywhere() {
			switch {
			case resp.InStep:
				n.markSynced(true)
			case n.inStepAnswer():
				n.markSynced(false)
			default:
				p.mu.Lock()
				p.fresh = true
				p.mu.Unlock()
				if n.newGroup() {
					n.markSynced(false)
				}
			}
		}
		var behind uint64
		for o, seq := range resp.Vector {
			if mine := vec[o]; seq > mine {
				behind += seq - mine
			}
		}
		p.mu.Lock()
		p.outOK, p.err, p.behind = n.now(), "", behind
		if err != nil {
			p.err = err.Error()
		}
		p.mu.Unlock()
		// Records that were sent and not applied come again with the next
		// call at once; do not spin on them. Nor on a member whose complete
		// answer did not make this node in step (neither is in step yet):
		// it is asked again a second later.
		waiting := err == nil && !resp.More && !n.synced.Load()
		if (err != nil || (applied == 0 && len(resp.Records) > 0) || waiting) && !pause(time.Second) {
			return
		}
	}
}

// statusFile is where a running node writes what it sees of its peers, for
// `schild cluster status`, which reads the directory and not the process.
// A file of its own and not rows of the store: the view is written every
// two seconds, and a commit to the store wakes every sync call that waits
// and makes the node look at its member records again. An idle node used
// to do that every two seconds for nothing but this heartbeat.
const statusFile = "status.json"

// statusView is the content of statusFile.
type statusView struct {
	// At is when the node wrote it, unix ms: the sign that it runs.
	At       int64                 `json:"at_ms"`
	Peers    map[string]statusPeer `json:"peers"`
	Counters map[string]uint64     `json:"counters"`
	// Clocks: how far the clock of a member is off this node's (NoteClock).
	Clocks map[string]statusClock `json:"clocks,omitempty"`
}

type statusPeer struct {
	OutOK  int64  `json:"out_ok_ms"`
	InOK   int64  `json:"in_ok_ms"`
	Error  string `json:"error,omitempty"`
	Behind uint64 `json:"behind"`
}

type statusClock struct {
	SkewMS int64 `json:"skew_ms"`
	At     int64 `json:"at_ms"`
}

// saveStatus writes what the node sees of its peers, for the status command.
func (n *Node) saveStatus() {
	v := statusView{At: n.now().UnixMilli(), Peers: map[string]statusPeer{}, Clocks: map[string]statusClock{},
		Counters: map[string]uint64{"applied": n.Applied.Load(), "rejected": n.Rejected.Load(), "deferred": n.Deferred.Load(), "unread": n.Unread.Load()}}
	n.pmu.Lock()
	ps := make([]*peer, 0, len(n.peers))
	for _, p := range n.peers {
		ps = append(ps, p)
	}
	for id, c := range n.clocks {
		v.Clocks[id] = c
	}
	n.pmu.Unlock()
	for _, p := range ps {
		p.mu.Lock()
		v.Peers[p.id] = statusPeer{OutOK: ms(p.outOK), InOK: ms(p.inOK), Error: p.err, Behind: p.behind}
		p.mu.Unlock()
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	// Written aside and moved into place: a reader never sees half a file.
	n.statusMu.Lock()
	defer n.statusMu.Unlock()
	path := filepath.Join(n.dir, statusFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// readStatusView reads statusFile of a cluster directory; ok false: none.
func readStatusView(dir string) (v statusView, ok bool) {
	raw, err := os.ReadFile(filepath.Join(dir, statusFile))
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &v) != nil {
		return statusView{}, false
	}
	return v, true
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// Tell and OnTell carry what is said once and never stored: the counts a
// node saw in the last second. A peer that is away misses it; that costs a
// second of counting and nothing else.

type tellRequest struct {
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}

// maxTell bounds one message.
const maxTell = 1 << 20

// OnTell registers f for messages of a kind; from is the id of the sender.
func (n *Node) OnTell(kind string, f func(from string, body []byte)) {
	n.hmu.Lock()
	if n.tells == nil {
		n.tells = map[string]func(string, []byte){}
	}
	n.tells[kind] = f
	n.hmu.Unlock()
}

// Tell sends body to every gateway this node reached lately, each in its
// own goroutine with one second to answer, and returns at once. A peer that
// still works on the message before gets none.
func (n *Node) Tell(ctx context.Context, kind string, body []byte) {
	n.TellTo(ctx, nil, kind, body)
}

// TellTo is Tell to the gateways named by id only; nil means every one.
func (n *Node) TellTo(ctx context.Context, ids []string, kind string, body []byte) {
	if len(body) > maxTell {
		return
	}
	n.pmu.Lock()
	now := n.now()
	var to []*peer
	for id, p := range n.peers {
		if ids != nil && !slices.Contains(ids, id) {
			continue
		}
		p.mu.Lock()
		ok := p.aliveLocked(now)
		p.mu.Unlock()
		if ok && p.startTell(kind) {
			to = append(to, p)
		}
	}
	n.pmu.Unlock()
	for _, p := range to {
		go func(p *peer) {
			defer p.endTell(kind)
			c := p.teller(n.cert)
			tctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			var out struct{}
			_ = postJSON(tctx, c, "https://"+p.address+pathTell, tellRequest{Kind: kind, Body: body}, &out)
		}(p)
	}
}

// aliveLocked reports whether the peer answered its last call, and lately.
// A call that failed makes it unreachable at once: who keeps the locks and
// runs the group's jobs must not wait ten seconds for a node that is gone.
// Called with p.mu held.
func (p *peer) aliveLocked(now time.Time) bool {
	return p.err == "" && !p.outOK.IsZero() && now.Sub(p.outOK) < reachable
}

// startTell reports whether a message of this kind may go to the peer: one
// of a kind at a time, the kinds do not wait for each other.
func (p *peer) startTell(kind string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.telling[kind] {
		return false
	}
	if p.telling == nil {
		p.telling = map[string]bool{}
	}
	p.telling[kind] = true
	return true
}

func (p *peer) endTell(kind string) {
	p.mu.Lock()
	delete(p.telling, kind)
	p.mu.Unlock()
}

func (p *peer) teller(cert tls.Certificate) *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tellClient == nil {
		key := p.key
		p.tellClient = meshClient(cert, func(k ed25519.PublicKey) bool { return k.Equal(key) }, 2*time.Second)
	}
	return p.tellClient
}

func (n *Node) serveTell(w http.ResponseWriter, r *http.Request) {
	key, ok := peerKey(r.TLS)
	if !ok {
		http.Error(w, "no key", http.StatusForbidden)
		return
	}
	id, ok := n.activeKey(key, contract.RoleGateway)
	if !ok {
		n.refuse(w, key)
		return
	}
	var req tellRequest
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTell+4096))
	if err := d.Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	n.hmu.Lock()
	f := n.tells[req.Kind]
	n.hmu.Unlock()
	if f != nil {
		f(id, req.Body)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{}"))
}

// Ask and OnAsk are a question to one member and its answer: a node asks
// another for the events it wrote after a cursor. Like every call of the
// mesh it has a deadline, and the answer is input from outside.

// maxAnswerBody bounds the answer to an Ask.
const maxAnswerBody = 8 << 20

// OnAsk registers f for questions of a kind; from is the id of the asker.
func (n *Node) OnAsk(kind string, f func(from string, body []byte) ([]byte, error)) {
	n.hmu.Lock()
	if n.asks == nil {
		n.asks = map[string]func(string, []byte) ([]byte, error){}
	}
	n.asks[kind] = f
	n.hmu.Unlock()
}

// Reachable returns the gateways this node reached lately, by id.
func (n *Node) Reachable() []string {
	n.pmu.Lock()
	defer n.pmu.Unlock()
	now := n.now()
	var out []string
	for id, p := range n.peers {
		p.mu.Lock()
		if p.aliveLocked(now) {
			out = append(out, id)
		}
		p.mu.Unlock()
	}
	sort.Strings(out)
	return out
}

// PeerName is the name of a member, or its id.
func (n *Node) PeerName(id string) string {
	n.rmu.RLock()
	defer n.rmu.RUnlock()
	for _, e := range n.roster.Members() {
		if e.ID == id {
			return e.Member.Name
		}
	}
	return id
}

// Ask sends a question to one member and returns its answer.
func (n *Node) Ask(ctx context.Context, peerID, kind string, body []byte) ([]byte, error) {
	n.pmu.Lock()
	p := n.peers[peerID]
	n.pmu.Unlock()
	if p == nil {
		return nil, errors.New("cluster: no such peer")
	}
	raw, err := json.Marshal(tellRequest{Kind: kind, Body: body})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+p.address+pathAsk, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.asker(n.cert).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Kind: kind, Code: resp.StatusCode}
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBody+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxAnswerBody {
		return nil, errors.New("cluster: answer too large")
	}
	return out, nil
}

// StatusError is the answer of a member to an Ask that was not 200.
// http.StatusNotFound: the member does not know the kind (an earlier build).
type StatusError struct {
	Kind string
	Code int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("cluster: ask %s: %d %s", e.Kind, e.Code, http.StatusText(e.Code))
}

func (p *peer) asker(cert tls.Certificate) *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.askClient == nil {
		key := p.key
		p.askClient = meshClient(cert, func(k ed25519.PublicKey) bool { return k.Equal(key) }, 15*time.Second)
	}
	return p.askClient
}

func (n *Node) serveAsk(w http.ResponseWriter, r *http.Request) {
	key, ok := peerKey(r.TLS)
	if !ok {
		http.Error(w, "no key", http.StatusForbidden)
		return
	}
	id, ok := n.activeKey(key, contract.RoleGateway)
	if !ok {
		n.refuse(w, key)
		return
	}
	var req tellRequest
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTell+4096))
	if err := d.Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	n.hmu.Lock()
	f := n.asks[req.Kind]
	n.hmu.Unlock()
	if f == nil {
		http.Error(w, "unknown kind", http.StatusNotFound)
		return
	}
	out, err := f(id, req.Body)
	if err != nil {
		http.Error(w, "failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// A long answer travels compressed when the asking side takes that
	// (Go's HTTP client says so by itself and unpacks it, also the one of
	// earlier builds; it bounds what it reads after unpacking).
	if len(out) >= gzipFrom && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && !isBlock(out) {
		zw := gzipPool.Get().(*gzip.Writer)
		n.Compressed.Add(1)
		w.Header().Set("Content-Encoding", "gzip")
		zw.Reset(w)
		_, _ = zw.Write(out)
		_ = zw.Close()
		gzipPool.Put(zw)
		return
	}
	_, _ = w.Write(out)
}

// gzipFrom is the size from which an answer is compressed.
const gzipFrom = 2048

var gzipPool = sync.Pool{New: func() any {
	zw, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	return zw
}}

// isBlock reports whether an answer is in a compact binary form already
// (it does not start like JSON): compressing it again costs more than it
// saves.
func isBlock(out []byte) bool {
	return len(out) > 0 && out[0] != '{' && out[0] != '['
}
