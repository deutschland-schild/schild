package cluster

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
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
	pathSync = "/mesh/v0/sync"
	pathJoin = "/mesh/v0/join"
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
}

type joinRequest struct {
	Secret  string `json:"secret"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

type joinResponse struct {
	Group   string            `json:"group"`
	Records []json.RawMessage `json:"records"`
}

func (n *Node) listen() (*http.Server, net.Listener, error) {
	ln, err := net.Listen("tcp", n.opts.Listen)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: listen %s: %w", n.opts.Listen, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+pathSync, n.serveSync)
	mux.HandleFunc("POST "+pathJoin, n.serveJoin)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{n.cert},
			// Any certificate may connect; the handlers decide by its key
			// (a member for sync, a join code for join).
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
		http.Error(w, "no member", http.StatusForbidden)
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
	n.seenIn(id)
	wait := min(time.Duration(req.WaitMS)*time.Millisecond, n.opts.Hold)
	deadline := time.NewTimer(max(wait, 0))
	defer deadline.Stop()
	for {
		news := n.waitNews()
		recs, covered, more, err := n.after(r.Context(), req.Vector, maxBatch)
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
			// wake this call, so it looks again every 500 ms.
			poll := time.NewTimer(500 * time.Millisecond)
			select {
			case <-r.Context().Done():
				poll.Stop()
				return
			case <-news:
			case <-poll.C:
			case <-deadline.C:
				expired = true
			}
			poll.Stop()
			if !expired {
				continue
			}
		}
		vec, _ := n.vector()
		if recs == nil {
			recs = []json.RawMessage{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(syncResponse{Vector: vec, Covered: covered, Records: recs, More: more})
		return
	}
}

// serveJoin admits the key of the caller's certificate for a join code of
// this node: one use, one hour. The answer is the member list.
func (n *Node) serveJoin(w http.ResponseWriter, r *http.Request) {
	key, ok := peerKey(r.TLS)
	if !ok {
		http.Error(w, "no key", http.StatusForbidden)
		return
	}
	var req joinRequest
	if !readJSON(w, r, &req) {
		return
	}
	secret, err := base64.StdEncoding.DecodeString(req.Secret)
	if err != nil || len(secret) != 16 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raws, err := n.admit(key, secret, req.Name, req.Address)
	switch {
	case errors.Is(err, errInvite):
		time.Sleep(500 * time.Millisecond) // a guess costs time
		http.Error(w, "join code not valid", http.StatusForbidden)
		return
	case errors.Is(err, contract.ErrSchema):
		http.Error(w, "name or address not valid", http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, "store", http.StatusInternalServerError)
		return
	}
	_ = n.reload()
	n.wake()
	n.log.Info("cluster: member joined", "name", req.Name, "node", contract.NodeID(key), "address", req.Address)
	out := joinResponse{Group: n.group}
	for _, raw := range raws {
		out.Records = append(out.Records, raw)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// client returns an HTTP client that talks to exactly one key: the check of
// the peer's certificate is the comparison of its key.
func meshClient(cert tls.Certificate, accept func(ed25519.PublicKey) bool, timeout time.Duration) *http.Client {
	tr := &http.Transport{ForceAttemptHTTP2: true, MaxIdleConns: 2, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
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
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	// maxBatch records of at most MaxRecord bytes each.
	return json.NewDecoder(io.LimitReader(resp.Body, maxBatch*contract.MaxRecord+maxBody)).Decode(out)
}

// peer is the outgoing side toward one member.
type peer struct {
	id, name, address string
	cancel            context.CancelFunc
	done              chan struct{}

	mu     sync.Mutex
	outOK  time.Time
	inOK   time.Time
	err    string
	behind uint64
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
		p := &peer{id: id, name: m.Name, address: m.Address, cancel: cancel, done: make(chan struct{})}
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

func (n *Node) seenIn(id string) {
	n.pmu.Lock()
	p := n.peers[id]
	n.pmu.Unlock()
	if p != nil {
		p.mu.Lock()
		p.inOK = n.now()
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
	for ctx.Err() == nil {
		vec, err := n.vector()
		if err != nil {
			if !pause(time.Second) {
				return
			}
			continue
		}
		var resp syncResponse
		err = postJSON(ctx, c, "https://"+p.address+pathSync, syncRequest{Group: n.group, Vector: vec, WaitMS: int(n.opts.Hold / time.Millisecond)}, &resp)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
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
		applied, err := n.take(resp.Records, resp.Covered)
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
		// call at once; do not spin on them.
		if (err != nil || (applied == 0 && len(resp.Records) > 0)) && !pause(time.Second) {
			return
		}
	}
}

// saveStatus writes what the node sees of its peers, for the status command.
func (n *Node) saveStatus() {
	n.pmu.Lock()
	ps := make([]*peer, 0, len(n.peers))
	for _, p := range n.peers {
		ps = append(ps, p)
	}
	n.pmu.Unlock()
	n.wmu.Lock()
	defer n.wmu.Unlock()
	tx, err := n.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM peers`); err != nil {
		return
	}
	for _, p := range ps {
		p.mu.Lock()
		_, err := tx.Exec(`INSERT INTO peers(node, out_ok_ms, in_ok_ms, error, behind) VALUES(?, ?, ?, ?, ?)`, p.id, ms(p.outOK), ms(p.inOK), p.err, int64(p.behind))
		p.mu.Unlock()
		if err != nil {
			return
		}
	}
	for k, v := range map[string]uint64{"applied": n.Applied.Load(), "rejected": n.Rejected.Load(), "deferred": n.Deferred.Load(), "unread": n.Unread.Load()} {
		if _, err := tx.Exec(`INSERT INTO counters(k, n) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET n = excluded.n`, k, int64(v)); err != nil {
			return
		}
	}
	_ = setMeta(tx, "status_ms", []byte(fmt.Sprint(n.now().UnixMilli())))
	_ = tx.Commit()
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}
