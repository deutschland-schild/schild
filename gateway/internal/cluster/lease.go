package cluster

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// Locks of the group, for the one thing that must not run twice: an order
// at a certificate authority. There is no majority to ask, so the lock is
// held by one member, the one with the lowest node id among the gateways
// this node reaches; the others ask it. Nodes that cannot reach each other
// each find a keeper on their side: both sides may then order the same
// certificate. That is one order too many and two valid certificates, and
// it is counted.

const (
	// leaseTTL ends a lock whose holder went away.
	leaseTTL = 5 * time.Minute
	// reachable: a peer answered within this time.
	reachable = 10 * time.Second
)

type lease struct {
	holder string
	until  time.Time
}

// release is what the last holder of a lock had written when it gave the
// lock back: the next holder waits until it holds that, so it finds the
// certificate the last one stored instead of ordering it again.
type release struct {
	Origin string `json:"origin"`
	Seq    uint64 `json:"seq"`
}

type leases struct {
	mu       sync.Mutex
	held     map[string]lease
	released map[string]release
}

type lockRequest struct {
	Name string `json:"name"`
	// Seq, on unlock: how far the holder is with its own records.
	Seq uint64 `json:"seq,omitempty"`
}

type lockResponse struct {
	Granted bool    `json:"granted"`
	After   release `json:"after"`
}

func (l *leases) grant(name, holder string, now time.Time) (bool, release) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held == nil {
		l.held, l.released = map[string]lease{}, map[string]release{}
	}
	if cur, ok := l.held[name]; ok && cur.holder != holder && cur.until.After(now) {
		return false, release{}
	}
	l.held[name] = lease{holder: holder, until: now.Add(leaseTTL)}
	return true, l.released[name]
}

func (l *leases) release(name, holder string, seq uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cur, ok := l.held[name]; ok && cur.holder == holder {
		delete(l.held, name)
		l.released[name] = release{Origin: holder, Seq: seq}
		if len(l.released) > 4096 {
			for k := range l.released {
				delete(l.released, k)
				break
			}
		}
	}
}

// keeper returns the member that keeps the locks as this node sees it: the
// lowest id among itself and the gateways that answered lately. nil: itself.
func (n *Node) keeper() *peer {
	n.pmu.Lock()
	defer n.pmu.Unlock()
	now := n.now()
	ids := []string{n.id}
	for id, p := range n.peers {
		p.mu.Lock()
		ok := !p.outOK.IsZero() && now.Sub(p.outOK) < reachable
		p.mu.Unlock()
		if ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return n.peers[ids[0]] // nil for n.id
}

func (n *Node) ownSeq() uint64 {
	v, _ := n.vector()
	return v[n.id]
}

// Lock takes the group's lock of a name and blocks until it has it or ctx
// ends. Before it returns it waits, for at most 10 s, until this node holds
// what the last holder had written.
func (n *Node) Lock(ctx context.Context, name string) error {
	for {
		var granted bool
		var after release
		if k := n.keeper(); k == nil {
			granted, after = n.leases.grant(name, n.id, n.now())
		} else {
			var resp lockResponse
			c := meshClient(n.cert, func(key ed25519.PublicKey) bool { return key.Equal(k.key) }, 5*time.Second)
			err := postJSON(ctx, c, "https://"+k.address+pathLock, lockRequest{Name: name}, &resp)
			c.CloseIdleConnections()
			granted, after = err == nil && resp.Granted, resp.After
		}
		if granted {
			n.waitFor(ctx, after, 10*time.Second)
			return nil
		}
		t := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Unlock gives a lock back, at the keeper and here: the keeper may have
// changed since Lock.
func (n *Node) Unlock(ctx context.Context, name string) {
	seq := n.ownSeq()
	n.leases.release(name, n.id, seq)
	if k := n.keeper(); k != nil {
		c := meshClient(n.cert, func(key ed25519.PublicKey) bool { return key.Equal(k.key) }, 5*time.Second)
		var resp lockResponse
		_ = postJSON(ctx, c, "https://"+k.address+pathUnlock, lockRequest{Name: name, Seq: seq}, &resp)
		c.CloseIdleConnections()
	}
}

// waitFor waits until this node saw the records of r.Origin up to r.Seq.
func (n *Node) waitFor(ctx context.Context, r release, limit time.Duration) {
	if r.Origin == "" || r.Origin == n.id {
		return
	}
	deadline := n.now().Add(limit)
	for n.now().Before(deadline) && ctx.Err() == nil {
		if v, err := n.vector(); err == nil && v[r.Origin] >= r.Seq {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// WaitAcked waits until every gateway this node reaches said it holds the
// records of this node up to seq, at most limit, and reports whether all
// did. A challenge token has to be on every node before the certificate
// authority is told to look: its check may land on any of them.
func (n *Node) WaitAcked(ctx context.Context, seq uint64, limit time.Duration) bool {
	deadline := n.now().Add(limit)
	for {
		n.pmu.Lock()
		now, all := n.now(), true
		for _, p := range n.peers {
			p.mu.Lock()
			if !p.outOK.IsZero() && now.Sub(p.outOK) < reachable && p.inSeq < seq {
				all = false
			}
			p.mu.Unlock()
		}
		n.pmu.Unlock()
		if all {
			return true
		}
		if !now.Before(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (n *Node) lockCaller(w http.ResponseWriter, r *http.Request) (string, *lockRequest) {
	key, ok := peerKey(r.TLS)
	if !ok {
		http.Error(w, "no key", http.StatusForbidden)
		return "", nil
	}
	id, ok := n.activeKey(key, contract.RoleGateway)
	if !ok {
		n.refuse(w, key)
		return "", nil
	}
	var req lockRequest
	if !readJSON(w, r, &req) {
		return "", nil
	}
	if req.Name == "" || len(req.Name) > contract.MaxID {
		http.Error(w, "bad request", http.StatusBadRequest)
		return "", nil
	}
	return id, &req
}

func (n *Node) serveLock(w http.ResponseWriter, r *http.Request) {
	id, req := n.lockCaller(w, r)
	if req == nil {
		return
	}
	granted, after := n.leases.grant(req.Name, id, n.now())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(lockResponse{Granted: granted, After: after})
}

func (n *Node) serveUnlock(w http.ResponseWriter, r *http.Request) {
	id, req := n.lockCaller(w, r)
	if req == nil {
		return
	}
	n.leases.release(req.Name, id, req.Seq)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(lockResponse{})
}
