package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// Options of a running node.
type Options struct {
	// Dir is <data>/cluster.
	Dir string
	// Listen is host:port of the mesh listener.
	Listen string
	Log    *slog.Logger
	Now    func() time.Time
	// Hold is how long a sync call waits for news (default 4 s).
	Hold time.Duration
	// Peers are cluster.peers: where a node set up by configuration finds
	// the group.
	Peers []string
}

// Node is this gateway in its group.
type Node struct {
	*state
	opts Options
	log  *slog.Logger

	rmu        sync.RWMutex
	roster     *contract.Roster
	rosterMark string

	hmu      sync.Mutex
	handlers map[string][]func(*contract.Record)
	tells    map[string]func(from string, body []byte)
	asks     map[string]func(from string, body []byte) ([]byte, error)
	edgeAsks map[string]func(from string, body []byte) ([]byte, error)

	// news wakes the sync calls that wait.
	nmu  sync.Mutex
	news chan struct{}

	pmu   sync.Mutex
	peers map[string]*peer
	// edgeSeen: when each edge asked this node last.
	edgeSeen map[string]time.Time

	cert tls.Certificate

	leases leases
	// takeMu: see take.
	takeMu sync.Mutex
	// wrapListener, in tests, stands between the mesh and its listener.
	wrapListener func(net.Listener) net.Listener

	// Counters of schild cluster status.
	Applied, Rejected, Deferred, Unread atomic.Uint64
	// Compressed counts the answers this node sent compressed.
	Compressed atomic.Uint64

	addr    atomic.Pointer[string]
	seeking atomic.Bool
	// removed: a member answered that this node was removed.
	removed atomic.Bool
	synced  atomic.Bool
	// heldBack: the last take put records off (see take).
	heldBack atomic.Bool
	// paused: schild cluster pause (setup.go).
	paused atomic.Bool
}

// Open loads the node of a data directory. ErrNoGroup: it belongs to none.
func Open(o Options) (*Node, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Hold <= 0 {
		o.Hold = 4 * time.Second
	}
	st, err := openState(o.Dir, false, o.Now)
	if err != nil {
		return nil, err
	}
	if st.group == "" {
		st.close()
		return nil, ErrNoGroup
	}
	n := &Node{state: st, opts: o, log: o.Log, handlers: map[string][]func(*contract.Record){}, news: make(chan struct{}), peers: map[string]*peer{}}
	if n.cert, err = selfCert(st.key); err != nil {
		st.close()
		return nil, err
	}
	if err := n.reload(); err != nil {
		st.close()
		return nil, err
	}
	return n, nil
}

// Close ends the node's database. Run has to have returned.
func (n *Node) Close() { n.state.close() }

// ID, Group and Name of this node.
func (n *Node) ID() string    { return n.id }
func (n *Node) Group() string { return n.group }
func (n *Node) Name() string {
	n.rmu.RLock()
	defer n.rmu.RUnlock()
	if m, ok := n.roster.Member(n.id); ok {
		return m.Name
	}
	return n.id
}

// Paused reports whether the node was paused on the host: it takes and
// hands over nothing.
func (n *Node) Paused() bool { return n.paused.Load() }

// Removed reports whether a member told this node that it was removed from
// the group. It then serves with the state it has and shares nothing.
func (n *Node) Removed() bool { return n.removed.Load() }

// Addr is the address the mesh listener bound; empty before Run.
func (n *Node) Addr() string {
	if p := n.addr.Load(); p != nil {
		return *p
	}
	return ""
}

// On registers f for records of a class that became the state here and
// were written by another node. It runs in the goroutine of the sync, one
// record at a time.
func (n *Node) On(class string, f func(*contract.Record)) {
	n.hmu.Lock()
	n.handlers[class] = append(n.handlers[class], f)
	n.hmu.Unlock()
}

// Publish writes a record of this node and hands it to the peers.
func (n *Node) Publish(class, id string, data any, deleted bool, expires time.Time) (*contract.Record, error) {
	rec, err := n.publish(class, id, data, deleted, expires)
	if err != nil {
		return nil, err
	}
	if class == contract.ClassMembers {
		_ = n.reload()
	}
	n.wake()
	return rec, nil
}

// Get returns the record that is the state of one thing; nil: none.
func (n *Node) Get(class, id string) (*contract.Record, error) {
	var raw []byte
	err := n.db.QueryRow(`SELECT raw FROM records WHERE class = ? AND id = ? AND state = ?`, class, id, stateWinner).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r contract.Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Mark and SetMark keep a note per thing next to the records: what of the
// local value this node last brought in step with the group.
func (n *Node) Mark(key string) string {
	v, _ := n.meta("mark:" + key)
	return string(v)
}

func (n *Node) SetMark(key, value string) error {
	n.wmu.Lock()
	defer n.wmu.Unlock()
	tx, err := n.db.Begin()
	if err != nil {
		return err
	}
	if err := setMeta(tx, "mark:"+key, []byte(value)); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Keep stores what a value of the group replaced on this node, so that
// nothing a node held before it joined is gone without a copy.
func (n *Node) Keep(key string, value []byte) error {
	n.wmu.Lock()
	defer n.wmu.Unlock()
	_, err := n.db.Exec(`INSERT INTO replaced(k, at_ms, v) VALUES(?, ?, ?)`, key, n.now().UnixMilli(), value)
	return err
}

// Synced reports whether this node took everything a member had to give
// since its start, or is the only gateway of its group. Before that it
// does not know what the group holds.
func (n *Node) Synced() bool {
	if n.synced.Load() {
		return true
	}
	n.rmu.RLock()
	defer n.rmu.RUnlock()
	own := ""
	for _, e := range n.roster.Members() {
		if !e.Removed && e.ID != n.id && e.Member.Role == contract.RoleGateway {
			return false
		}
		if e.ID == n.id {
			own = e.Member.Address
		}
	}
	// A node set up by configuration that knows no member yet is not alone:
	// its peers are named, it has only not reached one. Until it does, it
	// does not know what the group holds.
	for _, p := range n.opts.Peers {
		if p != own {
			return false
		}
	}
	return true
}

// State returns the records that are the state of a class.
func (n *Node) State(class string) ([]*contract.Record, error) {
	recs, _, err := n.winners(class)
	return recs, err
}

func (n *Node) wake() {
	n.nmu.Lock()
	close(n.news)
	n.news = make(chan struct{})
	n.nmu.Unlock()
}

func (n *Node) waitNews() <-chan struct{} {
	n.nmu.Lock()
	defer n.nmu.Unlock()
	return n.news
}

// reload builds the roster from the member records held, when they changed.
// A command on the host writes them into the same file (schild cluster
// remove), so the node looks before every decision that rests on the
// roster: a removed member must not pass for the second until a timer.
func (n *Node) reload() error {
	var mark string
	if err := n.db.QueryRow(`SELECT count(*) || ':' || coalesce(max(hlc), 0) || ':' || coalesce(sum(deleted), 0) FROM records WHERE class = ? AND state = ?`,
		contract.ClassMembers, stateWinner).Scan(&mark); err != nil {
		return err
	}
	n.rmu.RLock()
	same := n.roster != nil && mark == n.rosterMark
	n.rmu.RUnlock()
	if same {
		return nil
	}
	ro, err := n.state.roster()
	if err != nil {
		return err
	}
	n.rmu.Lock()
	n.roster, n.rosterMark = ro, mark
	n.rmu.Unlock()
	return nil
}

// IsMember reports whether id is an active member as this node sees it.
func (n *Node) IsMember(id string) bool {
	n.rmu.RLock()
	defer n.rmu.RUnlock()
	_, ok := n.roster.Member(id)
	return ok
}

func (n *Node) activeKey(pub ed25519.PublicKey, roles ...string) (string, bool) {
	if err := n.reload(); err != nil {
		return "", false
	}
	n.rmu.RLock()
	defer n.rmu.RUnlock()
	return n.roster.ActiveKey(pub, roles...)
}

// refuse answers a caller that is no member: 410 when it was one and was
// removed, so that node can say so in its log, else 403.
func (n *Node) refuse(w http.ResponseWriter, pub ed25519.PublicKey) {
	n.rmu.RLock()
	removed := n.roster.Removed(contract.NodeID(pub))
	n.rmu.RUnlock()
	if removed {
		w.Header().Set(headerGroup, n.group)
		http.Error(w, "removed from the group", http.StatusGone)
		return
	}
	http.Error(w, "no member", http.StatusForbidden)
}

// take checks and applies records a peer sent, and then moves the vector to
// what the answer covered. A record that may pass later (the clock, an
// origin not known yet) holds the vector of its origin back, so it is asked
// for again; a record that can never pass is counted and skipped.
func (n *Node) take(raws []json.RawMessage, covered map[string]uint64) (applied int, err error) {
	// A call that was under way when the node was paused brings its answer
	// to a node that takes nothing: it is asked for again after resume.
	if n.paused.Load() {
		return 0, nil
	}
	// One take at a time, to its end: a node calls several members at once
	// and each brings the same records. Without this the second call finds
	// nothing new and reports the node in step while the first still
	// applies what it took (an erasure takes a moment).
	n.takeMu.Lock()
	defer n.takeMu.Unlock()
	type item struct {
		rec contract.Record
		raw []byte
	}
	items := make([]item, 0, len(raws))
	for _, raw := range raws {
		var it item
		if len(raw) > contract.MaxRecord || json.Unmarshal(raw, &it.rec) != nil || it.rec.Origin == "" || it.rec.Seq == 0 {
			n.Rejected.Add(1)
			continue
		}
		it.raw = raw
		items = append(items, it)
	}
	// Members first: a record may be signed by a member this answer brings.
	sort.SliceStable(items, func(i, j int) bool {
		mi, mj := items[i].rec.Class == contract.ClassMembers, items[j].rec.Class == contract.ClassMembers
		if mi != mj {
			return mi
		}
		return items[i].rec.HLC < items[j].rec.HLC
	})
	have, err := n.vector()
	if err != nil {
		return 0, err
	}
	if err := n.reload(); err != nil {
		return 0, err
	}
	// The handlers run after the write lock is given back: a handler may
	// hold a lock of its own that a Publish of the same owner waits with.
	var won []*contract.Record
	defer func() {
		n.hmu.Lock()
		hs := n.handlers
		n.hmu.Unlock()
		for _, rec := range won {
			for _, f := range hs[rec.Class] {
				f(rec)
			}
		}
		if applied > 0 {
			n.wake() // the peers of this node may lack what it just took
		}
	}()
	n.wmu.Lock()
	defer n.wmu.Unlock()
	held := map[string]uint64{} // origin -> first sequence number to ask for again
	hold := func(r *contract.Record) {
		if cur, ok := held[r.Origin]; !ok || r.Seq < cur {
			held[r.Origin] = r.Seq
		}
	}
	now := n.now()
	for i := range items {
		rec, raw := &items[i].rec, items[i].raw
		if rec.Seq <= have[rec.Origin] {
			continue
		}
		n.rmu.RLock()
		cerr := n.roster.Check(rec, now)
		n.rmu.RUnlock()
		switch {
		case cerr == nil:
		case errors.Is(cerr, contract.ErrVersion):
			if rec.Group == n.group {
				tx, err := n.db.Begin()
				if err != nil {
					return applied, err
				}
				if err := putUnread(tx, rec, raw); err != nil {
					tx.Rollback()
					return applied, err
				}
				if err := tx.Commit(); err != nil {
					return applied, err
				}
				n.Unread.Add(1)
			}
			continue
		case errors.Is(cerr, contract.ErrClock), errors.Is(cerr, contract.ErrOrigin):
			if errors.Is(cerr, contract.ErrClock) {
				// Said in the log, not only counted: a clock that is off is the
				// operator's to set right, and nothing else names the node.
				ratelog.Warn(n.log, "cluster: a record is put off, its time is ahead of this node's clock by more than a minute; set the clocks of the nodes right (NTP)",
					"from", n.PeerName(rec.Origin), "ahead", contract.HLCTime(rec.HLC).Sub(now).Round(time.Second).String())
			}
			n.Deferred.Add(1)
			hold(rec)
			continue
		default:
			n.Rejected.Add(1)
			n.log.Warn("cluster: record refused", "origin", rec.Origin, "seq", rec.Seq, "class", rec.Class, "reason", cerr)
			continue
		}
		tx, err := n.db.Begin()
		if err != nil {
			return applied, err
		}
		ok, err := put(tx, rec, raw)
		if err != nil {
			tx.Rollback()
			return applied, err
		}
		if err := tx.Commit(); err != nil {
			return applied, err
		}
		n.clock.Observe(rec.HLC)
		if !ok {
			continue
		}
		applied++
		n.Applied.Add(1)
		if rec.Class == contract.ClassMembers {
			n.rmu.Lock()
			n.roster.Set(rec)
			n.rosterMark = ""
			n.rmu.Unlock()
		}
		if rec.Origin != n.id {
			won = append(won, rec)
		}
	}
	// Records put off (a clock ahead, an origin not known yet) are asked for
	// again: until they are taken this node is not in step with the member.
	n.heldBack.Store(len(held) > 0)
	tx, err := n.db.Begin()
	if err != nil {
		return applied, err
	}
	for origin, seq := range covered {
		if first, ok := held[origin]; ok && first <= seq {
			seq = first - 1
		}
		if seq > have[origin] {
			if err := raiseVector(tx, origin, seq); err != nil {
				tx.Rollback()
				return applied, err
			}
		}
	}
	return applied, tx.Commit()
}

// selfCert is the certificate the node shows in the mesh: self-signed with
// its key. Nobody reads its names or dates; a member is known by the key.
func selfCert(key ed25519.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "schild-cluster"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// peerKey is the Ed25519 key of the certificate a TLS peer showed.
func peerKey(cs *tls.ConnectionState) (ed25519.PublicKey, bool) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil, false
	}
	k, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	return k, ok
}

// watchEvery is how often a node looks whether a command on the host wrote
// into its store.
const watchEvery = 500 * time.Millisecond

// watchStore wakes the sync calls that wait for news when something wrote
// into the store that did not wake them itself: a command on the host
// (schild cluster remove, invite) writes into the same file. One look for
// the whole node, where every waiting call used to look for itself: with
// fifteen members waiting that was thirty queries a second on an idle node.
//
// SQLite counts the commits of other connections per connection (PRAGMA
// data_version), so the look keeps one connection of its own. Should that
// fail, the node falls back to waking the calls on every look, which is
// what they did before.
func (n *Node) watchStore(ctx context.Context) {
	conn, err := n.db.Conn(ctx)
	if err == nil {
		defer conn.Close()
	}
	t := time.NewTicker(watchEvery)
	defer t.Stop()
	var last int64 = -1
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if conn == nil {
			n.wake()
			continue
		}
		var v int64
		if err := conn.QueryRowContext(ctx, "PRAGMA data_version").Scan(&v); err != nil {
			n.wake()
			continue
		}
		if v != last {
			if last != -1 {
				n.wake()
			}
			last = v
		}
	}
}

// Run serves the mesh and keeps in step with every member until ctx ends.
func (n *Node) Run(ctx context.Context) error {
	srv, ln, err := n.listen()
	if err != nil {
		return err
	}
	a := ln.Addr().String()
	n.addr.Store(&a)
	n.log.Info("cluster: mesh listening", "listen", a, "group", n.group, "node", n.id)
	done := make(chan error, 1)
	go func() { done <- srv.ServeTLS(ln, "", "") }()
	go n.watchStore(ctx)
	n.seek(ctx)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var sweep int
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = srv.Shutdown(sctx)
			cancel()
			_ = srv.Close()
			n.stopPeers()
			return nil
		case err := <-done:
			n.stopPeers()
			return err
		case <-tick.C:
			if v, err := n.meta(metaPaused); err == nil && len(v) > 0 {
				if n.paused.CompareAndSwap(false, true) {
					n.log.Warn("cluster: paused. This node serves with the state it has; it takes and hands over nothing until schild cluster resume")
				}
			} else if n.paused.CompareAndSwap(true, false) {
				n.log.Info("cluster: resumed, taking what the group has")
			}
			if err := n.reload(); err != nil {
				n.log.Warn("cluster: member list not read", "err", err)
			}
			n.seek(ctx)
			n.syncPeers(ctx)
			if sweep++; sweep%2 == 0 {
				n.saveStatus()
			}
			if sweep%60 == 0 {
				if _, err := n.expire(n.now()); err != nil {
					n.log.Warn("cluster: expired records not dropped", "err", err)
				}
			}
		}
	}
}
