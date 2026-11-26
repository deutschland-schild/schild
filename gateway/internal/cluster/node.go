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
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
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

	// lookMu guards the look whether the store changed since the roster was
	// built (reload): the connection kept for it and the counter it read.
	lookMu   sync.Mutex
	lookConn *sql.Conn
	lookVer  int64
	lookSeen bool
	// vec: the vector as of the counter vecVer (vectorNow), under lookMu.
	vec        map[string]uint64
	vecVer     int64
	vecKept    bool
	rmu        sync.RWMutex
	roster     *contract.Roster
	rosterMark string

	hmu      sync.Mutex
	handlers map[string][]func(*contract.Record)
	// refused: per class, which records are not stored (Refuse).
	refused map[string]func(*contract.Record) bool
	tells   map[string]func(from string, body []byte)
	asks    map[string]func(from string, body []byte) ([]byte, error)

	// news wakes the sync calls that wait.
	nmu  sync.Mutex
	news chan struct{}

	pmu   sync.Mutex
	peers map[string]*peer
	// statusMu: one writer of statusFile at a time.
	statusMu sync.Mutex
	// clocks: what the app noted of the members' clocks (NoteClock), under pmu.
	clocks map[string]statusClock

	cert tls.Certificate

	leases leases
	// takeMu: see take.
	takeMu sync.Mutex
	// wrapListener, in tests, stands between the mesh and its listener.
	wrapListener func(net.Listener) net.Listener
	// ln is the mesh listener Bind opened; Run serves it.
	lnMu sync.Mutex
	ln   net.Listener

	// Counters of schild cluster status.
	Applied, Rejected, Deferred, Unread atomic.Uint64
	// Compressed counts the answers this node sent compressed.
	Compressed atomic.Uint64

	addr    atomic.Pointer[string]
	seeking atomic.Bool
	// seekNext: when seek asks the address of a removed member again;
	// read and written by the one seek under way.
	seekNext map[string]time.Time
	// removed: a member answered that this node was removed.
	removed atomic.Bool
	synced  atomic.Bool
	// syncedByMember: the answer that made this node in step came from a
	// member that is in step itself (not from the start of a new group).
	syncedByMember atomic.Bool
	// lastInStep: when this node was last noted in step with its group,
	// unix ms (markInStepAt); 0: never.
	lastInStep atomic.Int64
	// stale: at its start the node had not been in step for longer than a
	// tombstone lives (EntryTombstoneKeep), see Open.
	stale atomic.Bool
	// storeGen moves when the store of the node changed (watchStore).
	storeGen atomic.Uint64
	// taking counts the takes under way (Taking).
	taking atomic.Int32
	// retake: a Resync is under way (resync.go).
	retake atomic.Int32
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
	n := &Node{state: st, opts: o, log: o.Log, handlers: map[string][]func(*contract.Record){}, news: make(chan struct{}), peers: map[string]*peer{},
		seekNext: map[string]time.Time{}}
	if n.cert, err = selfCert(st.key); err != nil {
		st.close()
		return nil, err
	}
	if err := n.reload(); err != nil {
		st.close()
		return nil, err
	}
	n.opts.Peers = canonicalPeers(o.Peers)
	// A node removed before its stop stays removed: it serves with the
	// state it has and shares nothing, from its start on.
	if v, err := st.meta("removed"); err == nil && len(v) > 0 {
		n.removed.Store(true)
	}
	n.rmu.RLock()
	if n.roster.Removed(n.id) {
		n.removed.Store(true)
	}
	n.rmu.RUnlock()
	if at, err := strconv.ParseInt(n.Mark(markInStepAt), 10, 64); err == nil && at > 0 {
		n.lastInStep.Store(at)
		if away := st.now().Sub(time.UnixMilli(at)); away > EntryTombstoneKeep {
			if err := st.forgetShared(); err != nil {
				st.close()
				return nil, err
			}
			n.stale.Store(true)
			n.log.Warn("cluster: this node was not in step with its group for longer than a removed entry is remembered; it takes the state of its group anew from a member that is in step and hands over none of the settings, access and login entries it held",
				"away", away.Round(time.Hour).String(), "keep", EntryTombstoneKeep.String())
		}
	}
	return n, nil
}

// EntryTombstoneKeep is how long the record of a removed entry of the
// classes settings, access and logins stays (its expires). A node that was
// not in step with its group for longer may hold an entry whose removal the
// group has forgotten; it takes the group's state anew (Open, Stale).
const EntryTombstoneKeep = 30 * 24 * time.Hour

// markInStepAt is the note of when the node was last in step with its group
// (unix ms). A mark, so a move to a new group carries it.
const markInStepAt = "in_step_at"

// inStepNoteEvery is how often a node that is in step notes it again.
const inStepNoteEvery = 10 * time.Minute

// sharedClasses are the classes whose removed entries end with their
// tombstone (EntryTombstoneKeep).
var sharedClasses = []string{contract.ClassSettings, contract.ClassAccess, contract.ClassLogins}

// forgetShared drops what a node that was away too long holds of the
// shared classes, what it noted of having brought its values in step (the
// marks "entries:" of the gateway) and the gateway's mark "in_step": the
// records come again from a member, from the first on (runPeer), and are
// the group's state.
func (s *state) forgetShared() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, c := range sharedClasses {
		if _, err := tx.Exec(`DELETE FROM records WHERE class = ?`, c); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM meta WHERE k LIKE 'mark:entries:%'`); err != nil {
		return err
	}
	// The gateway's note that the node was in step once goes too: until a
	// member that is in step brings it in step again, it is a fresh node
	// and does not serve alone with what it held (the gateway's inService).
	if _, err := tx.Exec(`DELETE FROM meta WHERE k = 'mark:in_step'`); err != nil {
		return err
	}
	return tx.Commit()
}

// Stale reports whether this node had not been in step with its group for
// longer than EntryTombstoneKeep when it started.
func (n *Node) Stale() bool { return n.stale.Load() }

// TakesGroupState reports whether this node has to take the state of its
// group as it is and hand over nothing it held from before: it was away
// too long (Stale), and it came in step from a member that is in step. A
// node that came in step with the start of a new group (every member as
// fresh or away as itself) has nobody to take from and hands over what it
// holds.
func (n *Node) TakesGroupState() bool {
	return n.stale.Load() && n.synced.Load() && n.syncedByMember.Load()
}

// canonicalPeers writes every address of cluster.peers the way a member
// record carries it (netip.AddrPort.String), so the two compare.
func canonicalPeers(peers []string) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		if ap, err := netip.ParseAddrPort(p); err == nil {
			p = ap.String()
		}
		out = append(out, p)
	}
	return out
}

// Bind opens the mesh listener, so a port that is taken stops the start of
// the gateway instead of the mesh later. Run binds it itself when Bind was
// not called.
func (n *Node) Bind() error {
	n.lnMu.Lock()
	defer n.lnMu.Unlock()
	if n.ln != nil {
		return nil
	}
	ln, err := net.Listen("tcp", n.opts.Listen)
	if err != nil {
		return fmt.Errorf("cluster.listen %s: %w", n.opts.Listen, err)
	}
	n.ln = ln
	return nil
}

// takeListener hands the listener Bind opened to Run, once.
func (n *Node) takeListener() net.Listener {
	n.lnMu.Lock()
	defer n.lnMu.Unlock()
	ln := n.ln
	n.ln = nil
	return ln
}

// Registered lists the handlers registered (On, OnTell, OnAsk) as
// "on:<class>", "tell:<kind>" and "ask:<kind>", sorted.
func (n *Node) Registered() []string {
	n.hmu.Lock()
	defer n.hmu.Unlock()
	var out []string
	for c := range n.handlers {
		out = append(out, "on:"+c)
	}
	for k := range n.tells {
		out = append(out, "tell:"+k)
	}
	for k := range n.asks {
		out = append(out, "ask:"+k)
	}
	sort.Strings(out)
	return out
}

// inStepAnswer is what this node answers a sync call with as in_step: it
// is in step now, or was within EntryTombstoneKeep (a node of a group that
// restarts as a whole holds the group's state before any of them synced).
func (n *Node) inStepAnswer() bool {
	if n.Synced() {
		return true
	}
	at := n.lastInStep.Load()
	return !n.stale.Load() && at > 0 && n.now().Sub(time.UnixMilli(at)) < EntryTombstoneKeep
}

// markSynced makes the node in step; byMember: the answer came from a
// member that is in step itself.
func (n *Node) markSynced(byMember bool) {
	if n.synced.Load() {
		return
	}
	if byMember {
		n.syncedByMember.Store(true)
	}
	if n.synced.CompareAndSwap(false, true) {
		n.noteInStep()
	}
}

// noteInStep keeps in the store when the node was in step (markInStepAt).
func (n *Node) noteInStep() {
	now := n.now().UnixMilli()
	if err := n.SetMark(markInStepAt, strconv.FormatInt(now, 10)); err != nil {
		n.log.Warn("cluster: the time this node was in step is not noted", "err", err)
		return
	}
	n.lastInStep.Store(now)
}

// newGroup reports whether every member this node knows has answered it in
// this run as a node that is not in step (and was not within
// EntryTombstoneKeep), and every address of cluster.peers is a member it
// knows: the group is new as a whole, nobody holds anything of it to wait
// for, and the nodes count each other's answers.
func (n *Node) newGroup() bool {
	n.rmu.RLock()
	members := n.roster.Members()
	n.rmu.RUnlock()
	addrs := map[string]bool{}
	var others []string
	for _, e := range members {
		if e.Removed || e.Member.Role != contract.RoleGateway {
			continue
		}
		addrs[e.Member.Address] = true
		if e.ID != n.id {
			others = append(others, e.ID)
		}
	}
	for _, p := range n.opts.Peers {
		if !addrs[p] {
			return false
		}
	}
	if len(others) == 0 {
		return false
	}
	n.pmu.Lock()
	defer n.pmu.Unlock()
	for _, id := range others {
		p := n.peers[id]
		if p == nil {
			return false
		}
		p.mu.Lock()
		fresh := p.fresh
		p.mu.Unlock()
		if !fresh {
			return false
		}
	}
	return true
}

// heldAnywhere reports whether the last answer of any member put records
// off (a clock ahead, an origin not known yet).
func (n *Node) heldAnywhere() bool {
	n.pmu.Lock()
	defer n.pmu.Unlock()
	for _, p := range n.peers {
		p.mu.Lock()
		held := p.held
		p.mu.Unlock()
		if held {
			return true
		}
	}
	return false
}

// Close ends the node's database, and the listener of a node that Bind
// opened and that never ran. Run has to have returned.
func (n *Node) Close() {
	if ln := n.takeListener(); ln != nil {
		_ = ln.Close()
	}
	n.state.close()
}

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
	// Copy on write: a take running at the same time holds the old map and
	// reads it without the lock.
	n.hmu.Lock()
	hs := make(map[string][]func(*contract.Record), len(n.handlers)+1)
	for c, fs := range n.handlers {
		hs[c] = fs
	}
	hs[class] = append(append([]func(*contract.Record){}, n.handlers[class]...), f)
	n.handlers = hs
	n.hmu.Unlock()
}

// Refuse registers f for the records of a class: a record that passed every
// check and that f reports is not stored and not applied. The vector moves
// past it as past a record that lost against the one held, so no member is
// asked for it again; a record of another class (a lift, an erasure) is why
// it must not come back, and the node holds that one and hands it on. f runs
// with the write lock of the store held: it may read the store and must not
// write to it or wait for a lock that a writer holds.
func (n *Node) Refuse(class string, f func(*contract.Record) bool) {
	n.hmu.Lock()
	rs := make(map[string]func(*contract.Record) bool, len(n.refused)+1)
	for c, r := range n.refused {
		rs[c] = r
	}
	rs[class] = f
	n.refused = rs
	n.hmu.Unlock()
}

// Drop removes the record that is the state of one thing from the store,
// before its time: the block a lift ended (contracts/cluster.md, lifts).
// The vector stays, so the record is not asked for again; that it is not
// stored when a member hands it over later is the word of Refuse.
func (n *Node) Drop(class, id string) error {
	n.wmu.Lock()
	defer n.wmu.Unlock()
	res, err := n.db.Exec(`DELETE FROM records WHERE class = ? AND id = ? AND state = ?`, class, id, stateWinner)
	if err != nil {
		return err
	}
	if c, _ := res.RowsAffected(); c > 0 {
		n.storeGen.Add(1)
	}
	return nil
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

// Alone reports whether this node is the only gateway of its group and
// names no peer to find: there is nobody it could be in step with.
func (n *Node) Alone() bool {
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
	for _, p := range n.opts.Peers {
		if p != own {
			return false
		}
	}
	return true
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
	n.storeGen.Add(1) // what woke the calls changed the store
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
//
// The look is the change counter of the file (PRAGMA data_version on a
// connection kept for it): it moves with every commit of any other
// connection, of this process or of a command on the host, at the moment of
// the commit. While it stands, nothing was written and the roster holds;
// the member records are read only when it moved. A node used to query
// them on every incoming call.
func (n *Node) reload() error {
	n.lookMu.Lock()
	defer n.lookMu.Unlock()
	ver, looked := n.lookVersion()
	if looked && n.lookSeen && ver == n.lookVer {
		n.rmu.RLock()
		holds := n.roster != nil && n.rosterMark != ""
		n.rmu.RUnlock()
		if holds {
			return nil
		}
	}
	var mark string
	if err := n.db.QueryRow(`SELECT count(*) || ':' || coalesce(max(hlc), 0) || ':' || coalesce(sum(deleted), 0) FROM records WHERE class = ? AND state = ?`,
		contract.ClassMembers, stateWinner).Scan(&mark); err != nil {
		return err
	}
	// The counter as read before the records: a commit in between moves it
	// again and the next look reads the records once more.
	n.lookVer, n.lookSeen = ver, looked
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

// vectorNow is the vector of this node. It is read from the store when the
// store changed since the last reading and kept otherwise: every sync call
// a member makes, and every answer the node takes, needs it, and on an idle
// node that was a query each for a vector that had not moved.
func (n *Node) vectorNow() (map[string]uint64, error) {
	n.lookMu.Lock()
	defer n.lookMu.Unlock()
	ver, looked := n.lookVersion()
	if !looked || !n.vecKept || n.vecVer != ver {
		v, err := n.state.vector()
		if err != nil {
			return nil, err
		}
		// Kept under the counter read before the vector: a commit in
		// between moves it and the next call reads again.
		n.vec, n.vecVer, n.vecKept = v, ver, looked
	}
	out := make(map[string]uint64, len(n.vec))
	for o, seq := range n.vec {
		out[o] = seq
	}
	return out, nil
}

// lookVersion reads the change counter of the store on the connection kept
// for it. ok false: it could not be read, and the caller reads the records.
// Called with lookMu held.
func (n *Node) lookVersion() (ver int64, ok bool) {
	if n.lookConn == nil {
		c, err := n.db.Conn(context.Background())
		if err != nil {
			return 0, false
		}
		n.lookConn, n.lookSeen = c, false
	}
	if err := n.lookConn.QueryRowContext(context.Background(), "PRAGMA data_version").Scan(&ver); err != nil {
		_ = n.lookConn.Close()
		n.lookConn = nil
		return 0, false
	}
	return ver, true
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

// take is takeRecords for the answer of a member.
func (n *Node) take(raws []json.RawMessage, covered map[string]uint64) (applied int, err error) {
	applied, _, err = n.takeRecords(raws, covered, true)
	return applied, err
}

// takeRecords checks and applies records a peer sent, and then moves the
// vector to what the answer covered. A record that may pass later (the
// clock, an origin not known yet) holds the vector of its origin back, so it
// is asked for again, and held says so; a record that can never pass is
// counted and skipped. member: the records come from a member's answer;
// otherwise (a hello and its answer, whose sender may be no member) a record
// of a version this node cannot read is not kept, so a stranger stores
// nothing it cannot check.
func (n *Node) takeRecords(raws []json.RawMessage, covered map[string]uint64, member bool) (applied int, held bool, err error) {
	// One take at a time, to its end: a node calls several members at once
	// and each brings the same records. Without this the second call finds
	// nothing new and reports the node in step while the first still
	// applies what it took (an erasure takes a moment).
	n.takeMu.Lock()
	defer n.takeMu.Unlock()
	// Counted until the handlers below have run (deferred later, so they
	// run before this).
	n.taking.Add(1)
	defer n.taking.Add(-1)
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
	have, err := n.vectorNow()
	if err != nil {
		return 0, false, err
	}
	again := n.retake.Load() > 0
	// An answer that brings nothing and covers nothing new, which is what
	// a member in step answers every few seconds, needs no look at the
	// roster and no write.
	if len(items) == 0 && !again {
		news := false
		for origin, seq := range covered {
			news = news || seq > have[origin]
		}
		if !news {
			return 0, false, nil
		}
	}
	if err := n.reload(); err != nil {
		return 0, false, err
	}
	// The handlers run after the write lock is given back: a handler may
	// hold a lock of its own that a Publish of the same owner waits with.
	var won []*contract.Record
	n.hmu.Lock()
	refused := n.refused
	n.hmu.Unlock()
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
	heldFrom := map[string]uint64{} // origin -> first sequence number to ask for again
	hold := func(r *contract.Record) {
		if cur, ok := heldFrom[r.Origin]; !ok || r.Seq < cur {
			heldFrom[r.Origin] = r.Seq
		}
	}
	now := n.now()
	for i := range items {
		rec, raw := &items[i].rec, items[i].raw
		// Resync looks at records the vector says this node has: the store
		// then decides, and leaves alone what it holds already.
		if rec.Seq <= have[rec.Origin] && !again {
			continue
		}
		n.rmu.RLock()
		cerr := n.roster.Check(rec, now)
		n.rmu.RUnlock()
		switch {
		case cerr == nil:
		case errors.Is(cerr, contract.ErrVersion), errors.Is(cerr, contract.ErrClass):
			// A version or a class of a later build: kept as it came and
			// handed on, read when this node runs that build (readUnread).
			if rec.Group == n.group && member {
				tx, err := n.db.Begin()
				if err != nil {
					return applied, false, err
				}
				if err := putUnread(tx, rec, raw); err != nil {
					tx.Rollback()
					return applied, false, err
				}
				if err := tx.Commit(); err != nil {
					return applied, false, err
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
		if f := refused[rec.Class]; f != nil && f(rec) {
			continue
		}
		tx, err := n.db.Begin()
		if err != nil {
			return applied, false, err
		}
		ok, err := put(tx, rec, raw)
		if err != nil {
			tx.Rollback()
			return applied, false, err
		}
		if err := tx.Commit(); err != nil {
			return applied, false, err
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
	held = len(heldFrom) > 0
	tx, err := n.db.Begin()
	if err != nil {
		return applied, held, err
	}
	for origin, seq := range covered {
		if first, ok := heldFrom[origin]; ok && first <= seq {
			seq = first - 1
		}
		if seq > have[origin] {
			if err := raiseVector(tx, origin, seq); err != nil {
				tx.Rollback()
				return applied, held, err
			}
		}
	}
	return applied, held, tx.Commit()
}

// readUnread looks again at the records this node keeps unread: a build
// before this one could not read their version or class. What this build
// reads is checked and applied like a record a member sent; what it still
// cannot read stays as it is. Called at the start, after the handlers of
// the classes are set.
func (n *Node) readUnread() error {
	rows, err := n.db.Query(`SELECT origin, seq, raw FROM records WHERE state = ? ORDER BY hlc, origin, seq`, stateUnread)
	if err != nil {
		return err
	}
	type key struct {
		origin string
		seq    uint64
	}
	var raws []json.RawMessage
	var keys []key
	now := n.now()
	for rows.Next() {
		var k key
		var raw []byte
		if err := rows.Scan(&k.origin, &k.seq, &raw); err != nil {
			rows.Close()
			return err
		}
		var rec contract.Record
		if json.Unmarshal(raw, &rec) != nil {
			continue
		}
		n.rmu.RLock()
		cerr := n.roster.Check(&rec, now)
		n.rmu.RUnlock()
		if errors.Is(cerr, contract.ErrVersion) || errors.Is(cerr, contract.ErrClass) {
			continue
		}
		// What may pass later (a clock ahead, an origin not known yet) stays
		// unread for the next start.
		if errors.Is(cerr, contract.ErrClock) || errors.Is(cerr, contract.ErrOrigin) {
			continue
		}
		raws, keys = append(raws, raw), append(keys, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(raws) == 0 {
		return err
	}
	// As a resync: the vector says this node has these records.
	n.retake.Add(1)
	applied, _, err := n.takeRecords(raws, nil, true)
	n.retake.Add(-1)
	if err != nil {
		return err
	}
	// A record that is now the state replaced its own row. What lost against
	// a later record, or is refused for good, is of no use unread.
	for _, k := range keys {
		if _, err := n.db.Exec(`DELETE FROM records WHERE origin = ? AND seq = ? AND state = ?`, k.origin, int64(k.seq), stateUnread); err != nil {
			return err
		}
	}
	n.log.Info("cluster: records of a class or version an earlier build kept unread were read", "records", len(raws), "applied", applied)
	return nil
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
// (schild cluster remove) writes into the same file. One look for
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
			n.storeGen.Add(1)
			n.wake()
			continue
		}
		var v int64
		if err := conn.QueryRowContext(ctx, "PRAGMA data_version").Scan(&v); err != nil {
			n.storeGen.Add(1)
			n.wake()
			continue
		}
		if v != last {
			n.storeGen.Add(1)
			if last != -1 {
				n.wake()
			}
			last = v
		}
	}
}

// StoreGen is a number that moves whenever something was written into the
// node's store, by the node or by a command on the host, seen within
// watchEvery. Equal numbers at two moments mean the records the node holds
// are the same; a caller that computed something from them may keep it.
func (n *Node) StoreGen() uint64 { return n.storeGen.Load() }

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
	if err := n.readUnread(); err != nil {
		n.log.Warn("cluster: the records kept unread were not looked at again", "err", err)
	}
	n.seek(ctx)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var sweep int
	var noted time.Time
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
			if err := n.reload(); err != nil {
				n.log.Warn("cluster: member list not read", "err", err)
			}
			n.seek(ctx)
			n.syncPeers(ctx)
			// Every fifth second: `schild cluster status` takes a node for
			// running while its view is younger than ten.
			if sweep++; sweep%5 == 0 {
				n.saveStatus()
			}
			if sweep%60 == 0 {
				if _, err := n.expire(n.now()); err != nil {
					n.log.Warn("cluster: expired records not dropped", "err", err)
				}
			}
			// In step and in touch with its group (or its only gateway):
			// noted now and then, so a node knows at its next start how
			// long it was away (Open).
			if n.now().Sub(noted) >= inStepNoteEvery && !n.Removed() && n.Synced() && (n.Alone() || len(n.Reachable()) > 0) {
				noted = n.now()
				n.noteInStep()
			}
		}
	}
}
