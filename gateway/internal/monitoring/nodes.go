package monitoring

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// The stored history across the nodes of a group (MVP-27, D105, contracts/
// cluster.md section 9a). Every gateway keeps the buckets of every other
// gateway next to its own: one ring store per member under
// storage.path/metrics-nodes, with the rings and so the bounds of its own
// metrics.db. A query reads its own store and the stores of the members
// and adds what it finds per bucket (mergeNodes). A single gateway has no
// such store and reads as it always did.

// NodesDir is the directory of the members' ring stores below storage.path.
const NodesDir = "metrics-nodes"

// MaxNodes bounds the ring stores of other members a gateway keeps.
const MaxNodes = 32

var nodeIDPattern = regexp.MustCompile(`^n-[0-9a-f]{32}$`)

// nodeStore is the ring store of one other member.
type nodeStore struct {
	id    string
	name  atomic.Pointer[string]
	store *ringStore
	// newest is the start (unix) of the newest bucket held per ring, 0: none.
	newest [3]atomic.Int64
}

type nodeSet struct {
	mu    sync.RWMutex
	self  string
	name  string
	nodes map[string]*nodeStore
}

// SetSelf names this gateway among the nodes of its group. Until it is
// called the monitor is the one of a single gateway.
func (m *Monitor) SetSelf(id, name string) {
	m.nodes.mu.Lock()
	m.nodes.self, m.nodes.name = id, name
	m.nodes.mu.Unlock()
}

func (m *Monitor) nodesPath() string { return filepath.Join(m.cfg.StoragePath, NodesDir) }

// node returns the ring store of a member, opened on first use.
func (m *Monitor) node(id, name string) (*nodeStore, error) {
	if !nodeIDPattern.MatchString(id) {
		return nil, errors.New("monitoring: not a node id")
	}
	m.nodes.mu.Lock()
	defer m.nodes.mu.Unlock()
	if id == m.nodes.self {
		return nil, errors.New("monitoring: own node")
	}
	if n := m.nodes.nodes[id]; n != nil {
		if name != "" && name != *n.name.Load() {
			n.name.Store(&name)
		}
		return n, nil
	}
	if len(m.nodes.nodes) >= MaxNodes {
		return nil, errors.New("monitoring: too many nodes")
	}
	if err := os.MkdirAll(m.nodesPath(), 0o700); err != nil {
		return nil, err
	}
	st, err := openRingStore(filepath.Join(m.nodesPath(), id+".db"), m.rings)
	if err != nil {
		return nil, err
	}
	n := &nodeStore{id: id, store: st}
	n.name.Store(&name)
	for i, r := range m.rings {
		var t sql.NullInt64
		_ = st.db.QueryRow(`SELECT MAX(t) FROM ` + tableOf(r.Resolution)).Scan(&t)
		n.newest[i].Store(t.Int64)
	}
	if m.nodes.nodes == nil {
		m.nodes.nodes = map[string]*nodeStore{}
	}
	m.nodes.nodes[id] = n
	return n, nil
}

// OpenNodes opens the ring stores of the members given (id to name) and
// removes the stores of everyone else: a removed member's history goes
// with its membership. Files that are no store of a member are left alone.
func (m *Monitor) OpenNodes(members map[string]string) {
	m.nodes.mu.RLock()
	self := m.nodes.self
	m.nodes.mu.RUnlock()
	for id, name := range members {
		if id == self {
			continue
		}
		if _, err := m.node(id, name); err != nil {
			ratelog.Warn(m.log, "monitoring: the history of another node cannot be opened", "node", id, "err", err)
		}
	}
	m.nodes.mu.Lock()
	var gone []*nodeStore
	for id, n := range m.nodes.nodes {
		if _, ok := members[id]; !ok {
			gone = append(gone, n)
			delete(m.nodes.nodes, id)
		}
	}
	m.nodes.mu.Unlock()
	for _, n := range gone {
		_ = n.store.close()
	}
	// Stores on disk of nodes that are no member (they left while this
	// gateway was down).
	entries, _ := os.ReadDir(m.nodesPath())
	for _, e := range entries {
		name := e.Name()
		id := ""
		for _, suffix := range []string{".db-wal", ".db-shm", ".db"} {
			if strings.HasSuffix(name, suffix) {
				id = strings.TrimSuffix(name, suffix)
				break
			}
		}
		if !nodeIDPattern.MatchString(id) {
			continue
		}
		if _, ok := members[id]; !ok {
			_ = os.Remove(filepath.Join(m.nodesPath(), name))
		}
	}
}

func (m *Monitor) closeNodes() {
	m.nodes.mu.Lock()
	defer m.nodes.mu.Unlock()
	for id, n := range m.nodes.nodes {
		_ = n.store.close()
		delete(m.nodes.nodes, id)
	}
}

// maxNodeBucketAhead is how far ahead of this gateway's clock a bucket of
// another node may start.
const maxNodeBucketAhead = 2 * time.Minute

// PutNodeBuckets stores buckets another member handed over (Ask `metrics`)
// and returns the start of the newest one taken. A bucket is input from
// outside: one whose time is no bucket start of the ring, lies ahead of
// this gateway's clock or before what the ring keeps is left out.
func (m *Monitor) PutNodeBuckets(id, name string, res cm.Resolution, items []cm.MetricBucket, now time.Time) (newest time.Time, err error) {
	ri := -1
	for i, r := range m.rings {
		if r.Resolution == res {
			ri = i
		}
	}
	if ri < 0 {
		return time.Time{}, &ErrInvalid{"resolution", "10s, 1m or 10m"}
	}
	n, err := m.node(id, name)
	if err != nil {
		return time.Time{}, err
	}
	ring := m.rings[ri]
	oldest := ring.Oldest(now)
	for i := range items {
		b := &items[i]
		t, perr := time.Parse(time.RFC3339, b.T)
		if perr != nil || !ring.Start(t).Equal(t) || t.After(now.Add(maxNodeBucketAhead)) || t.Before(oldest) {
			continue
		}
		if err := n.store.put(ring, t, b); err != nil {
			return newest, err
		}
		if t.After(newest) {
			newest = t
		}
	}
	if u := newest.Unix(); !newest.IsZero() && u > n.newest[ri].Load() {
		n.newest[ri].Store(u)
	}
	return newest, nil
}

// NodeView is the stored history as a choice of nodes shows it: the whole
// group, this gateway alone, or one other member.
type NodeView struct {
	*Monitor
	// only is the id of the one node read ("" every node).
	only string
}

// ErrNoNode is returned for a node that is no member this gateway holds
// history of.
var ErrNoNode = &ErrInvalid{"node", "no such node of the group"}

// Nodes returns the history of every node of the group ("" or "all") or of
// one node by its id. A single gateway knows no node id but "" and "all".
func (m *Monitor) Nodes(id string) (NodeView, error) {
	if id == "" || id == "all" {
		return NodeView{Monitor: m}, nil
	}
	m.nodes.mu.RLock()
	defer m.nodes.mu.RUnlock()
	if _, ok := m.nodes.nodes[id]; !ok && id != m.nodes.self {
		return NodeView{}, ErrNoNode
	}
	return NodeView{Monitor: m, only: id}, nil
}

// all is the view of the whole group; on a single gateway the gateway.
func (m *Monitor) all() NodeView { return NodeView{Monitor: m} }

// chosen returns whether the own store is read and the other stores read.
func (v NodeView) chosen() (own bool, others []*nodeStore) {
	s := &v.Monitor.nodes
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v.only != "" {
		if v.only == s.self {
			return true, nil
		}
		if n := s.nodes[v.only]; n != nil {
			return false, []*nodeStore{n}
		}
		return false, nil
	}
	for _, n := range s.nodes {
		others = append(others, n)
	}
	sort.Slice(others, func(i, j int) bool { return others[i].id < others[j].id })
	return true, others
}

// Merged reports whether the view adds up more than one node.
func (v NodeView) Merged() bool {
	_, others := v.chosen()
	return v.only == "" && len(others) > 0
}

// Foreign reports whether the view shows one other member alone: nothing
// this gateway holds in memory belongs to it.
func (v NodeView) Foreign() bool {
	own, _ := v.chosen()
	return !own
}

// One reports whether the view shows a single node of a group, not the
// group: the request ring, which holds every node's requests without
// their node, cannot answer it.
func (v NodeView) One() bool { return v.only != "" }

// readNodes is ringStore.read over the nodes of the view: fn gets one
// bucket per start, oldest first, the buckets of the nodes added up
// (mergeNodes). A start a member has not handed over yet, while it has
// nothing newer either, makes the bucket partial: its part is still on the
// way.
func (v NodeView) readNodes(r cm.Ring, from, to time.Time, parts readParts, fn func(t time.Time, b *cm.MetricBucket)) error {
	own, others := v.chosen()
	if len(others) == 0 {
		if !own {
			return nil
		}
		return v.store.read(r, from, to, parts, fn)
	}
	ri := 0
	for i := range v.rings {
		if v.rings[i].Resolution == r.Resolution {
			ri = i
		}
	}
	type slot struct {
		t time.Time
		b *cm.MetricBucket
		// have: the other nodes whose bucket is in b.
		have []bool
	}
	slots := map[int64]*slot{}
	at := func(t time.Time) *slot {
		s := slots[t.Unix()]
		if s == nil {
			s = &slot{t: t, have: make([]bool, len(others))}
			slots[t.Unix()] = s
		}
		return s
	}
	if own {
		if err := v.store.read(r, from, to, parts, func(t time.Time, b *cm.MetricBucket) { at(t).b = b }); err != nil {
			return err
		}
	}
	sum := own || len(others) > 1
	for i, n := range others {
		// A member's store that cannot be read leaves its part out; the
		// answer names the node as partial (Scope).
		err := n.store.read(r, from, to, parts, func(t time.Time, b *cm.MetricBucket) {
			s := at(t)
			s.have[i] = true
			if s.b == nil {
				if sum {
					// Host values are those of one machine: a sum of nodes never
					// shows another machine's as its own.
					b.Values, b.Objects = cm.MetricValues{}, nil
				}
				s.b = b
				return
			}
			mergeNodes(s.b, b)
		})
		if err != nil {
			ratelog.Warn(v.log, "monitoring: the history of another node cannot be read", "node", n.id, "err", err)
		}
	}
	order := make([]*slot, 0, len(slots))
	for _, s := range slots {
		order = append(order, s)
	}
	sort.Slice(order, func(i, j int) bool { return order[i].t.Before(order[j].t) })
	for _, s := range order {
		for i, n := range others {
			if !s.have[i] && s.t.Unix() > n.newest[ri].Load() {
				s.b.Partial = true
			}
		}
		fn(s.t, s.b)
	}
	return nil
}

// mergeNodes adds the bucket of another node to dst: the same span on
// another machine. Counters, latency histograms and top lists add as in
// mergeBucket. The estimates of distinct clients do not: a visitor may
// have reached both nodes, so the larger estimate stands as a lower bound
// of the group's. Gauges and host values stay those of dst: in an answer
// over several nodes they are this gateway's, since no sum of machines has
// a CPU load.
func mergeNodes(dst, src *cm.MetricBucket) {
	if src.Partial {
		dst.Partial = true
		dst.GapKind = worseGap(dst.GapKind, src.GapKind)
	}
	dst.Traffic.Add(&src.Traffic)
	mergeLatency(&dst.Latency, &src.Latency)
	maxClients(&dst.Clients, &src.Clients)
	dst.Top = mergeTop(dst.Top, src.Top, cm.TopK, cm.EstimatedDimensions)
	for _, ss := range src.Sites {
		i := -1
		for j := range dst.Sites {
			if dst.Sites[j].Site == ss.Site {
				i = j
				break
			}
		}
		if i < 0 {
			dst.Sites = append(dst.Sites, ss)
			continue
		}
		ds := &dst.Sites[i]
		ds.Traffic.Add(&ss.Traffic)
		switch {
		case ds.Latency == nil:
			ds.Latency = ss.Latency
		case ss.Latency != nil:
			mergeLatency(ds.Latency, ss.Latency)
		}
		switch {
		case ds.Clients == nil:
			ds.Clients = ss.Clients
		case ss.Clients != nil:
			maxClients(ds.Clients, ss.Clients)
		}
		ds.Top = mergeTop(ds.Top, ss.Top, cm.SiteTopK, siteEstimated)
	}
}

func maxClients(dst, src *cm.BucketClients) {
	larger := func(d **int64, s *int64) {
		if s != nil && (*d == nil || *s > **d) {
			v := *s
			*d = &v
		}
	}
	larger(&dst.Unique, src.Unique)
	larger(&dst.New, src.New)
	larger(&dst.Bots, src.Bots)
	larger(&dst.UniqueDay, src.UniqueDay)
}

// nodeArrival is how long a finished bucket of another node may take to
// arrive before the node counts as missing in an answer: the 10 s bucket
// closes, the pull comes within ten seconds, and a margin for a slow round.
const nodeArrival = 30 * time.Second

// Scope says which nodes an answer adds up and which of them lack a part
// of the span [from, to]; nil on a single gateway. A node lacks a part when
// what this gateway holds of it ends before the span does, with the time a
// bucket needs to arrive allowed for. How long the span is plays no part: a
// node that has been silent for minutes is named in an answer about the
// last minute as in one about the last day (finding N2 of the second lab
// run: a rule by the 1 min ring named a killed node in a 2 min span only
// in the first seconds of each minute, and never in the answer for now).
func (v NodeView) Scope(from, to, now time.Time) *cm.ClusterScope {
	s := &v.Monitor.nodes
	s.mu.RLock()
	self, selfName := s.self, s.name
	s.mu.RUnlock()
	if self == "" {
		return nil
	}
	own, others := v.chosen()
	out := &cm.ClusterScope{Node: "all", Nodes: []cm.ClusterNode{}, PartialNodes: []cm.ClusterPartialNode{}}
	if v.only != "" {
		out.Node = v.only
	}
	if own {
		out.Nodes = append(out.Nodes, cm.ClusterNode{ID: self, Name: selfName, Self: true})
	}
	if to.After(now) {
		to = now
	}
	need := to.Add(-nodeArrival)
	for _, n := range others {
		name := *n.name.Load()
		out.Nodes = append(out.Nodes, cm.ClusterNode{ID: n.id, Name: name})
		held := n.heldUntil(v.rings)
		switch {
		case held.IsZero():
			out.PartialNodes = append(out.PartialNodes, cm.ClusterPartialNode{Node: n.id, Name: name})
		case held.Before(need):
			u := ts(held)
			out.PartialNodes = append(out.PartialNodes, cm.ClusterPartialNode{Node: n.id, Name: name, Until: &u})
		}
	}
	out.ClientsAtLeast = v.only == "" && len(others) > 0
	return out
}

// heldUntil is the end of what this gateway holds of the member: the end of
// its newest bucket in any ring, so by the 10 s ring to ten seconds. Zero:
// nothing held.
func (n *nodeStore) heldUntil(rings []cm.Ring) time.Time {
	var end time.Time
	for i, r := range rings {
		if i >= len(n.newest) {
			break
		}
		if u := n.newest[i].Load(); u > 0 {
			if e := time.Unix(u, 0).UTC().Add(r.Step); e.After(end) {
				end = e
			}
		}
	}
	return end
}

// NodeNewest is the start of the newest bucket held of a member in a ring.
func (m *Monitor) NodeNewest(id string, res cm.Resolution) time.Time {
	m.nodes.mu.RLock()
	defer m.nodes.mu.RUnlock()
	n := m.nodes.nodes[id]
	if n == nil {
		return time.Time{}
	}
	for i, r := range m.rings {
		if r.Resolution == res {
			if u := n.newest[i].Load(); u > 0 {
				return time.Unix(u, 0).UTC()
			}
		}
	}
	return time.Time{}
}
