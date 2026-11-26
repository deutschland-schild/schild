package app

import (
	"context"
	"encoding/base64"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The blocks of a group (contracts/cluster.md section 5, D109): a block is
// one record under its incident number, written by the node that decided
// it, and what ends a block before its time is a record of class lifts.
// Two blocks of one client are two records and never touch each other.
//
// The request path does not come here. A block starts and ends in the
// engine as on a single gateway, and the engine keeps one block per client;
// which of the blocks the group holds of a client runs is chosen here: a
// client the node holds a block of is blocked on it, unless its own
// allowlist or mode says otherwise. A loop hands the blocks this node
// decided to the group and the lifts made on this node, and starts a block
// for every client that should have one; the records of the other nodes
// are applied in the goroutine of the sync.

const (
	// At most 200 blocks and 200 lifts a second leave a node (section 13).
	groupBlocksPerTick = 50
	groupLiftsPerTick  = 50
	// groupStartsPerTick bounds the blocks a round starts for clients that
	// have none: a block table that is full drops one block for each it
	// takes, and the round must not turn that into work without end.
	groupStartsPerTick = 200
	// groupBlocksMax: a node hands no block to the group while it holds
	// this many that run (section 13).
	groupBlocksMax = 20000
	// liftKeep is how long a lift stays: as long as any block of before
	// could run.
	liftKeep = contract.MaxBlockS*time.Second + time.Hour
)

// groupBlocks is what this node holds of the blocks of its group: per
// incident the block record that is not lifted and not over.
type groupBlocks struct {
	mu   sync.Mutex
	held map[string]*groupBlock
	// clients: the incidents of the blocks held per client.
	clients map[behaviour.Key]map[string]bool
	// lifted: the incidents whose lift the node holds, of either class,
	// and until when. A block of one of them runs on no node.
	lifted map[string]time.Time
	// read: held and lifted are what the store of the node holds. Before
	// that the node ends no block for want of its record.
	read bool
	// waiting counts blocks that had to wait for a later round.
	waiting uint64
	// max is groupBlocksMax; tests lower it.
	max atomic.Int64

	// erased is when the group erased a client, under emu and never under
	// mu alone: the store asks while it holds its write lock
	// (refuseGroupBlock), and a writer to the store may hold mu.
	emu    sync.Mutex
	erased map[behaviour.Key]erasure
	// pruned is when the erasures that are over were last dropped.
	pruned time.Time
}

// erasure is the erasure of one client: when, and until when the group
// keeps its record.
type erasure struct{ at, until time.Time }

type groupBlock struct {
	key  behaviour.Key
	bits int
	info behaviour.BlockInfo
	// node is the name of the node that decided the block, self whether
	// that is this node.
	node string
	self bool
	// legacy: the node holds the block as a record of class blocks only
	// (section 16).
	legacy bool
}

func (g *groupBlocks) put(b *groupBlock) {
	g.held[b.info.Incident] = b
	if g.clients[b.key] == nil {
		g.clients[b.key] = map[string]bool{}
	}
	g.clients[b.key][b.info.Incident] = true
}

func (g *groupBlocks) remove(incident string) {
	b := g.held[incident]
	if b == nil {
		return
	}
	delete(g.held, incident)
	delete(g.clients[b.key], incident)
	if len(g.clients[b.key]) == 0 {
		delete(g.clients, b.key)
	}
}

// testBlockRuns, in tests, runs right after a block of a record started here.
var testBlockRuns atomic.Pointer[func(a *App, incident string)]

// testLiftWrite, in tests, runs before a lift is written to the group; its
// error is the error of the write.
var testLiftWrite atomic.Pointer[func(a *App, incident string) error]

// testClientBlocks, in tests, runs in withClientBlocks after the blocks of
// the client were read and before the release or the erasure acts.
var testClientBlocks atomic.Pointer[func(a *App)]

// startGroupBlocks wires the blocks of the group into the node and applies
// what the node holds. Called before the mesh runs.
func (a *App) startGroupBlocks(ctx context.Context) {
	node := a.Cluster
	g := &a.groupBlocks
	g.mu.Lock()
	g.held, g.clients, g.lifted = map[string]*groupBlock{}, map[behaviour.Key]map[string]bool{}, map[string]time.Time{}
	g.mu.Unlock()
	g.emu.Lock()
	g.erased = map[behaviour.Key]erasure{}
	g.emu.Unlock()
	g.max.CompareAndSwap(0, groupBlocksMax)
	a.Behaviour.KnownIncidents(a.incidentKnown)
	a.Dashboard.ClientBlocks, a.Dashboard.LiftIncident, a.Dashboard.BlockHeld = a.withClientBlocks, a.endIncident, a.groupHolds
	for _, class := range []string{contract.ClassIncidentBlocks, contract.ClassBlocks} {
		node.Refuse(class, a.refuseGroupBlock)
	}
	node.On(contract.ClassIncidentBlocks, a.applyGroupBlock)
	node.On(contract.ClassLifts, a.applyGroupLift)
	node.On(contract.ClassBlocks, a.applyBlockBefore)
	if n, _ := a.applyGroupBlocks(); n > 0 {
		a.log.Info("cluster: blocks of the group applied at start", "blocks", n)
	}
	// The first round before the mesh runs: what the node kept over its
	// restart and must not run (a block that was lifted, a block of another
	// node it holds no record of) ends before a request meets it.
	a.publishGroupBlocks()
	a.goLoop(ctx, "cluster-blocks", tick(250*time.Millisecond, a.publishGroupBlocks))
	a.goLoop(ctx, "cluster-blocks-cut", a.cutToIncidentBlocks)
}

// groupBlockOf reads the block of a record: one of class incident_blocks,
// or one of class blocks that names an incident (section 16).
func (a *App) groupBlockOf(rec *contract.Record) (*groupBlock, bool) {
	var b *contract.IncidentBlock
	incident := rec.ID
	switch rec.Class {
	case contract.ClassIncidentBlocks:
		nb, err := contract.DecodeIncidentBlock(rec)
		if err != nil {
			return nil, false
		}
		b = nb
	case contract.ClassBlocks:
		if rec.Deleted {
			return nil, false
		}
		old, err := contract.DecodeBlock(rec)
		if err != nil || old.Incident == "" {
			return nil, false
		}
		incident = old.Incident
		b = incidentBlockOf(old)
	default:
		return nil, false
	}
	key, ok := behaviour.ParseClientKey(b.Client, b.Bits)
	until, err := time.Parse(time.RFC3339, b.Until)
	since, err2 := time.Parse(time.RFC3339, b.Since)
	if !ok || err != nil || err2 != nil {
		return nil, false
	}
	self := rec.Origin == a.Cluster.ID()
	return &groupBlock{key: key, bits: b.Bits, node: b.Node, self: self, legacy: rec.Class == contract.ClassBlocks,
		info: behaviour.BlockInfo{Scenario: strings.TrimPrefix(b.Source, "behaviour:"), Since: since, Until: until, Level: b.Level, Incident: incident, EventID: b.EventID,
			NetClass: b.NetClass, Duration: time.Duration(b.DurationS) * time.Second, Taken: !self}}, true
}

// incidentBlockOf is the block of a record of class blocks as the data of
// class incident_blocks.
func incidentBlockOf(old *contract.Block) *contract.IncidentBlock {
	return &contract.IncidentBlock{Client: old.Client, Bits: old.Bits, Scope: contract.ScopeGateway, Source: old.Source, Level: old.Level, Since: old.Since, Until: old.Until,
		DurationS: old.DurationS, EventID: old.EventID, NetClass: old.NetClass, Node: old.Node}
}

// groupLifted reports whether the group holds a lift of the block: a record
// of class lifts under its incident, or the tombstone of class blocks of
// its client that names the incident (section 16). It reads the store of
// the node and takes no lock of the app.
func (a *App) groupLifted(b *groupBlock) bool {
	node := a.Cluster
	if r, err := node.Get(contract.ClassLifts, b.info.Incident); err == nil && r != nil {
		return true
	}
	r, err := node.Get(contract.ClassBlocks, b.key.Addr().String())
	if err != nil || r == nil || !r.Deleted {
		return false
	}
	l, err := contract.DecodeLift(r)
	return err == nil && l.Incident == b.info.Incident
}

// erasedBefore reports whether the group erased the client and the block
// is from before: its since lies before the erasure or within the bound of
// clocks after it. Where two clocks leave it open which came first, the
// erasure wins.
func (a *App) erasedBefore(key behaviour.Key, since time.Time) bool {
	g := &a.groupBlocks
	g.emu.Lock()
	defer g.emu.Unlock()
	e, ok := g.erased[key]
	return ok && !since.After(e.at.Add(contract.MaxClockAhead))
}

// refuseGroupBlock keeps a block record out of the store that a lift or an
// erasure of the group ended: handed over later, or with a later clock, it
// does not bring the block back (cluster.Node.Refuse).
func (a *App) refuseGroupBlock(rec *contract.Record) bool {
	b, ok := a.groupBlockOf(rec)
	return ok && (a.groupLifted(b) || a.erasedBefore(b.key, b.info.Since))
}

// dropGroupBlock removes the records of a block from the store of the node:
// the one under its incident and, while section 16 applies, the one of
// class blocks under its client when it names this incident.
func (a *App) dropGroupBlock(b *groupBlock) {
	node := a.Cluster
	if err := node.Drop(contract.ClassIncidentBlocks, b.info.Incident); err != nil {
		ratelog.Warn(a.log, "cluster: the record of a block that ended is not dropped; it leaves at the end of the block", "err", err)
	}
	client := b.key.Addr().String()
	r, err := node.Get(contract.ClassBlocks, client)
	if err != nil || r == nil || r.Deleted {
		return
	}
	if old, err := contract.DecodeBlock(r); err == nil && old.Incident == b.info.Incident {
		if err := node.Drop(contract.ClassBlocks, client); err != nil {
			ratelog.Warn(a.log, "cluster: the record of a block that ended is not dropped; it leaves at the end of the block", "err", err)
		}
	}
}

// holdGroupBlock takes the block of a record into what this node holds and
// names its client. A block that a lift or an erasure of the group ended is
// not held: its record leaves the store, and the block ends if it runs
// here. lifted says whether the group holds a lift of a block. Called with
// groupBlocks.mu held.
func (a *App) holdGroupBlock(rec *contract.Record, lifted func(*groupBlock) bool) (behaviour.Key, bool) {
	b, ok := a.groupBlockOf(rec)
	if !ok || !b.info.Until.After(time.Now()) {
		return behaviour.Key{}, false
	}
	g := &a.groupBlocks
	incident := b.info.Incident
	if b.legacy {
		a.forgetReplaced(b.key, incident)
	}
	if lifted(b) {
		a.dropGroupBlock(b)
		g.remove(incident)
		// A block kept over a restart may run here all the same.
		a.Behaviour.LiftIncident(incident)
		return b.key, true
	}
	if a.erasedBefore(b.key, b.info.Since) {
		a.dropGroupBlock(b)
		g.remove(incident)
		if run, runs := a.Behaviour.ActiveBlock(b.key.Addr()); runs && run.Incident == incident {
			a.Behaviour.Forget(b.key.Addr())
		}
		return b.key, true
	}
	cur := g.held[incident]
	if cur != nil {
		if b.legacy && !cur.legacy {
			return cur.key, true // the record under the incident is the block
		}
		g.remove(incident)
	}
	// The incident with the record: whoever sees the block here can release
	// it, also in the moment it starts.
	if cur == nil && !b.self {
		a.noteGroupIncident(b)
	}
	g.put(b)
	return b.key, true
}

// forgetReplaced drops what the node holds of class blocks alone for a
// client under another incident than this one: that class has one record
// per client (section 16), so a record that arrives for the client replaced
// the one before in the store. Called with groupBlocks.mu held.
func (a *App) forgetReplaced(key behaviour.Key, incident string) {
	g := &a.groupBlocks
	for other := range g.clients[key] {
		if b := g.held[other]; b.legacy && other != incident {
			g.remove(other)
		}
	}
}

// startGroupBlock starts a block of the client when none runs here: of the
// blocks held that are not over, the one with the latest end. The node
// decides again with what it holds itself: an address on its allowlist is
// not blocked, and the test profile blocks nothing. Nothing else keeps a
// block the group holds from running: no status of its incident, only its
// lift, and a lift made here that waits for the group counts as one. It
// reads no database. Called with groupBlocks.mu held; it reports whether a
// block started.
func (a *App) startGroupBlock(key behaviour.Key) bool {
	if _, runs := a.Behaviour.ActiveBlock(key.Addr()); runs {
		return false
	}
	if a.Config().Mode == config.ModeObserve {
		return false
	}
	now := time.Now()
	if lvl, _ := a.Allow.Match(key.Addr(), now); lvl != "" {
		return false
	}
	g := &a.groupBlocks
	var next *groupBlock
	for incident := range g.clients[key] {
		b := g.held[incident]
		if !b.info.Until.After(now) || a.Store.LiftNoted(incident) {
			continue
		}
		if next == nil || b.info.Until.After(next.info.Until) || (b.info.Until.Equal(next.info.Until) && incident < next.info.Incident) {
			next = b
		}
	}
	if next == nil || !a.Behaviour.ApplyBlock(next.key, next.bits, next.info) {
		return false // none to start, or a block of this client started meanwhile
	}
	// A release that comes in this moment ends the block when it has the
	// lock (endIncident, withClientBlocks): it notes its lift before.
	if f := testBlockRuns.Load(); f != nil {
		// Without the lock, as a person's release comes: it takes it.
		g.mu.Unlock()
		(*f)(a, next.info.Incident)
		g.mu.Lock()
	}
	return true
}

// noteGroupIncident stores the incident of a block another node set, from
// what the block's record says. The incident itself follows with the events
// of that node, up to a second later; until then the dashboard of this node
// lists the block, and "Freigeben" on it has to find its incident (finding
// F2 of the lab measurement: 404 for a block the page showed). What the
// record does not say (website, reason) is filled in when the incident
// arrives (store.MergeIncident).
func (a *App) noteGroupIncident(b *groupBlock) {
	if a.Store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	in := &store.Incident{Incident: b.info.Incident, EventID: b.info.EventID, Time: b.info.Since, IP: b.key.Addr().String(), Status: "blocked",
		Sources: []string{behaviour.BlockSource(b.info.Scenario)}}
	// Another node's incident: no news of this node (store.OwnGen).
	if err := a.Store.InsertIncident(store.Foreign(ctx), in); err != nil {
		ratelog.Warn(a.log, "cluster: incident of a block of another node not stored; it follows with that node's events", "err", err)
	}
}

// applyGroupBlocks applies the blocks of both classes this node holds,
// minus those a lift or an erasure ended, and returns how many it holds
// then, and whether it read them. At the start: what ran when the node
// stopped runs again, also blocks under 24 h, which a single gateway
// forgets with a restart.
func (a *App) applyGroupBlocks() (int, bool) {
	node := a.Cluster
	g := &a.groupBlocks
	if recs, err := node.State(contract.ClassErasure); err == nil {
		for _, rec := range recs {
			if e, err := contract.DecodeErasure(rec); err == nil {
				if ip, err := netip.ParseAddr(e.IP); err == nil {
					a.noteErased(ip, rec)
				}
			}
		}
	}
	// Read under the lock: a lift that arrives meanwhile waits, and finds
	// the block it ends held.
	g.mu.Lock()
	defer g.mu.Unlock()
	lifts, err1 := node.State(contract.ClassLifts)
	before, err2 := node.State(contract.ClassBlocks)
	blocks, err3 := node.State(contract.ClassIncidentBlocks)
	for _, err := range []error{err1, err2, err3} {
		if err != nil {
			ratelog.Warn(a.log, "cluster: blocks of the group not read; the next round reads them", "err", err)
			return 0, false
		}
	}
	for _, rec := range lifts {
		a.noteLifted(rec.ID, rec)
	}
	for _, rec := range before {
		if l, err := contract.DecodeLift(rec); rec.Deleted && err == nil && l.Incident != "" {
			a.noteLifted(l.Incident, rec)
		}
	}
	clients := map[behaviour.Key]bool{}
	for _, rec := range append(before, blocks...) {
		if key, ok := a.holdGroupBlock(rec, func(b *groupBlock) bool { _, ok := g.lifted[b.info.Incident]; return ok }); ok {
			clients[key] = true
		}
	}
	for key := range clients {
		a.startGroupBlock(key)
	}
	g.read = true
	return len(g.held), true
}

// noteLifted notes that the node holds the lift of an incident, until its
// record is over. Called with groupBlocks.mu held.
func (a *App) noteLifted(incident string, rec *contract.Record) {
	until, ok := rec.ExpiresAt()
	if !ok {
		until = time.Now().Add(liftKeep)
	}
	a.groupBlocks.lifted[incident] = until
}

// applyGroupBlock takes the block record of another node.
func (a *App) applyGroupBlock(rec *contract.Record) {
	g := &a.groupBlocks
	g.mu.Lock()
	defer g.mu.Unlock()
	if key, ok := a.holdGroupBlock(rec, a.groupLifted); ok {
		a.startGroupBlock(key)
	}
}

// applyGroupLift takes the lift another node wrote.
func (a *App) applyGroupLift(rec *contract.Record) {
	if _, err := contract.DecodeIncidentLift(rec); err != nil {
		return
	}
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	a.noteLifted(rec.ID, rec)
	a.liftGroupBlock(rec.ID)
}

// applyBlockBefore takes a record of class blocks, which a build before
// D109 wrote (section 16): a block that names an incident is a block of
// that incident, a tombstone that names one is its lift. A record without
// an incident is not read.
func (a *App) applyBlockBefore(rec *contract.Record) {
	if !rec.Deleted {
		a.applyGroupBlock(rec)
		return
	}
	l, err := contract.DecodeLift(rec)
	if err != nil || l.Incident == "" {
		return
	}
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	// The tombstone took the place of the record of its client, whatever
	// incident that one named.
	if ip, err := netip.ParseAddr(rec.ID); err == nil {
		if key, _ := behaviour.KeyOf(ip); key.IsValid() {
			a.forgetReplaced(key, l.Incident)
		}
	}
	a.noteLifted(l.Incident, rec)
	a.liftGroupBlock(l.Incident)
}

// liftGroupBlock ends the block of an incident whose lift the group holds:
// its record leaves the store of this node, the block ends if it runs here,
// and the next block the group holds of that client starts at once, also
// when the block that ended was one the node held no record of. Nothing is
// written to the group: the lift is the record of the node the person
// released on. Called with groupBlocks.mu held.
func (a *App) liftGroupBlock(incident string) {
	g := &a.groupBlocks
	key, ok := a.Behaviour.IncidentKey(incident)
	if b := g.held[incident]; b != nil {
		a.dropGroupBlock(b)
		g.remove(incident)
		key, ok = b.key, true
	} else if err := a.Cluster.Drop(contract.ClassIncidentBlocks, incident); err != nil {
		ratelog.Warn(a.log, "cluster: the record of a lifted block is not dropped; it leaves at the end of the block", "err", err)
	}
	a.Behaviour.LiftIncident(incident)
	if ok {
		a.startGroupBlock(key)
	}
}

// endIncident ends the running block of an incident on this node, as
// Engine.LiftIncident does, for the unblock a person or an agent made here,
// and starts the next block the group holds of that client: the client of
// two blocks stays blocked when one of them is released. The lift for the
// group is noted by the caller before.
func (a *App) endIncident(incident string) bool {
	if a.Cluster == nil {
		return a.Behaviour.LiftIncident(incident)
	}
	g := &a.groupBlocks
	g.mu.Lock()
	defer g.mu.Unlock()
	key, ok := a.Behaviour.IncidentKey(incident)
	ended := a.Behaviour.LiftIncident(incident)
	if ok {
		a.startGroupBlock(key)
	}
	return ended
}

// groupHolds reports whether the group holds a block record of the incident
// that is not lifted and not over.
func (a *App) groupHolds(incident string) bool {
	g := &a.groupBlocks
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.held[incident]
	return b != nil && b.info.Until.After(time.Now()) && !a.Store.LiftNoted(incident)
}

// noteErased notes the erasure record of the client of ip.
func (a *App) noteErased(ip netip.Addr, rec *contract.Record) (behaviour.Key, bool) {
	key, _ := behaviour.KeyOf(ip)
	if !key.IsValid() {
		return key, false
	}
	e := erasure{at: contract.HLCTime(rec.HLC)}
	e.until, _ = rec.ExpiresAt()
	g := &a.groupBlocks
	g.emu.Lock()
	if cur, ok := g.erased[key]; !ok || e.at.After(cur.at) {
		g.erased[key] = e
	}
	g.emu.Unlock()
	return key, true
}

// pruneErased drops the erasures whose record is over, once a minute.
func (a *App) pruneErased(now time.Time) {
	g := &a.groupBlocks
	g.emu.Lock()
	defer g.emu.Unlock()
	if now.Sub(g.pruned) < time.Minute {
		return
	}
	g.pruned = now
	for key, e := range g.erased {
		if !e.until.IsZero() && !e.until.After(now) {
			delete(g.erased, key)
		}
	}
}

// eraseGroupBlocks applies the erasure record of a client to its blocks: a
// block from before the erasure (erasedBefore) runs on no node, the node's
// own included, and its record leaves the store. So the client is forgotten
// in the engine too, on the node that erased once more: a block may have
// started there since. A block set later than the erasure is a new decision
// and stands, and one the group holds starts when none runs.
func (a *App) eraseGroupBlocks(ip netip.Addr, rec *contract.Record) {
	key, ok := a.noteErased(ip, rec)
	if !ok {
		return
	}
	g := &a.groupBlocks
	g.mu.Lock()
	defer g.mu.Unlock()
	for incident := range g.clients[key] {
		if b := g.held[incident]; a.erasedBefore(key, b.info.Since) {
			a.dropGroupBlock(b)
			g.remove(incident)
		}
	}
	later, runs := a.Behaviour.ActiveBlock(ip)
	a.Behaviour.Forget(ip)
	if runs && !a.erasedBefore(key, later.Since) {
		a.Behaviour.ApplyBlock(key, key.Bits(), later)
	}
	a.startGroupBlock(key)
}

// withClientBlocks runs f with the incidents of the blocks this node holds
// for the client of ip, its running block and the block records of the
// group, for the release and the erasure of the address. It holds the lock
// of the blocks meanwhile: no block record of the group arrives and starts
// between the look and what f ends, so what f notes as lifts is what the
// group held, and a block that f ends is none the group does not learn of.
func (a *App) withClientBlocks(ip netip.Addr, f func(incidents []string) error) error {
	key, _ := behaviour.KeyOf(ip)
	if !key.IsValid() {
		return f(nil)
	}
	g := &a.groupBlocks
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	run, runs := a.Behaviour.ActiveBlock(ip)
	if runs && run.Incident != "" {
		out = append(out, run.Incident)
	}
	for incident := range g.clients[key] {
		if !runs || incident != run.Incident {
			out = append(out, incident)
		}
	}
	sort.Strings(out)
	if hook := testClientBlocks.Load(); hook != nil {
		(*hook)(a)
	}
	return f(out)
}

// incidentKnown reports whether this node holds an incident, a block record
// or a lift of the number: a new block then draws another (section 5, "Two
// blocks with one number").
func (a *App) incidentKnown(incident string) bool {
	node := a.Cluster
	for _, class := range []string{contract.ClassIncidentBlocks, contract.ClassLifts} {
		if r, err := node.Get(class, incident); err == nil && r != nil {
			return true
		}
	}
	if a.Store.LiftNoted(incident) {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := a.Store.GetIncident(ctx, incident)
	return err == nil
}

// publishGroupBlocks is the round of the blocks, four times a second. It
// hands to the group what this node decided: the lifts made here, and each
// block this node decided that runs and that the group holds no record of.
// A block the node took from the group is never written again, with or
// without its record (the engine keeps who decided, also over a restart).
// Nothing is written when a block ends at its time, when a full table drops
// it or when a lift of the group ended it.
//
// It ends what must not run here: a block whose incident is lifted, by a
// record the node holds or by a release made here that waits for the
// group, and a block another node decided that the node holds no record
// of. Such blocks come back with a restart when their kept row outlived
// the lift or the record (a write that was dropped, a stop before it, a
// backup put back).
//
// Then it starts a block for every client the node holds one of and runs
// none for: the block before ended at its time, a full table dropped it,
// the address left the allowlist, the mode changed. It starts none that
// the block table has no room for: a full table would drop another block
// for each, round after round.
func (a *App) publishGroupBlocks() {
	node := a.Cluster
	if node == nil {
		return
	}
	a.groupBlocks.mu.Lock()
	read := a.groupBlocks.read
	a.groupBlocks.mu.Unlock()
	if !read {
		if _, read = a.applyGroupBlocks(); !read {
			return
		}
	}
	a.publishGroupLifts()
	if node.Removed() {
		return
	}
	now := time.Now()
	a.pruneErased(now)
	g := &a.groupBlocks
	g.emu.Lock()
	erasures := len(g.erased) > 0
	g.emu.Unlock()
	// The blocks that run are read under the lock, not before it: a block
	// of another node that arrived in between would be missing from them
	// and started a second time.
	g.mu.Lock()
	defer g.mu.Unlock()
	for incident, b := range g.held {
		if !b.info.Until.After(now) {
			g.remove(incident)
		}
	}
	for incident, until := range g.lifted {
		if !until.After(now) {
			delete(g.lifted, incident)
		}
	}
	waiting := a.Store.LiftsWaiting()
	name := node.Name()
	running := a.Behaviour.RunningBlocks()
	runs := make(map[behaviour.Key]bool, len(running))
	// A flood of blocks must not become a flood of records: at most
	// groupBlocksPerTick leave per round, and none while the node holds
	// groupBlocksMax. What waits runs on this node all the same and leaves
	// with a later round.
	sent, room := 0, int(g.max.Load())-len(g.held)
	for _, rb := range running {
		// A block from before an erasure of its client, or from the bound
		// of clocks after it, runs on no node: also one decided here since.
		if erasures && a.erasedBefore(rb.Key, rb.Since) {
			a.Behaviour.Forget(rb.Key.Addr())
			continue
		}
		if _, lifted := g.lifted[rb.Incident]; lifted || (waiting && a.Store.LiftNoted(rb.Incident)) {
			a.Behaviour.LiftIncident(rb.Incident)
			continue
		}
		held := g.held[rb.Incident]
		if rb.Taken {
			// Not this node's decision: it runs by its record, and is
			// never written to the group by this node.
			if held == nil || held.key != rb.Key {
				a.Behaviour.DropIncident(rb.Incident)
				continue
			}
			runs[rb.Key] = true
			continue
		}
		runs[rb.Key] = true
		if rb.Incident == "" || held != nil {
			continue
		}
		if sent >= groupBlocksPerTick || sent >= room {
			g.waiting++
			continue
		}
		until := rb.Until.UTC().Truncate(time.Second)
		if !until.After(now) {
			continue
		}
		b := &groupBlock{key: rb.Key, bits: rb.Key.Bits(), info: rb.BlockInfo, node: name, self: true}
		b.info.Until = until
		sent++
		blk := contract.IncidentBlock{Client: rb.Key.Addr().String(), Bits: rb.Key.Bits(), Scope: contract.ScopeGateway, Source: behaviour.BlockSource(rb.Scenario), Level: rb.Level,
			Since: contract.TimeText(rb.Since), Until: contract.TimeText(until), DurationS: max(int(rb.Duration/time.Second), 1), EventID: rb.EventID, NetClass: rb.NetClass, Node: name}
		if _, err := node.Publish(contract.ClassIncidentBlocks, rb.Incident, &blk, false, until); err != nil {
			ratelog.Warn(a.log, "cluster: block not handed to the group (it runs on this node)", "err", err)
			continue
		}
		g.put(b)
	}
	if a.Config().Mode == config.ModeObserve {
		return
	}
	fits := a.Behaviour.BlockRoom()
	started := 0
	for key := range g.clients {
		if !runs[key] && fits(key) && a.startGroupBlock(key) {
			if started++; started >= groupStartsPerTick {
				break
			}
		}
	}
}

// publishGroupLifts writes the lifts noted in schild.db to the group
// (store/outbox.go). A lift stays noted until its write succeeded, so a
// write that fails is made again with the next round and after a restart.
// The bound of blocks does not hold a lift back.
func (a *App) publishGroupLifts() {
	if !a.Store.LiftsWaiting() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lifts, err := a.Store.WaitingLifts(ctx, groupLiftsPerTick)
	if err != nil {
		ratelog.Warn(a.log, "cluster: the lifts that wait for the group are not read", "err", err)
		return
	}
	for _, l := range lifts {
		// One lift that fails does not hold the others back.
		if !liftID(l.Incident) {
			a.log.Warn("cluster: a lift is noted under a number that is no incident number; no node would take its record, so it is dropped", "incident", l.Incident)
		} else if err := a.writeGroupLift(l); err != nil {
			ratelog.Warn(a.log, "cluster: lift not handed to the group; it is tried again", "err", err)
			continue
		}
		if err := a.Store.LiftWritten(ctx, l.Incident); err != nil {
			ratelog.Warn(a.log, "cluster: a lift handed to the group stays noted and is written again", "err", err)
		}
	}
}

// liftID reports whether a record of class lifts can carry this id, by the
// check every node makes of such a record.
func liftID(id string) bool {
	_, err := contract.DecodeIncidentLift(&contract.Record{Class: contract.ClassLifts, ID: id, Expires: "-",
		Data: base64.StdEncoding.EncodeToString([]byte(`{"node":""}`))})
	return err == nil
}

// writeGroupLift writes one lift to the group and ends its block here as a
// lift of another node does. A node that was removed shares nothing; a
// lift the group holds already is not written a second time.
func (a *App) writeGroupLift(l store.Lift) error {
	node := a.Cluster
	if expires := l.At.Add(liftKeep); !node.Removed() && expires.After(time.Now()) {
		if f := testLiftWrite.Load(); f != nil {
			if err := (*f)(a, l.Incident); err != nil {
				return err
			}
		}
		held, err := node.Get(contract.ClassLifts, l.Incident)
		if err != nil {
			return err
		}
		if held == nil {
			if _, err := node.Publish(contract.ClassLifts, l.Incident, &contract.IncidentLift{Node: node.Name()}, false, expires); err != nil {
				return err
			}
		}
	}
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	a.groupBlocks.lifted[l.Incident] = l.At.Add(liftKeep)
	a.liftGroupBlock(l.Incident)
	return nil
}

// markBlocksCut notes in the node's store how far the node is with the cut
// of section 16: "written" when it wrote anew what it held of class blocks,
// "asked" when it asked a member for every record once.
const markBlocksCut = "blocks_by_incident"

// cutToIncidentBlocks is the first start of a node with a build that has
// D109 (section 16), once: it writes its own running blocks of class
// blocks as records of incident_blocks and its own tombstones as lifts,
// then asks every member it reaches for every record from the first on,
// because it refused the records of the new classes while it ran the build
// before (one member alone may still run that build and hold none).
func (a *App) cutToIncidentBlocks(ctx context.Context) {
	node := a.Cluster
	if node.Removed() || node.Mark(markBlocksCut) == "asked" {
		return
	}
	if node.Mark(markBlocksCut) == "" {
		if !a.writeBlocksAnew(ctx) {
			return // the next start tries again
		}
		if err := node.SetMark(markBlocksCut, "written"); err != nil {
			a.log.Warn("cluster: the cut to blocks by incident is not noted; the next start makes it again", "err", err)
			return
		}
	}
	asked := map[string]bool{}
	var first time.Time
	for !node.Alone() {
		for _, id := range node.Reachable() {
			if asked[id] {
				continue
			}
			rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			_, err := node.Resync(rctx, id)
			cancel()
			if err != nil {
				continue
			}
			if asked[id] = true; first.IsZero() {
				first = time.Now()
			}
		}
		// Every member, or those the node reached within cutAskFor of the
		// first: a member that is away for good does not hold the node up.
		if len(asked) > 0 && (a.askedEveryMember(asked) || time.Since(first) > cutAskFor) {
			break
		}
		t := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	if err := node.SetMark(markBlocksCut, "asked"); err != nil {
		a.log.Warn("cluster: the cut to blocks by incident is not noted; the next start asks a member again", "err", err)
	}
}

// cutAskFor is how long the first start waits for the members it has not
// reached yet, from the first member that answered.
const cutAskFor = 2 * time.Minute

// askedEveryMember reports whether asked names every other gateway of the
// group.
func (a *App) askedEveryMember(asked map[string]bool) bool {
	st, err := a.Cluster.Live()
	if err != nil {
		return false
	}
	for _, m := range st.Members {
		if !m.Self && !m.Removed && m.Member.Role == contract.RoleGateway && !asked[m.ID] {
			return false
		}
	}
	return true
}

// writeBlocksAnew writes what this node signed of class blocks in the new
// classes: each block that runs here as a record of incident_blocks, each
// tombstone that names an incident and is not over as a lift. The blocks
// leave within the bound of section 13; the lifts go the way of every lift
// (store/outbox.go). It reports whether it came to its end.
func (a *App) writeBlocksAnew(ctx context.Context) bool {
	node := a.Cluster
	recs, err := node.State(contract.ClassBlocks)
	if err != nil {
		a.log.Warn("cluster: the records of class blocks are not read for the cut to blocks by incident", "err", err)
		return false
	}
	g := &a.groupBlocks
	now := time.Now()
	// Its own: signed by this node and named after it. A node that moved to
	// another group signed everything it carried, also the blocks and lifts
	// of the others; the name of the node that decided stays in the data.
	name := node.Name()
	blocks, lifts := 0, 0
	for _, rec := range recs {
		if rec.Origin != node.ID() {
			continue
		}
		if rec.Deleted {
			l, err := contract.DecodeLift(rec)
			expires, ok := rec.ExpiresAt()
			if err != nil || l.Incident == "" || l.Node != name || !ok || !expires.After(now) {
				continue
			}
			if held, err := node.Get(contract.ClassLifts, l.Incident); err != nil || held != nil {
				continue
			}
			// Noted with the time of the lift, so the record ends when
			// the tombstone would have.
			if err := a.Store.NoteLifts(ctx, expires.Add(-liftKeep), l.Incident); err != nil {
				a.log.Warn("cluster: a lift of class blocks is not noted for the cut to blocks by incident", "err", err)
				return false
			}
			lifts++
			continue
		}
		old, err := contract.DecodeBlock(rec)
		if err != nil || old.Incident == "" || old.Node != name {
			continue
		}
		g.mu.Lock()
		b := g.held[old.Incident]
		run, runs := a.Behaviour.ActiveBlock(netip.MustParseAddr(old.Client))
		if b == nil || !b.legacy || !runs || run.Incident != old.Incident {
			g.mu.Unlock()
			continue
		}
		_, err = node.Publish(contract.ClassIncidentBlocks, old.Incident, incidentBlockOf(old), false, b.info.Until)
		if err == nil {
			b.legacy = false
		}
		g.mu.Unlock()
		if err != nil {
			a.log.Warn("cluster: a block of class blocks is not written anew for the cut to blocks by incident", "err", err)
			return false
		}
		if blocks++; blocks%groupBlocksPerTick == 0 {
			t := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				t.Stop()
				return false
			case <-t.C:
			}
		}
	}
	if blocks+lifts > 0 {
		a.log.Info("cluster: blocks and lifts of the build before written anew by incident (D109)", "blocks", blocks, "lifts", lifts)
	}
	return true
}

// blockNode names the node that decided the block of a client, as the
// group's record says: its name, and whether it is this node.
func (a *App) blockNode(key behaviour.Key, incident string) (name string, self, ok bool) {
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	b := a.groupBlocks.held[incident]
	if b == nil || b.key != key || b.node == "" {
		return "", false, false
	}
	return b.node, b.self, true
}

// groupBlockCount is how many blocks of the group this node holds that are
// not lifted and not over, of both classes.
func (a *App) groupBlockCount() int {
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	return len(a.groupBlocks.held)
}
