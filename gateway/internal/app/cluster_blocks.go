package app

import (
	"context"
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
// which of the blocks the group holds of a client runs is chosen here. A
// loop hands the blocks this node decided to the group and the lifts made
// on this node; the records of the other nodes are applied in the goroutine
// of the sync.

const (
	// At most 200 blocks and 200 lifts a second leave a node (section 13).
	groupBlocksPerTick = 50
	groupLiftsPerTick  = 50
	// liftKeep is how long a lift stays: as long as any block of before
	// could run.
	liftKeep = contract.MaxBlockS*time.Second + time.Hour
)

// groupBlocksMax: a node hands no block to the group while it holds this
// many that run (section 13). Tests lower it.
var groupBlocksMax atomic.Int64

func init() { groupBlocksMax.Store(20000) }

// groupBlocks is what this node holds of the blocks of its group: per
// incident the block record that is not lifted and not over.
type groupBlocks struct {
	mu   sync.Mutex
	held map[string]*groupBlock
	// clients: the incidents of the blocks held per client.
	clients map[behaviour.Key]map[string]bool
	// waiting counts blocks that had to wait for a later round.
	waiting uint64

	// erased is when the group erased a client, under emu and never under
	// mu: the store asks while it holds its write lock (refuseGroupBlock),
	// and a writer to the store may hold mu.
	emu    sync.Mutex
	erased map[behaviour.Key]time.Time
}

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
	// off: this node holds the incident as unblocked, so the block does
	// not start here.
	off bool
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

// startGroupBlocks wires the blocks of the group into the node and applies
// what the node holds. Called before the mesh runs.
func (a *App) startGroupBlocks(ctx context.Context) {
	node := a.Cluster
	g := &a.groupBlocks
	g.held, g.clients, g.erased = map[string]*groupBlock{}, map[behaviour.Key]map[string]bool{}, map[behaviour.Key]time.Time{}
	if err := a.Store.ShareLifts(ctx); err != nil {
		a.log.Error("cluster: the lifts that wait for the group were not read; a release on this node is not handed to the group until the next start", "err", err)
	}
	a.Behaviour.KnownIncidents(a.incidentKnown)
	a.Dashboard.BlockIncidents = a.blockIncidents
	for _, class := range []string{contract.ClassIncidentBlocks, contract.ClassBlocks} {
		node.Refuse(class, a.refuseGroupBlock)
	}
	node.On(contract.ClassIncidentBlocks, a.applyGroupBlock)
	node.On(contract.ClassLifts, a.applyGroupLift)
	node.On(contract.ClassBlocks, a.applyBlockBefore)
	if n := a.applyGroupBlocks(); n > 0 {
		a.log.Info("cluster: blocks of the group applied at start", "blocks", n)
	}
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
	return &groupBlock{key: key, bits: b.Bits, node: b.Node, self: rec.Origin == a.Cluster.ID(), legacy: rec.Class == contract.ClassBlocks,
		info: behaviour.BlockInfo{Scenario: strings.TrimPrefix(b.Source, "behaviour:"), Since: since, Until: until, Level: b.Level, Incident: incident, EventID: b.EventID,
			NetClass: b.NetClass, Duration: time.Duration(b.DurationS) * time.Second}}, true
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
	at, ok := g.erased[key]
	return ok && !since.After(at.Add(contract.MaxClockAhead))
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
// not held: its record leaves the store. lifted says whether the group
// holds a lift of a block. Called with groupBlocks.mu held.
func (a *App) holdGroupBlock(rec *contract.Record, lifted func(*groupBlock) bool) (behaviour.Key, bool) {
	b, ok := a.groupBlockOf(rec)
	if !ok || !b.info.Until.After(time.Now()) {
		return behaviour.Key{}, false
	}
	g := &a.groupBlocks
	incident := b.info.Incident
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
		return b.key, true
	}
	if cur := g.held[incident]; cur != nil {
		if b.legacy && !cur.legacy {
			return cur.key, true // the record under the incident is the block
		}
		g.remove(incident)
	}
	// A person may have released the incident here before the record of
	// its block came: the incident travels with the events of its node, on
	// another way than the record. The lift of that release is on its way
	// to the group; the block must not start here meanwhile.
	if a.liftedHere(incident) {
		b.off = true
		a.Behaviour.LiftIncident(incident)
	}
	g.put(b)
	return b.key, true
}

// startGroupBlock starts a block of the client when none runs: of the
// blocks held that are not over, the one with the latest end. The node
// decides again with what it holds itself: an address on its allowlist is
// not blocked, and the test profile blocks nothing. Called with
// groupBlocks.mu held.
func (a *App) startGroupBlock(key behaviour.Key) {
	if _, runs := a.Behaviour.ActiveBlock(key.Addr()); runs {
		return
	}
	if a.Config().Mode == config.ModeObserve {
		return
	}
	now := time.Now()
	if lvl, _ := a.Allow.Match(key.Addr(), now); lvl != "" {
		return
	}
	g := &a.groupBlocks
	var next []*groupBlock
	for incident := range g.clients[key] {
		if b := g.held[incident]; !b.off && b.info.Until.After(now) {
			next = append(next, b)
		}
	}
	sort.Slice(next, func(i, j int) bool {
		if !next[i].info.Until.Equal(next[j].info.Until) {
			return next[i].info.Until.After(next[j].info.Until)
		}
		return next[i].info.Incident < next[j].info.Incident
	})
	for _, b := range next {
		incident := b.info.Incident
		if a.liftedHere(incident) {
			b.off = true
			continue
		}
		// The incident before the block: whoever sees the block here can
		// release it, also in the moment it starts.
		a.noteGroupIncident(b)
		if !a.Behaviour.ApplyBlock(b.key, b.bits, b.info) {
			return // a block of this client started meanwhile; that one stands
		}
		if f := testBlockRuns.Load(); f != nil {
			(*f)(a, incident)
		}
		// Looked at again now that the block runs: a release that came
		// between the first look and the start found no block to end. Its
		// mark in the store is written before it ends the block, so one of
		// the two sees the other.
		if a.liftedHere(incident) {
			b.off = true
			a.Behaviour.LiftIncident(incident)
			continue
		}
		return
	}
}

// liftedHere reports whether this node holds the incident as unblocked: a
// person or an agent released it here, or the node took that word from the
// node that wrote the incident.
func (a *App) liftedHere(incident string) bool {
	if a.Store == nil || incident == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if a.Store.LiftNoted(ctx, incident) {
		return true
	}
	in, err := a.Store.GetIncident(ctx, incident)
	return err == nil && in.Status == "unblocked"
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
// then. At the start: what ran when the node stopped runs again, also
// blocks under 24 h, which a single gateway forgets with a restart.
func (a *App) applyGroupBlocks() int {
	node := a.Cluster
	g := &a.groupBlocks
	if recs, err := node.State(contract.ClassErasure); err == nil {
		for _, rec := range recs {
			if e, err := contract.DecodeErasure(rec); err == nil {
				if ip, err := netip.ParseAddr(e.IP); err == nil {
					a.noteErased(ip, contract.HLCTime(rec.HLC))
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
			a.log.Warn("cluster: blocks of the group not read", "err", err)
			return 0
		}
	}
	lifted := map[string]bool{}
	for _, rec := range lifts {
		lifted[rec.ID] = true
	}
	for _, rec := range before {
		if l, err := contract.DecodeLift(rec); rec.Deleted && err == nil && l.Incident != "" {
			lifted[l.Incident] = true
		}
	}
	clients := map[behaviour.Key]bool{}
	for _, rec := range append(before, blocks...) {
		if key, ok := a.holdGroupBlock(rec, func(b *groupBlock) bool { return lifted[b.info.Incident] }); ok {
			clients[key] = true
		}
	}
	for key := range clients {
		a.startGroupBlock(key)
	}
	return len(g.held)
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
	a.liftGroupBlock(l.Incident)
}

// liftGroupBlock ends the block of an incident whose lift the group holds:
// its record leaves the store of this node, the block ends if it runs here,
// and the next block of the client starts. Nothing is written to the group:
// the lift is the record of the node the person released on. Called with
// groupBlocks.mu held.
func (a *App) liftGroupBlock(incident string) {
	g := &a.groupBlocks
	b := g.held[incident]
	if b != nil {
		a.dropGroupBlock(b)
		g.remove(incident)
	} else if err := a.Cluster.Drop(contract.ClassIncidentBlocks, incident); err != nil {
		ratelog.Warn(a.log, "cluster: the record of a lifted block is not dropped; it leaves at the end of the block", "err", err)
	}
	a.Behaviour.LiftIncident(incident)
	if b != nil {
		a.startGroupBlock(b.key)
	}
}

// noteErased notes when the group erased the client of ip.
func (a *App) noteErased(ip netip.Addr, at time.Time) (behaviour.Key, bool) {
	key, _ := behaviour.KeyOf(ip)
	if !key.IsValid() {
		return key, false
	}
	g := &a.groupBlocks
	g.emu.Lock()
	if cur, ok := g.erased[key]; !ok || at.After(cur) {
		g.erased[key] = at
	}
	g.emu.Unlock()
	return key, true
}

// eraseGroupBlocks drops the block records of a client the group erased at
// the time at, as far as they are from before the erasure (erasedBefore),
// and forgets the client in the engine when forget is set: the node takes
// the erasure of another node. A block set later than the erasure is a new
// decision and stands; the erasure of what is stored about the address
// does not end it.
func (a *App) eraseGroupBlocks(ip netip.Addr, at time.Time, forget bool) {
	key, ok := a.noteErased(ip, at)
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
	if !forget {
		return
	}
	later, runs := a.Behaviour.ActiveBlock(ip)
	a.Behaviour.Forget(ip)
	if runs && !a.erasedBefore(key, later.Since) {
		a.Behaviour.ApplyBlock(key, key.Bits(), later)
	}
}

// blockIncidents names the incidents of the blocks this node holds for the
// client of ip: its own running block and the block records of the group.
// A release or an erasure of the address lifts each of them.
func (a *App) blockIncidents(ip netip.Addr) []string {
	key, _ := behaviour.KeyOf(ip)
	if !key.IsValid() {
		return nil
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
	return out
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if a.Store.LiftNoted(ctx, incident) {
		return true
	}
	_, err := a.Store.GetIncident(ctx, incident)
	return err == nil
}

// publishGroupBlocks hands to the group what this node decided: the lifts
// made here, and each block that runs here and that the group holds no
// record of. A block the node took from the group has its record and is
// never written again. Nothing is written when a block ends at its time,
// when a full table drops it or when a lift of the group ended it; then the
// next block the group holds of that client starts.
func (a *App) publishGroupBlocks() {
	node := a.Cluster
	if node == nil {
		return
	}
	a.publishGroupLifts()
	if node.Removed() {
		return
	}
	now := time.Now()
	g := &a.groupBlocks
	// The blocks that run are read under the lock, not before it: a block
	// of another node that arrived in between would run and be missing from
	// what this node holds, and be written as its own.
	g.mu.Lock()
	defer g.mu.Unlock()
	for incident, b := range g.held {
		if !b.info.Until.After(now) {
			g.remove(incident)
		}
	}
	name := node.Name()
	// A flood of blocks must not become a flood of records: at most
	// groupBlocksPerTick leave per round, and none while the node holds
	// groupBlocksMax. What waits runs on this node all the same and leaves
	// with a later round.
	sent, room := 0, int(groupBlocksMax.Load())-len(g.held)
	for _, rb := range a.Behaviour.RunningBlocks() {
		if rb.Incident == "" || g.held[rb.Incident] != nil {
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
		// A block kept over a restart whose lift arrived before the stop.
		if a.groupLifted(b) {
			a.Behaviour.LiftIncident(rb.Incident)
			continue
		}
		// Within the bound of clocks after an erasure of the client no
		// node stores a block of it; this one runs here alone.
		if a.erasedBefore(rb.Key, rb.Since) {
			continue
		}
		sent++
		blk := contract.IncidentBlock{Client: rb.Key.Addr().String(), Bits: rb.Key.Bits(), Scope: contract.ScopeGateway, Source: behaviour.BlockSource(rb.Scenario), Level: rb.Level,
			Since: contract.TimeText(rb.Since), Until: contract.TimeText(until), DurationS: max(int(rb.Duration/time.Second), 1), EventID: rb.EventID, NetClass: rb.NetClass, Node: name}
		if _, err := node.Publish(contract.ClassIncidentBlocks, rb.Incident, &blk, false, until); err != nil {
			ratelog.Warn(a.log, "cluster: block not handed to the group (it runs on this node)", "err", err)
			continue
		}
		g.put(b)
	}
	// Only a client with more than one block has a next one to start when
	// the block that ran is over.
	for key, incidents := range g.clients {
		if len(incidents) > 1 {
			a.startGroupBlock(key)
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
		if err := a.writeGroupLift(l); err != nil {
			ratelog.Warn(a.log, "cluster: lift not handed to the group; it is tried again", "err", err)
			return
		}
		if err := a.Store.LiftWritten(ctx, l.Incident); err != nil {
			ratelog.Warn(a.log, "cluster: a lift handed to the group stays noted and is written again", "err", err)
			return
		}
	}
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
// then asks one member for every record from the first on, because it
// refused the records of the new classes while it ran the build before.
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
	for {
		if node.Alone() {
			break
		}
		if ids := node.Reachable(); len(ids) > 0 {
			rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			_, err := node.Resync(rctx, ids[0])
			cancel()
			if err == nil {
				break
			}
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
	blocks, lifts := 0, 0
	for _, rec := range recs {
		if rec.Origin != node.ID() {
			continue
		}
		if rec.Deleted {
			l, err := contract.DecodeLift(rec)
			expires, ok := rec.ExpiresAt()
			if err != nil || l.Incident == "" || !ok || !expires.After(now) {
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
		if err != nil || old.Incident == "" {
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
