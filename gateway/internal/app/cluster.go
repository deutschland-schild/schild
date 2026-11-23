package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The group of MVP-27 (D105), first version: the address blocks of every
// node act on every node.
//
// The request path does not come here. A block starts and ends in the
// engine as on a single gateway; a loop compares the blocks that run with
// what this node told the group and publishes the difference, and a record
// of another node is applied to the engine in the goroutine of the sync.

// ClusterDir is where a node keeps its key and its copy of the group's
// records.
func ClusterDir(dataDir string) string { return filepath.Join(dataDir, "cluster") }

const (
	groupBlocksPerTick = 50
	groupBlocksMax     = 20000
)

// groupBlocks is what this node knows the group knows: per client key the
// incident and the end of the block that runs.
type groupBlocks struct {
	mu    sync.Mutex
	known map[behaviour.Key]groupBlock
	// waiting counts blocks that had to wait for a later round.
	waiting uint64
}

type groupBlock struct {
	incident string
	until    time.Time
	// node is the name of the node that decided the block, self whether
	// that is this node.
	node string
	self bool
}

// openCluster opens the node of a gateway with cluster.enabled and binds
// its mesh listener, at the end of New: a node that cannot run (its port is
// taken, its key does not load, it belongs to no group) stops the start, so
// no gateway of a group runs alone while its readiness answer says 200.
func (a *App) openCluster(cfg *config.Site) error {
	if !cfg.Cluster.Enabled {
		return nil
	}
	node, err := cluster.Open(cluster.Options{Dir: ClusterDir(a.dataDir), Listen: cfg.Cluster.Listen, Log: a.log, Peers: cfg.Cluster.Peers})
	if errors.Is(err, cluster.ErrNoGroup) {
		return fmt.Errorf("cluster.enabled, but this node belongs to no group: set cluster.secret_file (the same file on every node, schild cluster secret makes one) and cluster.peers, or set cluster.enabled false: %w", err)
	}
	if err != nil {
		return fmt.Errorf("cluster: the node does not open (%w): a node key that does not load belongs to its owner alone (chmod 0600 node.key) or, when it is broken, goes with its cluster directory (%s), which the next start makes anew from cluster.secret_file; or set cluster.enabled false", err, ClusterDir(a.dataDir))
	}
	if err := node.Bind(); err != nil {
		node.Close()
		return fmt.Errorf("cluster: the mesh does not listen (%w): free the port or change cluster.listen, or set cluster.enabled false", err)
	}
	a.clusterNode = node
	return nil
}

// startCluster starts the node New opened and its loops. Every handler of
// the node is registered before the mesh runs, so no record or message that
// arrives at once misses its handler.
func (a *App) startCluster(ctx context.Context) {
	cfg := a.Config()
	if !cfg.Cluster.Enabled {
		return
	}
	a.Gate.InService = a.inService
	a.Gate.Leaving = a.Draining
	node := a.clusterNode
	if node == nil {
		return // New refused a start without it; tests that build the app by hand
	}
	a.Cluster = node
	if node.Removed() {
		a.log.Warn("cluster: this node was removed from its group. It serves with the state it has and shares nothing. To take it out for good: cluster.enabled false; to bring it back: delete its cluster directory and start schild again")
	}
	a.groupBlocks.known = map[behaviour.Key]groupBlock{}
	node.On(contract.ClassBlocks, a.applyGroupRecord)
	a.seedGroupBlocks()
	a.goLoop(ctx, "cluster-blocks", tick(250*time.Millisecond, a.publishGroupBlocks))
	a.goLoop(ctx, "cluster-ready", tick(time.Second, a.noteReadiness))
	a.startSharedState(ctx)
	a.startCounts(ctx)
	a.startGroupData(ctx)
	a.startGroupMetrics(ctx)
	a.startGroupHub(ctx)
	a.startGroupVersions(ctx)
	a.startClockWatch(ctx)
	if cfg.CaddyIngress() {
		a.startGroupFiles(ctx, a.storageRoot())
	}
	if f := testBeforeMesh; f != nil {
		f(a)
	}
	a.goLoop(ctx, "cluster", func(ctx context.Context) {
		if err := node.Run(ctx); err != nil {
			a.log.Error("cluster: the mesh stopped, this gateway runs with its last state", "err", err)
			<-ctx.Done()
		}
	})
}

// testBeforeMesh, in tests, runs right before the mesh starts.
var testBeforeMesh func(*App)

// seedGroupBlocks applies the blocks of the group this node holds at its
// start: what ran when it stopped runs again, also blocks under 24 h, which
// a single gateway forgets with a restart.
func (a *App) seedGroupBlocks() {
	recs, err := a.Cluster.State(contract.ClassBlocks)
	if err != nil {
		a.log.Warn("cluster: blocks of the group not read", "err", err)
		return
	}
	n := 0
	for _, rec := range recs {
		if !rec.Deleted && a.applyGroupBlock(rec) {
			n++
		}
	}
	if n > 0 {
		a.log.Info("cluster: blocks of the group applied at start", "blocks", n)
	}
}

func (a *App) applyGroupRecord(rec *contract.Record) {
	if rec.Deleted {
		a.applyGroupLift(rec)
		return
	}
	a.applyGroupBlock(rec)
}

// applyGroupBlock starts the block of a record here. The node decides again
// with what it holds itself: an address on its allowlist is not blocked,
// and the test profile blocks nothing.
func (a *App) applyGroupBlock(rec *contract.Record) bool {
	b, err := contract.DecodeBlock(rec)
	if err != nil {
		return false
	}
	key, ok := behaviour.ParseClientKey(b.Client, b.Bits)
	until, err := time.Parse(time.RFC3339, b.Until)
	since, err2 := time.Parse(time.RFC3339, b.Since)
	if !ok || err != nil || err2 != nil || !until.After(time.Now()) {
		return false
	}
	if a.Config().Mode == config.ModeObserve {
		return false
	}
	if lvl, _ := a.Allow.Match(key.Addr(), time.Now()); lvl != "" {
		return false
	}
	bi := behaviour.BlockInfo{Scenario: strings.TrimPrefix(b.Source, "behaviour:"), Since: since, Until: until, Level: b.Level, Incident: b.Incident, EventID: b.EventID,
		NetClass: b.NetClass, Duration: time.Duration(b.DurationS) * time.Second}
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	// A lift may have been made here before the record of the block came:
	// the incident of a block travels with the events of its node, on
	// another way than the record, and "Freigeben" needs only the incident.
	// The block must not start then, and nobody told the group yet (N1).
	if a.liftedHere(b.Incident) {
		// A block kept over a restart may run here all the same; ended
		// first, so the loop does not hand it to the group as a new one.
		a.Behaviour.LiftIncident(b.Incident)
		a.liftForGroup(key, b.Incident)
		return false
	}
	if !a.Behaviour.ApplyBlock(key, b.Bits, bi) {
		// A block of this client runs here already. When it is the same
		// one (a restart), the group knows it.
		if cur, ok := a.Behaviour.ActiveBlock(key.Addr()); ok && cur.Incident == b.Incident {
			a.groupBlocks.known[key] = groupBlock{incident: b.Incident, until: until, node: b.Node, self: rec.Origin == a.Cluster.ID()}
		}
		return false
	}
	// Looked at again now that the block runs: a lift that came between the
	// first look and the start found no block to end. Its mark in the store
	// is written before it ends the block, so one of the two sees the other.
	if a.liftedHere(b.Incident) {
		a.Behaviour.LiftIncident(b.Incident)
		a.liftForGroup(key, b.Incident)
		return false
	}
	a.groupBlocks.known[key] = groupBlock{incident: b.Incident, until: until, node: b.Node, self: rec.Origin == a.Cluster.ID()}
	a.noteGroupIncident(b, key, since)
	return true
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
	in, err := a.Store.GetIncident(ctx, incident)
	return err == nil && in.Status == "unblocked"
}

// liftForGroup tells the group that the block of an incident is lifted,
// for a block this node never ran: the lift was made before the block's
// record came. Called with groupBlocks.mu held, and only for the record
// that is the group's state of the client at this moment, so the tombstone
// replaces that block and no other.
func (a *App) liftForGroup(key behaviour.Key, incident string) {
	node := a.Cluster
	if node == nil || node.Removed() {
		return
	}
	delete(a.groupBlocks.known, key)
	expires := time.Now().Add(contract.MaxBlockS*time.Second + time.Hour)
	if _, err := node.Publish(contract.ClassBlocks, key.Addr().String(), &contract.Lift{Incident: incident, Node: node.Name()}, true, expires); err != nil {
		ratelog.Warn(a.log, "cluster: lift not handed to the group (the block was lifted on this node before its record came)", "err", err)
		return
	}
	a.groupLiftsLate.Add(1)
}

// noteGroupIncident stores the incident of a block another node set, from
// what the block's record says. The incident itself follows with the events
// of that node, up to a second later; until then the dashboard of this node
// lists the block, and "Freigeben" on it has to find its incident (finding
// F2 of the lab measurement: 404 for a block the page showed). What the
// record does not say (website, reason) is filled in when the incident
// arrives (store.MergeIncident).
func (a *App) noteGroupIncident(b *contract.Block, key behaviour.Key, since time.Time) {
	if a.Store == nil || b.Incident == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	in := &store.Incident{Incident: b.Incident, EventID: b.EventID, Time: since, IP: key.Addr().String(), Status: "blocked", Sources: []string{b.Source}}
	// Another node's incident: no news of this node (store.OwnGen).
	if err := a.Store.InsertIncident(store.Foreign(ctx), in); err != nil {
		ratelog.Warn(a.log, "cluster: incident of a block of another node not stored; it follows with that node's events", "err", err)
	}
}

// applyGroupLift ends the block another node lifted.
func (a *App) applyGroupLift(rec *contract.Record) {
	l, err := contract.DecodeLift(rec)
	if err != nil {
		return
	}
	ip, err := netip.ParseAddr(rec.ID)
	if err != nil {
		return
	}
	key, _ := behaviour.KeyOf(ip)
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	cur, ok := a.Behaviour.ActiveBlock(ip)
	if !ok || (l.Incident != "" && cur.Incident != l.Incident) {
		return // another block than the one that was lifted
	}
	// Forget it first, so the loop does not take its end for a lift of
	// this node and tell the group again.
	delete(a.groupBlocks.known, key)
	a.Behaviour.LiftIncident(cur.Incident)
}

// publishGroupBlocks tells the group what changed on this node: a block
// that started here, and a block that ended before its time (a release in
// the dashboard, a lift by an agent, an address that went onto the
// allowlist). A block that ends at its time needs no word: it ends on every
// node at the same second.
func (a *App) publishGroupBlocks() {
	node := a.Cluster
	if node == nil || node.Removed() {
		return
	}
	now := time.Now()
	// The blocks that run are read under the lock, not before it: a block
	// of another node that arrived in between would be known and missing
	// from an older reading, taken for one that ended early here, and
	// lifted for the whole group.
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	running := a.Behaviour.RunningBlocks()
	seen := make(map[behaviour.Key]bool, len(running))
	name := node.Name()
	// A flood of blocks must not become a flood of records: at most
	// groupBlocksPerTick leave per round (200 a second), and none while the
	// group knows groupBlocksMax. What waits runs on this node all the same
	// and leaves with a later round.
	sent, room := 0, groupBlocksMax-len(a.groupBlocks.known)
	for _, rb := range running {
		seen[rb.Key] = true
		if k, ok := a.groupBlocks.known[rb.Key]; ok && k.incident == rb.Incident {
			continue
		}
		if sent >= groupBlocksPerTick || sent >= room {
			a.groupBlocks.waiting++
			continue
		}
		sent++
		until := rb.Until.UTC().Truncate(time.Second)
		blk := contract.Block{Client: rb.Key.Addr().String(), Bits: rb.Key.Bits(), Source: behaviour.BlockSource(rb.Scenario), Level: rb.Level,
			Since: contract.TimeText(rb.Since), Until: contract.TimeText(until), DurationS: max(int(rb.Duration/time.Second), 1), Incident: rb.Incident, EventID: rb.EventID,
			NetClass: rb.NetClass, Node: name}
		if _, err := node.Publish(contract.ClassBlocks, blk.Client, &blk, false, until); err != nil {
			ratelog.Warn(a.log, "cluster: block not handed to the group (it runs on this node)", "err", err)
			continue
		}
		a.groupBlocks.known[rb.Key] = groupBlock{incident: rb.Incident, until: until, node: name, self: true}
	}
	for key, k := range a.groupBlocks.known {
		if seen[key] {
			continue
		}
		delete(a.groupBlocks.known, key)
		if !now.Before(k.until.Add(-time.Second)) {
			continue // ended at its time
		}
		// The tombstone stays as long as any block of before could run.
		expires := now.Add(contract.MaxBlockS*time.Second + time.Hour)
		if _, err := node.Publish(contract.ClassBlocks, key.Addr().String(), &contract.Lift{Incident: k.incident, Node: name}, true, expires); err != nil {
			ratelog.Warn(a.log, "cluster: lift not handed to the group (the block ended on this node)", "err", err)
		}
	}
}

// firstSyncWait is how long a node that reaches no member waits before it
// says it is in service with the state it has.
var firstSyncWaitNS atomic.Int64 // set in init; tests shorten it

func init() { firstSyncWaitNS.Store(int64(10 * time.Second)) }

// firstSyncWait reads it: loops of a node read while a test sets.
func firstSyncWait() time.Duration { return time.Duration(firstSyncWaitNS.Load()) }

// inService is the readiness of a node of a group, next to the gate's own
// (/.schild/readyz, the health check of the balancer): not while it drains,
// and not before it took the state of the group and applied it, so a node
// that just started lets nobody pass whom the group blocks.
//
// A node that reaches no member serves after ten seconds with the state it
// has, but only when it was in step with its group once: a node that never
// was (a fresh one, one the group refused) holds nothing of the group and
// stays out of traffic until it reaches a member. A node that reaches a
// member and cannot take what it has (its clock is far behind) stays out
// too, as long as that lasts.
func (a *App) inService() bool {
	if a.draining.Load() {
		return false
	}
	node := a.Cluster
	if node == nil || node.Removed() {
		// Removed, it serves with the state it has and says so.
		return true
	}
	if node.Synced() {
		// What was taken is applied by syncShared; the first round after
		// the node came in step has to be through.
		if !a.sharedApplied.Load() {
			return false
		}
		// The running counts of the group are taken too, or it is settled
		// that they cannot be (cluster_warm.go): limits and scenarios judge
		// the first request with what the group counted before.
		if !a.warmDone.Load() {
			return false
		}
		// A clock a minute off the group's, and the node knows it is the odd
		// one (cluster_clock.go).
		return !a.clockOut.Load()
	}
	if time.Since(a.started) <= firstSyncWait() || len(node.Reachable()) > 0 {
		return false
	}
	return node.Mark(markInStep) != ""
}

// waitInStep blocks until this node may act for its group on its own: it is
// in step, or it was once and reaches no member after the wait (the rule of
// inService, without the drain). A node that never was in step waits until
// it reaches a member, or until ctx ends.
func (a *App) waitInStep(ctx context.Context) error {
	node := a.Cluster
	for {
		if node == nil || node.Removed() || node.Synced() {
			return nil
		}
		if time.Since(a.started) > firstSyncWait() && len(node.Reachable()) == 0 && node.Mark(markInStep) != "" {
			return nil
		}
		t := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// noteReadiness says in the log when this node leaves or enters traffic by
// the rule of inService, and why it is out: a person who finds the
// readiness answer 503 finds the reason there (N3 of the second lab run:
// the log of a node that waited for its group said nothing).
func (a *App) noteReadiness() {
	node := a.Cluster
	if node == nil || a.draining.Load() {
		return
	}
	in := a.inService()
	said := a.readyNotedOnce.Swap(true)
	if was := a.readyNoted.Swap(in); said && was == in {
		return
	}
	switch {
	case in:
		a.log.Info("cluster: this node is in service (readiness 200)")
	case node.Synced():
		a.log.Info("cluster: this node is out of traffic (readiness 503): it applies what it took of its group")
	case len(node.Reachable()) > 0:
		a.log.Warn("cluster: this node is out of traffic (readiness 503): it reaches a member and has not taken the state of the group yet; when this lasts, look at the clocks (schild cluster status)")
	case node.Mark(markInStep) == "":
		a.log.Warn("cluster: this node is out of traffic (readiness 503): it never was in step with its group and reaches no member (cluster.peers, the mesh port, the cluster secret); it stays out until it reaches one")
	default:
		a.log.Info("cluster: this node is out of traffic (readiness 503): it reaches no member yet and serves alone with the state it has after the wait", "wait", firstSyncWait().String())
	}
}

// markInStep notes in the node's store that it was in step with its group
// once (see inService).
const markInStep = "in_step"

// Drain takes this node out of traffic and stops it, like SIGTERM.
func (a *App) Drain() { a.drainOnce.Do(func() { close(a.drainCh) }) }

// Draining reports whether the node left traffic.
func (a *App) Draining() bool { return a.draining.Load() }

// leaveTraffic is the first part of a stop in a group: the readiness answer
// turns to 503 and the node serves on for cluster.drain.delay_s, so the
// balancer sees it and sends new connections elsewhere before a single one
// is refused. Then the stop goes on; Caddy ends idle connections and lets
// running requests finish within cluster.drain.grace_s.
func (a *App) leaveTraffic() {
	cfg := a.Config()
	if !cfg.Cluster.Enabled || a.opts.NoListeners {
		return
	}
	a.setDraining()
	d := cfg.Cluster.Drain.Delay()
	if d <= 0 {
		return
	}
	a.log.Info("cluster: this node left traffic (readiness 503), it stops when the balancer had time to see it", "delay", d.String(), "grace", cfg.Cluster.Drain.Grace().String())
	time.Sleep(d)
}

// testGroupHashKey replaces the hash key of the group in tests that run
// nodes of two groups in one process: the keyed hashes of the behaviour
// package are one per process (behaviour.SetHashKey), so a second group
// would break the tables of the first. Nil outside those tests.
var testGroupHashKey *[16]byte

// prepareCluster runs before the behaviour engine is made: a node set up by
// configuration lets itself into its group (cluster.secret_file), and the
// keyed hashes of the engine take the key of the group, so the nodes can
// merge what they count (behaviour.SetHashKey). A node that cannot be set
// up stops the start: with cluster.enabled a gateway never runs alone.
func (a *App) prepareCluster(cfg *config.Site) error {
	if !cfg.Cluster.Enabled {
		return nil
	}
	dir := ClusterDir(a.dataDir)
	if cfg.Cluster.SecretFile != "" {
		// The same files were deployed to every node.
		secret, err := cluster.ReadSecret(cfg.Cluster.SecretFile)
		if err != nil {
			return fmt.Errorf("cluster: the node is not set up (%w); deploy the group secret to cluster.secret_file (schild cluster secret makes one), or set cluster.enabled false", err)
		}
		host, _ := os.Hostname()
		_, moved, err := cluster.Configure(dir, cfg.MemberName(host), cfg.Cluster.Address(), secret, nil)
		if moved != nil {
			a.log.Warn("cluster: cluster.secret_file names another group than this node was in: it moved there and took along what it held. The other nodes follow when they start with the same file",
				"from", moved.From, "to", moved.To, "records", moved.Carried, "left", moved.Skipped, "old_directory", moved.Aside)
		}
		switch {
		case errors.Is(err, cluster.ErrRemovedSelf):
			// A removed node serves with the state it has and shares
			// nothing, as it did before its stop (startCluster).
		case err != nil:
			return fmt.Errorf("cluster: the node is not set up from cluster.secret_file (%w); the cluster directory %s stays as it was. Fix the cause, or set cluster.enabled false", err, dir)
		}
	}
	if id, ok := cluster.Identity(dir); ok {
		a.groupNodeID = id
	}
	if key, ok := cluster.HashKey(dir); ok {
		if testGroupHashKey != nil {
			key = *testGroupHashKey
		}
		behaviour.SetHashKey(key)
		a.groupHash = true
		a.groupHashKey = key
	}
	return nil
}

// tellCounts tells the other nodes what this one counted in the last second.
func (a *App) tellCounts(ctx context.Context) {
	c := a.Behaviour.TakeCounts()
	if c == nil || a.Cluster.Removed() {
		return
	}
	body, err := json.Marshal(c)
	if err != nil {
		return
	}
	a.Cluster.Tell(ctx, tellCounts, body)
}

const tellCounts = "counts"

// startCounts makes limits and scenarios count for the group
// (behaviour/shared.go). Without the group's hash key the nodes would
// compare hashes that mean nothing to each other, so it stays off.
func (a *App) startCounts(ctx context.Context) {
	if !a.groupHash {
		a.log.Warn("cluster: this node holds no hash key of its group: limits and scenarios count per node. Stop schild, delete its cluster directory and start it again: it sets itself up from cluster.secret_file")
		a.warmDone.Store(true) // nothing is counted for the group, nothing to take
		return
	}
	a.Behaviour.EnableSharing()
	a.startWarm(ctx)
	a.Cluster.OnTell(tellCounts, func(_ string, body []byte) {
		var c behaviour.Counts
		if json.Unmarshal(body, &c) == nil {
			a.Behaviour.ApplyCounts(&c)
		}
	})
	a.goLoop(ctx, "cluster-counts", tick(time.Second, func() { a.tellCounts(ctx) }))
}

// eventNode is the name the events of this gateway carry as their source.
// In a group it is the node's name in the group (cluster.name, with
// cluster.name_from_host its host, else node_name) and ends with the start
// of the node id: the nodes tell their own events from the others' by it,
// and a deployment often gives every node the same node_name.
func (a *App) eventNode(cfg *config.Site) string {
	if a.groupNodeID == "" {
		return cfg.NodeName
	}
	host, _ := os.Hostname()
	name := cfg.MemberName(host)
	if len(name) > 48 {
		name = name[:48]
	}
	return name + "." + strings.TrimPrefix(a.groupNodeID, "n-")[:12]
}
