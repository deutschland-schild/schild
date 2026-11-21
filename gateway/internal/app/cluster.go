package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// The group of MVP-27 (D103), first version: the address blocks of every
// node act on every node.
//
// The request path does not come here. A block starts and ends in the
// engine as on a single gateway; a loop compares the blocks that run with
// what this node told the group and publishes the difference, and a record
// of another node is applied to the engine in the goroutine of the sync.

// ClusterDir is where a node keeps its key and its copy of the group's
// records.
func ClusterDir(dataDir string) string { return filepath.Join(dataDir, "cluster") }

// groupBlocks is what this node knows the group knows: per client key the
// incident and the end of the block that runs.
type groupBlocks struct {
	mu    sync.Mutex
	known map[behaviour.Key]groupBlock
}

type groupBlock struct {
	incident string
	until    time.Time
}

// startCluster opens the node and starts its loops. A gateway with
// cluster.enabled that joined no group runs alone and says so.
func (a *App) startCluster(ctx context.Context) {
	cfg := a.Config()
	if !cfg.Cluster.Enabled {
		return
	}
	a.Gate.InService = a.inService
	dir := ClusterDir(a.dataDir)
	if a.clusterSetupErr != nil {
		a.log.Error("cluster: the node is not set up from schild.yaml, this gateway runs alone", "err", a.clusterSetupErr)
		return
	}
	node, err := cluster.Open(cluster.Options{Dir: dir, Listen: cfg.Cluster.Listen, Log: a.log, Peers: cfg.Cluster.Peers})
	if errors.Is(err, cluster.ErrNoGroup) {
		a.log.Warn("cluster.enabled, but this node belongs to no group: it runs alone. Set cluster.secret_file and cluster.peers on every node, or by hand: schild cluster init on the first node, schild cluster join ADDRESS CODE on every other, then restart schild")
		return
	}
	if err != nil {
		a.log.Error("cluster: the node does not start, this gateway runs alone", "err", err)
		return
	}
	a.Cluster = node
	a.groupBlocks.known = map[behaviour.Key]groupBlock{}
	node.On(contract.ClassBlocks, a.applyGroupRecord)
	a.seedGroupBlocks()
	a.goLoop(ctx, "cluster", func(ctx context.Context) {
		if err := node.Run(ctx); err != nil {
			a.log.Error("cluster: the mesh stopped, this gateway runs with its last state", "err", err)
			<-ctx.Done()
		}
	})
	a.goLoop(ctx, "cluster-blocks", tick(250*time.Millisecond, a.publishGroupBlocks))
	a.startSharedState(ctx)
	a.startCounts(ctx)
	a.startGroupData(ctx)
	if cfg.CaddyIngress() {
		a.startGroupFiles(ctx, a.storageRoot())
	}
}

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
	if !a.Behaviour.ApplyBlock(key, b.Bits, bi) {
		// A block of this client runs here already. When it is the same
		// one (a restart), the group knows it.
		if cur, ok := a.Behaviour.ActiveBlock(key.Addr()); ok && cur.Incident == b.Incident {
			a.groupBlocks.known[key] = groupBlock{incident: b.Incident, until: until}
		}
		return false
	}
	a.groupBlocks.known[key] = groupBlock{incident: b.Incident, until: until}
	return true
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
	if node == nil {
		return
	}
	now := time.Now()
	running := a.Behaviour.RunningBlocks()
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	seen := make(map[behaviour.Key]bool, len(running))
	name := node.Name()
	for _, rb := range running {
		seen[rb.Key] = true
		if k, ok := a.groupBlocks.known[rb.Key]; ok && k.incident == rb.Incident {
			continue
		}
		until := rb.Until.UTC().Truncate(time.Second)
		blk := contract.Block{Client: rb.Key.Addr().String(), Bits: rb.Key.Bits(), Source: behaviour.BlockSource(rb.Scenario), Level: rb.Level,
			Since: contract.TimeText(rb.Since), Until: contract.TimeText(until), DurationS: max(int(rb.Duration/time.Second), 1), Incident: rb.Incident, EventID: rb.EventID,
			NetClass: rb.NetClass, Node: name}
		if _, err := node.Publish(contract.ClassBlocks, blk.Client, &blk, false, until); err != nil {
			ratelog.Warn(a.log, "cluster: block not handed to the group (it runs on this node)", "err", err)
			continue
		}
		a.groupBlocks.known[rb.Key] = groupBlock{incident: rb.Incident, until: until}
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
const firstSyncWait = 10 * time.Second

// inService is the readiness of a node of a group, next to the gate's own
// (/.schild/readyz, the health check of the balancer): not while it drains,
// and not before it took the state of the group, so a node that just
// started lets nobody pass whom the group blocks. A node that reaches no
// member serves after ten seconds with the state it has.
func (a *App) inService() bool {
	if a.draining.Load() {
		return false
	}
	node := a.Cluster
	return node == nil || node.Synced() || time.Since(a.started) > firstSyncWait
}

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
	a.draining.Store(true)
	d := cfg.Cluster.Drain.Delay()
	if d <= 0 {
		return
	}
	a.log.Info("cluster: this node left traffic (readiness 503), it stops when the balancer had time to see it", "delay", d.String(), "grace", cfg.Cluster.Drain.Grace().String())
	time.Sleep(d)
}

// prepareCluster runs before the behaviour engine is made: a node set up by
// configuration lets itself into its group (cluster.secret_file), and the
// keyed hashes of the engine take the key of the group, so the nodes can
// merge what they count (behaviour.SetHashKey).
func (a *App) prepareCluster(cfg *config.Site) {
	if !cfg.Cluster.Enabled {
		return
	}
	dir := ClusterDir(a.dataDir)
	if cfg.Cluster.SecretFile != "" {
		// The same files were deployed to every node.
		secret, err := cluster.ReadSecret(cfg.Cluster.SecretFile)
		if err == nil {
			_, err = cluster.Configure(dir, cfg.NodeName, cfg.Cluster.Address(), secret, nil)
		}
		if err != nil {
			a.clusterSetupErr = err
			return
		}
	}
	if id, ok := cluster.Identity(dir); ok {
		a.groupNodeID = id
	}
	if key, ok := cluster.HashKey(dir); ok {
		behaviour.SetHashKey(key)
		a.groupHash = true
	}
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
		a.log.Warn("cluster: this node holds no hash key of its group (it joined with an older schild): limits and scenarios count per node. Let it join again")
		return
	}
	a.Behaviour.EnableSharing()
	a.Cluster.OnTell(tellCounts, func(_ string, body []byte) {
		var c behaviour.Counts
		if json.Unmarshal(body, &c) == nil {
			a.Behaviour.ApplyCounts(&c)
		}
	})
	a.goLoop(ctx, "cluster-counts", tick(time.Second, func() { a.tellCounts(ctx) }))
}

// eventNode is the name the events of this gateway carry as their source.
// In a group it ends with the start of the node id: the nodes tell their
// own events from the others' by it, and a deployment often gives every
// node the same node_name.
func (a *App) eventNode(cfg *config.Site) string {
	if a.groupNodeID == "" {
		return cfg.NodeName
	}
	name := cfg.NodeName
	if len(name) > 48 {
		name = name[:48]
	}
	return name + "." + strings.TrimPrefix(a.groupNodeID, "n-")[:12]
}
