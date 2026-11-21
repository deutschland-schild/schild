package app

import (
	"context"
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
	dir := ClusterDir(a.dataDir)
	if cfg.Cluster.SecretFile != "" {
		// Set up by configuration: the node lets itself into the group of
		// the secret, as on every other node the same files were deployed to.
		secret, err := cluster.ReadSecret(cfg.Cluster.SecretFile)
		if err == nil {
			_, err = cluster.Configure(dir, cfg.NodeName, cfg.Cluster.Address(), secret, nil)
		}
		if err != nil {
			a.log.Error("cluster: the node is not set up from schild.yaml, this gateway runs alone", "err", err)
			return
		}
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
