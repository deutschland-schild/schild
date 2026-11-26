package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
)

// The group of MVP-27 (D105): this file opens and starts the node of a
// gateway and says when it is in service. The blocks of the group are in
// cluster_blocks.go.

// ClusterDir is where a node keeps its key and its copy of the group's
// records.
func ClusterDir(dataDir string) string { return filepath.Join(dataDir, "cluster") }

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
	a.startGroupBlocks(ctx)
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
