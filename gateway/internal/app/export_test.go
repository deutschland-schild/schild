package app

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
)

// ConfigHash is the config version the agent API shows (tests).
func (a *App) ConfigHash() string {
	if p := a.configHash.Load(); p != nil {
		return *p
	}
	return ""
}

// GroupConfigVersion is the config version a node tells its group (tests).
var GroupConfigVersion = groupConfigVersion

// TakesForeignRequest reports whether this node would store a request a
// member of its group hands over (tests).
func (a *App) TakesForeignRequest(e *reqring.Entry) bool {
	return a.groupData != nil && a.groupData.takesRequest(e, time.Now())
}

// RequestsMissed counts requests of other nodes that were gone from their
// log before this node asked (tests).
func (a *App) RequestsMissed() uint64 {
	if a.groupData == nil {
		return 0
	}
	return a.groupData.requestsMissed.Load()
}

// SetHubShare puts another hub source in for the group (tests).
func (a *App) SetHubShare(h interface {
	SharedIndex() (hub.IndexInfo, []byte, bool)
	WantsIndex(hub.IndexInfo) bool
	TakeIndex(ctx context.Context, in hub.IndexInfo, gz []byte) error
}) {
	var x hubIndex = h
	a.hubShare.Store(&x)
}

// AgeHumanCheckKeys sets when the keys of the browser check were rotated
// (tests of the rotation).
func (a *App) AgeHumanCheckKeys(ctx context.Context, at time.Time) error {
	a.humanCheckMu.Lock()
	defer a.humanCheckMu.Unlock()
	next := a.HumanCheck.State().Clone()
	next.KeysRotatedAt = at
	if err := a.storeHumanCheck(ctx, next); err != nil {
		return err
	}
	a.HumanCheck.Store(next)
	return nil
}

// CleanVitals bounds the vitals another node told (cluster_status.go).
var CleanVitals = cleanVitals

// LeaveTraffic marks the node as draining, as the first step of a stop does.
func (a *App) LeaveTraffic() { a.setDraining() }

// SetRequestsLog makes the log of served requests in memory n entries long
// for nodes started afterwards, and returns how to undo it (tests).
func SetRequestsLog(n int) (undo func()) {
	old := requestsLog
	requestsLog = n
	return func() { requestsLog = old }
}

// ClusterReasons are the baseline reasons the overview takes from the group.
func (a *App) ClusterReasons() []string { return a.clusterReasons() }

// OneGroupHashKey makes every node started from now on hash under one key,
// whatever its group: for tests that run two groups in one process. It
// returns the function that ends it.
func OneGroupHashKey() func() {
	testGroupHashKey = &[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	return func() { testGroupHashKey = nil }
}

// PullGroupMetrics asks the members for their metric buckets now, as the
// loop does every ten seconds (cluster_metrics.go).
func (a *App) PullGroupMetrics(ctx context.Context) {
	if a.groupMetrics != nil {
		a.groupMetrics.round(ctx)
	}
}

// InService is the readiness of a node of a group (cluster.go).
func (a *App) InService() bool { return a.inService() }

// SetFirstSyncWait shortens how long a node that reaches no member waits
// before it serves with the state it has, and returns how to undo it.
func SetFirstSyncWait(d time.Duration) (undo func()) {
	old := firstSyncWaitNS.Swap(int64(d))
	return func() { firstSyncWaitNS.Store(old) }
}

// WaitInStep blocks until the node may act for its group on its own
// (cluster.go).
func (a *App) WaitInStep(ctx context.Context) error { return a.waitInStep(ctx) }

// SetClocks makes the node see these clock differences to the gateways it
// reaches, instead of what they tell (tests).
func (a *App) SetClocks(f func() []time.Duration) { a.testClocks.Store(&f) }

// ClockOdd is the rule by which a node knows its clock is the odd one.
var ClockOdd = clockOdd

// WarmDone and WarmFailed report on the handover of the running counts.
func (a *App) WarmDone() bool   { return a.warmDone.Load() }
func (a *App) WarmFailed() bool { return a.warmFailed.Load() }

// SetStateDiffTimes shortens from when a difference of the state hashes is
// shown and repaired, and returns how to undo it.
func SetStateDiffTimes(shown, repair, every time.Duration) (undo func()) {
	a, b, c := stateDiffShown, stateDiffRepair, stateRepairEvery
	stateDiffShown, stateDiffRepair, stateRepairEvery = shown, repair, every
	return func() { stateDiffShown, stateDiffRepair, stateRepairEvery = a, b, c }
}

// BreakSharedKey stores a value under a key of the store and notes it as in
// step with the group, as a node would hold it that did not apply a change
// of another node.
func (a *App) BreakSharedKey(ctx context.Context, key string, v []byte) error {
	a.sharedMu.Lock()
	defer a.sharedMu.Unlock()
	if err := a.Store.Put(ctx, key, v); err != nil {
		return err
	}
	t := a.genericThing(key)
	entries, err := t.codec.split(v)
	if err != nil {
		return err
	}
	marks := a.marksOf(t)
	for k := range marks {
		delete(marks, k)
	}
	for k, e := range entries {
		marks[k] = sum(e)
	}
	a.saveMarks(t)
	return nil
}

// StateRepairs counts the repairs of the state that ran.
func (a *App) StateRepairs() int64 { return a.stateWatch.repairs.Load() }

// StateDiffers reports whether the overview names a state that differs.
func (a *App) StateDiffers() bool { return a.stateDiffers(time.Now()) }

// PerNodeTables are the tables of schild.db that stay on one node, with
// their reasons (cluster_per_node.go).
func PerNodeTables() map[string]string { return perNodeTables }

// SharedThingIDs returns the things registered by hand, per class.
func (a *App) SharedThingIDs() map[string][]string {
	out := map[string][]string{}
	for _, t := range a.sharedThings() {
		out[t.class] = append(out[t.class], t.id)
	}
	return out
}

// OrderLock reports whether a lock of the certificate storage waits for the
// node to be in step (cluster_files.go).
var OrderLock = orderLock

// SetBeforeMesh runs f right before the mesh of a node starts (startCluster),
// and returns how to undo it. Not safe while a node starts.
func SetBeforeMesh(f func(*App)) (undo func()) {
	old := testBeforeMesh
	testBeforeMesh = f
	return func() { testBeforeMesh = old }
}

// SetTestBlockRuns sets what runs right after a block of a record started on
// a node, and returns how to take it back.
func SetTestBlockRuns(f func(a *App, incident string)) (undo func()) {
	testBlockRuns.Store(&f)
	return func() { testBlockRuns.Store(nil) }
}

// SetWarmRetry sets the retry interval after a failed warm handover and returns
// how to undo it.
func SetWarmRetry(d time.Duration) (undo func()) {
	old := warmRetryNS.Swap(int64(d))
	return func() { warmRetryNS.Store(old) }
}

// SetTestLiftWrite makes f run before a node writes a lift to its group; an
// error of f is the error of the write.
func SetTestLiftWrite(f func(a *App, incident string) error) (undo func()) {
	testLiftWrite.Store(&f)
	return func() { testLiftWrite.Store(nil) }
}

// SetGroupBlocksMax sets how many running blocks this node holds before it
// hands no further block to its group.
func (a *App) SetGroupBlocksMax(n int64) { a.groupBlocks.max.Store(n) }

// SetTestClientBlocks makes f run while a node releases or erases an
// address, after it read the blocks of the client and before it acts.
func SetTestClientBlocks(f func(a *App, done bool)) (undo func()) {
	testClientBlocks.Store(&f)
	return func() { testClientBlocks.Store(nil) }
}

// GroupBlocked is the incident of the block of ip that runs on this node,
// read while no change of the node's blocks is under way.
func (a *App) GroupBlocked(ip netip.Addr) string {
	a.groupBlocks.mu.Lock()
	defer a.groupBlocks.mu.Unlock()
	bi, _ := a.Behaviour.ActiveBlock(ip)
	return bi.Incident
}

// HashedBlocks are the incident numbers the hash of blocks covers now.
func (a *App) HashedBlocks() []string {
	out, _ := a.hashedBlocks(time.Now())
	sort.Strings(out)
	return out
}

// IncidentKnown reports whether the node would draw another number than
// this one for a new block.
func (a *App) IncidentKnown(incident string) bool { return a.incidentKnown(incident) }

// SetTestUnmarkedBlocks makes f run when a node reads the kept blocks that
// do not say who decided them; an error of f is the error of the read.
func SetTestUnmarkedBlocks(f func(a *App) error) (undo func()) {
	testUnmarkedBlocks.Store(&f)
	return func() { testUnmarkedBlocks.Store(nil) }
}
