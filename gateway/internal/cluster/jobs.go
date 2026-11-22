package cluster

import (
	"context"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// Tasks that run once for the whole group: a rotation of keys, later a
// notification or a report. Every node calls Every with the same name and
// interval; one of them runs the task each time it is due.
//
// There is no main node and no election. The task is run by the node that
// keeps the group's locks, the lowest node id among the gateways a node
// reaches (lease.go), so the role moves by itself when that node is gone.
// When a task last started is a record of the group (class jobs): every
// node knows it, also the one that takes over, and none runs the task again
// because it restarted or became the keeper a moment ago.
//
// A node that just became the keeper waits three seconds before it runs a
// task. The record is written before the task runs. So a task runs at most once
// per interval while the nodes reach each other; a run that fails is tried
// again with the next interval, not at once. Nodes that cannot reach each
// other each find a keeper on their side: then a task may run on both
// sides. A task that must never run twice, whatever the network does, does
// not belong here.

// keeperSettle is how long a node has to be the keeper, and the job due,
// before it runs a job.
const keeperSettle = 3 * time.Second

// LastRun returns when a job last started for the group; ok false: never.
func (n *Node) LastRun(name string) (at time.Time, node string, ok bool) {
	rec, err := n.Get(contract.ClassJobs, name)
	if err != nil || rec == nil {
		return time.Time{}, "", false
	}
	j, at, err := contract.DecodeJob(rec)
	if err != nil {
		return time.Time{}, "", false
	}
	return at, j.Node, true
}

// due reports whether this node should run the job now: it is in step with
// the group, it keeps the locks, and the interval since the last start is
// over.
func (n *Node) due(name string, every time.Duration) bool {
	if n.paused.Load() || n.removed.Load() || !n.Synced() || n.keeper() != nil {
		return false
	}
	at, _, ok := n.LastRun(name)
	return !ok || n.now().Sub(at) >= every
}

// Every runs f once per interval for the whole group until ctx ends. Call
// it on every node with the same name and interval. f gets a context that
// ends with ctx; what it returns is logged and changes nothing else.
func (n *Node) Every(ctx context.Context, name string, every time.Duration, f func(ctx context.Context) error) {
	if !contract.JobName(name) || every <= 0 {
		n.log.Error("cluster: job not started: it needs a name of a-z, 0-9, _ . - and an interval", "job", name)
		return
	}
	// Looking is one read of the node's own database: often enough that a
	// job starts within seconds of being due or of its keeper going away.
	look := min(max(every/20, time.Second), 2*time.Second)
	var since time.Time // since when this node could run the job
	t := time.NewTicker(look)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// A node runs a job only when it kept the locks for a while without
		// a break: at its start it has not heard from every member yet, and
		// one failed call does not make it the keeper.
		if !n.due(name, every) {
			since = time.Time{}
			continue
		}
		if since.IsZero() {
			since = n.now()
		}
		if n.now().Sub(since) < keeperSettle {
			continue
		}
		lock := "job:" + name
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := n.Lock(lctx, lock)
		cancel()
		if err != nil {
			continue
		}
		// Under the lock: another node may have run it in the meantime.
		if n.due(name, every) {
			if _, err := n.Publish(contract.ClassJobs, name, &contract.Job{At: contract.TimeText(n.now()), Node: n.Name()}, false, time.Time{}); err != nil {
				n.log.Warn("cluster: job not run: its start could not be written", "job", name, "err", err)
			} else if err := f(ctx); err != nil {
				n.log.Warn("cluster: job failed, it runs again with its next interval", "job", name, "err", err)
			}
		}
		n.Unlock(ctx, lock)
	}
}
