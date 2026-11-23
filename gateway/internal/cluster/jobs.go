package cluster

import (
	"context"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/jobs"
)

// Tasks that run once per period for the whole group: a rotation of keys, a
// summary by mail. The rules of a run are in package jobs, the same for a
// single gateway and for a group; this file is the group's side of it.
//
// There is no main node and no election. A task is run by the node that
// keeps the group's locks, the lowest node id among the gateways a node
// reaches (lease.go), so the role moves by itself when that node is gone.
// What a task has done is noted in records of the group (class jobs): its
// latest start, the period it runs, the period it finished and, per item,
// the period for which the item is done. Every node holds them, also the
// one that takes over: it does not run a period again that is finished, and
// it finishes one that was broken off, without doing again what is noted.
//
// A node that just became the keeper waits three seconds before it runs a
// task. So a period runs once while the nodes reach each other. Nodes that
// cannot reach each other each find a keeper on their side: then a period
// may run on both sides, and an item may be done twice. At least once, not
// exactly once: a task that must never happen twice, whatever the network
// does, does not belong here.

// keeperSettle is how long a node has to be the keeper, and the job due,
// before it runs a job.
const keeperSettle = 3 * time.Second

// LastRun returns when a job last started (or said it is alive) for the
// group; ok false: never.
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

// groupJobs keeps the notes of the tasks in records of class jobs and lets
// the keeper of the group's locks run them.
type groupJobs struct{ n *Node }

// Jobs returns where the tasks of the group keep their notes and who may
// run them (jobs.Loop).
func (n *Node) Jobs() (jobs.Store, jobs.Lead) {
	g := groupJobs{n}
	return g, g
}

func (g groupJobs) Get(id string) (time.Time, bool) {
	at, _, ok := g.n.LastRun(id)
	return at, ok
}

func (g groupJobs) Put(id string, at, expires time.Time) error {
	_, err := g.n.Publish(contract.ClassJobs, id, &contract.Job{At: contract.TimeText(at), Node: g.n.Name()}, false, expires)
	return err
}

// Leads: the node is in step with the group and keeps its locks.
func (g groupJobs) Leads() bool {
	n := g.n
	return !n.removed.Load() && n.Synced() && n.keeper() == nil
}

func (g groupJobs) Lock(ctx context.Context, name string) error { return g.n.Lock(ctx, name) }
func (g groupJobs) Unlock(ctx context.Context, name string)     { g.n.Unlock(ctx, name) }
func (g groupJobs) Settle() time.Duration                       { return keeperSettle }
