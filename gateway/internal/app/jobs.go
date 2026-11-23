package app

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/jobs"
)

// oncePerPeriod runs a named task once per period: on a single gateway once
// for that gateway, on a node of a group once for the group, on the node
// that keeps the group's locks. It is the way for anything that must not
// happen once per node and must not be forgotten either: a rotation of
// keys, a summary by mail. A feature calls it the same way in both cases.
//
//   - schedule is asked at every look (once a second), so a time of day
//     changed in the dashboard holds at once. The zero jobs.Schedule
//     switches the task off.
//   - run does the work of one period. A run that returns an error, or that
//     ends with the process, leaves the period unfinished: it is taken up
//     again after the schedule's grace time, by this node or by the node
//     that took over. run asks r.Done(item) before each item and calls
//     r.Note(item) after it, so a run that is taken up does only what is
//     missing (at most jobs.MaxItems items a run).
//   - At least once, not exactly once: an item is done again when the run
//     broke off between the item and its note, and in a group whose nodes
//     cannot reach each other the task may run on both sides.
//
// Every node of a group has to call it with the same name.
func (a *App) oncePerPeriod(ctx context.Context, name string, schedule func() jobs.Schedule, run func(context.Context, *jobs.Run) error) {
	var st jobs.Store = &localJobs{a: a}
	var lead jobs.Lead = jobs.Alone{}
	if node := a.Cluster; node != nil {
		st, lead = node.Jobs()
	}
	task := jobs.Task{Name: name, Schedule: schedule, Run: run, Now: jobsNow, Look: jobsLook, Log: a.log}
	a.goLoop(ctx, "job-"+name, func(ctx context.Context) { jobs.Loop(ctx, st, lead, task) })
}

// jobsNow and jobsLook are the clock and the pace of the tasks (variables
// for tests).
var (
	jobsNow  func() time.Time
	jobsLook time.Duration
)

// localJobsKey holds the notes of the tasks of a single gateway in
// schild.db. A node of a group keeps them in records of the group instead
// (cluster.Node.Jobs); this key is per node and is not shared.
const localJobsKey = "jobs_local_v1"

type localNote struct {
	At      time.Time `json:"at"`
	Expires time.Time `json:"expires,omitzero"`
}

// localJobs is the jobs.Store of a single gateway: one small value in
// schild.db, read and written whole.
type localJobs struct{ a *App }

// localJobsMu serialises the notes of all tasks: they share one value, and
// two tasks that write at once must not lose each other's note.
var localJobsMu sync.Mutex

func (l *localJobs) load() map[string]localNote {
	m := map[string]localNote{}
	if raw, err := l.a.Store.Get(context.Background(), localJobsKey); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func (l *localJobs) Get(id string) (time.Time, bool) {
	localJobsMu.Lock()
	defer localJobsMu.Unlock()
	n, ok := l.load()[id]
	return n.At, ok
}

func (l *localJobs) Put(id string, at, expires time.Time) error {
	localJobsMu.Lock()
	defer localJobsMu.Unlock()
	m := l.load()
	now := time.Now()
	for k, n := range m {
		if !n.Expires.IsZero() && n.Expires.Before(now) {
			delete(m, k)
		}
	}
	m[id] = localNote{At: at.UTC(), Expires: expires}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return l.a.Store.Put(context.Background(), localJobsKey, raw)
}

// startJobs starts the tasks that run once per period, for a single
// gateway and for a group alike.
func (a *App) startJobs(ctx context.Context) {
	// The keys of the browser check: looked at every hour, rotated when
	// they are older than a day. A single gateway used to rotate them at
	// its start only; now it does while it runs too.
	a.oncePerPeriod(ctx, jobHumanCheckKeys,
		func() jobs.Schedule { return jobs.Schedule{Every: humanCheckKeysLook, Grace: 10 * time.Minute} },
		func(ctx context.Context, _ *jobs.Run) error { return a.rotateHumanCheckKeys(ctx) })
}

// humanCheckKeysLook is how often the age of the browser check's keys is
// looked at (a variable for tests).
var humanCheckKeysLook = time.Hour
