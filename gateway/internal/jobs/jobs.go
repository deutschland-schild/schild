package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Store keeps the notes of the tasks: for a single gateway rows of its own
// database, for a group records every node holds (class jobs). A note is a
// time under an id; ids are the task's name and names derived from it:
//
//	<name>          when the latest run started or last said it is alive
//	<name>.period   the period of the latest run (the instant it was due)
//	<name>.done     the latest period that was finished
//	<name>.i.<h>    the period for which the item with hash h is done
type Store interface {
	// Get returns the note under id; ok false: none.
	Get(id string) (at time.Time, ok bool)
	// Put writes the note; expires zero: it is kept.
	Put(id string, at time.Time, expires time.Time) error
}

// Lead says whether this process may run tasks now, and serialises a run
// against the others that may. A single gateway always leads.
type Lead interface {
	// Leads reports whether this process is the one that runs tasks.
	Leads() bool
	// Lock and Unlock hold the task's run against every other process.
	Lock(ctx context.Context, name string) error
	Unlock(ctx context.Context, name string)
	// Settle is how long Leads has to hold without a break before a run.
	Settle() time.Duration
}

// Task is one named task.
type Task struct {
	// Name: 1 to MaxName of a-z, 0-9, "_", "-". The same on every node.
	Name string
	// Schedule is asked at every look, so a schedule changed while the
	// process runs holds from the next look on.
	Schedule func() Schedule
	// Run does the work of one period. It may be called again for the same
	// period after a failure or a takeover: it asks run.Done before each
	// item and calls run.Note after it. An error leaves the period
	// unfinished; it is taken up again after the grace time.
	Run func(ctx context.Context, run *Run) error
	// Now is the clock (tests); nil: time.Now.
	Now func() time.Time
	// Look is how often the task is looked at; 0: one second.
	Look time.Duration
	Log  *slog.Logger
}

// ErrTooManyItems: a run noted more than MaxItems items.
var ErrTooManyItems = errors.New("jobs: a run notes at most 256 items")

// Run is one run of a task for one period.
type Run struct {
	// Period is the instant the period was due (UTC, whole seconds). The
	// same for every run of the period, on every node.
	Period time.Time
	// Resumed: the period was started before and not finished.
	Resumed bool

	st      Store
	name    string
	expires time.Time
	mu      sync.Mutex
	noted   int
}

func itemID(name, item string) string {
	h := sha256.Sum256([]byte(item))
	return name + ".i." + hex.EncodeToString(h[:8])
}

// Done reports whether item was noted as done for this period, by this
// run or by a run before it, on whichever node.
func (r *Run) Done(item string) bool {
	at, ok := r.st.Get(itemID(r.name, item))
	return ok && at.Equal(r.Period)
}

// Note records that item is done for this period. Call it after the item's
// work succeeded: between the work and the note the run may break off, and
// then the item is done once more (at least once, not exactly once).
func (r *Run) Note(item string) error {
	r.mu.Lock()
	if r.noted >= MaxItems {
		r.mu.Unlock()
		return ErrTooManyItems
	}
	r.noted++
	r.mu.Unlock()
	return r.st.Put(itemID(r.name, item), r.Period, r.expires)
}

// ValidName reports whether s names a task.
func ValidName(s string) bool {
	if s == "" || len(s) > MaxName {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

type action int

const (
	actNone action = iota
	// actBaseline: a Daily task seen for the first time starts with its
	// next occurrence; the current one is noted as done without a run.
	actBaseline
	actStart
	actResume
)

// decide says what a look at the task's notes asks for at now.
func decide(name string, s Schedule, st Store, now time.Time) (action, time.Time) {
	if s.off() || s.check() != nil {
		return actNone, time.Time{}
	}
	now = now.UTC()
	started, okS := st.Get(name)
	period, okP := st.Get(name + ".period")
	done, okD := st.Get(name + ".done")
	if !okP && okS && s.Every > 0 {
		// Written by a build that knew the start only: that run counts as
		// a finished period.
		period, okP, done, okD = started, true, started, true
	}
	finished := okP && okD && !done.Before(period)

	if s.Every > 0 {
		if !okP || !now.Before(period.Add(s.Every)) {
			return actStart, now.Truncate(time.Second)
		}
	} else {
		occ := s.latest(now)
		if occ.IsZero() {
			return actNone, time.Time{}
		}
		if !okP {
			return actBaseline, occ
		}
		late := s.MaxLate > 0 && now.Sub(occ) > s.MaxLate
		// A changed time of day must not bring a second run of a period
		// that ran: the next one is at least half a period after it.
		if occ.After(period) && occ.Sub(period) >= s.nominal()/2 && !late {
			return actStart, occ
		}
		if s.MaxLate > 0 && now.Sub(period) > s.MaxLate {
			return actNone, time.Time{}
		}
	}
	if okP && !finished {
		// Started and not finished. Silent for the grace time (or no start
		// was written at all): broken off, taken up again. A clock that
		// was put back makes the silence negative: wait.
		if !okS || now.Sub(started) >= s.grace() {
			return actResume, period
		}
	}
	return actNone, time.Time{}
}

// Loop looks at the task until ctx ends and runs it when it is due and
// this process leads. Call it on every node with the same task.
func Loop(ctx context.Context, st Store, lead Lead, t Task) {
	log := t.Log
	if log == nil {
		log = slog.Default()
	}
	if !ValidName(t.Name) || t.Schedule == nil || t.Run == nil {
		log.Error("job not started: it needs a name of a-z, 0-9, _ and -, a schedule and a task", "job", t.Name)
		return
	}
	now := t.Now
	if now == nil {
		now = time.Now
	}
	look := t.Look
	if look <= 0 {
		look = time.Second
	}
	tick := time.NewTicker(look)
	defer tick.Stop()
	var since time.Time // since when this process could run the task
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		s := t.Schedule()
		if err := s.check(); err != nil {
			continue
		}
		if act, _ := decide(t.Name, s, st, now()); act == actNone || !lead.Leads() {
			since = time.Time{}
			continue
		}
		// A process runs a task only when it led for a while without a
		// break: at its start a node has not heard from every member, and
		// one failed call does not make it the keeper.
		if since.IsZero() {
			since = now()
		}
		if now().Sub(since) < lead.Settle() {
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := lead.Lock(lctx, "job:"+t.Name)
		cancel()
		if err != nil {
			continue
		}
		once(ctx, st, lead, t, s, now, log)
		lead.Unlock(ctx, "job:"+t.Name)
	}
}

// once does what the notes ask for, under the task's lock.
func once(ctx context.Context, st Store, lead Lead, t Task, s Schedule, now func() time.Time, log *slog.Logger) {
	// Under the lock: another process may have run it in the meantime.
	act, period := decide(t.Name, s, st, now())
	if act == actNone || !lead.Leads() {
		return
	}
	if act == actBaseline {
		if err := st.Put(t.Name+".period", period, time.Time{}); err == nil {
			_ = st.Put(t.Name+".done", period, time.Time{})
		}
		return
	}
	if act == actStart {
		if err := st.Put(t.Name+".period", period, time.Time{}); err != nil {
			log.Warn("job not run: its period could not be written", "job", t.Name, "err", err)
			return
		}
	}
	if err := st.Put(t.Name, now().UTC().Truncate(time.Second), time.Time{}); err != nil {
		log.Warn("job not run: its start could not be written", "job", t.Name, "err", err)
		return
	}
	// While the task works it says so, or a long run would look broken off.
	grace := s.grace()
	rctx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		beat := time.NewTicker(grace / 3)
		defer beat.Stop()
		for {
			select {
			case <-rctx.Done():
				return
			case <-beat.C:
				_ = st.Put(t.Name, now().UTC().Truncate(time.Second), time.Time{})
			}
		}
	}()
	// The notes of the items are dropped when two periods have passed.
	expires := now().UTC().Add(min(2*s.nominal()+24*time.Hour, 40*24*time.Hour)).Truncate(time.Second)
	run := &Run{Period: period, Resumed: act == actResume, st: st, name: t.Name, expires: expires}
	err := t.Run(rctx, run)
	stop()
	wg.Wait()
	if err != nil {
		log.Warn("job failed, it is taken up again after its grace time", "job", t.Name, "period", period.Format(time.RFC3339), "grace", grace.String(), "err", err)
		return
	}
	if ctx.Err() != nil {
		return // stopped in the middle: the next process finishes it
	}
	if err := st.Put(t.Name+".done", period, time.Time{}); err != nil {
		log.Warn("job done, but that could not be written: it may run again", "job", t.Name, "err", err)
	}
}

// Alone is the Lead of a single gateway.
type Alone struct{}

func (Alone) Leads() bool                        { return true }
func (Alone) Lock(context.Context, string) error { return nil }
func (Alone) Unlock(context.Context, string)     {}
func (Alone) Settle() time.Duration              { return 0 }
