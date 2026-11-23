package jobs

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// memStore is a Store in memory, shared by "processes" of a test.
type memStore struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newMem() *memStore { return &memStore{m: map[string]time.Time{}} }

func (s *memStore) Get(id string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[id]
	return t, ok
}

func (s *memStore) Put(id string, at, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = at.UTC()
	return nil
}

// clock is a clock a test moves by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func berlin(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no time zone data: ", err)
	}
	return loc
}

func utc(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

func TestTimeOfDayAcrossTheChangesOfTheClockInBerlin(t *testing.T) {
	berlin(t)
	s := Schedule{Daily: true, Hour: 2, Minute: 30, Zone: "Europe/Berlin"}
	for _, c := range []struct{ now, want, why string }{
		// A usual winter day: 02:30 CET is 01:30 UTC.
		{"2026-03-28T12:00:00Z", "2026-03-28T01:30:00Z", "winter"},
		// 29 March 2026: 02:00 to 03:00 do not exist. 02:30 falls on the
		// next minute that does, 03:00 CEST, which is 01:00 UTC.
		{"2026-03-29T00:59:00Z", "2026-03-28T01:30:00Z", "the minute before the clock is put forward"},
		{"2026-03-29T01:00:00Z", "2026-03-29T01:00:00Z", "a time that does not exist runs at the next minute"},
		{"2026-03-29T12:00:00Z", "2026-03-29T01:00:00Z", "later that day"},
		// A usual summer day: 02:30 CEST is 00:30 UTC.
		{"2026-06-01T12:00:00Z", "2026-06-01T00:30:00Z", "summer"},
		// 25 October 2026: 02:00 to 03:00 exist twice. The first 02:30 is
		// CEST (00:30 UTC), the second CET (01:30 UTC): the first counts.
		{"2026-10-25T00:29:00Z", "2026-10-24T00:30:00Z", "before the first 02:30"},
		{"2026-10-25T00:30:00Z", "2026-10-25T00:30:00Z", "the first 02:30"},
		{"2026-10-25T01:30:00Z", "2026-10-25T00:30:00Z", "the second 02:30 is the same period"},
		{"2026-10-26T12:00:00Z", "2026-10-26T01:30:00Z", "winter again"},
	} {
		if got := s.latest(utc(c.now)); !got.Equal(utc(c.want)) {
			t.Errorf("%s: latest(%s) = %s, want %s", c.why, c.now, got.Format(time.RFC3339), c.want)
		}
	}
	// One day of the week only.
	mon := time.Monday
	w := Schedule{Daily: true, Hour: 7, Zone: "Europe/Berlin", Weekday: &mon}
	if got := w.latest(utc("2026-11-22T12:00:00Z")); !got.Equal(utc("2026-11-16T06:00:00Z")) { // a Sunday: last Monday
		t.Errorf("weekly: %s", got.Format(time.RFC3339))
	}
	if got := w.latest(utc("2026-11-23T06:00:00Z")); !got.Equal(utc("2026-11-23T06:00:00Z")) {
		t.Errorf("weekly at its minute: %s", got.Format(time.RFC3339))
	}
}

func TestScheduleIsChecked(t *testing.T) {
	day := time.Weekday(9)
	for _, s := range []Schedule{
		{Every: time.Hour, Daily: true},
		{Daily: true, Hour: 24},
		{Daily: true, Minute: 60},
		{Daily: true, Zone: "Mars/Olympus"},
		{Daily: true, Weekday: &day},
	} {
		if s.check() == nil {
			t.Errorf("schedule %+v accepted", s)
		}
	}
	if (Schedule{}).check() != nil || !(Schedule{}).off() {
		t.Error("the zero schedule has to be valid and off")
	}
	if (Schedule{Grace: time.Nanosecond}).grace() != MinGrace || (Schedule{Grace: 48 * time.Hour}).grace() != MaxGrace || (Schedule{}).grace() != DefaultGrace {
		t.Error("grace not bounded")
	}
}

// runner is one process that looks at a task.
type runner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func start(st Store, lead Lead, c *clock, name string, sched func() Schedule, run func(context.Context, *Run) error) *runner {
	ctx, cancel := context.WithCancel(context.Background())
	r := &runner{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		Loop(ctx, st, lead, Task{Name: name, Schedule: sched, Run: run, Now: c.now, Look: 2 * time.Millisecond})
	}()
	return r
}

func (r *runner) stop() { r.cancel(); <-r.done }

type counter struct {
	mu      sync.Mutex
	periods []time.Time
}

func (c *counter) run(_ context.Context, r *Run) error {
	c.mu.Lock()
	c.periods = append(c.periods, r.Period)
	c.mu.Unlock()
	return nil
}

func (c *counter) n() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.periods) }

func settle() { time.Sleep(60 * time.Millisecond) }

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestIntervalRunsOncePerPeriodAlsoAcrossARestartAndAClockPutBack(t *testing.T) {
	st, c, cnt := newMem(), &clock{t: utc("2026-11-22T10:00:00Z")}, &counter{}
	sched := func() Schedule { return Schedule{Every: time.Hour} }
	r := start(st, Alone{}, c, "task", sched, cnt.run)
	waitFor(t, "the first run", func() bool { return cnt.n() == 1 })
	settle()
	if cnt.n() != 1 {
		t.Fatalf("ran %d times at once", cnt.n())
	}
	// The process ends and starts again: the notes say the period ran.
	r.stop()
	r = start(st, Alone{}, c, "task", sched, cnt.run)
	settle()
	c.add(59 * time.Minute)
	settle()
	if cnt.n() != 1 {
		t.Fatalf("ran again before the interval was over, or because of the restart: %d", cnt.n())
	}
	c.add(time.Minute)
	waitFor(t, "the second run", func() bool { return cnt.n() == 2 })
	// The clock is put back a few seconds: nothing runs a second time.
	c.add(-5 * time.Second)
	settle()
	c.add(-time.Hour)
	settle()
	if cnt.n() != 2 {
		t.Fatalf("a clock that was put back made the task run again: %d", cnt.n())
	}
	r.stop()
}

func TestTimeOfDayStartsWithItsNextOccurrenceAndASwitchedOffTaskNeverRuns(t *testing.T) {
	berlin(t)
	st, c, cnt := newMem(), &clock{t: utc("2026-11-22T14:00:00Z")}, &counter{} // 15:00 in Berlin
	var mu sync.Mutex
	s := Schedule{}
	sched := func() Schedule { mu.Lock(); defer mu.Unlock(); return s }
	set := func(n Schedule) { mu.Lock(); s = n; mu.Unlock() }
	r := start(st, Alone{}, c, "summary", sched, cnt.run)
	defer r.stop()
	settle()
	if cnt.n() != 0 {
		t.Fatal("a task that is switched off ran")
	}
	// Set up at 15:00 for 07:00: it does not send for this morning.
	set(Schedule{Daily: true, Hour: 7, Zone: "Europe/Berlin"})
	settle()
	if cnt.n() != 0 {
		t.Fatal("a task set up after its time of day ran at once")
	}
	c.set(utc("2026-11-23T05:59:59Z"))
	settle()
	if cnt.n() != 0 {
		t.Fatal("ran before its time")
	}
	c.set(utc("2026-11-23T06:00:00Z"))
	waitFor(t, "the run at 07:00", func() bool { return cnt.n() == 1 })
	if !cnt.periods[0].Equal(utc("2026-11-23T06:00:00Z")) {
		t.Errorf("period %s", cnt.periods[0])
	}
}

func TestAChangedTimeOfDayBringsNoSecondRunOfAPeriodThatRan(t *testing.T) {
	berlin(t)
	st, c, cnt := newMem(), &clock{t: utc("2026-11-22T14:00:00Z")}, &counter{}
	var mu sync.Mutex
	s := Schedule{Daily: true, Hour: 7, Zone: "Europe/Berlin"}
	sched := func() Schedule { mu.Lock(); defer mu.Unlock(); return s }
	set := func(n Schedule) { mu.Lock(); s = n; mu.Unlock() }
	r := start(st, Alone{}, c, "summary", sched, cnt.run)
	defer r.stop()
	settle()
	c.set(utc("2026-11-23T06:00:00Z")) // 07:00: runs
	waitFor(t, "the run at 07:00", func() bool { return cnt.n() == 1 })
	// At noon the time is changed to 18:00. Today ran: 18:00 today is the
	// same day's summary again and is left out.
	c.set(utc("2026-11-23T11:00:00Z"))
	set(Schedule{Daily: true, Hour: 18, Zone: "Europe/Berlin"})
	settle()
	c.set(utc("2026-11-23T17:00:00Z")) // 18:00 the same day
	settle()
	if cnt.n() != 1 {
		t.Fatalf("the changed time of day made a second run on the same day: %d", cnt.n())
	}
	c.set(utc("2026-11-24T17:00:00Z")) // 18:00 the next day
	waitFor(t, "the run at 18:00 the next day", func() bool { return cnt.n() == 2 })
	// Back to 07:00 in the evening: the next morning is 13 hours later and runs.
	c.set(utc("2026-11-24T19:00:00Z"))
	set(Schedule{Daily: true, Hour: 7, Zone: "Europe/Berlin"})
	settle()
	if cnt.n() != 2 {
		t.Fatal("a change back ran at once")
	}
	c.set(utc("2026-11-25T06:00:00Z"))
	waitFor(t, "the run the next morning", func() bool { return cnt.n() == 3 })
}

func TestAPeriodNobodyWasUpForRunsOnceWhenStillCurrentAndIsNeverMadeUpInARow(t *testing.T) {
	berlin(t)
	st, c, cnt := newMem(), &clock{t: utc("2026-11-22T14:00:00Z")}, &counter{}
	sched := func() Schedule { return Schedule{Daily: true, Hour: 7, Zone: "Europe/Berlin"} }
	r := start(st, Alone{}, c, "summary", sched, cnt.run)
	settle() // first seen: starts with the next occurrence
	r.stop()
	// Nobody is up for three mornings. At the next start, in the afternoon
	// of the third day, the summary of that day runs, once.
	c.set(utc("2026-11-25T13:00:00Z"))
	r = start(st, Alone{}, c, "summary", sched, cnt.run)
	waitFor(t, "the late run", func() bool { return cnt.n() == 1 })
	settle()
	if cnt.n() != 1 || !cnt.periods[0].Equal(utc("2026-11-25T06:00:00Z")) {
		t.Fatalf("missed periods were made up, or the wrong one ran: %v", cnt.periods)
	}
	r.stop()

	// With MaxLate a period that is too old is left out.
	st, cnt = newMem(), &counter{}
	c.set(utc("2026-11-22T14:00:00Z"))
	late := func() Schedule { return Schedule{Daily: true, Hour: 7, Zone: "Europe/Berlin", MaxLate: 2 * time.Hour} }
	r = start(st, Alone{}, c, "summary", late, cnt.run)
	settle()
	r.stop()
	c.set(utc("2026-11-25T13:00:00Z")) // 7 hours after 07:00
	r = start(st, Alone{}, c, "summary", late, cnt.run)
	settle()
	if cnt.n() != 0 {
		t.Fatal("a period older than MaxLate ran")
	}
	c.set(utc("2026-11-26T06:30:00Z")) // half an hour late: runs
	waitFor(t, "the run within MaxLate", func() bool { return cnt.n() == 1 })
	r.stop()
}

// A run that fails or breaks off is taken up again after the grace time,
// for the same period, and does only the items that are not noted.
func TestABrokenRunIsTakenUpAgainAndDoesOnlyWhatIsMissing(t *testing.T) {
	st, c := newMem(), &clock{t: utc("2026-11-22T10:00:00Z")}
	sched := func() Schedule { return Schedule{Every: 24 * time.Hour, Grace: 10 * time.Second} }
	var mu sync.Mutex
	sent := map[string]int{}
	var periods []time.Time
	var resumed []bool
	fail := true
	run := func(_ context.Context, r *Run) error {
		mu.Lock()
		periods = append(periods, r.Period)
		resumed = append(resumed, r.Resumed)
		failNow := fail
		mu.Unlock()
		for _, to := range []string{"a@example.org", "b@example.org", "c@example.org"} {
			if r.Done(to) {
				continue
			}
			if failNow && to == "b@example.org" {
				return errors.New("mail server away")
			}
			mu.Lock()
			sent[to]++
			mu.Unlock()
			if err := r.Note(to); err != nil {
				return err
			}
		}
		return nil
	}
	r := start(st, Alone{}, c, "summary", sched, run)
	defer r.stop()
	waitFor(t, "the first run", func() bool { mu.Lock(); defer mu.Unlock(); return len(periods) == 1 })
	settle()
	// Within the grace time nothing is tried again.
	c.add(9 * time.Second)
	settle()
	mu.Lock()
	if len(periods) != 1 {
		t.Fatalf("tried again within the grace time: %d runs", len(periods))
	}
	fail = false
	mu.Unlock()
	c.add(2 * time.Second)
	waitFor(t, "the run is taken up again", func() bool { mu.Lock(); defer mu.Unlock(); return len(periods) == 2 })
	settle()
	mu.Lock()
	defer mu.Unlock()
	if !periods[0].Equal(periods[1]) || resumed[0] || !resumed[1] {
		t.Errorf("the second run is not the same period taken up again: periods %v, resumed %v", periods, resumed)
	}
	for _, to := range []string{"a@example.org", "b@example.org", "c@example.org"} {
		if sent[to] != 1 {
			t.Errorf("%s was served %d times, want once: %v", to, sent[to], sent)
		}
	}
	if len(periods) != 2 {
		t.Errorf("a finished period ran again: %d runs", len(periods))
	}
}

// lead is a Lead a test switches.
type lead struct {
	mu    sync.Mutex
	leads bool
	lock  *sync.Mutex
}

func (l *lead) Leads() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.leads }
func (l *lead) set(v bool)  { l.mu.Lock(); l.leads = v; l.mu.Unlock() }
func (l *lead) Lock(context.Context, string) error {
	l.lock.Lock()
	return nil
}
func (l *lead) Unlock(context.Context, string) { l.lock.Unlock() }
func (l *lead) Settle() time.Duration          { return 0 }

// The process that runs a task dies in the middle: the one that takes over
// finishes the period after the grace time and does only what is missing.
// While the first one works (it says so), nobody takes the run from it.
func TestATakeOverFinishesTheRunOfTheProcessThatDied(t *testing.T) {
	st, c := newMem(), &clock{t: utc("2026-11-22T10:00:00Z")}
	sched := func() Schedule { return Schedule{Every: 24 * time.Hour, Grace: 9 * time.Second} }
	lk := &sync.Mutex{}
	first, second := &lead{leads: true, lock: lk}, &lead{lock: lk}
	var mu sync.Mutex
	sent := map[string][]string{}
	hang := make(chan struct{})
	run := func(who string, stall bool) func(context.Context, *Run) error {
		return func(ctx context.Context, r *Run) error {
			for _, to := range []string{"a", "b", "c"} {
				if r.Done(to) {
					continue
				}
				if stall && to == "b" {
					close(hang)
					<-ctx.Done() // dies here
					return ctx.Err()
				}
				mu.Lock()
				sent[to] = append(sent[to], who)
				mu.Unlock()
				if err := r.Note(to); err != nil {
					return err
				}
			}
			return nil
		}
	}
	r1 := start(st, first, c, "summary", sched, run("first", true))
	r2 := start(st, second, c, "summary", sched, run("second", false))
	defer r2.stop()
	<-hang
	// The first one dies; the second one leads from now on.
	first.set(false)
	r1.stop()
	second.set(true)
	c.add(8 * time.Second)
	settle()
	mu.Lock()
	if len(sent["b"]) != 0 {
		t.Fatal("the run was taken over within the grace time")
	}
	mu.Unlock()
	c.add(2 * time.Second)
	waitFor(t, "the second one finishes the run", func() bool { mu.Lock(); defer mu.Unlock(); return len(sent["c"]) == 1 })
	settle()
	mu.Lock()
	defer mu.Unlock()
	if len(sent["a"]) != 1 || sent["a"][0] != "first" || len(sent["b"]) != 1 || sent["b"][0] != "second" || len(sent["c"]) != 1 {
		t.Errorf("after the take-over: %v, want a by the first, b and c by the second, each once", sent)
	}
	if done, ok := st.Get("summary.done"); !ok || !done.Equal(utc("2026-11-22T10:00:00Z")) {
		t.Errorf("the period is not noted as finished: %v %v", done, ok)
	}
}

// Two processes that both lead (as far as each knows) are held apart by the
// lock: the period runs once.
func TestTwoProcessesRunAPeriodOnce(t *testing.T) {
	st, c, cnt := newMem(), &clock{t: utc("2026-11-22T10:00:00Z")}, &counter{}
	sched := func() Schedule { return Schedule{Every: time.Hour} }
	lk := &sync.Mutex{}
	var rs []*runner
	for i := 0; i < 4; i++ {
		rs = append(rs, start(st, &lead{leads: true, lock: lk}, c, "task", sched, cnt.run))
	}
	for round := 1; round <= 5; round++ {
		waitFor(t, "a run", func() bool { return cnt.n() == round })
		settle()
		if cnt.n() != round {
			t.Fatalf("round %d: ran %d times", round, cnt.n())
		}
		c.add(time.Hour)
	}
	for _, r := range rs {
		r.stop()
	}
}

func TestARunNotesABoundedNumberOfItemsAndNamesAreChecked(t *testing.T) {
	st := newMem()
	r := &Run{Period: utc("2026-11-22T10:00:00Z"), st: st, name: "task"}
	for i := 0; i < MaxItems; i++ {
		if err := r.Note(string(rune('a'+i%26)) + time.Duration(i).String()); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Note("one more"); !errors.Is(err, ErrTooManyItems) {
		t.Errorf("item %d: %v", MaxItems+1, err)
	}
	// The same item of another period is not done.
	if (&Run{Period: utc("2026-11-23T10:00:00Z"), st: st, name: "task"}).Done("a0s") {
		t.Error("an item noted for one period counts for the next")
	}
	for _, n := range []string{"", "Upper", "with.dot", "with space", "abcdefghijklmnopqrstuvwxyzabcdefghijklmno"} {
		if ValidName(n) {
			t.Errorf("name %q accepted", n)
		}
	}
	if !ValidName("daily_summary") || len(itemID("abcdefghijklmnopqrstuvwxyzabcdefghijklmn", "x")) > 64 {
		t.Error("a valid name refused, or an item id longer than a job record's id")
	}
}

// A record of a build that knew the start of a job only counts as a period
// that ran: the first node of the new build does not run the task again.
func TestNotesOfTheBuildBeforeCountAsAFinishedPeriod(t *testing.T) {
	st, c, cnt := newMem(), &clock{t: utc("2026-11-22T10:00:00Z")}, &counter{}
	_ = st.Put("task", utc("2026-11-22T09:30:00Z"), time.Time{})
	r := start(st, Alone{}, c, "task", func() Schedule { return Schedule{Every: time.Hour} }, cnt.run)
	defer r.stop()
	settle()
	if cnt.n() != 0 {
		t.Fatal("ran although the build before ran it half an hour ago")
	}
	c.add(30 * time.Minute)
	waitFor(t, "the run when the interval is over", func() bool { return cnt.n() == 1 })
}
