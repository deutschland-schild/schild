//go:build !release

package app_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/jobs"
)

// testClock is a clock a test moves by hand.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// A single gateway runs a task once per period, also across a restart: when
// it last ran is in schild.db. A feature calls the same function as on a
// node of a group.
func TestSingleGatewayRunsATaskOncePerPeriodAcrossARestart(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}
	defer app.SetJobsClock(clock.now, 5*time.Millisecond)()
	var runs atomic.Int32
	sched := func() jobs.Schedule { return jobs.Schedule{Every: time.Hour} }
	run := func(context.Context, *jobs.Run) error { runs.Add(1); return nil }
	dir := t.TempDir()
	h := apptest.New(t, apptest.Options{Dir: dir})
	if h.App.Cluster != nil {
		t.Fatal("a single gateway has a cluster node")
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.App.OncePerPeriod(ctx, "test_task", sched, run)
	h.WaitFor("the task ran", func() bool { return runs.Load() == 1 })
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if runs.Load() != 1 {
		t.Fatalf("ran %d times in its first period", runs.Load())
	}
	// The same gateway starts again, half an hour later: the period ran.
	clock.add(30 * time.Minute)
	h = apptest.New(t, apptest.Options{Dir: dir})
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	h.App.OncePerPeriod(ctx, "test_task", sched, run)
	time.Sleep(300 * time.Millisecond)
	if runs.Load() != 1 {
		t.Fatalf("the restart made the task run again: %d", runs.Load())
	}
	clock.add(30 * time.Minute)
	h.WaitFor("the task ran when its interval was over", func() bool { return runs.Load() == 2 })
}

// A task that notes what it has done picks up after a failure where it
// stopped, on a single gateway as in a group.
func TestSingleGatewayTakesUpAFailedRunWhereItStopped(t *testing.T) {
	// 10:00 of today: the note of an item expires by the real clock, three
	// days after the period (a fixed date fails from then on), and the test
	// must not run into the next period.
	clock := &testClock{t: time.Now().UTC().Truncate(24 * time.Hour).Add(10 * time.Hour)}
	defer app.SetJobsClock(clock.now, 5*time.Millisecond)()
	h := apptest.New(t, apptest.Options{})
	var mu sync.Mutex
	sent := map[string]int{}
	calls, fail := 0, true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.App.OncePerPeriod(ctx, "test_mail",
		func() jobs.Schedule { return jobs.Schedule{Every: 24 * time.Hour, Grace: 10 * time.Second} },
		func(_ context.Context, r *jobs.Run) error {
			mu.Lock()
			calls++
			failNow := fail
			mu.Unlock()
			for _, to := range []string{"a", "b"} {
				if r.Done(to) {
					continue
				}
				if failNow && to == "b" {
					return context.DeadlineExceeded
				}
				mu.Lock()
				sent[to]++
				mu.Unlock()
				if err := r.Note(to); err != nil {
					return err
				}
			}
			return nil
		})
	h.WaitFor("the first run", func() bool { mu.Lock(); defer mu.Unlock(); return calls == 1 })
	mu.Lock()
	fail = false
	mu.Unlock()
	clock.add(11 * time.Second)
	h.WaitFor("the run is taken up again", func() bool { mu.Lock(); defer mu.Unlock(); return sent["b"] == 1 })
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if sent["a"] != 1 || sent["b"] != 1 || calls != 2 {
		t.Errorf("sent %v in %d runs, want each once in two runs", sent, calls)
	}
}

// A single gateway rotates the keys of the browser check while it runs,
// not only at its start: the task is the one the group runs.
func TestSingleGatewayRotatesBrowserCheckKeysWhileItRuns(t *testing.T) {
	clock := &testClock{t: time.Now().UTC()}
	defer app.SetJobsClock(clock.now, 5*time.Millisecond)()
	h := apptest.New(t, apptest.Options{})
	key := string(h.App.HumanCheck.State().ClearanceKey)
	// The first look finds young keys and changes nothing.
	time.Sleep(200 * time.Millisecond)
	if string(h.App.HumanCheck.State().ClearanceKey) != key {
		t.Fatal("young keys were rotated")
	}
	if err := h.App.AgeHumanCheckKeys(context.Background(), time.Now().UTC().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	clock.add(time.Hour + time.Second)
	h.WaitFor("the keys are rotated", func() bool {
		st := h.App.HumanCheck.State()
		return string(st.ClearanceKey) != key && string(st.PrevClearanceKey) == key
	})
}
