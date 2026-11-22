package cluster

import (
	"context"
	"sync"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/jobs"
)

// The node that runs a task for the group goes away in the middle of a run.
// The node that keeps the locks next finishes the same period after the
// grace time and does only the items the first one had not noted: what a
// task has done is a record of the group, not a memory of one node.
func TestTheNextKeeperFinishesARunAndDoesOnlyWhatIsMissing(t *testing.T) {
	a, b, c := threeNodes(t)
	nodes := []*testNode{a, b, c}
	var mu sync.Mutex
	sent := map[string][]string{} // item -> the nodes that did it
	var periods []time.Time
	stalled := make(chan string, 1)
	sched := func() jobs.Schedule { return jobs.Schedule{Every: time.Hour, Grace: jobs.MinGrace} }
	cancels := map[string]context.CancelFunc{}
	first := true
	for _, tn := range nodes {
		ctx, cancel := context.WithCancel(context.Background())
		cancels[tn.name] = cancel
		defer cancel()
		st, lead := tn.node.Jobs()
		go jobs.Loop(ctx, st, lead, jobs.Task{Name: "summary", Log: quiet(), Schedule: sched,
			Run: func(ctx context.Context, r *jobs.Run) error {
				mu.Lock()
				periods = append(periods, r.Period)
				stall := first
				first = false
				mu.Unlock()
				for _, to := range []string{"a@example.org", "b@example.org", "c@example.org"} {
					if r.Done(to) {
						continue
					}
					if stall && to == "b@example.org" {
						stalled <- tn.name
						<-ctx.Done() // the node dies here
						return ctx.Err()
					}
					mu.Lock()
					sent[to] = append(sent[to], tn.name)
					mu.Unlock()
					if err := r.Note(to); err != nil {
						return err
					}
				}
				return nil
			}})
	}
	var dead string
	select {
	case dead = <-stalled:
	case <-time.After(20 * time.Second):
		t.Fatal("no node started the task")
	}
	// The others hold the note of the first item before the node is gone.
	for _, tn := range nodes {
		waitFor(t, tn.name+" holds the note of the first item", func() bool {
			recs, err := tn.node.State(contract.ClassJobs)
			if err != nil {
				return false
			}
			n := 0
			for _, r := range recs {
				if len(r.ID) > len("summary.i.") && r.ID[:len("summary.i.")] == "summary.i." {
					n++
				}
			}
			return n == 1
		})
	}
	for _, tn := range nodes {
		if tn.name == dead {
			cancels[tn.name]()
			tn.stop()
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		mu.Lock()
		done := len(sent["c@example.org"]) > 0
		mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no other node finished the run")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for _, to := range []string{"a@example.org", "b@example.org", "c@example.org"} {
		if len(sent[to]) != 1 {
			t.Errorf("%s was served %d times, want once: %v", to, len(sent[to]), sent)
		}
	}
	if len(sent["a@example.org"]) == 1 && sent["a@example.org"][0] != dead {
		t.Errorf("the first item was not done by the node that started: %v (started: %s)", sent, dead)
	}
	if len(sent["b@example.org"]) == 1 && sent["b@example.org"][0] == dead {
		t.Errorf("the node that went away did the second item: %v", sent)
	}
	if len(periods) != 2 || !periods[0].Equal(periods[1]) {
		t.Errorf("runs %v, want two runs of one period", periods)
	}
	// The period is noted as finished on the nodes that are left.
	for _, tn := range nodes {
		if tn.name == dead {
			continue
		}
		waitFor(t, tn.name+" knows the period is finished", func() bool {
			p, _, okP := tn.node.LastRun("summary.period")
			d, _, okD := tn.node.LastRun("summary.done")
			return okP && okD && p.Equal(d)
		})
	}
}
