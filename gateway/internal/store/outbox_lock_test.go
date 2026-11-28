package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The paths that note a lift, the round that removes written ones and the
// question whether a lift is noted run side by side without standing in
// each other's way: the lock of the outbox and the write lock of the
// database are taken in one order. (A note that held the write lock and
// waited for the outbox, against a removal that held the outbox and waited
// for the write lock, stood for the 10 s of busy_timeout, with every other
// writer of schild.db behind it.) And the question never waits behind a
// transaction: the request path asks it.
func TestNotingAndRemovingLiftsDoNotStandInEachOthersWay(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	s.ShareLifts()
	const writers, rounds = 4, 40
	// A path that stands behind another waits for the busy timeout of the
	// database, 10 s. The bound lies below that and well above what the
	// work takes on a loaded machine with the race detector (about 2 s on
	// a hosted runner that runs other packages beside this one).
	const stall = 8 * time.Second
	start := time.Now()
	stop := make(chan struct{})
	var wg, loops sync.WaitGroup
	var failed atomic.Value
	fail := func(err error) {
		if err != nil {
			failed.CompareAndSwap(nil, err.Error())
		}
	}
	// The round: removes what it finds.
	loops.Add(1)
	go func() {
		defer loops.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			lifts, err := s.WaitingLifts(ctx, 50)
			fail(err)
			for _, l := range lifts {
				fail(s.LiftWritten(ctx, l.Incident))
			}
		}
	}()
	// The request path: asks, and must never wait long.
	var slowest atomic.Int64
	loops.Add(1)
	go func() {
		defer loops.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			t0 := time.Now()
			s.LiftNoted("K7QM-AAA2")
			if d := int64(time.Since(t0)); d > slowest.Load() {
				slowest.Store(d)
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()
	for w := 0; w < writers; w++ {
		for kind := 0; kind < 3; kind++ {
			wg.Add(1)
			go func(w, kind int) {
				defer wg.Done()
				for i := 0; i < rounds; i++ {
					id := fmt.Sprintf("K%dW%d-%04d", kind, w, i)
					switch kind {
					case 0:
						fail(s.NoteLifts(ctx, time.Now(), id))
					case 1:
						fail(s.MarkUnblockedLift(ctx, Unblock{Incident: id, At: time.Now(), Live: true, Lift: true}))
					default:
						_, err := s.DeleteIP(ctx, fmt.Sprintf("198.51.%d.%d", w, i), false, func(b []byte, _ string) []byte { return b }, id)
						fail(err)
					}
				}
			}(w, kind)
		}
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(stall):
		t.Fatalf("the paths that note lifts stand after %s (first error: %v)", stall, failed.Load())
	}
	// What is left is removed, and nothing stays in memory.
	deadline := time.Now().Add(2 * time.Second)
	for s.LiftsWaiting() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	loops.Wait()
	if err := failed.Load(); err != nil {
		t.Fatalf("a path failed: %v", err)
	}
	if took := time.Since(start); took > stall {
		t.Errorf("%d notes and their removal took %s, want under %s: a path stood behind another", 3*writers*rounds, took.Round(time.Millisecond), stall)
	}
	if d := time.Duration(slowest.Load()); d > 100*time.Millisecond {
		t.Errorf("the question whether a lift is noted waited %s: it stood behind a transaction", d.Round(time.Millisecond))
	}
	if s.LiftsWaiting() || len(noted(t, s)) != 0 {
		t.Errorf("after every lift was written the store says waiting %v, rows %v", s.LiftsWaiting(), noted(t, s))
	}
}
