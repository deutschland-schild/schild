package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func item(id string, p Priority) Item {
	return Item{Prio: p, Kind: "signal", ID: id, ReceivedMS: time.Now().UnixMilli(), Issuer: "issuer-test-1", KeyID: "test-site-a",
		Expires: time.Now().Add(time.Hour).Unix(), Payload: json.RawMessage(`{"x":1}`)}
}

func enqueue(t *testing.T, q *Queue, items ...Item) {
	t.Helper()
	done, err := q.Enqueue(items)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPriorityOrderAndDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue")
	q, err := Open(Options{Path: path, MaxDepth: 100})
	if err != nil {
		t.Fatal(err)
	}
	enqueue(t, q, item("b1", Baseline), item("r1", Repeat), item("n1", NewPattern), item("n2", NewPattern))
	if d := q.Depth(); d != [3]int64{2, 1, 1} {
		t.Fatalf("depth %v", d)
	}
	got, err := q.Read(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].ID != "n1" || got[1].ID != "n2" || got[2].ID != "r1" {
		t.Fatalf("priority order wrong: %+v", got)
	}
	if err := q.Done(got[:2]); err != nil {
		t.Fatal(err)
	}
	q.Close()

	// Reopen: undeleted items survive, ids are still remembered.
	q, err = Open(Options{Path: path, MaxDepth: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if d := q.Depth(); d != [3]int64{0, 1, 1} {
		t.Fatalf("depth after reopen %v", d)
	}
	if q.Reserve("r1", time.Now().Add(time.Hour).Unix()) {
		t.Fatal("queued id forgotten after restart (replay)")
	}
	// Processed ids come back through Remember (from the lab store).
	q.Remember("n1", time.Now().Add(time.Hour).Unix())
	if q.Reserve("n1", time.Now().Add(time.Hour).Unix()) {
		t.Fatal("remembered id accepted again")
	}
	got, _ = q.Read(10)
	if len(got) != 2 || got[0].ID != "r1" || got[1].ID != "b1" {
		t.Fatalf("after reopen: %+v", got)
	}
}

func TestTieredAdmission(t *testing.T) {
	q, err := Open(Options{Path: filepath.Join(t.TempDir(), "q"), MaxDepth: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	var items []Item
	for i := 0; i < 80; i++ {
		items = append(items, item(fmt.Sprint("x", i), Repeat))
	}
	enqueue(t, q, items...)
	if q.Admit(Baseline, 1) {
		t.Fatal("baseline admitted at 80 %")
	}
	if !q.Admit(Repeat, 15) || q.Admit(Repeat, 16) {
		t.Fatal("repeat tier wrong")
	}
	if !q.Admit(NewPattern, 20) || q.Admit(NewPattern, 21) {
		t.Fatal("new-pattern tier wrong")
	}
}

func TestDedupeAndGC(t *testing.T) {
	q, err := Open(Options{Path: filepath.Join(t.TempDir(), "q")})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	exp := time.Now().Add(-time.Second).Unix()
	if !q.Reserve("a", time.Now().Add(time.Hour).Unix()) || q.Reserve("a", time.Now().Add(time.Hour).Unix()) {
		t.Fatal("reserve")
	}
	q.Release("a")
	if !q.Reserve("a", exp) {
		t.Fatal("released id must be reservable")
	}
	if !q.Reserve("a", time.Now().Add(time.Hour).Unix()) {
		t.Fatal("expired reservation must not block")
	}
	q.Remember("gone", time.Now().Add(time.Hour).Unix())
	q.Reserve("old", exp)
	if n := q.GC(time.Now()); n < 1 {
		t.Fatalf("GC removed %d", n)
	}
}

func TestGroupCommitUnderConcurrency(t *testing.T) {
	q, err := Open(Options{Path: filepath.Join(t.TempDir(), "q"), MaxDepth: 1_000_000})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	var wg sync.WaitGroup
	for w := 0; w < 200; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				done, err := q.Enqueue([]Item{item(fmt.Sprintf("%d-%d", w, i), NewPattern)})
				if err != nil {
					t.Error(err)
					return
				}
				if err := <-done; err != nil {
					t.Error(err)
				}
			}
		}(w)
	}
	wg.Wait()
	if d := q.Depth(); d[0] != 2000 {
		t.Fatalf("depth %v", d)
	}
	if c := q.Commits(); c >= 2000 {
		t.Fatalf("no group commit happened (%d commits for 2000 items)", c)
	}
	t.Logf("2000 items in %d commits", q.Commits())
}

func TestTornTailAndSegmentCleanup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "queue")
	q, err := Open(Options{Path: dir, SegmentBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		enqueue(t, q, item(fmt.Sprint("s", i), Repeat))
	}
	q.mu.Lock()
	segs := len(q.segs)
	q.mu.Unlock()
	if segs < 3 {
		t.Fatalf("expected rotation, got %d segments", segs)
	}
	got, _ := q.Read(30)
	if err := q.Done(got); err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	after := len(q.segs)
	q.mu.Unlock()
	if after >= segs {
		t.Fatalf("drained segments not deleted: %d -> %d", segs, after)
	}
	q.Close()
	// Simulate a crash in the middle of a write: garbage at the tail.
	ents, _ := os.ReadDir(dir)
	var last string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "seg-") {
			last = filepath.Join(dir, e.Name())
		}
	}
	f, _ := os.OpenFile(last, os.O_APPEND|os.O_WRONLY, 0o600)
	f.Write([]byte{0, 0, 1, 0, 9, 9})
	f.Close()
	q, err = Open(Options{Path: dir, SegmentBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if d := q.Depth(); d[Repeat] != 10 {
		t.Fatalf("after torn tail: depth %v, want 10 pending", d)
	}
	rest, _ := q.Read(100)
	if len(rest) != 10 || rest[0].ID != "s30" || string(rest[0].Payload) != `{"x":1}` {
		t.Fatalf("recovered items wrong: %d %+v", len(rest), rest[0])
	}
	enqueue(t, q, item("after", NewPattern)) // appends after the cut tail
	if d := q.Depth(); d[NewPattern] != 1 {
		t.Fatal("append after recovery failed")
	}
}
