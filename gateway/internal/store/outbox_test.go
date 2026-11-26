package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func noted(t *testing.T, s *Store) []string {
	t.Helper()
	lifts, err := s.WaitingLifts(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range lifts {
		out = append(out, l.Incident)
	}
	return out
}

// A node of a group notes the lift of a block in the transaction of the
// change that made it, and the note survives a restart until the lift was
// written. A single gateway notes nothing, so no rows pile up.
func TestLiftsAreNotedForTheGroupUntilWritten(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schild.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, id := range []string{"K7QM-AAA2", "K7QM-AAA3", "K7QM-AAA4", "K7QM-AAA5"} {
		if err := s.InsertIncident(ctx, &Incident{Incident: id, Time: now, IP: "203.0.113.9", Status: "blocked"}); err != nil {
			t.Fatal(err)
		}
	}
	// A single gateway.
	if err := s.MarkUnblockedLift(ctx, "K7QM-AAA2", now, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.NoteLifts(ctx, now, "K7QM-AAA3"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteIP(ctx, "198.51.100.1", false, func(b []byte, _ string) []byte { return b }, "K7QM-AAA3"); err != nil {
		t.Fatal(err)
	}
	if got := noted(t, s); len(got) != 0 || s.LiftsWaiting() {
		t.Fatalf("a single gateway noted the lifts %v", got)
	}
	if in, _ := s.GetIncident(ctx, "K7QM-AAA2"); in.Status != "unblocked" {
		t.Fatalf("the unblock is not stored: %s", in.Status)
	}

	// A node of a group.
	if err := s.ShareLifts(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkUnblockedLift(ctx, "K7QM-AAA2", now, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an incident that is unblocked already: %v, want ErrNotFound", err)
	}
	if got := noted(t, s); len(got) != 0 {
		t.Fatalf("a lift was noted for an unblock that did not happen: %v", got)
	}
	if err := s.MarkUnblockedLift(ctx, "K7QM-AAA4", now, ""); err != nil {
		t.Fatal(err)
	}
	// An incident the node does not hold is lifted all the same, and one
	// lift per incident is noted once.
	if err := s.NoteLifts(ctx, now.Add(time.Second), "K7QM-AAA3", "K7QM-ZZZZ", "K7QM-AAA4"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteIP(ctx, "198.51.100.1", false, func(b []byte, _ string) []byte { return b }, "K7QM-AAA5"); err != nil {
		t.Fatal(err)
	}
	want := []string{"K7QM-AAA4", "K7QM-AAA3", "K7QM-ZZZZ", "K7QM-AAA5"}
	got := noted(t, s)
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("noted %v, want %v (oldest first)", got, want)
	}
	if in, _ := s.GetIncident(ctx, "K7QM-AAA3"); in.Status != "unblocked" {
		t.Fatalf("the incident of a noted lift is %s", in.Status)
	}
	if !s.LiftNoted(ctx, "K7QM-ZZZZ") || s.LiftNoted(ctx, "K7QM-AAA2") {
		t.Fatal("LiftNoted does not say what is noted")
	}
	var address int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM cluster_outbox WHERE incident LIKE '%.%' OR incident LIKE '%:%'`).Scan(&address); err != nil || address != 0 {
		t.Fatalf("the notes carry an address (%d, %v)", address, err)
	}

	// Over a restart, and until written.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err = Open(path); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.LiftsWaiting() {
		t.Fatal("lifts wait before the store was told that it is a node of a group")
	}
	if err := s.ShareLifts(ctx); err != nil {
		t.Fatal(err)
	}
	if got := noted(t, s); len(got) != len(want) || !s.LiftsWaiting() {
		t.Fatalf("after the restart %v wait, want %v", got, want)
	}
	for _, id := range want {
		if err := s.LiftWritten(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if got := noted(t, s); len(got) != 0 || s.LiftsWaiting() {
		t.Fatalf("after the writes %v wait", got)
	}
}
