package store

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
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
	if err := s.MarkUnblockedLift(ctx, Unblock{Incident: "K7QM-AAA2", At: now, AllowEntry: "", Lift: true}); err != nil {
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
	s.ShareLifts()
	if err := s.MarkUnblockedLift(ctx, Unblock{Incident: "K7QM-AAA2", At: now, AllowEntry: "", Lift: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an incident that is unblocked already: %v, want ErrNotFound", err)
	}
	if got := noted(t, s); len(got) != 0 {
		t.Fatalf("a lift was noted for an unblock that did not happen: %v", got)
	}
	if err := s.MarkUnblockedLift(ctx, Unblock{Incident: "K7QM-AAA4", At: now, AllowEntry: "", Lift: true}); err != nil {
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
	if !s.LiftNoted("K7QM-ZZZZ") || s.LiftNoted("K7QM-AAA2") {
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
	s.ShareLifts()
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

// A node of a group notes lifts from the moment it says that it is one:
// the switch is no call that can fail, and what waited before the start is
// known when the store opened (a failed read at the start once left the
// switch off, and every lift of that process was lost without a word).
func TestLiftsAreNotedFromTheStartOfANode(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schild.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.ShareLifts()
	if err := s.NoteLifts(ctx, time.Now(), "K7QM-AAA2"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err = Open(path); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The start of the node, while the lifts cannot be read: the table is
	// away for a moment.
	if _, err := s.DB().Exec(`ALTER TABLE cluster_outbox RENAME TO away`); err != nil {
		t.Fatal(err)
	}
	s.ShareLifts()
	if !s.LiftsWaiting() {
		t.Fatal("a node that could not read its lifts yet says that none waits")
	}
	if _, err := s.WaitingLifts(ctx, 10); err == nil {
		t.Fatal("the lifts were read without their table")
	}
	if _, err := s.DB().Exec(`ALTER TABLE away RENAME TO cluster_outbox`); err != nil {
		t.Fatal(err)
	}
	// From then on every release is noted, and the lift from before the
	// restart is found with the next look.
	if err := s.NoteLifts(ctx, time.Now(), "K7QM-AAA3"); err != nil {
		t.Fatal(err)
	}
	if got := noted(t, s); len(got) != 2 || !s.LiftNoted("K7QM-AAA2") || !s.LiftNoted("K7QM-AAA3") {
		t.Fatalf("%v wait, want the lift from before the restart and the one after the failed read", got)
	}
}

// The unblock of an incident whose block the allowlist entry of the same
// request ended first: the reference to the entry and the lift for the
// group are one transaction.
func TestUnblockAfterTheAllowlistEndedTheBlockNotesItsLift(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	s.ShareLifts()
	now := time.Now()
	if err := s.InsertIncident(ctx, &Incident{Incident: "K7QM-AAA2", Time: now, IP: "203.0.113.9", Status: "blocked"}); err != nil {
		t.Fatal(err)
	}
	// Sink.Ended of the engine: unblocked, no reference, no lift.
	if err := s.MarkUnblocked(ctx, "K7QM-AAA2", now, ""); err != nil {
		t.Fatal(err)
	}
	if s.LiftsWaiting() {
		t.Fatal("the end of a block by the allowlist noted a lift")
	}
	if err := s.MarkUnblockedLift(ctx, Unblock{Incident: "K7QM-AAA2", At: now, AllowEntry: "entry-1", Lift: true}); err != nil {
		t.Fatal(err)
	}
	in, err := s.GetIncident(ctx, "K7QM-AAA2")
	if err != nil || in.AllowlistEntry != "entry-1" || !s.LiftNoted("K7QM-AAA2") {
		t.Fatalf("incident %+v (%v), lift noted: %v", in, err, s.LiftNoted("K7QM-AAA2"))
	}
	// A second unblock finds the reference set and notes nothing new.
	if err := s.MarkUnblockedLift(ctx, Unblock{Incident: "K7QM-AAA2", At: now, AllowEntry: "entry-2", Lift: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second unblock: %v, want ErrNotFound", err)
	}
}

// A kept block carries who decided it: this gateway, another node of its
// group, or nobody says (a row of a build before the mark). A gateway in no
// group owns the rows that do not say, and never one it took from a group.
func TestKeptBlockCarriesWhoDecidedIt(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	b := events.ActiveBlock{ClientKey: "203.0.113.1", KeyBits: 32, NetClass: "hosting", Source: "dashboard", Level: 1, DurationS: 172800,
		Since: "2026-11-26T10:00:00Z", Until: "2026-11-28T10:00:00Z", Incident: "K7QM-AAA2"}
	if err := s.PutBlock(ctx, b); err != nil {
		t.Fatal(err)
	}
	b.ClientKey, b.Incident = "203.0.113.2", "K7QM-AAA3"
	if err := s.PutTakenBlock(ctx, b); err != nil {
		t.Fatal(err)
	}
	// As 0.1.0-alpha.6 wrote rows: without the column.
	for _, k := range []string{"203.0.113.3", "203.0.113.4"} {
		if _, err := s.DB().Exec(`INSERT INTO kept_blocks(client_key, key_bits, net_class, source, level, duration_s, since_ms, until_ms, incident)
			VALUES(?, 32, 'hosting', 'dashboard', 1, 172800, 1, 2, ?)`, k, "K7QM-"+k[len(k)-1:]); err != nil {
			t.Fatal(err)
		}
	}
	state := func() (taken []string, unmarked map[string]string) {
		t.Helper()
		taken, err := s.TakenBlocks(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if unmarked, err = s.UnmarkedBlocks(ctx); err != nil {
			t.Fatal(err)
		}
		sort.Strings(taken)
		return taken, unmarked
	}
	taken, unmarked := state()
	if len(taken) != 1 || taken[0] != "203.0.113.2" || len(unmarked) != 2 || unmarked["203.0.113.3"] != "K7QM-3" {
		t.Fatalf("taken %v, not marked %v: want the taken block, and the two rows of the build before as not marked", taken, unmarked)
	}
	// A node of a group decides on one of them, each way, and once.
	if err := s.MarkKeptBlock(ctx, "203.0.113.3", false); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkKeptBlock(ctx, "203.0.113.3", true); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkKeptBlock(ctx, "203.0.113.1", false); err != nil {
		t.Fatal(err)
	}
	if taken, unmarked = state(); len(taken) != 2 || taken[1] != "203.0.113.3" || len(unmarked) != 1 {
		t.Fatalf("after the node decided: taken %v, not marked %v", taken, unmarked)
	}
	// A gateway in no group owns what does not say, and nothing it took.
	if err := s.OwnKeptBlocks(ctx); err != nil {
		t.Fatal(err)
	}
	if taken, unmarked = state(); len(taken) != 2 || len(unmarked) != 0 {
		t.Fatalf("after a start in no group: taken %v, not marked %v, want the taken blocks as they were", taken, unmarked)
	}
	if all, _ := s.ListBlocks(ctx); len(all) != 4 {
		t.Fatalf("%d kept blocks, want 4", len(all))
	}
}

// The unblock a person made: with the lifts of the other blocks of the
// client, of a block that runs although its incident reads unblocked, and
// of an incident that has no block.
func TestUnblockOfAPerson(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	s.ShareLifts()
	now := time.Now()
	for _, id := range []string{"K7QM-AAA2", "K7QM-AAA3", "K7QM-AAA4", "K7QM-AAA5", "K7QM-AAA6"} {
		if err := s.InsertIncident(ctx, &Incident{Incident: id, Time: now, IP: "203.0.113.9", Status: "blocked"}); err != nil {
			t.Fatal(err)
		}
	}
	status := func(id string) string {
		in, err := s.GetIncident(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return in.Status + " " + in.AllowlistEntry
	}
	// With the other blocks of the client, one of them of an incident the
	// node does not hold.
	if err := s.MarkUnblockedLift(ctx, Unblock{Incident: "K7QM-AAA2", At: now, AllowEntry: "entry-1", Lift: true, Others: []string{"K7QM-AAA3", "K7QM-AAA2", "K7QM-ZZZZ"}}); err != nil {
		t.Fatal(err)
	}
	if status("K7QM-AAA2") != "unblocked entry-1" || status("K7QM-AAA3") != "unblocked " {
		t.Fatalf("the clicked incident is %q, the other %q: want both unblocked, the entry with the clicked one alone", status("K7QM-AAA2"), status("K7QM-AAA3"))
	}
	if got := noted(t, s); len(got) != 3 || !s.LiftNoted("K7QM-AAA3") || !s.LiftNoted("K7QM-ZZZZ") {
		t.Fatalf("noted %v, want one lift for each of the three incidents", got)
	}
	// An incident without a block: unblocked, no lift, and no other.
	if err := s.MarkUnblockedLift(ctx, Unblock{Incident: "K7QM-AAA4", At: now, Others: []string{"K7QM-AAA5"}}); err != nil {
		t.Fatal(err)
	}
	if status("K7QM-AAA4") != "unblocked " || status("K7QM-AAA5") != "blocked " || s.LiftNoted("K7QM-AAA4") || s.LiftNoted("K7QM-AAA5") {
		t.Fatalf("an unblock without a lift: %q, %q, lifts %v", status("K7QM-AAA4"), status("K7QM-AAA5"), noted(t, s))
	}
	// A block that runs although its incident reads unblocked.
	if err := s.MarkUnblocked(ctx, "K7QM-AAA6", now, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkUnblockedLift(ctx, Unblock{Incident: "K7QM-AAA6", At: now, Lift: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an incident that is unblocked and has no running block: %v, want ErrNotFound", err)
	}
	if s.LiftNoted("K7QM-AAA6") {
		t.Fatal("a lift was noted for an unblock that did not happen")
	}
	if err := s.MarkUnblockedLift(ctx, Unblock{Incident: "K7QM-AAA6", At: now, Live: true, Lift: true}); err != nil {
		t.Fatal(err)
	}
	if !s.LiftNoted("K7QM-AAA6") {
		t.Fatal("no lift for the block that runs although its incident reads unblocked")
	}
}

// A lift is in memory when its note is committed, as one step for the
// round that removes it: a lift written to the group right after the
// commit does not stay in memory.
func TestLiftWrittenRightAfterItsNoteLeavesNothingBehind(t *testing.T) {
	ctx := context.Background()
	for name, note := range map[string]func(s *Store) error{
		"NoteLifts": func(s *Store) error { return s.NoteLifts(ctx, time.Now(), "K7QM-AAA2") },
		"DeleteIP": func(s *Store) error {
			_, err := s.DeleteIP(ctx, "198.51.100.1", false, func(b []byte, _ string) []byte { return b }, "K7QM-AAA2")
			return err
		},
		"MarkUnblockedLift": func(s *Store) error {
			return s.MarkUnblockedLift(ctx, Unblock{Incident: "K7QM-AAA2", At: time.Now(), Live: true, Lift: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			s.ShareLifts()
			written := make(chan error, 1)
			outboxCommitted = func() {
				// The round finds the row and writes the lift at once.
				go func() { written <- s.LiftWritten(ctx, "K7QM-AAA2") }()
				time.Sleep(100 * time.Millisecond)
			}
			defer func() { outboxCommitted = nil }()
			if err := note(s); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if s.LiftNoted("K7QM-AAA2") || s.LiftsWaiting() || len(noted(t, s)) != 0 {
				t.Fatalf("the lift is written and removed, and the store says: noted %v, waiting %v, rows %v", s.LiftNoted("K7QM-AAA2"), s.LiftsWaiting(), noted(t, s))
			}
		})
	}
}
