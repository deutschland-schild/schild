package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIncidentAggregateHits(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 29, 12, 0, 10, 0, time.UTC)
	if err := s.InsertIncident(ctx, &Incident{Incident: "K7QM-4XWD", EventID: "00000000-0000-4000-8000-000000000001", Time: t0, IP: "203.0.113.42", Status: "blocked"}); err != nil {
		t.Fatal(err)
	}
	in, err := s.GetIncident(ctx, "K7QM-4XWD")
	if err != nil {
		t.Fatal(err)
	}
	if in.Count != 1 || !in.FirstSeen.Equal(t0) || !in.LastSeen.Equal(t0) {
		t.Fatalf("new incident: %+v", in)
	}
	missing, err := s.AddIncidentHits(ctx, []IncidentHits{
		{Incident: "K7QM-4XWD", Count: 4, FirstMS: t0.Add(-2 * time.Second).UnixMilli(), LastMS: t0.Add(30 * time.Second).UnixMilli()},
		{Incident: "A2BC-3DEF", Count: 1, FirstMS: t0.UnixMilli(), LastMS: t0.UnixMilli()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].Incident != "A2BC-3DEF" {
		t.Fatalf("missing = %+v", missing)
	}
	if _, err := s.AddIncidentHits(ctx, []IncidentHits{{Incident: "K7QM-4XWD", Count: 2, FirstMS: t0.UnixMilli(), LastMS: t0.Add(10 * time.Second).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	in, _ = s.GetIncident(ctx, "K7QM-4XWD")
	if in.Count != 7 || !in.FirstSeen.Equal(t0.Add(-2*time.Second)) || !in.LastSeen.Equal(t0.Add(30*time.Second)) || !in.Time.Equal(t0) {
		t.Fatalf("aggregated: count %d first %v last %v time %v", in.Count, in.FirstSeen, in.LastSeen, in.Time)
	}
	list, err := s.IncidentsBetween(ctx, t0.Add(-time.Minute), t0.Add(time.Minute), "", 10)
	if err != nil || len(list) != 1 || list[0].Count != 7 {
		t.Fatalf("list: %v %+v", err, list)
	}
}

// Open creates a new or empty file with the schema and its version and
// opens it again; a database with tables of a pre-release build (no schema
// version) is refused with the path in the error and left unchanged. The
// upgrades between releases are in migrate_test.go (D75).
func TestSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schild.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var v int
	if err := s.DB().QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != latestVersion() {
		t.Fatalf("user_version %d (%v)", v, err)
	}
	s.Close()
	if s, err = Open(path); err != nil {
		t.Fatal(err)
	}
	s.Close()

	for _, migrate := range []bool{false, true} {
		old := filepath.Join(t.TempDir(), "schild.db")
		db, err := sql.Open("sqlite", "file:"+old)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE TABLE incidents (incident TEXT PRIMARY KEY, event_id TEXT NOT NULL, time_ms INTEGER NOT NULL);
			INSERT INTO incidents VALUES('K7QM-4XWD', 'e', 1793016000000);`); err != nil {
			t.Fatal(err)
		}
		db.Close()
		s, err := openDB(old, migrate, nil)
		if err == nil {
			s.Close()
			t.Fatalf("migrate %v: opened", migrate)
		}
		if !strings.Contains(err.Error(), old) || !strings.Contains(err.Error(), "pre-release") || !strings.Contains(err.Error(), "move the file away") {
			t.Fatalf("migrate %v: %v", migrate, err)
		}
		db, _ = sql.Open("sqlite", "file:"+old)
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("migrate %v: %d tables after the refusal (%v)", migrate, n, err)
		}
		db.Close()
		if m, _ := filepath.Glob(old + ".backup*"); len(m) > 0 {
			t.Fatalf("migrate %v: backup of a refused database: %v", migrate, m)
		}
	}
}

// A node of a group stores the incident of a block of another node from the
// block's record, before the incident itself arrives: the incident then
// fills in what the record did not say, and an incident this node wrote
// itself keeps its own values.
func TestMergeIncidentFillsARowMadeFromABlock(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 22, 12, 0, 10, 0, time.UTC)
	if err := s.InsertIncident(ctx, &Incident{Incident: "K7QM-4XWD", Time: t0, IP: "203.0.113.42", Status: "blocked", Sources: []string{"dashboard"}}); err != nil {
		t.Fatal(err)
	}
	full := &Incident{Incident: "K7QM-4XWD", EventID: "00000000-0000-4000-8000-000000000001", Time: t0.Add(-time.Second), IP: "203.0.113.42", Status: "blocked",
		Reason: "Manuell gesperrt", Sources: []string{"dashboard"}, Site: "shop"}
	if err := s.MergeIncident(ctx, full); err != nil {
		t.Fatal(err)
	}
	in, err := s.GetIncident(ctx, "K7QM-4XWD")
	if err != nil {
		t.Fatal(err)
	}
	if in.Reason != "Manuell gesperrt" || in.Site != "shop" || in.EventID != full.EventID || !in.Time.Equal(full.Time) {
		t.Fatalf("the row made from the block was not filled in: %+v", in)
	}
	// Another incident with other values does not rewrite one that is complete.
	other := *full
	other.Reason, other.Site = "anders", "blog"
	if err := s.MergeIncident(ctx, &other); err != nil {
		t.Fatal(err)
	}
	if in, _ = s.GetIncident(ctx, "K7QM-4XWD"); in.Reason != "Manuell gesperrt" || in.Site != "shop" {
		t.Fatalf("a complete incident was rewritten: %+v", in)
	}
}
