package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// IncidentsOfSource must filter by event source before applying LIMIT, so a
// backlog of foreign incidents cannot starve newer own incidents.
func TestIncidentsOfSourceFiltersBeforeLimit(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	const (
		ownSource     = "schild://web-1.000000000001"
		foreignSource = "schild://web-2.000000000002"
		batchLimit    = 500
		foreignCount  = batchLimit*4 + 100 // 2100 > limit*4
	)
	base := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	// Insert foreign events and incidents inside one transaction for speed.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	evStmt, err := tx.PrepareContext(ctx, `INSERT INTO events (id, time_ms, type, ip, incident, body, cls) VALUES (?, ?, 'schild.waf.blocked.v1', '203.0.113.1', ?, ?, 1)`)
	if err != nil {
		t.Fatal(err)
	}
	inStmt, err := tx.PrepareContext(ctx, `INSERT INTO incidents (incident, event_id, time_ms, ip, status, count, first_ms, last_ms) VALUES (?, ?, ?, '203.0.113.1', 'blocked', 1, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	foreignBody := []byte(`{"source":"` + foreignSource + `"}`)
	for i := 0; i < foreignCount; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond).UnixMilli()
		evID := fmt.Sprintf("ev-f-%d", i)
		inID := fmt.Sprintf("IN-F-%04d", i)
		if _, err := evStmt.ExecContext(ctx, evID, ts, inID, foreignBody); err != nil {
			t.Fatal(err)
		}
		if _, err := inStmt.ExecContext(ctx, inID, evID, ts, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	// Also include one malformed JSON body to ensure invalid JSON is skipped cleanly.
	badTS := base.Add(time.Duration(foreignCount) * time.Millisecond).UnixMilli()
	if _, err := evStmt.ExecContext(ctx, "ev-bad", badTS, "IN-BAD", []byte("{not-json")); err != nil {
		t.Fatal(err)
	}
	if _, err := inStmt.ExecContext(ctx, "IN-BAD", "ev-bad", badTS, badTS, badTS); err != nil {
		t.Fatal(err)
	}
	// One newer own incident after all foreign incidents.
	ownTS := base.Add(time.Duration(foreignCount+10) * time.Millisecond).UnixMilli()
	ownBody := []byte(`{"source":"` + ownSource + `"}`)
	if _, err := evStmt.ExecContext(ctx, "ev-own-1", ownTS, "IN-OWN-1", ownBody); err != nil {
		t.Fatal(err)
	}
	if _, err := inStmt.ExecContext(ctx, "IN-OWN-1", "ev-own-1", ownTS, ownTS, ownTS); err != nil {
		t.Fatal(err)
	}
	evStmt.Close()
	inStmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	got, err := s.IncidentsOfSource(ctx, ownSource, base.UnixMilli(), batchLimit)
	if err != nil {
		t.Fatalf("IncidentsOfSource: %v", err)
	}
	if len(got) != 1 || got[0].Incident != "IN-OWN-1" {
		t.Fatalf("got %d incidents (%v), want [IN-OWN-1]", len(got), got)
	}
}
