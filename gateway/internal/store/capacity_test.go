package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/storage"
)

// capEvent is an event of a given type and outcome with a body of size n.
func capEvent(i int, typ, outcome string, sampled bool, t time.Time, n int) *EventRow {
	body := fmt.Sprintf(`{"data":{"sampled":%t,"pad":%q}}`, sampled, strings.Repeat("x", n))
	return &EventRow{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), Time: t, Type: typ, IP: "203.0.113.9", Country: "NL",
		Method: "GET", Host: "shop.example", Path: "/", Status: 200, Outcome: outcome, Sampled: sampled, Body: []byte(body)}
}

func countWhere(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// flood writes total bytes of rows made by mk in batches over ten minutes
// of simulated time, running a retention pass whenever the scheduler says
// it is due, and returns the highest page bytes ((page_count -
// freelist_count) * page_size) and WAL size seen after a batch, the used
// bytes (pages + WAL) at the end and the largest batch.
func flood(t *testing.T, s *Store, capMB, total int, mk func(i int, at time.Time) []*EventRow, inc func(i int, at time.Time) *Incident) (peak, peakWAL, end, batch int64) {
	t.Helper()
	ctx := context.Background()
	start := time.Now().UTC().Add(-time.Hour)
	sched := NewCapScheduler(s)
	ret := Retention{RawIPDays: 7, EventsDays: 14, MaxSizeMB: capMB, SummariesDays: 90}
	run := func(now time.Time) {
		if sched.Due(now, capMB) {
			sched.Ran(now)
			res, err := s.ApplyRetention(ctx, now, ret, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.Cap != nil && res.Cap.Unreachable {
				t.Fatalf("unreachable during the flood: %+v", res.Cap)
			}
		}
	}
	run(start)
	written := s.Written()
	steps := 0
	for i := 0; s.Written()-written < int64(total); i++ {
		at := start.Add(time.Duration(i) * 10 * time.Millisecond)
		w0 := s.Written()
		if mk != nil {
			if err := s.InsertEvents(ctx, mk(i, at)); err != nil {
				t.Fatal(err)
			}
		}
		if inc != nil {
			for j := 0; j < 64; j++ {
				if err := s.InsertIncident(ctx, inc(i*64+j, at)); err != nil {
					t.Fatal(err)
				}
			}
		}
		batch = max(batch, s.Written()-w0)
		steps++
		// Ten minutes of simulated time for the whole flood.
		now := start.Add(time.Duration(steps) * 100 * time.Millisecond)
		run(now)
		peak = max(peak, s.pageBytes(ctx))
		peakWAL = max(peakWAL, s.WALBytes())
	}
	if d := time.Duration(steps) * 100 * time.Millisecond; d > 10*time.Minute {
		t.Fatalf("flood took %s of simulated time", d)
	}
	return peak, peakWAL, s.pageBytes(ctx) + s.WALBytes(), batch
}

// D38: a flood that writes 3 x the cap within 10 minutes ends at most 10 %
// above the cap (plus one write batch).
func TestCapFloodBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 30 MB")
	}
	s := open(t)
	const capMB = 10
	capBytes := int64(capMB) * storage.MiB
	peak, peakWAL, end, batch := flood(t, s, capMB, 3*capMB*storage.MiB, func(i int, at time.Time) []*EventRow {
		var rows []*EventRow
		for j := 0; j < 128; j++ {
			rows = append(rows, capEvent(i*128+j, "schild.request.evaluated.v1", "passed", true, at, 1500))
		}
		return rows
	}, nil)
	t.Logf("cap %d, peak pages %d (%.3f), peak WAL %d, end used %d (%.3f), batch %d", capBytes, peak, float64(peak)/float64(capBytes), peakWAL,
		end, float64(end)/float64(capBytes), batch)
	// Between passes the WAL grows up to the autocheckpoint (1000 pages)
	// on top of the pages; it is truncated at the end of every pass.
	if limit := capBytes + capBytes/10 + batch; peak > limit || end > limit {
		t.Fatalf("peak %d end %d over %d", peak, end, limit)
	}
	if n := countWhere(t, s, `SELECT COUNT(*) FROM events`); n < storage.FloorRows {
		t.Fatalf("%d events left", n)
	}
}

// D38: a flood of incidents never leaves 0 events: every event class keeps
// its newest FloorRows rows.
func TestCapIncidentFloodKeepsEvents(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 30 MB")
	}
	s := open(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-2 * time.Hour)
	var rows []*EventRow
	for i := 0; i < 150; i++ {
		rows = append(rows, capEvent(i, "schild.request.blocked.v1", "blocked", false, old.Add(time.Duration(i)*time.Millisecond), 1000))
		rows = append(rows, capEvent(1000+i, "schild.request.evaluated.v1", "passed", true, old.Add(time.Duration(i)*time.Millisecond), 1000))
	}
	if err := s.InsertEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	reason := strings.Repeat("r", 2000)
	_, _, _, _ = flood(t, s, 10, 30*storage.MiB, nil, func(i int, at time.Time) *Incident {
		return &Incident{Incident: fmt.Sprintf("I%09d", i), EventID: "e", Time: at, IP: "203.0.113.9", Status: "blocked", Reason: reason}
	})
	blocked := countWhere(t, s, `SELECT COUNT(*) FROM events WHERE type = 'schild.request.blocked.v1'`)
	sampled := countWhere(t, s, `SELECT COUNT(*) FROM events WHERE type = 'schild.request.evaluated.v1'`)
	if blocked != storage.FloorRows || sampled != storage.FloorRows {
		t.Fatalf("blocked %d sampled %d, want the floor %d each", blocked, sampled, storage.FloorRows)
	}
	// The newest of each class stayed.
	if _, err := s.GetEvent(ctx, rows[len(rows)-1].ID); err != nil {
		t.Fatal("newest sampled event deleted")
	}
	if n := countWhere(t, s, `SELECT COUNT(*) FROM incidents`); n < storage.FloorRows {
		t.Fatalf("%d incidents left", n)
	}
}

// D38: a flood of passed requests keeps a rule change (class record).
func TestCapPassedFloodKeepsRuleChange(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 30 MB")
	}
	s := open(t)
	ctx := context.Background()
	rule := capEvent(999999, "schild.rule.repository_updated.v1", "", false, time.Now().UTC().Add(-3*time.Hour), 200)
	if err := s.InsertEvents(ctx, []*EventRow{rule}); err != nil {
		t.Fatal(err)
	}
	_, _, _, _ = flood(t, s, 10, 30*storage.MiB, func(i int, at time.Time) []*EventRow {
		var rows []*EventRow
		for j := 0; j < 128; j++ {
			rows = append(rows, capEvent(i*128+j, "schild.request.evaluated.v1", "passed", false, at, 1500))
		}
		return rows
	}, nil)
	if _, err := s.GetEvent(ctx, rule.ID); err != nil {
		t.Fatal("rule change deleted by a flood of passed requests")
	}
}

// A mixed flood (sampled, logged and blocked rows sharing pages) stays
// within the bound too: the pass measures pages, not row sizes.
func TestCapMixedFloodBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 30 MB")
	}
	s := open(t)
	const capMB = 10
	capBytes := int64(capMB) * storage.MiB
	kinds := []struct {
		outcome string
		sampled bool
	}{{"passed", true}, {"passed", false}, {"blocked", false}}
	peak, _, end, batch := flood(t, s, capMB, 3*capMB*storage.MiB, func(i int, at time.Time) []*EventRow {
		var rows []*EventRow
		for j := 0; j < 128; j++ {
			k := kinds[j%3]
			rows = append(rows, capEvent(i*128+j, "schild.request.evaluated.v1", k.outcome, k.sampled, at, 1500))
		}
		return rows
	}, nil)
	t.Logf("cap %d, peak pages %d (%.3f), end used %d (%.3f)", capBytes, peak, float64(peak)/float64(capBytes), end, float64(end)/float64(capBytes))
	if limit := capBytes + capBytes/10 + batch; peak > limit || end > limit {
		t.Fatalf("peak %d end %d over %d", peak, end, limit)
	}
	if n := countWhere(t, s, `SELECT COUNT(*) FROM events WHERE outcome = 'blocked'`); n < storage.FloorRows {
		t.Fatalf("%d blocked rows left", n)
	}
}

// Deletion order: the oldest rows of the first class go first, the newest
// FloorRows of a class stay, later classes are not touched while an
// earlier one has rows above its floor.
func TestCapOrder(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	var rows []*EventRow
	// Blocked rows are the oldest: they still go after the sampled ones.
	for i := 0; i < 200; i++ {
		rows = append(rows, capEvent(i, "schild.request.blocked.v1", "blocked", false, base.Add(time.Duration(i)*time.Millisecond), 4000))
	}
	for i := 0; i < 2000; i++ {
		rows = append(rows, capEvent(10000+i, "schild.request.evaluated.v1", "passed", true, base.Add(time.Minute+time.Duration(i)*time.Millisecond), 4000))
	}
	if err := s.InsertEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	s.Checkpoint(ctx)
	used := s.SizeBytes()
	// A pass under the cap deletes nothing and leaves no mark.
	if _, err := s.SizeCap(ctx, int(used/storage.MiB)+10); err != nil || !s.LastCapDeleted().IsZero() {
		t.Fatalf("under the cap: %v %v", s.LastCapDeleted(), err)
	}
	capMB := int(used/storage.MiB) - 2
	res, err := s.SizeCap(ctx, capMB)
	if err != nil {
		t.Fatal(err)
	}
	// Overview.counters_24h.partial reads this mark (D36 open items).
	if s.LastCapDeleted().IsZero() {
		t.Fatal("a pass that deleted rows did not record it")
	}
	if res.Deleted[storage.ClassSampled] == 0 || res.Deleted[storage.ClassBlocked] != 0 || res.Unreachable {
		t.Fatalf("%+v", res)
	}
	if res.UsedAfter > res.CapBytes {
		t.Fatalf("used %d after the pass, cap %d", res.UsedAfter, res.CapBytes)
	}
	// The oldest sampled rows went, the newer ones stayed (no gaps).
	n := res.Deleted[storage.ClassSampled]
	for i, e := range rows[200:] {
		_, err := s.GetEvent(ctx, e.ID)
		if gone := err != nil; gone != (i < n) {
			t.Fatalf("sampled row %d: gone=%t, %d deleted", i, gone, n)
		}
	}
	// A cap far below: sampled down to its floor, then blocked down to its
	// floor, and the pass reports the cap as unreachable.
	res, err = s.SizeCap(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Unreachable {
		t.Fatalf("%+v", res)
	}
	if b, sm := countWhere(t, s, `SELECT COUNT(*) FROM events WHERE cls = ?`, classCode[storage.ClassBlocked]),
		countWhere(t, s, `SELECT COUNT(*) FROM events WHERE cls = ?`, classCode[storage.ClassSampled]); b != storage.FloorRows || sm != storage.FloorRows {
		t.Fatalf("blocked %d sampled %d", b, sm)
	}
	// Another pass deletes nothing more.
	res, err = s.SizeCap(ctx, 1)
	if err != nil || res.Total() != 0 || !res.Unreachable {
		t.Fatalf("%+v %v", res, err)
	}
}

// The scheduler: due at the first call, after 600 s, and after a tenth of
// the cap was written.
func TestCapScheduler(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	c := NewCapScheduler(s)
	if !c.Due(now, 10) {
		t.Fatal("not due at start")
	}
	c.Ran(now)
	if c.Due(now.Add(599*time.Second), 10) {
		t.Fatal("due before 600 s")
	}
	if !c.Due(now.Add(600*time.Second), 10) {
		t.Fatal("not due after 600 s")
	}
	var rows []*EventRow
	for i := 0; i < 400; i++ {
		rows = append(rows, capEvent(i, "schild.request.evaluated.v1", "passed", true, now, 3000))
	}
	if err := s.InsertEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if !c.Due(now.Add(time.Second), 10) {
		t.Fatalf("not due after %d bytes written", s.Written())
	}
	if c.Full(now.Add(time.Second)) || !c.Full(now.Add(600*time.Second)) {
		t.Fatal("full retention due only on the timer")
	}
	if c.Due(now.Add(time.Second), 100) {
		t.Fatal("due with a cap of 100 MB")
	}
}

// D38 section 4: every pass deletes ended kept blocks and allowlist entries
// past their expiry.
func TestRetentionPrunesBoundedTables(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for i, until := range []time.Time{now.Add(-time.Minute), now.Add(time.Hour)} {
		if _, err := s.DB().Exec(`INSERT INTO kept_blocks(client_key, key_bits, net_class, source, level, duration_s, since_ms, until_ms) VALUES(?, 32, 'hosting', 'behaviour:x', 1, 1, ?, ?)`,
			fmt.Sprintf("203.0.113.%d", i), ms(now.Add(-48*time.Hour)), ms(until)); err != nil {
			t.Fatal(err)
		}
	}
	for i, exp := range []string{"never", now.Add(-time.Second).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)} {
		if err := s.AddAllow(ctx, &AllowEntry{ID: fmt.Sprintf("al-%d", i), IP: fmt.Sprintf("192.0.2.%d", i), Label: "x", Level: "no_block", Expires: exp, CreatedAt: now, Source: "dashboard"}); err != nil {
			t.Fatal(err)
		}
	}
	v0 := s.AllowVersion(ctx)
	res, err := s.ApplyRetention(ctx, now, Retention{RawIPDays: 7, EventsDays: 14, MaxSizeMB: 100, SummariesDays: 90}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.KeptBlocks != 1 || res.Allow != 1 {
		t.Fatalf("%+v", res)
	}
	if bs, _ := s.ListBlocks(ctx); len(bs) != 1 || bs[0].ClientKey != "203.0.113.1" {
		t.Fatalf("%+v", bs)
	}
	al, _ := s.ListAllow(ctx)
	if len(al) != 2 || al[0].ID != "al-0" || al[1].ID != "al-2" {
		t.Fatalf("%+v", al)
	}
	if s.AllowVersion(ctx) == v0 {
		t.Fatal("allow version not bumped")
	}
}

// D38: schild.db limits its WAL to 64 MiB, and the used bytes count the
// WAL.
func TestJournalSizeLimitAndWAL(t *testing.T) {
	s := open(t)
	var n int64
	if err := s.DB().QueryRow("PRAGMA journal_size_limit").Scan(&n); err != nil || n != storage.WALLimitBytes {
		t.Fatalf("journal_size_limit %d %v", n, err)
	}
	ctx := context.Background()
	var rows []*EventRow
	for i := 0; i < 200; i++ {
		rows = append(rows, capEvent(i, "schild.request.evaluated.v1", "passed", true, time.Now(), 2000))
	}
	if err := s.InsertEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	wal := s.WALBytes()
	if wal == 0 || s.SizeBytes() != s.pageBytes(ctx)+wal {
		t.Fatalf("wal %d size %d", wal, s.SizeBytes())
	}
	s.Checkpoint(ctx)
	if w := s.WALBytes(); w != 0 {
		t.Fatalf("wal %d after a TRUNCATE checkpoint", w)
	}
}
