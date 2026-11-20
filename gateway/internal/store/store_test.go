package store

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestFilesPrivate: the database and its -wal and -shm files hold visitor
// addresses and are readable by the owner only, also when the database is
// new (SQLite gives -wal and -shm the mode of the database file).
func TestFilesPrivate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "schild.db")
	check := func(s *Store) {
		t.Helper()
		if err := s.InsertEvents(context.Background(), []*EventRow{ev(1, "203.0.113.42", time.Now())}); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{p, p + "-wal", p + "-shm"} {
			st, err := os.Stat(f)
			if err != nil {
				t.Fatal(err)
			}
			if m := st.Mode().Perm(); m != 0o600 {
				t.Errorf("%s: mode %o, want 600", filepath.Base(f), m)
			}
		}
	}
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	check(s)
	// Files left world-readable (copied in, or another umask) are narrowed.
	for _, f := range []string{p, p + "-wal", p + "-shm"} {
		if err := os.Chmod(f, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	check(s2)
	s.Close()
}

func ev(i int, ip string, t time.Time) *EventRow {
	return &EventRow{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), Time: t, Type: "schild.request.evaluated.v1", IP: ip, Country: "NL",
		ASN: 64500, Method: "GET", Host: "shop.example", Path: fmt.Sprintf("/p/%d", i%3), Status: 200, Outcome: "passed",
		Rules: []string{"930120"}, Body: []byte(fmt.Sprintf(`{"data":{"client":{"ip":%q}}}`, ip))}
}

func TestEventsListFilterCursor(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	var rows []*EventRow
	for i := 1; i <= 25; i++ {
		ip := "203.0.113.42"
		if i%2 == 0 {
			ip = "198.51.100.7"
		}
		rows = append(rows, ev(i, ip, now.Add(time.Duration(i)*time.Second)))
	}
	rows[3].Incident = "K7QM-4XWD"
	rows[3].Outcome = "blocked"
	if err := s.InsertEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	// Paging through everything returns every row exactly once, newest first.
	seen := map[string]bool{}
	var cursor int64
	pages := 0
	for {
		page, next, err := s.ListEvents(ctx, EventFilter{}, cursor, 10)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, e := range page {
			if seen[e.ID] {
				t.Fatal("duplicate across pages")
			}
			seen[e.ID] = true
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	if len(seen) != 25 || pages != 3 {
		t.Fatalf("got %d rows in %d pages", len(seen), pages)
	}
	for f, want := range map[string]EventFilter{
		"13": {IP: "203.0.113.42"},
		"12": {IP: "198.51.100.0/24"},
		"1":  {Outcome: "blocked"},
		"25": {Rule: "930120"},
		"8":  {Path: "/p/0"},
		"0":  {Rule: "93012"},
	} {
		n, err := s.CountEvents(ctx, want)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(n) != f {
			t.Errorf("filter %+v: got %d want %s", want, n, f)
		}
	}
	if _, _, err := s.ListEvents(ctx, EventFilter{IP: "not-an-ip"}, 0, 10); err == nil {
		t.Fatal("invalid ip filter must fail")
	}
	after, err := s.EventsAfter(ctx, EventFilter{}, rows[20].Seq, 100)
	if err != nil || len(after) != 4 {
		t.Fatalf("after: %d %v", len(after), err)
	}
	got, err := s.GetEvent(ctx, rows[0].ID)
	if err != nil || got.IP != "203.0.113.42" {
		t.Fatal(err)
	}
	if _, err := s.GetEvent(ctx, "nope"); err != ErrNotFound {
		t.Fatal(err)
	}
}

func TestPrivacyAndRetention(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-8 * 24 * time.Hour)
	rows := []*EventRow{ev(1, "203.0.113.42", old), ev(2, "203.0.113.42", now), ev(3, "198.51.100.7", now)}
	rows[1].Incident = "K7QM-4XWD"
	if err := s.InsertEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	_ = s.InsertIncident(ctx, &Incident{Incident: "K7QM-4XWD", EventID: rows[1].ID, Time: now, IP: "203.0.113.42", Status: "blocked", Sources: []string{"crs"}})
	_ = s.AddAllow(ctx, &AllowEntry{IP: "203.0.113.42", Label: "x", Level: "no_block", Expires: "never", CreatedAt: now, Source: "dashboard"})

	sum, err := s.SummarizeIP(ctx, "203.0.113.42")
	if err != nil || sum.Events != 2 || len(sum.Incidents) != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
	trunc := func(b []byte, short string) []byte { return bytes.ReplaceAll(b, []byte("203.0.113.42"), []byte(short)) }
	res, err := s.ApplyRetention(ctx, now, Retention{RawIPDays: 7, EventsDays: 14, MaxSizeMB: 100, SummariesDays: 90}, trunc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated != 1 {
		t.Fatalf("truncated %d", res.Truncated)
	}
	e, _ := s.GetEvent(ctx, rows[0].ID)
	if e.IP != "203.0.113.0" || bytes.Contains(e.Body, []byte("203.0.113.42")) {
		t.Fatalf("not truncated: %s %s", e.IP, e.Body)
	}
	// Delete keeping incidents: the blocked event stays with a truncated address.
	v0 := s.AllowVersion(ctx)
	del, err := s.DeleteIP(ctx, "203.0.113.42", true, trunc)
	if err != nil {
		t.Fatal(err)
	}
	if del.Events != 0 || del.Allowlist != 1 {
		t.Fatalf("%+v", del)
	}
	if s.AllowVersion(ctx) == v0 {
		t.Fatal("allow version not bumped")
	}
	if n, _ := s.CountEvents(ctx, EventFilter{IP: "203.0.113.42"}); n != 0 {
		t.Fatalf("%d events still hold the address", n)
	}
	inc, _ := s.GetIncident(ctx, "K7QM-4XWD")
	if inc.IP != "203.0.113.0" {
		t.Fatal(inc.IP)
	}
	del, err = s.DeleteIP(ctx, "198.51.100.7", false, trunc)
	if err != nil || del.Events != 1 {
		t.Fatalf("%+v %v", del, err)
	}
	// Old events go after events_days.
	_ = s.InsertEvents(ctx, []*EventRow{ev(9, "192.0.2.1", now.Add(-15*24*time.Hour))})
	res, _ = s.ApplyRetention(ctx, now, Retention{RawIPDays: 7, EventsDays: 14, MaxSizeMB: 100, SummariesDays: 90}, trunc)
	if res.Deleted != 1 {
		t.Fatalf("deleted %d", res.Deleted)
	}
}

func TestSizeCap(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	big := bytes.Repeat([]byte("x"), 8000)
	var rows []*EventRow
	for i := 0; i < 3000; i++ {
		e := ev(i, "203.0.113.1", now)
		e.Body = big
		rows = append(rows, e)
	}
	if err := s.InsertEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if s.SizeBytes() < 20<<20 {
		t.Fatalf("db too small for the test: %d", s.SizeBytes())
	}
	res, err := s.ApplyRetention(ctx, now, Retention{RawIPDays: 7, EventsDays: 14, MaxSizeMB: 10, SummariesDays: 90}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.SizeBytes() > 10<<20 || res.DeletedSize == 0 {
		t.Fatalf("size %d after cap, deleted %d", s.SizeBytes(), res.DeletedSize)
	}
	// Newest events are kept.
	if _, err := s.GetEvent(ctx, rows[2999].ID); err != nil {
		t.Fatal("newest event deleted")
	}
}

// The agent API call log is a bounded ring, and the size cap trims it
// before any event (MVP-21 measurement: call log rows pushed out events).
func TestAgentCallLogNeverPushesOutEvents(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	var rows []*EventRow
	for i := 0; i < 50; i++ {
		rows = append(rows, ev(i, "203.0.113.1", now))
	}
	if err := s.InsertEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	// Twice the ring of successful calls with large fields.
	batch := make([]AgentCall, 0, 1000)
	for i := 0; i < 2*AgentCallsMax; i++ {
		batch = append(batch, AgentCall{TokenID: "tok_test", Time: now, Op: "getMonitoringNow" + strings.Repeat("x", 100), Status: 200, Rows: 1, Bytes: 1000})
		if len(batch) == cap(batch) {
			if err := s.LogAgentCalls(ctx, batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	var n int
	_ = s.DB().QueryRow(`SELECT COUNT(*) FROM agent_calls`).Scan(&n)
	if n != AgentCallsMax {
		t.Fatalf("call log has %d rows, want the ring of %d", n, AgentCallsMax)
	}
	// A size cap below the call log: the call log is trimmed (at most its
	// older half per pass, never wiped, D38), the events stay.
	s.Checkpoint(ctx)
	size := s.SizeBytes()
	res, err := s.ApplyRetention(ctx, now, Retention{RawIPDays: 7, EventsDays: 14, MaxSizeMB: int(size>>20) - 2, SummariesDays: 90}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.DeletedSize != 0 {
		t.Fatalf("size cap deleted %d events while the call log had rows", res.DeletedSize)
	}
	for _, e := range rows {
		if _, err := s.GetEvent(ctx, e.ID); err != nil {
			t.Fatalf("event %s deleted", e.ID)
		}
	}
	_ = s.DB().QueryRow(`SELECT COUNT(*) FROM agent_calls`).Scan(&n)
	if n == AgentCallsMax || n < AgentCallsMax/2 {
		t.Fatalf("call log has %d rows after the pass, want trimmed to at least its newer half", n)
	}
	if res.Cap == nil || res.Cap.Calls != AgentCallsMax-n {
		t.Fatalf("cap result %+v", res.Cap)
	}
	// The newest call survives.
	var newest int64
	_ = s.DB().QueryRow(`SELECT MAX(seq) FROM agent_calls`).Scan(&newest)
	if newest == 0 {
		t.Fatal("newest call deleted")
	}
}

func TestUsersSessions(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if s.HasUsers(ctx) {
		t.Fatal("fresh db has users")
	}
	if err := s.CreateFirstUser(ctx, User{Name: "admin", Hash: "h", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirstUser(ctx, User{Name: "evil", Hash: "h", Role: "admin"}); err == nil {
		t.Fatal("second first user must fail")
	}
	now := time.Now()
	_ = s.CreateSession(ctx, Session{TokenHash: "t", User: "admin", CSRF: "c", Created: now, Expires: now.Add(time.Hour)})
	if _, err := s.GetSession(ctx, "t", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "t", now.Add(2*time.Hour)); err != ErrNotFound {
		t.Fatal("expired session returned")
	}
	_ = s.SetPassword(ctx, "admin", "h2")
	if _, err := s.GetSession(ctx, "t", now); err != ErrNotFound {
		t.Fatal("password change must end sessions")
	}
}
