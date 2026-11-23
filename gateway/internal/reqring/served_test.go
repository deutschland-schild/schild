package reqring

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func servedRing(t *testing.T, max, maxBytes int) *Ring {
	t.Helper()
	r, err := New(Config{StoragePath: t.TempDir(), RawPath: rawPaths})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	r.Tee(max, maxBytes)
	return r
}

// rawPaths: records keep the real path, as on the gateway (D63).
func rawPaths(string) bool { return true }

func served(i int, ip string) *Entry {
	return &Entry{T: time.Now().UnixMilli(), Client: netip.MustParseAddr(ip), Host: "shop.example", RawPath: fmt.Sprintf("/p/%d", i), Template: "/p/{n}"}
}

// The served log hands out what came after a cursor, once, in order.
func TestServedLogAnswersAfterACursor(t *testing.T) {
	r := servedRing(t, 100, 1<<20)
	if rows, first, next := r.Served(0, 10, 1<<20); len(rows) != 0 || first != 1 || next != 0 {
		t.Fatalf("empty log: %d rows, first %d, next %d", len(rows), first, next)
	}
	for i := 1; i <= 25; i++ {
		r.Add(served(i, "203.0.113.5"))
	}
	var got []string
	cursor := uint64(0)
	for round := 0; round < 10; round++ {
		rows, first, next := r.Served(cursor, 10, 1<<20)
		if first != 1 {
			t.Fatalf("first %d", first)
		}
		for _, e := range rows {
			got = append(got, e.RawPath)
		}
		if next == cursor {
			break
		}
		cursor = next
	}
	if len(got) != 25 || got[0] != "/p/1" || got[24] != "/p/25" || cursor != 25 {
		t.Fatalf("got %d rows (%v), cursor %d", len(got), got, cursor)
	}
	// Nothing twice, and a cursor of another run of the node gets nothing.
	if rows, _, next := r.Served(25, 10, 1<<20); len(rows) != 0 || next != 25 {
		t.Errorf("after the end: %d rows, next %d", len(rows), next)
	}
	if rows, _, next := r.Served(9999, 10, 1<<20); len(rows) != 0 || next != 25 {
		t.Errorf("a cursor beyond the log: %d rows, next %d", len(rows), next)
	}
	// An answer is bounded by bytes too.
	if rows, _, next := r.Served(0, 100, 200); len(rows) == 0 || len(rows) > 3 || next != uint64(len(rows)) {
		t.Errorf("an answer of about 200 bytes: %d rows, next %d", len(rows), next)
	}
}

// The log in memory is bounded by entries and by the bytes of their
// strings: the oldest leave it. They stay in the segments, and an answer to
// a cursor further back comes from there.
func TestServedLogIsBoundedAndTheDiskGoesOn(t *testing.T) {
	r := servedRing(t, 8, 1<<20)
	for i := 1; i <= 20; i++ {
		r.Add(served(i, "203.0.113.5"))
	}
	// Memory holds 13 to 20; 4 to 12 come from disk, then memory goes on.
	rows, first, next := r.Served(3, 100, 1<<20)
	if first != 1 || next != 12 || len(rows) != 9 || rows[0].RawPath != "/p/4" || rows[8].RawPath != "/p/12" {
		t.Fatalf("from disk: first %d, next %d, %d rows", first, next, len(rows))
	}
	rows, _, next = r.Served(next, 100, 1<<20)
	if next != 20 || len(rows) != 8 || rows[0].RawPath != "/p/13" {
		t.Fatalf("then memory: next %d, %d rows", next, len(rows))
	}
	// An answer from disk is bounded like one from memory.
	if rows, _, next := r.Served(0, 5, 1<<20); len(rows) != 5 || next != 5 {
		t.Fatalf("5 from disk: %d rows, next %d", len(rows), next)
	}
	// 1 KiB of strings in memory: entries of about 400 bytes fit twice.
	r = servedRing(t, 1000, 1024)
	for i := 1; i <= 10; i++ {
		e := served(i, "203.0.113.5")
		e.UA = strings.Repeat("u", 380)
		r.Add(e)
	}
	rows, _, next = r.Served(8, 100, 1<<20)
	if len(rows) != 2 || next != 10 {
		t.Fatalf("bounded by bytes: %d rows, next %d", len(rows), next)
	}
}

// What a node served is still handed out after it restarted: the numbers
// go on above the old ones, the name of the run stays, and nothing comes
// twice.
func TestServedLogSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	open := func() *Ring {
		r, err := New(Config{StoragePath: dir, RawPath: rawPaths})
		if err != nil {
			t.Fatal(err)
		}
		r.Tee(100, 1<<20)
		return r
	}
	r := open()
	epoch := r.ServedEpoch()
	for i := 1; i <= 30; i++ {
		e := served(i, "203.0.113.5")
		e.UA, e.Referrer, e.EventID, e.Status, e.Site = "curl/8", "example.org", "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", 403, "shop"
		e.Rules[0], e.NRules, e.Score, e.Outcome, e.Country = "942100", 1, 5, OutBlockedWAF, [2]byte{'D', 'E'}
		r.Add(e)
	}
	rows, _, cursor := r.Served(0, 10, 1<<20) // another node took the first ten, then went away
	if len(rows) != 10 || cursor != 10 {
		t.Fatalf("before the restart: %d rows, cursor %d", len(rows), cursor)
	}
	r.Close()

	r = open()
	defer r.Close()
	if r.ServedEpoch() != epoch || epoch == "" {
		t.Fatalf("the run of numbers is named %q after the restart, %q before", r.ServedEpoch(), epoch)
	}
	for i := 31; i <= 35; i++ {
		r.Add(served(i, "203.0.113.5"))
	}
	var got []Entry
	for round := 0; round < 20; round++ {
		rows, first, next := r.Served(cursor, 7, 1<<20)
		if first != 1 {
			t.Fatalf("first %d: nothing was deleted", first)
		}
		got = append(got, rows...)
		if next == cursor {
			break
		}
		cursor = next
	}
	if len(got) != 25 {
		t.Fatalf("after the restart the other node gets %d requests, 25 were open", len(got))
	}
	for i, e := range got {
		if want := fmt.Sprintf("/p/%d", i+11); e.RawPath != want {
			t.Fatalf("row %d is %s, want %s", i, e.RawPath, want)
		}
		if i > 0 && e.Seq <= got[i-1].Seq {
			t.Fatalf("numbers not rising at row %d", i)
		}
	}
	// What came from disk carries what the record holds.
	e := got[0]
	if e.Client.String() != "203.0.113.5" || e.Host != "shop.example" || e.UA != "curl/8" || e.Referrer != "example.org" || e.Site != "shop" ||
		e.EventID != "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b" || e.Status != 403 || e.Rules[0] != "942100" || e.NRules != 1 || e.Score != 5 ||
		e.Outcome != OutBlockedWAF || e.Country != [2]byte{'D', 'E'} {
		t.Errorf("a request from disk lost fields: %+v", e)
	}
	if got[20].Seq <= got[19].Seq+1000 {
		t.Errorf("the numbers of the new run (%d) do not jump above the old (%d)", got[20].Seq, got[19].Seq)
	}
}

// A request another node served carries no number here: this node never
// hands it on as its own.
func TestForeignRequestsAreNotServedOn(t *testing.T) {
	r := servedRing(t, 4, 1<<20)
	for i := 1; i <= 10; i++ {
		r.Add(served(i, "203.0.113.5"))
		f := served(100+i, "203.0.113.9")
		f.Seq = uint64(5000 + i) // the number it had on the node that served it
		r.AddForeign(f)
	}
	var got []Entry
	cursor := uint64(0)
	for round := 0; round < 10; round++ {
		rows, _, next := r.Served(cursor, 100, 1<<20)
		got = append(got, rows...)
		if next == cursor {
			break
		}
		cursor = next
	}
	if len(got) != 10 {
		t.Fatalf("%d rows, this node served 10", len(got))
	}
	for _, e := range got {
		if e.Client.String() != "203.0.113.5" {
			t.Errorf("handed on a request of another node: %s", e.RawPath)
		}
	}
}

// An erased address is not handed out from disk either, and the numbers of
// the others stay.
func TestForgetIPHoldsForTheServedLogOnDisk(t *testing.T) {
	r := servedRing(t, 2, 1<<20)
	r.Start(context.Background())
	for i := 1; i <= 12; i++ {
		ip := "203.0.113.5"
		if i%2 == 0 {
			ip = "203.0.113.6"
		}
		r.Add(served(i, ip))
	}
	if _, err := r.ForgetIP(context.Background(), netip.MustParseAddr("203.0.113.6")); err != nil {
		t.Fatal(err)
	}
	var got []Entry
	cursor := uint64(0)
	for round := 0; round < 10; round++ {
		rows, _, next := r.Served(cursor, 100, 1<<20)
		got = append(got, rows...)
		if next == cursor {
			break
		}
		cursor = next
	}
	if len(got) != 6 {
		t.Fatalf("%d rows after the erasure, 6 are of the other address", len(got))
	}
	for i, e := range got {
		if e.Client.String() != "203.0.113.5" || e.Seq != uint64(2*i+1) {
			t.Errorf("row %d: %s number %d", i, e.Client, e.Seq)
		}
	}
}

// Segments deleted by retention take their numbers with them: the answer
// names the lowest number that is still certain, so a node whose cursor
// lies below knows it missed requests for good.
func TestServedLogNamesWhatRetentionDeleted(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	r, err := New(Config{StoragePath: t.TempDir(), RawPath: rawPaths, KeepHours: 1, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.Tee(2, 1<<20)
	add := func(i int) {
		e := served(i, "203.0.113.5")
		e.T = now.UnixMilli()
		r.Add(e)
	}
	for i := 1; i <= 5; i++ {
		add(i)
	}
	r.Flush()
	now = now.Add(3 * time.Hour)
	for i := 6; i <= 9; i++ {
		add(i)
	}
	r.Flush()
	r.housekeep(now) // closes the old segment and deletes it
	rows, first, _ := r.Served(2, 100, 1<<20)
	if first != 6 {
		t.Fatalf("first %d after the segment with 1 to 5 was deleted", first)
	}
	if len(rows) == 0 || rows[0].RawPath != "/p/6" {
		t.Fatalf("the answer starts at %v", rows)
	}
}

// A segment of a version without numbers still reads, and holds nothing to
// hand out.
func TestRecordWithoutNumberStillDecodes(t *testing.T) {
	rec := Rec{T: 1000, Site: "s", Host: "h", Path: "/", UA: "ua", IP: netip.MustParseAddr("203.0.113.5")}
	old := appendRec(nil, &rec, 0, nil)
	rec.Seq = 77
	withSeq := appendRec(nil, &rec, 0, nil)
	if len(withSeq) != len(old)+1 {
		t.Fatalf("the number costs %d bytes", len(withSeq)-len(old))
	}
	var got Rec
	if err := decodeRec(old, 0, nil, &got); err != nil || got.Seq != 0 || got.UA != "ua" {
		t.Fatalf("old record: %v, %+v", err, got)
	}
	if err := decodeRec(withSeq, 0, nil, &got); err != nil || got.Seq != 77 || got.UA != "ua" {
		t.Fatalf("record with a number: %v, %+v", err, got)
	}
}

// An erased address leaves the served log: no node that asks later gets its
// requests, and the numbers of the others do not move.
func TestForgetIPTakesAnAddressOutOfTheServedLog(t *testing.T) {
	r := servedRing(t, 100, 1<<20)
	r.Start(context.Background())
	for i := 1; i <= 6; i++ {
		ip := "203.0.113.5"
		if i%2 == 0 {
			ip = "203.0.113.6"
		}
		r.Add(served(i, ip))
	}
	if _, err := r.ForgetIP(context.Background(), netip.MustParseAddr("203.0.113.6")); err != nil {
		t.Fatal(err)
	}
	rows, first, next := r.Served(0, 100, 1<<20)
	if len(rows) != 3 || first != 1 || next != 6 {
		t.Fatalf("after the erasure: %d rows, first %d, next %d", len(rows), first, next)
	}
	for _, e := range rows {
		if e.Client.String() != "203.0.113.5" {
			t.Errorf("the log still hands out %s", e.Client)
		}
	}
}

// Add stays free of allocations with the served log, also when the log is
// full and the oldest entry leaves.
func TestAddWithServedLogDoesNotAllocate(t *testing.T) {
	r := servedRing(t, 64, 1<<20)
	e := served(1, "203.0.113.5")
	for i := 0; i < 200; i++ {
		r.Add(e)
	}
	if n := testing.AllocsPerRun(20000, func() { r.Add(e) }); n != 0 {
		t.Errorf("Add with the served log allocates %.1f times per request", n)
	}
	if _, first, next := r.Served(0, 1, 1); next < first {
		t.Errorf("first %d, next %d", first, next)
	}
}

// A ring without a served log (a single gateway) answers nothing.
func TestServedWithoutLog(t *testing.T) {
	r, err := New(Config{StoragePath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.Add(served(1, "203.0.113.5"))
	if rows, first, next := r.Served(0, 10, 1<<20); rows != nil || first != 0 || next != 0 {
		t.Errorf("%d rows, first %d, next %d", len(rows), first, next)
	}
}
