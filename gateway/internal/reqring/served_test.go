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
	r, err := New(Config{StoragePath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	r.Tee(max, maxBytes)
	return r
}

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

// The log is bounded by entries and by the bytes of their strings: the
// oldest leave, and the answer says from where it still holds.
func TestServedLogIsBounded(t *testing.T) {
	r := servedRing(t, 8, 1<<20)
	for i := 1; i <= 20; i++ {
		r.Add(served(i, "203.0.113.5"))
	}
	rows, first, next := r.Served(3, 100, 1<<20)
	if first != 13 || next != 20 || len(rows) != 8 || rows[0].RawPath != "/p/13" {
		t.Fatalf("after 20 into 8: first %d, next %d, %d rows", first, next, len(rows))
	}
	// 1 KiB of strings: entries of about 400 bytes fit twice.
	r = servedRing(t, 1000, 1024)
	for i := 1; i <= 10; i++ {
		e := served(i, "203.0.113.5")
		e.UA = strings.Repeat("u", 380)
		r.Add(e)
	}
	rows, first, next = r.Served(0, 100, 1<<20)
	if len(rows) != 2 || first != 9 || next != 10 {
		t.Fatalf("bounded by bytes: %d rows, first %d, next %d", len(rows), first, next)
	}
	// One entry larger than the bound still passes alone.
	big := served(11, "203.0.113.5")
	big.UA = strings.Repeat("u", 5000)
	r.Add(big)
	if rows, first, _ := r.Served(0, 100, 1<<20); len(rows) != 1 || first != 11 {
		t.Fatalf("an entry over the bound: %d rows, first %d", len(rows), first)
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
