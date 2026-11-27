package auditlog

import (
	"context"
	"fmt"
	"testing"
)

// ids of the entries a log holds, each counted.
func idsOf(t *testing.T, e *env) map[string]int {
	t.Helper()
	if err := e.l.Move(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, err := e.l.db.Query(`SELECT id FROM entries`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out[id]++
	}
	return out
}

// The head moves with every entry a node stores; only an entry of its own
// is news for the members.
func TestHeadMovesAndOnlyOwnEntriesAreNews(t *testing.T) {
	a, b := open(t, t.TempDir()), open(t, t.TempDir())
	ctx := context.Background()
	a0, _ := a.l.Head(ctx)
	b0, _ := b.l.Head(ctx)
	if a0 == 0 || b0 == 0 {
		t.Fatalf("heads %d and %d: audit.start has no place", a0, b0)
	}
	if err := a.l.Write(ctx, allow("al_1", "203.0.113.7")); err != nil {
		t.Fatal(err)
	}
	rows, next, err := a.l.After(ctx, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("%d rows, %v", len(rows), err)
	}
	if h, _ := a.l.Head(ctx); h != next || h <= a0 {
		t.Fatalf("head %d, the last place handed on is %d, before the entry %d", h, next, a0)
	}
	if own, _ := a.l.OwnSince(ctx, a0); !own {
		t.Fatal("an entry this node wrote is no news")
	}
	if n, err := b.l.Import(ctx, rows); err != nil || n != 2 {
		t.Fatalf("took %d, %v", n, err)
	}
	b1, _ := b.l.Head(ctx)
	if b1 <= b0 {
		t.Fatalf("head %d after two entries were taken, %d before", b1, b0)
	}
	if own, _ := b.l.OwnSince(ctx, b0); own {
		t.Fatal("entries taken from a member count as news of this node")
	}
	// What is held already moves nothing.
	if n, _ := b.l.Import(ctx, rows); n != 0 {
		t.Fatalf("took %d entries a second time", n)
	}
	if h, _ := b.l.Head(ctx); h != b1 {
		t.Fatalf("head %d after entries that were held already, %d before", h, b1)
	}
}

// More entries than one answer holds: the cursor goes through them in the
// order they were stored, and what a node took from a member comes after.
func TestAfterGoesThroughTheLogInAnswers(t *testing.T) {
	a, b, c := open(t, t.TempDir()), open(t, t.TempDir()), open(t, t.TempDir())
	ctx := context.Background()
	const n = 2*AskBatch + 10
	entries := make([]Entry, n)
	for i := range entries {
		entries[i] = allow(fmt.Sprintf("al_%d", i), "203.0.113.7")
	}
	if err := a.l.Write(ctx, entries...); err != nil {
		t.Fatal(err)
	}
	var after int64
	var sizes []int
	for {
		rows, next, err := a.l.After(ctx, after)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		if next <= after {
			t.Fatalf("the cursor stays at %d with %d rows", after, len(rows))
		}
		if _, err := b.l.Import(ctx, rows); err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(rows))
		after = next
	}
	if len(sizes) != 3 || sizes[0] != AskBatch || sizes[1] != AskBatch || sizes[2] != n+1-2*AskBatch {
		t.Fatalf("answers of %v rows for %d entries and audit.start", sizes, n)
	}
	if got := len(idsOf(t, b)); got != n+2 {
		t.Fatalf("the asking node holds %d entries, want %d", got, n+2)
	}
	// An entry of a third node, taken later, is handed on behind the cursor.
	if err := c.l.Write(ctx, allow("al_c", "203.0.113.9")); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := c.l.After(ctx, 0)
	if taken, err := a.l.Import(ctx, rows); err != nil || taken != 2 {
		t.Fatalf("took %d, %v", taken, err)
	}
	rows, _, _ = a.l.After(ctx, after)
	if len(rows) != 2 {
		t.Fatalf("%d entries behind the cursor, want the two of the third node", len(rows))
	}
}

// Three nodes, one of them cut off: every node asks every node with a
// cursor per member, and after the cut every entry is once on every node.
// The asking ends by itself, although every node hands on all it holds.
func TestAfterAPartitionEveryEntryIsOnceOnEveryNode(t *testing.T) {
	ctx := context.Background()
	names := []string{"a", "b", "c"}
	logs := map[string]*env{}
	for _, n := range names {
		logs[n] = open(t, t.TempDir())
	}
	cursor := map[string]int64{}
	// round lets every node ask every member it reaches and returns how
	// many entries were new somewhere.
	round := func(reaches func(x, y string) bool) (taken int) {
		for _, to := range names {
			for _, from := range names {
				if to == from || !reaches(to, from) {
					continue
				}
				rows, next, err := logs[from].l.After(ctx, cursor[to+"<"+from])
				if err != nil {
					t.Fatal(err)
				}
				n, err := logs[to].l.Import(ctx, rows)
				if err != nil {
					t.Fatal(err)
				}
				cursor[to+"<"+from] = next
				taken += n
			}
		}
		return taken
	}
	write := func(on, id string) {
		if err := logs[on].l.Write(ctx, allow(id, "203.0.113.7")); err != nil {
			t.Fatal(err)
		}
	}
	all := func(x, y string) bool { return true }
	cut := func(x, y string) bool { return x != "a" && y != "a" }
	write("a", "al_1")
	round(all)
	write("a", "al_2") // a is cut off from here
	write("b", "al_3")
	write("c", "al_4")
	round(cut)
	round(cut)
	if got := len(idsOf(t, logs["a"])); got != 3+2 {
		t.Fatalf("the node that is cut off holds %d entries, want its own two and what came before", got)
	}
	// The cut ends.
	rounds := 0
	for round(all) > 0 {
		if rounds++; rounds > 4 {
			t.Fatal("the nodes keep handing entries to each other")
		}
	}
	want := idsOf(t, logs["a"])
	if len(want) != 3+4 {
		t.Fatalf("%d entries after the cut, want three audit.start and four changes", len(want))
	}
	for _, n := range names {
		got := idsOf(t, logs[n])
		if len(got) != len(want) {
			t.Errorf("%s holds %d entries, want %d", n, len(got), len(want))
		}
		for id := range want {
			if got[id] != 1 {
				t.Errorf("%s holds %s %d times", n, id, got[id])
			}
		}
	}
}
