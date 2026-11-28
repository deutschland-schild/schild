package auditlog

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// A schild.db from a backup knows lower numbers than the audit.db next to
// it. The entries written after the restore must not take ids of the file.
func TestRestoredStoreDrawsNoIDOfTheFile(t *testing.T) {
	dir := t.TempDir()
	e := open(t, dir)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := e.l.Write(ctx, allow(fmt.Sprintf("al_%d", i), "203.0.113.7")); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.l.Move(ctx); err != nil {
		t.Fatal(err)
	}
	name := e.l.Name(ctx)
	before := len(list(t, e.l, Filter{Action: "allowlist.add"}))
	e.l.Close()
	// The state of the backup: the same log, one change entry written.
	if err := e.st.AdoptAuditLog(ctx, name, map[string]int64{"k": 1}); err != nil {
		t.Fatal(err)
	}
	l, err := Open(ctx, e.st, filepath.Join(dir, FileName), Options{Node: "gw-1", Now: e.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 2; i++ {
		if err := l.Write(ctx, allow(fmt.Sprintf("al_new_%d", i), "203.0.113.8")); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Move(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(list(t, l, Filter{Action: "allowlist.add"})); got != before+2 {
		t.Fatalf("%d entries after two writes on %d: an entry was lost under an id of the file", got, before)
	}
	if holes, err := l.Holes(ctx); err != nil || len(holes) != 0 {
		t.Fatalf("holes %v %v", holes, err)
	}
}

// A call that changes nothing writes no entry and spends no budget.
func TestNoChangeSpendsNoBudget(t *testing.T) {
	e := open(t, t.TempDir())
	ctx := context.Background()
	same := map[string]any{"disabled": true}
	en := Entry{Action: "rule.set", Operation: "agent:updateAgentRule", Actor: Agent("tok_0123456789ab", "a"), Subject: "crs/942100",
		Before: same, After: same, IfChanged: true}
	for i := 0; i < audit.TokenEntriesPerHour+5; i++ {
		if err := e.l.Write(ctx, en); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(list(t, e.l, Filter{Action: "rule.set"})); got != 0 {
		t.Fatalf("%d entries of a call that changes nothing", got)
	}
	if ok, _ := e.l.BudgetLeft("tok_0123456789ab"); !ok {
		t.Fatal("calls that changed nothing used up the budget")
	}
}

// An entry whose time is past what the node keeps draws no number, so the
// numbers of the log have no hole.
func TestAnEntryTooOldLeavesNoHole(t *testing.T) {
	e := open(t, t.TempDir())
	ctx := context.Background()
	old := allow("al_old", "203.0.113.9")
	old.Time = e.clock.now().Add(-400 * 24 * time.Hour)
	for _, en := range []Entry{allow("al_1", "203.0.113.7"), old, allow("al_2", "203.0.113.7")} {
		if err := e.l.Write(ctx, en); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.l.Move(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(list(t, e.l, Filter{Action: "allowlist.add"})); got != 2 {
		t.Fatalf("%d entries, want the two that are young enough", got)
	}
	if holes, err := e.l.Holes(ctx); err != nil || len(holes) != 0 {
		t.Fatalf("holes %v %v", holes, err)
	}
}

// Entries that wait in the outbox are all reached, over as many pages as
// they need, and each once.
func TestTheOutboxIsPaged(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	// A command on the host: no audit.db, everything waits.
	cli := ForStore(ctx, st, "gw-1")
	for i := 0; i < 5; i++ {
		if err := cli.Write(ctx, allow(fmt.Sprintf("al_%d", i), "203.0.113.7")); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]int{}
	var order []string
	cursor, pages := "", 0
	for {
		items, next, err := cli.List(ctx, Filter{}, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) > 2 {
			t.Fatalf("a page of %d", len(items))
		}
		for _, it := range items {
			seen[it["id"].(string)]++
			order = append(order, it["subject"].(map[string]any)["id"].(string))
		}
		pages++
		if next == "" {
			break
		}
		if pages > 10 {
			t.Fatal("the pages do not end")
		}
		cursor = next
	}
	if len(seen) != 5 {
		t.Fatalf("%d of 5 waiting entries reached: %v", len(seen), order)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("%s listed %d times", id, n)
		}
	}
	if order[0] != "al_4" || order[4] != "al_0" {
		t.Fatalf("not newest first: %v", order)
	}
	if _, _, err := cli.List(ctx, Filter{}, "ox", 2); err != ErrCursor {
		t.Fatalf("a broken cursor: %v", err)
	}
}
