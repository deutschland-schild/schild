package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	dir   string
	st    *store.Store
	l     *Log
	clock *clock
	keep  int64
	out   *bytes.Buffer
}

func open(t *testing.T, dir string) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{dir: dir, st: st, clock: &clock{t: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)}, keep: 365, out: &bytes.Buffer{}}
	e.l, err = Open(context.Background(), st, filepath.Join(dir, FileName), Options{Node: "gw-1", KeepDays: func() int64 { return e.keep }, Stream: e.out, Now: e.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.l.Close(); st.Close() })
	return e
}

func allow(id, ip string) Entry {
	return Entry{Action: "allowlist.add", Operation: "dashboard:addAllowlistEntry", Actor: Dashboard("admin", "0a1b2c3d"), Address: "198.51.100.20",
		Subject: id, After: map[string]any{"ip": ip, "label": "Büro", "level": "no_block", "password": "MARKER-SECRET", "note": "MARKER-UNLISTED"}}
}

func list(t *testing.T, l *Log, f Filter) []map[string]any {
	t.Helper()
	items, _, err := l.List(context.Background(), f, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func TestFirstStartWritesAuditStart(t *testing.T) {
	e := open(t, t.TempDir())
	items := list(t, e.l, Filter{})
	if len(items) != 1 || items[0]["action"] != "audit.start" {
		t.Fatalf("want audit.start alone, got %v", items)
	}
	raw, _ := json.Marshal(items[0])
	if !strings.Contains(string(raw), `"after":"first"`) {
		t.Fatalf("reason first missing: %s", raw)
	}
}

func TestChangeAndEntryAreOneTransaction(t *testing.T) {
	e := open(t, t.TempDir())
	ctx := context.Background()
	boom := errors.New("boom")
	err := e.l.Tx(ctx, func(ctx context.Context, rec *Rec) error {
		if err := e.st.Put(ctx, "x", []byte("1")); err != nil {
			return err
		}
		rec.Add(allow("al_1", "203.0.113.7"))
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, err := e.st.Get(ctx, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the change of a failed transaction is there: %v", err)
	}
	// An entry that cannot be written refuses the change.
	err = e.l.Tx(ctx, func(ctx context.Context, rec *Rec) error {
		rec.Add(Entry{Action: "allowlist.add", Operation: "dashboard:noSuchOperation", Actor: Dashboard("admin", "0a1b2c3d"), Subject: "al_1"})
		return e.st.Put(ctx, "x", []byte("1"))
	})
	if err == nil {
		t.Fatal("an entry of an operation the action does not list was written")
	}
	if _, err := e.st.Get(ctx, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the change is there without its entry: %v", err)
	}
	if err := e.l.Tx(ctx, func(ctx context.Context, rec *Rec) error {
		rec.Add(allow("al_1", "203.0.113.7"))
		return e.st.Put(ctx, "x", []byte("1"))
	}); err != nil {
		t.Fatal(err)
	}
	items := list(t, e.l, Filter{Action: "allowlist.add"})
	if len(items) != 1 {
		t.Fatalf("want one entry, got %d", len(items))
	}
	// The failed changes left no hole: audit.start is 1, this is 2.
	if id := items[0]["id"].(string); !strings.HasSuffix(id, "-k-2") {
		t.Fatalf("id %s: a rolled back change used a number", id)
	}
	if holes, err := e.l.Holes(ctx); err != nil || len(holes) != 0 {
		t.Fatalf("holes %v %v", holes, err)
	}
}

func TestNoSecretAndNoUnlistedValue(t *testing.T) {
	e := open(t, t.TempDir())
	if err := e.l.Write(context.Background(), allow("al_1", "203.0.113.7")); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(list(t, e.l, Filter{Action: "allowlist.add"}))
	for _, marker := range []string{"MARKER-SECRET", "MARKER-UNLISTED"} {
		if strings.Contains(string(raw), marker) || strings.Contains(e.out.String(), marker) {
			t.Fatalf("%s is in the log: %s", marker, raw)
		}
	}
	if !strings.Contains(string(raw), `"hidden":"secret"`) || !strings.Contains(string(raw), `"hidden":"unlisted"`) || !strings.Contains(string(raw), "203.0.113.7") {
		t.Fatalf("fields: %s", raw)
	}
	// The copy holds every entry as one line.
	if n := strings.Count(e.out.String(), "\n"); n != 2 {
		t.Fatalf("copy has %d lines, want 2: %s", n, e.out.String())
	}
}

func TestFiltersAndCursor(t *testing.T) {
	e := open(t, t.TempDir())
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		e.clock.add(time.Second)
		en := allow(fmt.Sprintf("al_%d", i), "203.0.113.7")
		if i%5 == 0 {
			en = Entry{Action: "rule_exception.set", Operation: "agent:createAgentException", Actor: Agent("tok_0123456789ab", "coding-agent"),
				Subject: fmt.Sprint(i), Website: "shop.example", Event: "0190a1b2-c3d4-4e5f-8a9b-0c1d2e3f4a5b",
				After: map[string]any{"path": "/kontakt", "rules": []string{"942100"}}, Reason: "Contact form"}
		}
		if err := e.l.Write(ctx, en); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		f    Filter
		want int
	}{
		{Filter{}, 26},
		{Filter{Website: "shop.example"}, 5},
		{Filter{Way: WayAgent}, 5},
		{Filter{Actor: "tok_0123456789ab"}, 5},
		{Filter{Session: "0a1b2c3d"}, 20},
		{Filter{Subject: "allowlist_entry", SubjectID: "al_3"}, 1},
		{Filter{Event: "0190a1b2-c3d4-4e5f-8a9b-0c1d2e3f4a5b"}, 5},
		{Filter{Class: audit.ClassAccess}, 0},
		{Filter{From: e.clock.now().Add(-4 * time.Second)}, 5},
	} {
		if got := len(list(t, e.l, c.f)); got != c.want {
			t.Errorf("%+v: %d entries, want %d", c.f, got, c.want)
		}
	}
	var ids []string
	cursor := ""
	for {
		items, next, err := e.l.List(ctx, Filter{}, cursor, 7)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			ids = append(ids, it["id"].(string))
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(ids) != 26 {
		t.Fatalf("pages hold %d entries, want 26", len(ids))
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("%s twice", id)
		}
		seen[id] = true
	}
	if _, _, err := e.l.List(ctx, Filter{}, "nonsense", 7); !errors.Is(err, ErrCursor) {
		t.Fatalf("cursor: %v", err)
	}
	// An agent sees no people.
	items, _, err := e.l.View(ctx, Filter{}, audit.ViewAgent, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(items)
	if strings.Contains(string(raw), "admin") || strings.Contains(string(raw), "198.51.100.20") || strings.Contains(string(raw), "0a1b2c3d") {
		t.Fatalf("an agent sees people: %s", raw)
	}
	// A website sees its own entries alone.
	items, _, err = e.l.View(ctx, Filter{}, audit.ViewWebsite, "shop.example", "", 0)
	if err != nil || len(items) != 5 {
		t.Fatalf("website view: %d %v", len(items), err)
	}
	items, _, _ = e.l.View(ctx, Filter{}, audit.ViewWebsite, "other.example", "", 0)
	if len(items) != 0 {
		t.Fatalf("another website sees %d entries", len(items))
	}
}

func TestEntriesWaitInTheOutboxAndAreListed(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	// A command on the host writes while the gateway is stopped.
	cli := ForStore(ctx, st, "gw-1")
	if err := cli.Write(ctx, Entry{Action: "token.add", Operation: "cli:token add", Actor: CLI("root"), Subject: "tok_0123456789ab",
		After: map[string]any{"scope": "agent:read", "label": "x"}}); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := st.AuditOutboxLen(ctx); n != 1 {
		t.Fatalf("outbox holds %d", n)
	}
	l, err := Open(ctx, st, filepath.Join(dir, FileName), Options{Node: "gw-1"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if n, _, _ := st.AuditOutboxLen(ctx); n != 0 {
		t.Fatalf("outbox holds %d after the start", n)
	}
	items := list(t, l, Filter{})
	if len(items) != 2 {
		t.Fatalf("want token.add and audit.start, got %d", len(items))
	}
	// Both are of one log: the name the command drew stays.
	a, _, _ := splitID(items[0]["id"].(string))
	b, _, _ := splitID(items[1]["id"].(string))
	if a != b {
		t.Fatalf("two logs: %s %s", a, b)
	}
}

func TestMissingAndUnreadableFileStartANewLog(t *testing.T) {
	dir := t.TempDir()
	e := open(t, dir)
	name := e.l.Name(context.Background())
	e.l.Close()
	path := filepath.Join(dir, FileName)
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		_ = os.Remove(p)
	}
	l, err := Open(context.Background(), e.st, path, Options{Node: "gw-1"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(list(t, l, Filter{}))
	if l.Name(context.Background()) == name || !strings.Contains(string(raw), `"after":"missing"`) {
		t.Fatalf("missing file: name kept or no audit.start: %s", raw)
	}
	l.Close()
	for _, p := range []string{path + "-wal", path + "-shm"} {
		_ = os.Remove(p)
	}
	if err := os.WriteFile(path, []byte("this is not a database, but it is long enough to be read as a header of one"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err = Open(context.Background(), e.st, path, Options{Node: "gw-1"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	raw, _ = json.Marshal(list(t, l, Filter{}))
	if !strings.Contains(string(raw), `"after":"unreadable"`) {
		t.Fatalf("unreadable file: %s", raw)
	}
	kept, _ := filepath.Glob(path + ".unreadable-*")
	if len(kept) != 1 {
		t.Fatalf("the unreadable file was not kept: %v", kept)
	}
}

func TestRetainIsAuditDelete(t *testing.T) {
	for _, keep := range []int64{0, 14, 365} {
		e := open(t, t.TempDir())
		e.keep = keep
		ctx := context.Background()
		now := e.clock.now()
		rng := rand.New(rand.NewSource(42 + keep))
		classes := []string{audit.ClassChange, audit.ClassCredential, audit.ClassPrivacy, audit.ClassAccess, audit.ClassRefused}
		var rows []audit.Row
		// audit.start of the open is a row too.
		rows = append(rows, audit.Row{ID: list(t, e.l, Filter{})[0]["id"].(string), Class: audit.ClassChange, T: now.UnixMilli()})
		tx, _ := e.l.db.Begin()
		for i := 0; i < 400; i++ {
			class := classes[rng.Intn(len(classes))]
			age := time.Duration(rng.Intn(500*24)) * time.Hour
			t0 := now.Add(-age)
			id := fmt.Sprintf("%016x-%s-%d", 7, audit.Letter(class), i+1)
			c := cols{id: id, class: class, action: "x.y", way: "system", timeMS: t0.UnixMilli()}
			if _, err := insert(ctx, tx, c, []byte("{}"), true, false, now); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, audit.Row{ID: id, Class: class, T: t0.UnixMilli()})
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		// A small cap, so the cap of rows acts: the test changes the SQL's
		// constant through the contract's function with the same number.
		want := audit.Delete(rows, now.UnixMilli(), keep, audit.MaxAccessRows)
		if _, err := e.l.Retain(ctx); err != nil {
			t.Fatal(err)
		}
		gone := map[string]bool{}
		for _, id := range want {
			gone[id] = true
		}
		rs, _ := e.l.db.Query(`SELECT id FROM entries`)
		left := map[string]bool{}
		for rs.Next() {
			var id string
			_ = rs.Scan(&id)
			left[id] = true
		}
		rs.Close()
		for _, r := range rows {
			if gone[r.ID] == left[r.ID] {
				t.Errorf("keep_days %d: %s (class %s) deleted=%v, the contract says %v", keep, r.ID, r.Class, !left[r.ID], gone[r.ID])
			}
		}
	}
}

func TestKeepDays14LeavesNothingOlder(t *testing.T) {
	e := open(t, t.TempDir())
	ctx := context.Background()
	e.keep = 14
	if err := e.l.Write(ctx, allow("al_1", "203.0.113.7")); err != nil {
		t.Fatal(err)
	}
	e.l.Refused(RefusedCall{Action: "session.start", Operation: "dashboard:login", Actor: Actor{Kind: WayDashboard}, Address: "198.51.100.66"})
	e.l.flushRefused(ctx, true)
	// One more waits in the outbox when the days are over.
	cli := ForStore(ctx, e.st, "gw-1")
	cli.opts.Now = e.clock.now
	if err := cli.Write(ctx, allow("al_2", "203.0.113.8")); err != nil {
		t.Fatal(err)
	}
	e.clock.add(14*24*time.Hour + time.Second)
	if _, err := e.l.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	if items := list(t, e.l, Filter{}); len(items) != 0 {
		t.Fatalf("after 14 days %d entries are left: %v", len(items), items)
	}
	if n, _, _ := e.st.AuditOutboxLen(ctx); n != 0 {
		t.Fatalf("the outbox holds %d", n)
	}
}

func TestRefusedCallsAreGathered(t *testing.T) {
	e := open(t, t.TempDir())
	ctx := context.Background()
	call := RefusedCall{Action: "session.start", Operation: "dashboard:login", Actor: Actor{Kind: WayDashboard}, Address: "198.51.100.66"}
	for i := 0; i < 12; i++ {
		e.l.Refused(call)
		e.clock.add(time.Second)
	}
	e.l.Refused(RefusedCall{Action: "agent_api.call", Operation: "agent:any", Actor: Actor{Kind: WayAgent}, Address: "2001:db8::1"})
	e.l.Refused(RefusedCall{Action: "agent_api.call", Operation: "agent:any", Actor: Actor{Kind: WayAgent}, Address: "2001:db8::2"})
	e.l.flushRefused(ctx, false)
	items := list(t, e.l, Filter{Class: audit.ClassRefused})
	if len(items) != 2 {
		t.Fatalf("want 2 entries, got %d: %v", len(items), items)
	}
	// While its minute runs an entry is not handed to the group.
	rows, _, err := e.l.After(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if strings.Contains(string(r), `"refused"`) {
			t.Fatalf("an open entry was handed on: %s", r)
		}
	}
	e.l.Refused(call)
	e.clock.add(time.Minute)
	e.l.flushRefused(ctx, false)
	items = list(t, e.l, Filter{Action: "session.start"})
	if len(items) != 1 || fmt.Sprint(items[0]["count"]) != "13" || items[0]["result"] != "refused" {
		t.Fatalf("count: %v", items)
	}
	rows, _, _ = e.l.After(ctx, 0)
	n := 0
	for _, r := range rows {
		if strings.Contains(string(r), `"class":"refused"`) {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d refused entries handed on, want 2", n)
	}
	// A flood of clients: beyond the bound a call counts without address.
	for i := 0; i < audit.MaxOpenRefused+50; i++ {
		e.l.Refused(RefusedCall{Action: "agent_api.call", Operation: "agent:any", Actor: Actor{Kind: WayAgent}, Address: fmt.Sprintf("10.%d.%d.%d", i>>16, i>>8&255, i&255)})
	}
	e.l.flushRefused(ctx, true)
	var with, without int
	_ = e.l.db.QueryRow(`SELECT COUNT(*) FROM entries WHERE class = 'refused' AND CAST(body AS TEXT) LIKE '%"address":"10.%'`).Scan(&with)
	_ = e.l.db.QueryRow(`SELECT COUNT(*) FROM entries WHERE class = 'refused' AND action = 'agent_api.call' AND CAST(body AS TEXT) NOT LIKE '%"address"%'`).Scan(&without)
	if with != audit.MaxOpenRefused || without != 1 {
		t.Fatalf("flood: %d entries with a client, %d without; want %d and 1", with, without, audit.MaxOpenRefused)
	}
}

func TestGroupHandsOnEveryEntryOnce(t *testing.T) {
	a, b, c := open(t, t.TempDir()), open(t, t.TempDir()), open(t, t.TempDir())
	ctx := context.Background()
	if err := a.l.Write(ctx, allow("al_1", "203.0.113.7")); err != nil {
		t.Fatal(err)
	}
	pull := func(from, to *env, after int64) int64 {
		rows, next, err := from.l.After(ctx, after)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := to.l.Import(ctx, rows); err != nil {
			t.Fatal(err)
		}
		return next
	}
	pull(a, b, 0)
	// c never met a: it has a's entries from b.
	pull(b, c, 0)
	pull(c, a, 0)
	pull(b, a, 0)
	want := 3 + 1 // three audit.start and the change
	for name, e := range map[string]*env{"a": a, "b": b, "c": c} {
		if e != c && e != a {
			continue
		}
		if got := len(list(t, e.l, Filter{})); got != want {
			t.Errorf("%s holds %d entries, want %d", name, got, want)
		}
	}
	// Another content under a known id is not taken.
	rows, _, _ := a.l.After(ctx, 0)
	forged := []json.RawMessage{json.RawMessage(strings.Replace(string(rows[len(rows)-1]), "gw-1", "gw-9", 1))}
	before := len(list(t, c.l, Filter{}))
	if n, err := c.l.Import(ctx, forged); err != nil || n != 0 {
		t.Fatalf("forged: %d %v", n, err)
	}
	if c.l.Counters().Differing != 1 || len(list(t, c.l, Filter{})) != before {
		t.Fatalf("differing %d", c.l.Counters().Differing)
	}
	// An entry that does not pass is counted and skipped.
	if n, _ := c.l.Import(ctx, []json.RawMessage{json.RawMessage(`{"schema":"schild.audit/0.1"}`)}); n != 0 || c.l.Counters().Skipped != 1 {
		t.Fatalf("skipped %d", c.l.Counters().Skipped)
	}
	// What is too old here is not taken.
	c.keep = 1
	c.clock.add(48 * time.Hour)
	d := open(t, t.TempDir())
	_ = d.l.Write(ctx, allow("al_9", "203.0.113.9"))
	rows, _, _ = d.l.After(ctx, 0)
	if n, _ := c.l.Import(ctx, rows); n != 0 {
		t.Fatalf("%d entries older than audit.keep_days were taken", n)
	}
}

func TestHolesAreNamed(t *testing.T) {
	e := open(t, t.TempDir())
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := e.l.Write(ctx, allow(fmt.Sprintf("al_%d", i), "203.0.113.7")); err != nil {
			t.Fatal(err)
		}
	}
	_ = e.l.Move(ctx)
	name := e.l.Name(ctx)
	if _, err := e.l.db.Exec(`DELETE FROM entries WHERE id IN (?, ?)`, name+"-k-3", name+"-k-4"); err != nil {
		t.Fatal(err)
	}
	holes, err := e.l.Holes(ctx)
	if err != nil || len(holes) != 1 || holes[0].From != 3 || holes[0].To != 4 {
		t.Fatalf("holes %v %v", holes, err)
	}
}

func TestTokenBudget(t *testing.T) {
	e := open(t, t.TempDir())
	ctx := context.Background()
	en := Entry{Action: "rule.set", Operation: "agent:updateAgentRule", Actor: Agent("tok_0123456789ab", "a"), Subject: "crs/942100", After: map[string]any{"disabled": true}}
	for i := 0; i < audit.TokenEntriesPerHour; i++ {
		if ok, _ := e.l.BudgetLeft("tok_0123456789ab"); !ok {
			t.Fatalf("budget used up after %d entries", i)
		}
		if err := e.l.Write(ctx, en); err != nil {
			t.Fatal(err)
		}
	}
	if ok, retry := e.l.BudgetLeft("tok_0123456789ab"); ok || retry <= 0 {
		t.Fatalf("budget not used up: %v %d", ok, retry)
	}
	if ok, _ := e.l.BudgetLeft("tok_ffffffffffff"); !ok {
		t.Fatal("another token has no budget")
	}
	e.clock.add(time.Hour)
	if ok, _ := e.l.BudgetLeft("tok_0123456789ab"); !ok {
		t.Fatal("budget does not come back")
	}
}

func TestAnEntrySurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	e := open(t, dir)
	if err := e.l.Write(context.Background(), allow("al_1", "203.0.113.7")); err != nil {
		t.Fatal(err)
	}
	ids := func(l *Log) []string {
		var out []string
		for _, it := range list(t, l, Filter{}) {
			out = append(out, it["id"].(string))
		}
		sort.Strings(out)
		return out
	}
	before := ids(e.l)
	e.l.Close()
	l, err := Open(context.Background(), e.st, filepath.Join(dir, FileName), Options{Node: "gw-1"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if after := ids(l); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("entries after the restart: %v, before: %v", after, before)
	}
}
