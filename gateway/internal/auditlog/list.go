package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/contract/jsonx"
)

// Filter of List. An empty field does not narrow.
type Filter struct {
	// From and To bound the time of the entries, [From, To); zero: open.
	From, To time.Time
	Website  string
	Class    string
	// Classes narrows to several classes (the view of an agent).
	Classes   []string
	Action    string
	Way       string
	Actor     string // token or portal key id
	Subject   string
	SubjectID string
	Session   string
	Event     string
	// Incident: entries whose cause or subject is this incident.
	Incident string
}

func (f Filter) where() (string, []any) {
	var conds []string
	var args []any
	add := func(c string, a ...any) {
		conds = append(conds, c)
		args = append(args, a...)
	}
	if !f.From.IsZero() {
		add("time_ms >= ?", f.From.UnixMilli())
	}
	if !f.To.IsZero() {
		add("time_ms < ?", f.To.UnixMilli())
	}
	eq := func(col, v string) {
		if v != "" {
			add(col+" = ?", v)
		}
	}
	eq("website", f.Website)
	eq("class", f.Class)
	eq("action", f.Action)
	eq("way", f.Way)
	eq("actor", f.Actor)
	eq("subject", f.Subject)
	eq("subject_id", f.SubjectID)
	eq("session", f.Session)
	eq("event", f.Event)
	eq("incident", f.Incident)
	if len(f.Classes) > 0 {
		marks := strings.TrimSuffix(strings.Repeat("?,", len(f.Classes)), ",")
		conds = append(conds, "class IN ("+marks+")")
		for _, c := range f.Classes {
			args = append(args, c)
		}
	}
	if len(conds) == 0 {
		return "1", nil
	}
	return strings.Join(conds, " AND "), args
}

// match is where for an entry that is not in audit.db yet.
func (f Filter) match(c cols) bool {
	ok := func(want, have string) bool { return want == "" || want == have }
	if !f.From.IsZero() && c.timeMS < f.From.UnixMilli() || !f.To.IsZero() && c.timeMS >= f.To.UnixMilli() {
		return false
	}
	if len(f.Classes) > 0 {
		in := false
		for _, x := range f.Classes {
			in = in || x == c.class
		}
		if !in {
			return false
		}
	}
	return ok(f.Website, c.website) && ok(f.Class, c.class) && ok(f.Action, c.action) && ok(f.Way, c.way) && ok(f.Actor, c.actor) &&
		ok(f.Subject, c.subject) && ok(f.SubjectID, c.subjectID) && ok(f.Session, c.session) && ok(f.Event, c.event) && ok(f.Incident, c.incident)
}

// MaxPage is the most entries one List returns.
const MaxPage = 500

// ErrCursor: the cursor of a List is not one of its own.
var ErrCursor = fmt.Errorf("audit: invalid cursor")

func parseCursor(c string) (timeMS, seq int64, err error) {
	t, s, ok := strings.Cut(strings.TrimPrefix(c, "a"), ".")
	if !ok || !strings.HasPrefix(c, "a") {
		return 0, 0, ErrCursor
	}
	if timeMS, err = strconv.ParseInt(t, 10, 64); err != nil {
		return 0, 0, ErrCursor
	}
	if seq, err = strconv.ParseInt(s, 10, 64); err != nil {
		return 0, 0, ErrCursor
	}
	return timeMS, seq, nil
}

// List returns entries, newest first, and the cursor of the next page ("",
// when there is none). It answers from audit.db and from the outbox: an
// entry that waits there is on the first page.
func (l *Log) List(ctx context.Context, f Filter, cursor string, limit int) ([]map[string]any, string, error) {
	if l == nil {
		return nil, "", nil
	}
	if limit <= 0 || limit > MaxPage {
		limit = MaxPage
	}
	_ = l.Move(ctx) // best effort; what stays is read from the outbox below
	type item struct {
		timeMS int64
		e      map[string]any
	}
	var items []item
	if cursor == "" {
		rows, err := l.st.AuditOutbox(ctx, MaxPage)
		if err != nil {
			return nil, "", err
		}
		for _, r := range rows {
			e, err := jsonx.ParseObject(r.Body)
			if err != nil {
				continue
			}
			if c := columns(e); f.match(c) {
				items = append(items, item{c.timeMS, e})
			}
		}
		sort.SliceStable(items, func(i, j int) bool { return items[i].timeMS > items[j].timeMS })
		if len(items) > limit {
			items = items[:limit]
		}
	}
	next := ""
	if l.db != nil && len(items) < limit {
		where, args := f.where()
		if cursor != "" {
			t, seq, err := parseCursor(cursor)
			if err != nil {
				return nil, "", err
			}
			where += " AND (time_ms < ? OR (time_ms = ? AND seq < ?))"
			args = append(args, t, t, seq)
		}
		want := limit - len(items)
		rows, err := l.db.QueryContext(ctx, `SELECT seq, time_ms, body FROM entries WHERE `+where+` ORDER BY time_ms DESC, seq DESC LIMIT ?`, append(args, want+1)...)
		if err != nil {
			return nil, "", err
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			var seq, t int64
			var body []byte
			if err := rows.Scan(&seq, &t, &body); err != nil {
				return nil, "", err
			}
			if n == want {
				break
			}
			e, err := jsonx.ParseObject(body)
			if err != nil {
				continue
			}
			n++
			items = append(items, item{t, e})
			next = "a" + strconv.FormatInt(t, 10) + "." + strconv.FormatInt(seq, 10)
		}
		if err := rows.Err(); err != nil {
			return nil, "", err
		}
		if n < want {
			next = ""
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].timeMS > items[j].timeMS })
	out := make([]map[string]any, len(items))
	for i, it := range items {
		out[i] = it.e
	}
	return out, next, nil
}

// View is List for a viewer that does not see everything (contract/audit
// View): entries the viewer may not see are left out, so a page may hold
// fewer than limit.
func (l *Log) View(ctx context.Context, f Filter, viewer, website, cursor string, limit int) ([]map[string]any, string, error) {
	if viewer == audit.ViewAgent {
		f.Classes = []string{audit.ClassChange, audit.ClassCredential}
	}
	if viewer == audit.ViewWebsite {
		f.Website, f.Class = website, audit.ClassChange
	}
	items, next, err := l.List(ctx, f, cursor, limit)
	if err != nil {
		return nil, "", err
	}
	out := make([]map[string]any, 0, len(items))
	for _, e := range items {
		if v := audit.View(e, viewer, website); v != nil {
			out = append(out, v)
		}
	}
	return out, next, nil
}

// Hole is a run of numbers missing between two kept entries of one log:
// entries removed by hand, or written with a wrong clock.
type Hole struct {
	Log      string `json:"log"`
	From, To int64
}

// Holes names the numbers missing between the kept entries of the logs
// this node wrote. What audit.keep_days deletes is the oldest part of a log
// and leaves no hole.
func (l *Log) Holes(ctx context.Context) ([]Hole, error) {
	if l == nil || l.db == nil {
		return nil, nil
	}
	rows, err := l.db.QueryContext(ctx, `SELECT id FROM entries WHERE own = 1 AND class IN ('change', 'credential', 'privacy')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nums := map[string][]int64{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if name, letter, n := splitID(id); letter == audit.LetterKept {
			nums[name] = append(nums[name], n)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The outbox holds the newest numbers of the running log.
	if waiting, err := l.st.AuditOutbox(ctx, 100000); err == nil {
		for _, r := range waiting {
			if name, letter, n := splitID(r.ID); letter == audit.LetterKept {
				nums[name] = append(nums[name], n)
			}
		}
	}
	names := make([]string, 0, len(nums))
	for name := range nums {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Hole
	for _, name := range names {
		ns := nums[name]
		sort.Slice(ns, func(i, j int) bool { return ns[i] < ns[j] })
		for i := 1; i < len(ns); i++ {
			if ns[i] > ns[i-1]+1 {
				out = append(out, Hole{Log: name, From: ns[i-1] + 1, To: ns[i] - 1})
			}
		}
	}
	return out, nil
}

// Naming returns the entries that name an address, newest first, at most
// limit: the address a call came from, a value that was recorded (an own
// IP, a released or blocked client), or an item of a recorded list. It
// reads every entry, so it is for the export of what is stored about one
// address (privacy/export) and for nothing that runs often. A network that
// holds the address is not a match: the entry names the network.
func (l *Log) Naming(ctx context.Context, address string, limit int) ([]map[string]any, error) {
	if l == nil || address == "" {
		return nil, nil
	}
	if limit <= 0 || limit > MaxPage {
		limit = MaxPage
	}
	_ = l.Move(ctx)
	quoted, err := json.Marshal(address)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	take := func(body []byte) {
		if !bytes.Contains(body, quoted) {
			return
		}
		if e, err := jsonx.ParseObject(body); err == nil {
			out = append(out, e)
		}
	}
	if waiting, err := l.st.AuditOutbox(ctx, MaxPage); err == nil {
		for i := len(waiting) - 1; i >= 0 && len(out) < limit; i-- {
			take(waiting[i].Body)
		}
	}
	if l.db == nil {
		return out, nil
	}
	rows, err := l.db.QueryContext(ctx, `SELECT body FROM entries WHERE instr(body, ?) > 0 ORDER BY time_ms DESC, seq DESC LIMIT ?`, quoted, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() && len(out) < limit {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		take(body)
	}
	return out, rows.Err()
}
