//go:build !release

// Package audittest checks audit entries as a reader of the log sees them
// (MVP-36, contracts/audit.md): the tests of the dashboard API and of the
// agent API share it. It reads the catalogue of actions and decides nothing
// the contract does not say. TEST ONLY.
package audittest

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/audit"
)

// Entry is one entry as an API returns it.
type Entry = map[string]any

// Any stands for a value of a field that is there and not compared (a time
// the gateway chose).
var Any = &struct{}{}

// Log reads the audit log through an API.
type Log struct {
	T testing.TB
	// Get answers the list for a query string (without the question mark).
	Get func(query string) (status int, body []byte)
	// Way narrows Fresh to the entries made through one way (dashboard,
	// agent); "" is every way.
	Way  string
	seen map[string]bool
}

type page struct {
	Items      []Entry `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// Pages reads the list page by page with a limit and returns the pages. An
// entry on two pages fails the test.
func (l *Log) Pages(query string, limit int) [][]Entry {
	l.T.Helper()
	var out [][]Entry
	ids := map[string]bool{}
	cursor := ""
	for n := 0; ; n++ {
		q := query
		if q != "" {
			q += "&"
		}
		q += fmt.Sprintf("limit=%d", limit)
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		code, b := l.Get(q)
		if code != 200 {
			l.T.Fatalf("audit list ?%s: %d %s", q, code, b)
		}
		var p page
		if err := json.Unmarshal(b, &p); err != nil {
			l.T.Fatalf("audit list ?%s: %v: %s", q, err, b)
		}
		if len(p.Items) > limit {
			l.T.Errorf("audit list ?%s: %d items with limit %d", q, len(p.Items), limit)
		}
		for _, e := range p.Items {
			id := Str(e, "id")
			if ids[id] {
				l.T.Errorf("audit list ?%s: entry %s is on two pages", query, id)
			}
			ids[id] = true
		}
		out = append(out, p.Items)
		if p.NextCursor == nil || *p.NextCursor == "" {
			return out
		}
		if len(p.Items) == 0 || n > 10000 {
			l.T.Fatalf("audit list ?%s: a cursor after an empty page, or pages without end", query)
		}
		cursor = *p.NextCursor
	}
}

// All returns every entry of the list for a query, newest first.
func (l *Log) All(query string) []Entry {
	l.T.Helper()
	var out []Entry
	for _, p := range l.Pages(query, 200) {
		out = append(out, p...)
	}
	return out
}

// Fresh returns the entries of Way that no call of Fresh returned before,
// oldest first. Refused calls are left out: they are gathered and written
// by a loop.
func (l *Log) Fresh() []Entry {
	l.T.Helper()
	if l.seen == nil {
		l.seen = map[string]bool{}
	}
	all := l.All("")
	var out []Entry
	for i := len(all) - 1; i >= 0; i-- {
		e := all[i]
		id := Str(e, "id")
		if l.seen[id] {
			continue
		}
		l.seen[id] = true
		if Str(e, "class") == audit.ClassRefused || l.Way != "" && !strings.HasPrefix(Str(e, "operation"), l.Way+":") {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Field is what a test expects of one changed field.
type Field struct {
	// Change is added, changed or removed.
	Change string
	// Before and After are the values (Any: there, not compared).
	Before, After any
	// Added and Removed are the items of a list of texts.
	Added, Removed []string
	// Hidden is secret, unlisted, order, list or size: no value is there.
	Hidden string
}

// Want is what a test expects of one entry.
type Want struct {
	Action, Operation string
	// Subject is the id of the subject: "" none, "*" any.
	Subject string
	// Website: "" none, "*" any.
	Website         string
	Incident, Event string
	// Reason: "" none, "*" any.
	Reason string
	Fields map[string]Field
	// Absent are pointers the change must not name.
	Absent []string
}

// Expect reads the entries that are new and checks that they are exactly
// the wanted ones. It returns them in the order of wants (nil for one that
// is missing).
func (l *Log) Expect(t testing.TB, wants ...Want) []Entry {
	t.Helper()
	got := l.Fresh()
	out := make([]Entry, len(wants))
	used := make([]bool, len(got))
	for i, w := range wants {
		for j, e := range got {
			if used[j] || Str(e, "action") != w.Action || Str(e, "operation") != w.Operation {
				continue
			}
			if w.Subject != "" && w.Subject != "*" && Str(e, "subject", "id") != w.Subject {
				continue
			}
			used[j], out[i] = true, e
			break
		}
		if out[i] == nil {
			t.Errorf("no entry %s by %s (subject %q) among the %d new entries: %s", w.Action, w.Operation, w.Subject, len(got), brief(got))
			continue
		}
		Check(t, out[i])
		w.check(t, out[i])
	}
	for j, e := range got {
		if !used[j] {
			t.Errorf("an entry nobody expected: %s", JSON(e))
		}
	}
	return out
}

// None checks that no new entry was written.
func (l *Log) None(t testing.TB, what string) {
	t.Helper()
	for _, e := range l.Fresh() {
		t.Errorf("%s wrote an entry: %s", what, JSON(e))
	}
}

func brief(es []Entry) string {
	var s []string
	for _, e := range es {
		s = append(s, Str(e, "action")+" by "+Str(e, "operation")+" subject "+Str(e, "subject", "id"))
	}
	return "[" + strings.Join(s, "; ") + "]"
}

func (w Want) check(t testing.TB, e Entry) {
	t.Helper()
	name := w.Action + " by " + w.Operation
	text := func(what, want, got string) {
		t.Helper()
		switch {
		case want == "*" && got == "":
			t.Errorf("%s: no %s: %s", name, what, JSON(e))
		case want != "*" && want != got:
			t.Errorf("%s: %s is %q, want %q: %s", name, what, got, want, JSON(e))
		}
	}
	if got := Str(e, "result"); got != audit.ResultDone {
		t.Errorf("%s: result %q, want done", name, got)
	}
	text("subject", w.Subject, Str(e, "subject", "id"))
	text("website", w.Website, Str(e, "website"))
	text("cause incident", w.Incident, Str(e, "cause", "incident"))
	text("cause event", w.Event, Str(e, "cause", "event"))
	text("reason", w.Reason, Str(e, "reason"))
	for ptr, f := range w.Fields {
		got, ok := FieldOf(e, ptr)
		if !ok {
			t.Errorf("%s: the change does not name %s: %s", name, ptr, JSON(e["change"]))
			continue
		}
		if f.Change != "" && Str(got, "change") != f.Change {
			t.Errorf("%s: %s is %q, want %q: %s", name, ptr, Str(got, "change"), f.Change, JSON(got))
		}
		if f.Hidden != "" {
			if Str(got, "hidden") != f.Hidden {
				t.Errorf("%s: %s is not hidden as %s: %s", name, ptr, f.Hidden, JSON(got))
			}
			continue
		}
		if h := Str(got, "hidden"); h != "" {
			t.Errorf("%s: the value of %s is hidden (%s), the action lists the field: %s", name, ptr, h, JSON(got))
			continue
		}
		value := func(side string, want any) {
			t.Helper()
			have, there := got[side]
			switch {
			case want == nil && there:
				t.Errorf("%s: %s has a value %s: %s", name, ptr, side, JSON(got))
			case want == Any && !there:
				t.Errorf("%s: %s has no value %s: %s", name, ptr, side, JSON(got))
			case want != nil && want != Any && !same(want, have):
				t.Errorf("%s: %s %s is %s, want %s", name, ptr, side, JSON(have), JSON(want))
			}
		}
		if f.Added != nil || f.Removed != nil {
			if !same(f.Added, got["added"]) && !(len(f.Added) == 0 && got["added"] == nil) {
				t.Errorf("%s: %s added %s, want %s", name, ptr, JSON(got["added"]), JSON(f.Added))
			}
			if !same(f.Removed, got["removed"]) && !(len(f.Removed) == 0 && got["removed"] == nil) {
				t.Errorf("%s: %s removed %s, want %s", name, ptr, JSON(got["removed"]), JSON(f.Removed))
			}
			continue
		}
		value("before", f.Before)
		value("after", f.After)
	}
	for _, ptr := range w.Absent {
		if got, ok := FieldOf(e, ptr); ok {
			t.Errorf("%s: the change names %s, which did not change: %s", name, ptr, JSON(got))
		}
	}
}

// same compares two values as JSON.
func same(a, b any) bool {
	var x, y any
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	_ = json.Unmarshal(ra, &x)
	_ = json.Unmarshal(rb, &y)
	return reflect.DeepEqual(x, y)
}

// JSON is a value as JSON, for a message.
func JSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Str reads a text at a path of keys; "" when it is not there.
func Str(e map[string]any, path ...string) string {
	var cur any = e
	for _, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[k]
	}
	s, _ := cur.(string)
	return s
}

// Fields are the changed fields of an entry.
func Fields(e Entry) []map[string]any {
	c, _ := e["change"].(map[string]any)
	fs, _ := c["fields"].([]any)
	var out []map[string]any
	for _, f := range fs {
		if m, ok := f.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// FieldOf is the changed field with a pointer.
func FieldOf(e Entry, pointer string) (map[string]any, bool) {
	for _, f := range Fields(e) {
		if Str(f, "field") == pointer {
			return f, true
		}
	}
	return nil, false
}

var (
	idRE      = regexp.MustCompile(`^[0-9a-f]{16}-[kar]-[1-9][0-9]*$`)
	sessionRE = regexp.MustCompile(`^[0-9a-f]{8}$`)
	tokenRE   = regexp.MustCompile(`^tok_[0-9a-f]{12}$`)
)

// SessionRE matches the short id of a session.
func SessionRE() *regexp.Regexp { return sessionRE }

// secretWords are the endings of a segment that make a field a secret
// (contracts/audit.md section 3), written down here a second time so the
// check does not lean on the code it checks.
var secretWords = []string{"password", "passwd", "secret", "token", "key", "hash", "cookie", "code", "seed", "credential", "credentials", "authorization"}

// SecretPointer reports whether a pointer names a secret.
func SecretPointer(pointer string) bool {
	for _, seg := range strings.Split(pointer, "/") {
		s := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(seg))
		for _, w := range secretWords {
			if strings.HasSuffix(s, w) {
				return true
			}
		}
	}
	return false
}

// Listed reports whether an action lists a pointer (* stands for one
// segment).
func Listed(a *audit.Action, pointer string) bool {
	got := strings.Split(pointer, "/")
	for _, p := range a.Fields {
		want := strings.Split(p, "/")
		if len(want) != len(got) {
			continue
		}
		ok := true
		for i := range want {
			if want[i] != "*" && want[i] != got[i] {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// Check checks what the contract says of every entry, whoever wrote it: the
// id, the class and the subject of its action, the pair of action and
// operation, the website, and that a value stands only at a field the
// action lists and never at a secret.
func Check(t testing.TB, e Entry) {
	t.Helper()
	id := Str(e, "id")
	fail := func(format string, args ...any) {
		t.Helper()
		t.Errorf("entry %s (%s by %s): %s: %s", id, Str(e, "action"), Str(e, "operation"), fmt.Sprintf(format, args...), JSON(e))
	}
	if !idRE.MatchString(id) {
		fail("the id is not <log>-<letter>-<number>")
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", Str(e, "time")); err != nil {
		fail("time is not UTC seconds")
	}
	if Str(e, "node") == "" {
		fail("no node")
	}
	a := audit.Lookup(Str(e, "action"))
	if a == nil {
		fail("the action is not in the catalogue")
		return
	}
	class, result := Str(e, "class"), Str(e, "result")
	switch result {
	case audit.ResultDone:
		if class != a.Class {
			fail("class %q, the action says %q", class, a.Class)
		}
		if a.RefusedOnly {
			fail("the action is for refused calls only")
		}
	case audit.ResultRefused:
		if class != audit.ClassRefused {
			fail("a refused call of class %q", class)
		}
		if n, _ := e["count"].(float64); n < 1 {
			fail("a refused call without a count")
		}
		if _, err := time.Parse("2006-01-02T15:04:05Z", Str(e, "last")); err != nil {
			fail("a refused call without last")
		}
	default:
		fail("result %q", result)
	}
	if want := map[string]string{audit.ClassChange: "k", audit.ClassCredential: "k", audit.ClassPrivacy: "k", audit.ClassAccess: "a", audit.ClassRefused: "r"}[class]; !strings.Contains(id, "-"+want+"-") {
		fail("the letter of the id is not %q for class %q", want, class)
	}
	op := Str(e, "operation")
	found := false
	for _, o := range a.Operations {
		found = found || o == op
	}
	if !found {
		fail("the catalogue does not name operation %q for the action", op)
	}
	if kind := Str(e, "subject", "kind"); kind != a.Subject {
		fail("subject kind %q, the action says %q", kind, a.Subject)
	}
	if sid := Str(e, "subject", "id"); sid != "" {
		if _, err := netip.ParseAddr(sid); err == nil {
			fail("the subject is an address")
		}
		if _, err := netip.ParsePrefix(sid); err == nil {
			fail("the subject is a network")
		}
	}
	site := Str(e, "website")
	switch {
	case a.Website == "required" && site == "" && result == audit.ResultDone:
		fail("no website, the action says required")
	case a.Website == "none" && site != "":
		fail("website %q, the action says none", site)
	}
	if raw, _ := json.Marshal(e); len(raw) > 64<<10 {
		fail("the entry is %d bytes, over 64 KiB", len(raw))
	}
	seen := map[string]bool{}
	for _, f := range Fields(e) {
		ptr := Str(f, "field")
		if seen[ptr] {
			fail("field %s is named twice", ptr)
		}
		seen[ptr] = true
		if c := Str(f, "change"); c != "added" && c != "changed" && c != "removed" {
			fail("field %s: change %q", ptr, c)
		}
		hasValue := false
		for _, k := range []string{"before", "after", "added", "removed"} {
			if _, ok := f[k]; ok {
				hasValue = true
			}
		}
		hidden := Str(f, "hidden")
		switch {
		case SecretPointer(ptr):
			if hidden != "secret" || hasValue {
				fail("field %s is a secret and is not hidden as one", ptr)
			}
		case !Listed(a, ptr):
			if hidden != "unlisted" || hasValue {
				fail("field %s is not listed by the action and shows a value or is not marked unlisted", ptr)
			}
		case hidden != "" && hasValue:
			fail("field %s is hidden (%s) and shows a value", ptr, hidden)
		}
	}
}

// CheckDashboardActor checks the actor of an entry of the dashboard: the
// user and the short id of the session, and the address of the call.
func CheckDashboardActor(t testing.TB, e Entry, user, session, address string) {
	t.Helper()
	if k := Str(e, "actor", "kind"); k != "dashboard" {
		t.Errorf("%s: actor kind %q, want dashboard", Str(e, "id"), k)
	}
	if u := Str(e, "actor", "user"); u != user {
		t.Errorf("%s (%s): actor user %q, want %q", Str(e, "id"), Str(e, "action"), u, user)
	}
	s := Str(e, "actor", "session")
	if !sessionRE.MatchString(s) {
		t.Errorf("%s (%s): the session id %q is not 8 hex characters", Str(e, "id"), Str(e, "action"), s)
	}
	if session != "" && s != session {
		t.Errorf("%s (%s): session %q, want %q", Str(e, "id"), Str(e, "action"), s, session)
	}
	if a := Str(e, "address"); a != address {
		t.Errorf("%s (%s): address %q, want %q", Str(e, "id"), Str(e, "action"), a, address)
	}
}

// CheckAgentActor checks the actor of an entry of an agent token: its id
// and label, and the address of the call.
func CheckAgentActor(t testing.TB, e Entry, tokenID, label, address string) {
	t.Helper()
	if k := Str(e, "actor", "kind"); k != "agent" {
		t.Errorf("%s: actor kind %q, want agent", Str(e, "id"), k)
	}
	id := Str(e, "actor", "id")
	if !tokenRE.MatchString(id) || id != tokenID {
		t.Errorf("%s (%s): actor id %q, want %q", Str(e, "id"), Str(e, "action"), id, tokenID)
	}
	if l := Str(e, "actor", "label"); l != label {
		t.Errorf("%s (%s): actor label %q, want %q", Str(e, "id"), Str(e, "action"), l, label)
	}
	if a := Str(e, "address"); a != address {
		t.Errorf("%s (%s): address %q, want %q", Str(e, "id"), Str(e, "action"), a, address)
	}
}

// Operations returns the operations of a way the catalogue names for an
// action, without the way, sorted.
func Operations(way string) []string {
	set := map[string]bool{}
	for _, a := range audit.Actions.Actions {
		for _, o := range a.Operations {
			if name, ok := strings.CutPrefix(o, way+":"); ok {
				set[name] = true
			}
		}
	}
	var out []string
	for o := range set {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// Markers are values a test writes into fields, to find them again in the
// log, or not.
type Markers struct {
	secret, listed, unlisted map[string]string
}

func marker(field string) string { return "MARKER-" + field + "-9f3a" }

func put(m *map[string]string, field string) string {
	if *m == nil {
		*m = map[string]string{}
	}
	(*m)[field] = marker(field)
	return marker(field)
}

// Secret returns the marker of a secret field: it must be nowhere.
func (m *Markers) Secret(field string) string { return put(&m.secret, field) }

// SecretValue notes a secret the gateway made itself (a code, a token).
func (m *Markers) SecretValue(field, value string) {
	if m.secret == nil {
		m.secret = map[string]string{}
	}
	m.secret[field] = value
}

// Listed returns the marker of a field whose value the action records: it
// must be in the log.
func (m *Markers) Listed(field string) string { return put(&m.listed, field) }

// Unlisted returns the marker of a field that is no secret and that the
// action does not list: only its name may be in the log.
func (m *Markers) Unlisted(field string) string { return put(&m.unlisted, field) }

// Check looks for the markers in the entries an API returned and in raw
// stores (audit.db, the rows of the outbox) by name.
func (m *Markers) Check(t testing.TB, entries []Entry, raw map[string][]byte) {
	t.Helper()
	listed := JSON(entries)
	where := map[string]string{"the list of the API": listed}
	for name, b := range raw {
		where[name] = string(b)
	}
	for field, v := range m.secret {
		// As it is and as JSON writes it.
		quoted := strings.Trim(JSON(v), `"`)
		for name, text := range where {
			if strings.Contains(text, v) || strings.Contains(text, quoted) {
				t.Errorf("the secret of %s is in %s", field, name)
			}
		}
	}
	for field, v := range m.unlisted {
		for name, text := range where {
			if strings.Contains(text, v) {
				t.Errorf("the value of %s, which no action lists, is in %s", field, name)
			}
		}
	}
	for field, v := range m.listed {
		if !strings.Contains(listed, v) {
			t.Errorf("the value of %s, which its action lists, is not in the log", field)
		}
	}
}
