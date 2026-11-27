package audit

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/jsonx"
)

func TestCatalogueInSync(t *testing.T) {
	b, err := os.ReadFile("../../contracts/audit-actions.json")
	if os.IsNotExist(err) {
		t.Skip("contracts/ not present")
	}
	if err != nil || string(b) != string(actionsJSON) {
		t.Errorf("actions.json differs from contracts/audit-actions.json (run make contracts-sync): %v", err)
	}
}

func TestCatalogue(t *testing.T) {
	name := regexp.MustCompile(`^[a-z][a-z_]*\.[a-z][a-z_]*$`)
	op := regexp.MustCompile(`^(dashboard|agent|integration|cli|config|system):[A-Za-z][A-Za-z0-9_ -]*$`)
	field := regexp.MustCompile(`^(/([a-z_]+|\*))+$`)
	seen, used := map[string]bool{}, map[string]bool{}
	for _, a := range Actions.Actions {
		if !name.MatchString(a.Action) || seen[a.Action] {
			t.Errorf("action %q: malformed or twice", a.Action)
		}
		seen[a.Action] = true
		switch a.Class {
		case ClassChange, ClassCredential, ClassPrivacy, ClassAccess:
		default:
			t.Errorf("%s: class %q", a.Action, a.Class)
		}
		switch a.Website {
		case "none", "optional", "required":
		default:
			t.Errorf("%s: website %q", a.Action, a.Website)
		}
		if a.Portal && (a.Class != ClassChange || a.Website == "none") {
			t.Errorf("%s: a portal sees changes of a website only", a.Action)
		}
		if len(a.Operations) == 0 || a.Subject == "" {
			t.Errorf("%s: no operation or no subject", a.Action)
		}
		for _, o := range a.Operations {
			used[o] = true
			if !op.MatchString(o) {
				t.Errorf("%s: operation %q", a.Action, o)
			}
		}
		for _, f := range a.Fields {
			if !field.MatchString(f) {
				t.Errorf("%s: field %q", a.Action, f)
			}
		}
		for _, f := range a.Addresses {
			if !a.Records(f) {
				t.Errorf("%s: address field %s is not recorded", a.Action, f)
			}
		}
	}
	for _, o := range Actions.NotAudited {
		if used[o.Operation] || o.Reason == "" || !op.MatchString(o.Operation) {
			t.Errorf("not_audited %s: audited as well, or no reason", o.Operation)
		}
		used[o.Operation] = true
	}
	for _, o := range Actions.Undocumented {
		if !used[o.Operation] || o.Route == "" {
			t.Errorf("undocumented %s: in no action, or no route", o.Operation)
		}
	}
}

// entryOf wraps a change of a into an entry as a node writes it.
func entryOf(a Action, c Change) map[string]any {
	way, _, _ := strings.Cut(a.Operations[0], ":")
	actor := map[string]any{"kind": way}
	if way == "agent" {
		actor["id"] = "tok_0123456789ab"
	}
	e := map[string]any{"schema": "schild.audit/0.1", "id": "0a1b2c3d4e5f6071-" + Letter(a.Class) + "-1", "time": "2026-10-26T12:00:00Z", "node": "gw", "class": a.Class,
		"action": a.Action, "operation": a.Operations[0], "result": ResultDone, "actor": actor, "subject": map[string]any{"kind": a.Subject}, "change": c}
	if a.Website == "required" {
		e["website"] = "shop.example"
	}
	return e
}

// TestNoSecretInAnyEntry puts a marker into a field with a secret's name and
// into an unknown field of every action, at every depth its fields have.
func TestNoSecretInAnyEntry(t *testing.T) {
	for _, a := range Actions.Actions {
		if a.RefusedOnly {
			continue
		}
		state := map[string]any{}
		put := func(ptr string, v any) {
			m, seg := state, strings.Split(ptr[1:], "/")
			for _, s := range seg[:len(seg)-1] {
				n, ok := m[s].(map[string]any)
				if !ok {
					n = map[string]any{}
					m[s] = n
				}
				m = n
			}
			m[seg[len(seg)-1]] = v
		}
		for _, f := range a.Fields {
			for _, s := range secretEndings {
				if strings.Contains(f, "*") {
					put(strings.ReplaceAll(f, "*", "x_"+s), "marker-secret")
				}
				put(f[:strings.LastIndex(f, "/")+1]+"My-"+strings.ToUpper(s), []any{"marker-secret"})
			}
			if !a.Records(strings.ReplaceAll(f, "*", "x")) {
				put(strings.ReplaceAll(f, "*", "x"), "marker-secret")
			}
		}
		put("/not_listed/anywhere", "marker-unlisted")
		put("/not_listed_either", map[string]any{"deep": []any{"marker-unlisted"}})
		for _, c := range []Change{Diff(&a, nil, state), Diff(&a, state, nil)} {
			b, _ := jsonx.Marshal(c)
			if strings.Contains(string(b), "marker") {
				t.Errorf("%s: %s", a.Action, b)
			}
			raw, _ := jsonx.Marshal(entryOf(a, c))
			if _, _, err := ParseEntry(raw, true); err != nil {
				t.Errorf("%s: %v", a.Action, err)
			}
		}
	}
}

// TestDiffAlwaysFits: whatever changed, the entry passes its own check and
// stays far below MaxEntryBytes.
func TestDiffAlwaysFits(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	pieces := []string{"a", "\"", "\\", "\n", "‮", "ä", "💡", "/", "~", "203.0.113.7", "<", "\x00", "password", "key"}
	text := func(n int) string {
		var b strings.Builder
		for i := r.Intn(n); i > 0; i-- {
			b.WriteString(pieces[r.Intn(len(pieces))])
		}
		return b.String()
	}
	var value func(depth int) any
	value = func(depth int) any {
		switch k := r.Intn(9); {
		case k == 0:
			return nil
		case k == 1:
			return r.Intn(2) == 0
		case k == 2:
			return json.Number(fmt.Sprint(r.Intn(1000)))
		case k == 3:
			return json.Number(fmt.Sprint(r.Float64()))
		case k == 4:
			l := []any{}
			for i := r.Intn(60); i > 0; i-- {
				l = append(l, text(200))
			}
			return l
		case k == 5 && depth < 3:
			m := map[string]any{}
			for i := r.Intn(80); i > 0; i-- {
				m[text(30)] = value(depth + 1)
			}
			return m
		}
		return text(700)
	}
	biggest := 0
	for i := 0; i < 400; i++ {
		a := Actions.Actions[r.Intn(len(Actions.Actions))]
		if a.RefusedOnly {
			continue
		}
		state := func() map[string]any {
			m := map[string]any{}
			for _, f := range a.Fields {
				seg := strings.Split(f[1:], "/")
				if len(seg) > 1 {
					sub := map[string]any{}
					for j := r.Intn(60); j > 0; j-- {
						sub[text(12)] = value(1)
					}
					m[seg[0]] = sub
				} else {
					m[seg[0]] = value(0)
				}
			}
			return m
		}
		raw, err := jsonx.Marshal(entryOf(a, Diff(&a, state(), state())))
		if err != nil {
			t.Fatal(err)
		}
		biggest = max(biggest, len(raw))
		e, res, err := ParseEntry(raw, true)
		if err != nil || res.Stripped != 0 {
			t.Fatalf("%s: %v %+v\n%s", a.Action, err, res, raw)
		}
		// Cutting twice is cutting once, and the result is still an entry.
		in := CutInput{Entry: e, Now: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), RawIPDays: 14, Erased: []string{"203.0.113.9"}}
		once := Cut(in)
		in.Entry = once
		if twice := Cut(in); !reflect.DeepEqual(once, twice) {
			t.Fatalf("%s: cut twice differs\n%v\n%v", a.Action, once, twice)
		}
		out, _ := jsonx.Marshal(once)
		if _, _, err := ParseEntry(out, true); err != nil {
			t.Fatalf("%s: after the cut: %v", a.Action, err)
		}
	}
	if biggest > MaxEntryBytes/2 {
		t.Errorf("largest entry %d bytes", biggest)
	}
	t.Logf("largest entry %d bytes", biggest)
}

// TestCutListOnce: a text that only then holds a network changes an item of
// a list after the list was put in order. The list is still each item once,
// in byte order, and a second cut changes nothing.
func TestCutListOnce(t *testing.T) {
	late := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	soon := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name    string
		address string
		now     time.Time
		erased  []string
		in, out []any
	}{
		{"twice", "", late, nil, []any{"203.0.113.7", "a 203.0.113.0/24", "a 203.0.113.7"}, []any{"203.0.113.0/24", "a 203.0.113.0/24"}},
		{"order", "203.0.113.7", late, nil, []any{"203.0.113.5 a", "203.0.113.7 a"}, []any{"203.0.113.0/24 a", "203.0.113.5 a"}},
		{"erased", "", soon, []string{"203.0.113.7"}, []any{"a erased", "a 203.0.113.7", "203.0.113.7 a"}, []any{"a erased", "erased a"}},
		{"untouched", "", soon, []string{"203.0.113.7"}, []any{"b", "a"}, []any{"b", "a"}},
	} {
		a := *Lookup("rate_limit.remove")
		e := entryOf(a, Change{Fields: []Field{}})
		e["change"] = map[string]any{"fields": []any{map[string]any{"field": "/methods", "change": "removed", "removed": c.in}}}
		if c.address != "" {
			e["address"] = c.address
		}
		raw, _ := jsonx.Marshal(e)
		e, _, err := ParseEntry(raw, true)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		in := CutInput{Entry: e, Now: c.now, RawIPDays: 14, Erased: c.erased}
		once := Cut(in)
		if got := fields(once)[0]["removed"]; !reflect.DeepEqual(got, c.out) {
			t.Errorf("%s: %q, want %q", c.name, got, c.out)
		}
		in.Entry = once
		if twice := Cut(in); !reflect.DeepEqual(once, twice) {
			t.Errorf("%s: cut twice differs\n%v\n%v", c.name, once, twice)
		}
	}
}

// TestTypicalSize holds the number the storage estimate of audit.md is built on.
func TestTypicalSize(t *testing.T) {
	a := *Lookup("rule_exception.set")
	e := entryOf(a, Diff(&a, nil, map[string]any{"path": "/kontakt", "target": "ARGS:message", "repository": "crs", "rules": []any{"942100"}}))
	e["actor"] = map[string]any{"kind": "agent", "id": "tok_0123456789ab", "label": "coding-agent"}
	e["operation"] = "agent:createAgentException"
	e["reason"] = "Visitors write SQL words into the contact form, checked with the site's operator"
	raw, _ := jsonx.Marshal(e)
	t.Logf("%d bytes", len(raw))
	if len(raw) > 1024 {
		t.Errorf("%d bytes", len(raw))
	}
}
