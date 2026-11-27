package audit

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
)

// Letters of an entry id.
const (
	LetterKept    = "k"
	LetterAccess  = "a"
	LetterRefused = "r"
)

// Letter of the ids of a class.
func Letter(class string) string {
	switch class {
	case ClassAccess:
		return LetterAccess
	case ClassRefused:
		return LetterRefused
	}
	return LetterKept
}

// EntryResult of CheckEntry.
type EntryResult struct {
	Kept  bool `json:"kept"`
	Known bool `json:"known"` // this build knows the action
	// Stripped counts the fields whose values were taken out of an entry of
	// a member, because this build may not record them.
	Stripped int `json:"stripped"`
}

// CheckEntry checks an entry that passed its schema. local: this node writes
// it; otherwise a member of the group handed it over: an action this build
// does not know yet is taken, and a value this build may not record is taken
// out of e.
func CheckEntry(e map[string]any, local bool) (*EntryResult, error) {
	bad := func(format string, a ...any) (*EntryResult, error) {
		return nil, contract.Errf(contract.CodeSchema, format, a...)
	}
	id, class, name := str(e, "id"), str(e, "class"), str(e, "action")
	op, result := str(e, "operation"), str(e, "result")
	actor, subject := obj(e, "actor"), obj(e, "subject")
	_, hasChange := e["change"]
	_, hasCount := e["count"]
	_, hasLast := e["last"]
	_, hasSite := e["website"]
	for _, k := range []string{"time", "last"} {
		if s, ok := e[k].(string); ok {
			if _, err := time.Parse("2006-01-02T15:04:05Z", s); err != nil {
				return bad("%s: %v", k, err)
			}
		}
	}
	if id[17:18] != Letter(class) {
		return bad("id %s: not of class %s", id, class)
	}
	if (result == ResultRefused) != (class == ClassRefused) {
		return bad("class %s with result %s", class, result)
	}
	if class == ClassRefused {
		if hasChange {
			return bad("a refused call changes nothing")
		}
		if hasCount != hasLast {
			return bad("count and last belong together")
		}
	} else if hasCount || hasLast {
		return bad("count and last are for refused calls")
	}
	if way, _, _ := strings.Cut(op, ":"); str(actor, "kind") != way {
		return bad("actor %s with operation %s", str(actor, "kind"), op)
	}
	if k := str(actor, "kind"); result == ResultDone && (k == "agent" || k == "integration") && str(actor, "id") == "" {
		return bad("actor %s without id", k)
	}
	// A subject is never named by an address: every viewer sees the subject,
	// also a session of one website. A website may be one.
	if id := str(subject, "id"); id != "" {
		switch k := str(subject, "kind"); k {
		case "address", "client":
			return bad("a subject of kind %s has no id", k)
		case "website":
		default:
			if _, _, isAddr := parseNet(id); isAddr {
				return bad("subject %s is named by an address", k)
			}
		}
	}
	if hasLast && str(e, "last") < str(e, "time") {
		return bad("last before time")
	}
	a := Lookup(name)
	if a == nil {
		if local {
			return bad("unknown action %s", name)
		}
		n, err := checkFields(e, func(p string) bool { return !secretPointer(p) }, false)
		if err != nil {
			return nil, err
		}
		return &EntryResult{Kept: Letter(class) == LetterKept, Stripped: n}, nil
	}
	if class != ClassRefused && class != a.Class {
		return bad("action %s is of class %s", name, a.Class)
	}
	if a.RefusedOnly && class != ClassRefused {
		return bad("action %s is for refused calls", name)
	}
	if str(subject, "kind") != a.Subject {
		return bad("action %s is about %s", name, a.Subject)
	}
	if local {
		if !a.allows(op) {
			return bad("action %s by operation %s", name, op)
		}
		if class != ClassRefused && a.Website == "required" && !hasSite || hasSite && a.Website == "none" {
			return bad("action %s: website is %s", name, a.Website)
		}
	}
	n, err := checkFields(e, a.Records, local)
	if err != nil {
		return nil, err
	}
	return &EntryResult{Kept: Letter(class) == LetterKept, Known: true, Stripped: n}, nil
}

var valueKeys = []string{"before", "after", "added", "removed"}

// checkFields: a field has a value or a reason why it has none, and a value
// only where it may be recorded.
func checkFields(e map[string]any, records func(string) bool, local bool) (int, error) {
	n := 0
	for _, f := range fields(e) {
		p := str(f, "field")
		valued := false
		for _, k := range valueKeys {
			if _, ok := f[k]; ok {
				valued = true
			}
		}
		if _, hidden := f["hidden"]; valued == hidden {
			return 0, contract.Errf(contract.CodeSchema, "field %s: a value or a reason why there is none", p)
		}
		if !valued || records(p) {
			continue
		}
		if local {
			return 0, contract.Errf(contract.CodeSchema, "field %s may not be recorded", p)
		}
		hide(f, notRecorded(p))
		n++
	}
	return n, nil
}

// hide takes the values out of a field.
func hide(f map[string]any, why string) {
	for _, k := range []string{"before", "after", "added", "removed", "more", "cut"} {
		delete(f, k)
	}
	f["hidden"] = why
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func obj(m map[string]any, k string) map[string]any { o, _ := m[k].(map[string]any); return o }

func fields(e map[string]any) []map[string]any {
	l, _ := obj(e, "change")["fields"].([]any)
	out := make([]map[string]any, 0, len(l))
	for _, x := range l {
		if f, ok := x.(map[string]any); ok {
			out = append(out, f)
		}
	}
	return out
}

func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// parseNet parses address/bits; without bits it is the single address.
func parseNet(s string) (netip.Addr, int, bool) {
	addr, bits, has := strings.Cut(s, "/")
	a, ok := parseAddr(addr)
	if !ok {
		return a, 0, false
	}
	if !has {
		return a, a.BitLen(), true
	}
	n, err := strconv.Atoi(bits)
	if err != nil || strconv.Itoa(n) != bits || n < 0 || n > a.BitLen() || strings.Contains(addr, ":") && a.Is4() {
		return a, 0, false
	}
	return a, n, true
}
