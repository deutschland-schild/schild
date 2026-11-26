// Package audit holds the contract of the audit log (draft, MVP-36,
// contracts/audit.md): the closed list of actions, what an entry records of
// a change, whether an entry is valid, how refused calls are gathered, what
// is deleted and cut, and what a viewer sees. The Python cross-check
// (contracts/tools/crosscheck.py) computes the same results.
package audit

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed actions.json
var actionsJSON []byte

// Classes of an entry.
const (
	ClassChange     = "change"     // kept audit.keep_days
	ClassCredential = "credential" // kept audit.keep_days
	ClassPrivacy    = "privacy"    // kept audit.keep_days
	ClassAccess     = "access"     // sign-ins: AccessDays, MaxAccessRows
	ClassRefused    = "refused"    // refused calls: AccessDays, MaxAccessRows
)

// Results of an entry.
const (
	ResultDone    = "done"
	ResultRefused = "refused"
)

// Action is one entry of contracts/audit-actions.json.
type Action struct {
	Action     string   `json:"action"`
	Class      string   `json:"class"`
	Subject    string   `json:"subject"`
	Website    string   `json:"website"` // none, optional, required
	Operations []string `json:"operations"`
	// Fields lists the JSON pointers whose values may be recorded; * stands
	// for one segment. Every other field is recorded by name only.
	Fields []string `json:"fields"`
	// Addresses are the fields that hold client addresses (cut and erased).
	Addresses []string `json:"addresses,omitempty"`
	// Portal: a session of one website sees the entries of its website.
	Portal bool `json:"portal,omitempty"`
	// RefusedOnly: only entries with result refused.
	RefusedOnly bool `json:"refused_only,omitempty"`
}

// Operation that writes no entry, and why.
type Operation struct {
	Operation string `json:"operation"`
	Reason    string `json:"reason,omitempty"`
	Route     string `json:"route,omitempty"`
}

// Catalogue is contracts/audit-actions.json.
type Catalogue struct {
	Schema     string      `json:"schema"`
	Actions    []Action    `json:"actions"`
	NotAudited []Operation `json:"not_audited"`
	// Undocumented operations are served but stand in no API document.
	Undocumented []Operation `json:"undocumented"`
}

// Actions is the catalogue of this build.
var Actions = func() *Catalogue {
	var c Catalogue
	if err := json.Unmarshal(actionsJSON, &c); err != nil {
		panic("audit: actions.json: " + err.Error())
	}
	return &c
}()

var byName = func() map[string]*Action {
	m := map[string]*Action{}
	for i := range Actions.Actions {
		m[Actions.Actions[i].Action] = &Actions.Actions[i]
	}
	return m
}()

// Lookup returns an action, nil when this build does not know it.
func Lookup(name string) *Action { return byName[name] }

func (a *Action) allows(op string) bool {
	for _, o := range a.Operations {
		if o == op {
			return true
		}
	}
	return false
}

// Records reports whether the value of a field may be recorded.
func (a *Action) Records(pointer string) bool {
	return !secretPointer(pointer) && matchAny(a.Fields, pointer)
}

func (a *Action) isAddress(pointer string) bool { return matchAny(a.Addresses, pointer) }

func matchAny(patterns []string, pointer string) bool {
	seg := strings.Split(pointer, "/")
	for _, p := range patterns {
		ps := strings.Split(p, "/")
		if len(ps) != len(seg) {
			continue
		}
		ok := true
		for i := range ps {
			if ps[i] != "*" && ps[i] != seg[i] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// notRecorded says why the value of a field is not recorded.
func notRecorded(pointer string) string {
	if secretPointer(pointer) {
		return HiddenSecret
	}
	return HiddenUnlisted
}

// secretEndings: a field with a name that ends so is never recorded with its
// value, also when an action lists it.
var secretEndings = []string{"password", "passwd", "secret", "token", "key", "hash", "cookie", "code", "seed", "credential", "credentials", "authorization"}

func secretPointer(pointer string) bool {
	for _, seg := range strings.Split(pointer, "/") {
		var b strings.Builder
		for _, r := range seg {
			switch {
			case r == '-' || r == '_' || r == '.':
			case r >= 'A' && r <= 'Z':
				b.WriteRune(r + 'a' - 'A')
			default:
				b.WriteRune(r)
			}
		}
		n := b.String()
		for _, e := range secretEndings {
			if strings.HasSuffix(n, e) {
				return true
			}
		}
	}
	return false
}
