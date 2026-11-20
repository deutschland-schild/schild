package crowdsec

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
)

// Known is what the running set remembers about a rule.
type Known struct {
	Digest    string `json:"digest"`
	FirstSeen string `json:"first_seen"`
	ChangedAt string `json:"changed_at"`
}

// Limits of one update. Vectors lower them to stay small; the gateway uses
// DefaultLimits.
type Limits struct {
	IndexBytes int
	Rules      int
	SetBytes   int
	SetLines   int
	// ShrinkBase is what a new set is held against: the rule count of the
	// image snapshot. 0: there is no snapshot, the running set counts.
	// ShrinkOff: no check, the operator named this commit with a pin.
	ShrinkBase int
}

// DefaultLimits are the bounds of the gateway.
var DefaultLimits = Limits{IndexBytes: MaxIndexBytes, Rules: MaxRules, SetBytes: MaxSetBytes, SetLines: MaxSetLines}

// Shrinks reports whether a set of n rules is too small. It compares with the
// image snapshot, not with the running set: a set that once ran too large must
// not block the way back, and a set that shrank must not lower the mark, or a
// hollow index could walk the rules down in steps (D43).
func Shrinks(n, base, running int) bool {
	switch {
	case base == ShrinkOff:
		return false
	case base == 0:
		base = running
	}
	return n*MinShrinkDivisor < base
}

// SecLangSize counts the SecLang text and the SecRule lines of a set.
func SecLangSize(rules []SetRule) (size, lines int) {
	for i := range rules {
		for _, t := range rules[i].SecLang {
			size += len(t)
			lines += strings.Count(t, "\n") + 1
		}
	}
	return size, lines
}

// CheckSetBounds repeats the set bounds on a stored set before it loads: a row
// from an earlier version may hold more than this contract allows. "": fine.
func CheckSetBounds(rules []SetRule) string {
	size, lines := SecLangSize(rules)
	switch {
	case len(rules) > MaxRules:
		return RefuseTooManyRules
	case size > MaxSetBytes, lines > MaxSetLines:
		return RefuseSetTooLarge
	}
	return ""
}

// SkippedRule is one entry of the skipped list.
type SkippedRule struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Code    string `json:"code"`
}

// SetRule is a loaded rule with its history.
type SetRule struct {
	Rule
	FirstSeen string `json:"first_seen"`
	ChangedAt string `json:"changed_at"`
}

// Update is the result of checking one downloaded index. Outcome accepted: the
// set may be compiled and swapped. Outcome refused: Code says why, the running
// set stays and nothing else in the result is filled.
type Update struct {
	Outcome     string        `json:"outcome"` // accepted | refused
	Code        string        `json:"code,omitempty"`
	IndexDigest string        `json:"index_sha256,omitempty"`
	Rules       []SetRule     `json:"rules,omitempty"`
	Skipped     []SkippedRule `json:"skipped,omitempty"`
	NotSelected int           `json:"not_selected"`
	Added       []string      `json:"added,omitempty"`
	Changed     []string      `json:"changed,omitempty"`
	Removed     []string      `json:"removed,omitempty"`
}

func refused(code string) *Update { return &Update{Outcome: "refused", Code: code} }

// CheckIndex runs the update rules on a downloaded .index.json. previous is
// the running set (nil: none), now the time of the check. Never an error: a
// broken index is a refusal.
func CheckIndex(raw []byte, previous map[string]Known, lim Limits, now string) *Update {
	if len(raw) > lim.IndexBytes {
		return refused(RefuseIndexSize)
	}
	doc, err := jsonx.ParseObject(raw)
	if err != nil {
		return refused(RefuseMalformed)
	}
	items, ok := doc["appsec-rules"].(map[string]any)
	if !ok {
		return refused(RefuseMalformed)
	}
	colls, _ := doc["collections"].(map[string]any)
	coll, _ := colls[Collection].(map[string]any)
	list, ok := coll["appsec-rules"].([]any)
	if !ok {
		return refused(RefuseMalformed)
	}
	members := make(map[string]bool, len(list))
	for _, x := range list {
		s, ok := x.(string)
		if !ok {
			return refused(RefuseMalformed)
		}
		members[s] = true
	}
	names := make([]string, 0, len(items))
	notSelected := 0
	for n := range items {
		if Selected(n, members) {
			names = append(names, n)
		} else {
			notSelected++
		}
	}
	sort.Strings(names)
	if len(names) > lim.Rules {
		return refused(RefuseTooManyRules)
	}
	sum := sha256.Sum256(raw)
	u := &Update{Outcome: "accepted", IndexDigest: hex.EncodeToString(sum[:]), NotSelected: notSelected,
		Rules: []SetRule{}, Skipped: []SkippedRule{}, Added: []string{}, Changed: []string{}, Removed: []string{}}
	taken := map[int]string{}
	for _, name := range names {
		it, ok := items[name].(map[string]any)
		if !ok {
			return refused(RefuseMalformed)
		}
		path, ok1 := it["path"].(string)
		version, ok2 := it["version"].(string)
		content, ok3 := it["content"].(string)
		versions, ok4 := it["versions"].(map[string]any)
		if !ok1 || !ok2 || !ok3 || !ok4 || !reVersion.MatchString(version) {
			return refused(RefuseMalformed)
		}
		body, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return refused(RefuseMalformed)
		}
		sk := func(code string) {
			u.Skipped = append(u.Skipped, SkippedRule{Name: name, Version: version, Code: code})
		}
		if path != "appsec-rules/"+name+".yaml" {
			sk(SkipNameMismatch)
			continue
		}
		v, _ := versions[version].(map[string]any)
		want, _ := v["digest"].(string)
		bsum := sha256.Sum256(body)
		digest := hex.EncodeToString(bsum[:])
		if !reDigest.MatchString(want) || want != digest {
			sk(SkipDigest)
			continue
		}
		if d, _ := v["deprecated"].(bool); d {
			sk(SkipDeprecated)
			continue
		}
		desc, _ := it["description"].(string)
		r, s := Convert(name, version, digest, body, desc)
		if s != nil {
			sk(s.Code)
			continue
		}
		if other, dup := taken[r.BaseID]; dup {
			_ = other
			sk(SkipIDCollision)
			continue
		}
		taken[r.BaseID] = name
		sr := SetRule{Rule: *r, FirstSeen: now, ChangedAt: now}
		if k, ok := previous[name]; ok {
			sr.FirstSeen = k.FirstSeen
			if k.Digest == digest {
				sr.ChangedAt = k.ChangedAt
			} else {
				u.Changed = append(u.Changed, name)
			}
		} else {
			u.Added = append(u.Added, name)
		}
		u.Rules = append(u.Rules, sr)
	}
	if size, lines := SecLangSize(u.Rules); size > lim.SetBytes || lines > lim.SetLines {
		return refused(RefuseSetTooLarge)
	}
	if len(u.Rules) == 0 {
		return refused(RefuseEmpty)
	}
	if Shrinks(len(u.Rules), lim.ShrinkBase, len(previous)) {
		return refused(RefuseShrink)
	}
	loaded := make(map[string]bool, len(u.Rules))
	for _, r := range u.Rules {
		loaded[r.Name] = true
	}
	for n := range previous {
		if !loaded[n] {
			u.Removed = append(u.Removed, n)
		}
	}
	sort.Strings(u.Removed)
	return u
}

// Set values of a selection.
const (
	SetStored = "stored"
	SetImage  = "image"
	SetNone   = "none"
)

// Candidate is a set that could load at start.
type Candidate struct {
	Present bool
	Valid   bool // parses, digests match, loads at least one rule and compiles
	Commit  string
	Time    string // Set.Time: "" when the set has no usable date
}

// Selection says which set loads at start.
type Selection struct {
	Set string `json:"set"`
	// PinPending: a pin is set and the loaded set is not that commit yet.
	PinPending bool `json:"pin_pending"`
}

// usableTime reads a set date. A date that does not parse, or lies further in
// the future than the clock skew, counts as no date: a wrong clock must not
// keep a stale set alive.
func usableTime(s string, now time.Time) (time.Time, bool) {
	t, err := msg.ParseTime(s)
	if err != nil || t.After(now.Add(contract.MaxClockSkew)) {
		return time.Time{}, false
	}
	return t, true
}

// newer picks between two valid sets: the newer date wins, a date beats no
// date, and a tie or two sets without a date keep the stored set, which also
// holds this gateway's history of the rules.
func newer(stored, image Candidate, now time.Time) string {
	st, sok := usableTime(stored.Time, now)
	it, iok := usableTime(image.Time, now)
	if iok && (!sok || it.After(st)) {
		return SetImage
	}
	return SetStored
}

// SelectSet says which set loads at start. A set that matches the pin wins.
// Otherwise the newer of the valid sets runs, whatever auto_update says, and
// a pin stays pending. A set that fails to load is out, so the other one
// runs; with none no rules run. A start never fails because of this source.
func SelectSet(state, pin string, stored, image Candidate, now time.Time) Selection {
	if state == StateOff {
		return Selection{Set: SetNone}
	}
	storedOK, imageOK := stored.Present && stored.Valid, image.Present && image.Valid
	switch {
	case pin != "" && storedOK && stored.Commit == pin:
		return Selection{Set: SetStored}
	case pin != "" && imageOK && image.Commit == pin:
		return Selection{Set: SetImage}
	case storedOK && imageOK:
		return Selection{Set: newer(stored, image, now), PinPending: pin != ""}
	case storedOK:
		return Selection{Set: SetStored, PinPending: pin != ""}
	case imageOK:
		return Selection{Set: SetImage, PinPending: pin != ""}
	}
	return Selection{Set: SetNone, PinPending: pin != ""}
}
