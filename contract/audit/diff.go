package audit

import (
	"encoding/json"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"
)

// Bounds of what an entry records of a change.
const (
	MaxFields       = 64
	MaxChangeBytes  = 8192
	MaxValueBytes   = 512
	MaxItems        = 32
	MaxItemBytes    = 256
	MaxPointerBytes = 512
	fieldCost       = 16 // per recorded field, beside its pointer and values
	scalarCost      = 8  // a number or a boolean
)

// Reasons why a field has no value.
const (
	HiddenSecret   = "secret"   // named like a secret
	HiddenUnlisted = "unlisted" // not in the list of the action
	HiddenList     = "list"     // a list of something else than texts
	HiddenOrder    = "order"    // the same items in another order or number
	HiddenSize     = "size"     // MaxChangeBytes is used up
	HiddenOperator = "operator" // addresses the operator set, to a website's viewer
)

// Field is one changed field of an entry.
type Field struct {
	Field   string   `json:"field"`
	Change  string   `json:"change"`
	Before  any      `json:"before,omitempty"`
	After   any      `json:"after,omitempty"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	More    int      `json:"more,omitempty"`
	Cut     bool     `json:"cut,omitempty"`
	Hidden  string   `json:"hidden,omitempty"`
}

// Change is what an entry records of a change.
type Change struct {
	Fields     []Field `json:"fields"`
	MoreFields int     `json:"more_fields,omitempty"`
}

// Diff compares two JSON objects (nil: not there) field by field. A value is
// recorded only for a field the action lists; of every other field only that
// it changed. Nested objects are compared to their last field, a list is one
// field, null and an empty object are not there.
func Diff(a *Action, before, after map[string]any) Change {
	b, n := map[string]any{}, map[string]any{}
	flatten(before, "", b)
	flatten(after, "", n)
	ptrs := make([]string, 0, len(b)+len(n))
	for p := range b {
		ptrs = append(ptrs, p)
	}
	for p := range n {
		if _, ok := b[p]; !ok {
			ptrs = append(ptrs, p)
		}
	}
	sort.Strings(ptrs)
	out := Change{Fields: []Field{}}
	used := 0
	for _, p := range ptrs {
		x, inB := b[p]
		y, inN := n[p]
		if inB && inN && equal(x, y) {
			continue
		}
		name := clean(p)
		f := Field{Field: name, Change: "changed"}
		if !inB {
			f.Change = "added"
		} else if !inN {
			f.Change = "removed"
		}
		cost := len(name) + fieldCost
		if len(name) > MaxPointerBytes {
			out.MoreFields++
			continue
		}
		v, c := f, 0
		if a == nil || !a.Records(p) {
			v.Hidden = notRecorded(p)
		} else {
			c = values(&v, x, inB, y, inN)
		}
		if c > 0 && used+cost+c > MaxChangeBytes {
			v, c = f, 0
			v.Hidden = HiddenSize
		}
		if used+cost+c > MaxChangeBytes || len(out.Fields) == MaxFields {
			out.MoreFields++
			continue
		}
		used += cost + c
		out.Fields = append(out.Fields, v)
	}
	return out
}

// values puts the values of a field into f and returns what they cost.
func values(f *Field, x any, inB bool, y any, inN bool) int {
	_, lx := x.([]any)
	_, ly := y.([]any)
	if !lx && !ly {
		c := 0
		if inB {
			f.Before = scalar(f, x, &c)
		}
		if inN {
			f.After = scalar(f, y, &c)
		}
		return c
	}
	bs, ok1 := texts(x, inB)
	ns, ok2 := texts(y, inN)
	if !ok1 || !ok2 {
		f.Hidden = HiddenList
		return 0
	}
	added, removed := minus(ns, bs), minus(bs, ns)
	if len(added)+len(removed) == 0 {
		f.Hidden = HiddenOrder
		return 0
	}
	c := 0
	take := func(in []string) []string {
		var out []string
		for _, s := range in {
			if len(out) == MaxItems {
				f.More += len(in) - MaxItems
				break
			}
			s, was := clip(clean(s), MaxItemBytes)
			if was {
				f.Cut = true
			}
			out = append(out, s)
			c += len(s)
		}
		return out
	}
	f.Added, f.Removed = take(added), take(removed)
	return c + fieldCost
}

func scalar(f *Field, v any, cost *int) any {
	s, ok := v.(string)
	if !ok {
		*cost += scalarCost
		return v
	}
	s, was := clip(clean(s), MaxValueBytes)
	if was {
		f.Cut = true
	}
	*cost += len(s) + scalarCost
	return s
}

// texts returns the items of a list of texts; a missing list is empty.
func texts(v any, there bool) ([]string, bool) {
	if !there {
		return nil, true
	}
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// minus returns the items of a that are not in b, each once, in byte order.
func minus(a, b []string) []string {
	drop := map[string]bool{}
	for _, s := range b {
		drop[s] = true
	}
	var out []string
	for _, s := range a {
		if !drop[s] {
			drop[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func flatten(v any, ptr string, out map[string]any) {
	switch t := v.(type) {
	case nil:
	case map[string]any:
		for k, x := range t {
			flatten(x, ptr+"/"+strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1"), out)
		}
	default:
		out[ptr] = t
	}
}

// equal compares two JSON values; numbers by value.
func equal(x, y any) bool {
	switch a := x.(type) {
	case json.Number:
		b, ok := y.(json.Number)
		if !ok {
			return false
		}
		p, ok1 := new(big.Rat).SetString(string(a))
		q, ok2 := new(big.Rat).SetString(string(b))
		return ok1 && ok2 && p.Cmp(q) == 0
	case []any:
		b, ok := y.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !equal(a[i], b[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		b, ok := y.(map[string]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for k, v := range a {
			w, ok := b[k]
			if !ok || !equal(v, w) {
				return false
			}
		}
		return true
	}
	switch y.(type) {
	case []any, map[string]any:
		return false
	}
	return x == y
}

// clean replaces control characters and characters that change the direction
// of text or show nothing, so an entry reads as it is.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r >= 0x7f && r <= 0x9f, r >= 0x200b && r <= 0x200f, r >= 0x2028 && r <= 0x202e, r >= 0x2060 && r <= 0x2069, r == 0xfeff:
			return 0xfffd
		}
		return r
	}, s)
}

// clip cuts s to at most n bytes between two characters.
func clip(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

// Text is a text of an entry from outside (a reason, a label): without
// control characters, at most n bytes.
func Text(s string, n int) string {
	s, _ = clip(clean(s), n)
	return s
}
