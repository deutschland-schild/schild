package audit

import (
	"encoding/json"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Bounds of the inputs.
const (
	MaxInputBytes = 1 << 20
	// MaxEntryBytes bounds an entry as JSON, also one of another node.
	MaxEntryBytes = 64 << 10
)

// ParseEntry parses and checks an entry against its schema and CheckEntry.
func ParseEntry(raw []byte, local bool) (map[string]any, *EntryResult, error) {
	if len(raw) > MaxEntryBytes {
		return nil, nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxEntryBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(schema.AuditEntry, v); err != nil {
		return nil, nil, err
	}
	r, err := CheckEntry(v, local)
	return v, r, err
}

// RunVector parses and validates an audit vector input and returns the
// result of its op.
func RunVector(raw []byte) (any, error) {
	if len(raw) > MaxInputBytes {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(schema.Audit, v); err != nil {
		return nil, err
	}
	num := func(m map[string]any, k string) int64 {
		n, _ := jsonx.Normalize(m[k]).(json.Number)
		i, _ := n.Int64()
		return i
	}
	list := func(k string) []map[string]any {
		l, _ := v[k].([]any)
		var out []map[string]any
		for _, x := range l {
			m, _ := x.(map[string]any)
			out = append(out, m)
		}
		return out
	}
	entry := obj(v, "entry")
	if entry != nil && str(v, "op") != "entry" {
		if _, err := CheckEntry(entry, false); err != nil {
			return nil, err
		}
	}
	switch str(v, "op") {
	case "diff":
		a := Lookup(str(v, "action"))
		if a == nil {
			return nil, contract.Errf(contract.CodeSchema, "unknown action %s", str(v, "action"))
		}
		return Diff(a, obj(v, "before"), obj(v, "after")), nil
	case "entry":
		return CheckEntry(entry, str(v, "from") == "local")
	case "refused":
		var calls []Call
		for _, m := range list("calls") {
			calls = append(calls, Call{num(m, "t"), str(m, "action"), str(m, "operation"), str(m, "actor"), str(m, "address")})
		}
		return map[string]any{"entries": Gather(calls, int(num(v, "max_open")))}, nil
	case "keep":
		var rows []Row
		seen := map[string]bool{}
		for _, m := range list("rows") {
			r := Row{str(m, "id"), str(m, "class"), num(m, "t")}
			if seen[r.ID] || r.ID[17:18] != Letter(r.Class) {
				return nil, contract.Errf(contract.CodeSchema, "rows: id %s", r.ID)
			}
			seen[r.ID] = true
			rows = append(rows, r)
		}
		return map[string]any{"deleted": Delete(rows, num(v, "now"), num(v, "keep_days"), num(v, "max_rows"))}, nil
	default: // view
		w := obj(v, "viewer")
		var out any
		if e := View(entry, str(w, "kind"), str(w, "website")); e != nil {
			out = e
		}
		return map[string]any{"entry": out}, nil
	}
}
