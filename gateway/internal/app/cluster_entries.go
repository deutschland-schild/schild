package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
)

// A thing the group shares (a list, the settings overlay, the policies of
// the websites) is a set of entries, and each entry travels as a record of
// its own (contract/cluster Value). So two nodes that change different
// entries of one thing at the same moment both keep their change, and a
// node that joins adds what it holds to the group instead of losing it.
// Only two changes of the very same entry settle by the later clock.
//
// A codec cuts the value schild.db holds of a thing into entries and puts
// entries back into it. An entry's key names it on every node the same.

type entryCodec interface {
	// split returns the entries of a value: key -> canonical bytes.
	split(blob []byte) (map[string][]byte, error)
	// join returns the value with some entries set and some removed.
	join(blob []byte, set map[string][]byte, del []string) ([]byte, error)
}

func keyOf(parts ...any) string {
	b, _ := json.Marshal(parts)
	return string(b)
}

// ---- a table dump {"columns": [...], "rows": [[...]]}: one entry per row,
// keyed by its first pk columns.

type tableCodec struct{ pk int }

type tableDump struct {
	Columns []string          `json:"columns"`
	Rows    []json.RawMessage `json:"rows"`
}

func (c tableCodec) rowKey(row json.RawMessage) (string, error) {
	var vals []json.RawMessage
	if err := json.Unmarshal(row, &vals); err != nil || len(vals) < c.pk {
		return "", errors.New("row of a shared table has too few values")
	}
	var b bytes.Buffer
	b.WriteByte('[')
	for i, v := range vals[:c.pk] {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := json.Compact(&b, v); err != nil {
			return "", err
		}
	}
	b.WriteByte(']')
	return b.String(), nil
}

func (c tableCodec) split(blob []byte) (map[string][]byte, error) {
	var d tableDump
	if err := json.Unmarshal(blob, &d); err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(d.Rows))
	for _, row := range d.Rows {
		k, err := c.rowKey(row)
		if err != nil {
			return nil, err
		}
		out[k] = row
	}
	return out, nil
}

func (c tableCodec) join(blob []byte, set map[string][]byte, del []string) ([]byte, error) {
	var d tableDump
	if err := json.Unmarshal(blob, &d); err != nil {
		return nil, err
	}
	rows := map[string]json.RawMessage{}
	for _, row := range d.Rows {
		k, err := c.rowKey(row)
		if err != nil {
			return nil, err
		}
		rows[k] = row
	}
	for k, v := range set {
		// A row of another node has to be a row of this table.
		var vals []json.RawMessage
		if json.Unmarshal(v, &vals) != nil || len(vals) != len(d.Columns) {
			continue
		}
		if rk, err := c.rowKey(v); err != nil || rk != k {
			continue
		}
		rows[k] = v
	}
	for _, k := range del {
		delete(rows, k)
	}
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	d.Rows = d.Rows[:0]
	for _, k := range keys {
		d.Rows = append(d.Rows, rows[k])
	}
	if d.Rows == nil {
		d.Rows = []json.RawMessage{}
	}
	return json.Marshal(d)
}

// ---- a JSON object, cut along its keys down to depth: the settings
// overlay to its leaves, the state of the websites to one entry per website
// and one per other field.

type objectCodec struct{ depth int }

func (c objectCodec) walk(path []string, raw json.RawMessage, out map[string][]byte) {
	var obj map[string]json.RawMessage
	if len(path) < c.depth && len(raw) > 0 && raw[0] == '{' && json.Unmarshal(raw, &obj) == nil && len(obj) > 0 {
		for k, v := range obj {
			c.walk(append(append([]string{}, path...), k), v, out)
		}
		return
	}
	if len(path) == 0 {
		return // an empty object has no entries
	}
	parts := make([]any, len(path))
	for i, p := range path {
		parts[i] = p
	}
	var buf bytes.Buffer
	if json.Compact(&buf, raw) != nil {
		return
	}
	out[keyOf(parts...)] = buf.Bytes()
}

func (c objectCodec) split(blob []byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	if len(bytes.TrimSpace(blob)) == 0 {
		return out, nil
	}
	if !json.Valid(blob) {
		return nil, errors.New("value is no JSON")
	}
	c.walk(nil, bytes.TrimSpace(blob), out)
	return out, nil
}

func pathOf(key string) ([]string, bool) {
	var path []string
	if json.Unmarshal([]byte(key), &path) != nil || len(path) == 0 {
		return nil, false
	}
	return path, true
}

func (c objectCodec) join(blob []byte, set map[string][]byte, del []string) ([]byte, error) {
	root := map[string]any{}
	if len(bytes.TrimSpace(blob)) > 0 {
		d := json.NewDecoder(bytes.NewReader(blob))
		d.UseNumber()
		if err := d.Decode(&root); err != nil {
			return nil, err
		}
	}
	for k, v := range set {
		path, ok := pathOf(k)
		if !ok || len(path) > c.depth {
			continue
		}
		var val any
		d := json.NewDecoder(bytes.NewReader(v))
		d.UseNumber()
		if d.Decode(&val) != nil {
			continue
		}
		m := root
		for _, p := range path[:len(path)-1] {
			next, ok := m[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[p] = next
			}
			m = next
		}
		m[path[len(path)-1]] = val
	}
	for _, k := range del {
		path, ok := pathOf(k)
		if !ok {
			continue
		}
		// Remove the leaf, then every parent it left empty.
		chain := []map[string]any{root}
		m := root
		for _, p := range path[:len(path)-1] {
			next, ok := m[p].(map[string]any)
			if !ok {
				chain = nil
				break
			}
			chain = append(chain, next)
			m = next
		}
		if chain == nil {
			continue
		}
		delete(m, path[len(path)-1])
		for i := len(chain) - 1; i > 0; i-- {
			if len(chain[i]) == 0 {
				delete(chain[i-1], path[i-1])
			}
		}
	}
	return json.Marshal(root)
}

// ---- a JSON list of objects that carry an id: one entry per object.

type listCodec struct{ id string }

func (c listCodec) items(blob []byte) ([]string, map[string]json.RawMessage, error) {
	var list []json.RawMessage
	if len(bytes.TrimSpace(blob)) > 0 {
		if err := json.Unmarshal(blob, &list); err != nil {
			return nil, nil, err
		}
	}
	var order []string
	items := map[string]json.RawMessage{}
	for _, it := range list {
		var obj map[string]json.RawMessage
		if json.Unmarshal(it, &obj) != nil || len(obj[c.id]) == 0 {
			return nil, nil, errors.New("item of a shared list has no " + c.id)
		}
		k := "[" + string(obj[c.id]) + "]"
		if _, dup := items[k]; !dup {
			order = append(order, k)
		}
		var buf bytes.Buffer
		_ = json.Compact(&buf, it)
		items[k] = buf.Bytes()
	}
	return order, items, nil
}

func (c listCodec) split(blob []byte) (map[string][]byte, error) {
	_, items, err := c.items(blob)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(items))
	for k, v := range items {
		out[k] = v
	}
	return out, nil
}

func (c listCodec) join(blob []byte, set map[string][]byte, del []string) ([]byte, error) {
	order, items, err := c.items(blob)
	if err != nil {
		return nil, err
	}
	var added []string
	for k, v := range set {
		var obj map[string]json.RawMessage
		if json.Unmarshal(v, &obj) != nil || "["+string(obj[c.id])+"]" != k {
			continue
		}
		if _, ok := items[k]; !ok {
			added = append(added, k)
		}
		items[k] = v
	}
	for _, k := range del {
		delete(items, k)
	}
	// The order this node had, then what is new, the same on every node.
	sort.Strings(added)
	out := make([]json.RawMessage, 0, len(items))
	for _, k := range append(order, added...) {
		if v, ok := items[k]; ok {
			out = append(out, v)
		}
	}
	return json.Marshal(out)
}

// ---- a value that is one piece (a key).

type wholeCodec struct{}

func (wholeCodec) split(blob []byte) (map[string][]byte, error) {
	if len(blob) == 0 {
		return map[string][]byte{}, nil
	}
	return map[string][]byte{"": blob}, nil
}

func (wholeCodec) join(blob []byte, set map[string][]byte, del []string) ([]byte, error) {
	if v, ok := set[""]; ok {
		return v, nil
	}
	for _, k := range del {
		if k == "" {
			return nil, nil
		}
	}
	return blob, nil
}
