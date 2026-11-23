package app

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// Everything set at runtime is shared (initiator, 2026-11-22). The things
// of cluster_state.go are registered by hand, each with the codec and the
// reload it needs. Every other key of the key-value store in schild.db
// travels all the same, without a line here: a feature that stores a new
// setting is shared in a group the day it is written. Only the keys of
// contract.PerNodeSettings stay on their node, each with its reason.
//
// A key nobody registered is cut by the shape of its value (autoCodec). Its
// owner sees a change of another node in the store at once; an owner that
// keeps the value in memory registers a reload next to where it reads the
// key (App.OnSharedKey).

// maxGenericThings bounds the keys shared without registration.
const maxGenericThings = 256

// markGenericThings is the note of the keys this node has shared so far, so
// a key removed here is still known, and removed for the group.
const markGenericThings = "generic_things"

// autoCodec cuts a value nobody registered by its shape, so two nodes that
// change different parts of it both keep their change:
//
//   - a JSON object with fields: one entry per top-level field, key
//     `o["field"]`;
//   - a JSON list of objects that each carry a string "id", none twice: one
//     entry per object, key `l["id"]`;
//   - anything else, the empty object and the empty list included: one
//     entry, key "", and the later change wins.
//
// The first letter of a key names the shape, so a node that holds nothing
// of the value yet knows how to put the entries together.
type autoCodec struct{}

const (
	autoObject = 'o'
	autoList   = 'l'
)

func autoShape(blob []byte) byte {
	t := bytes.TrimSpace(blob)
	if len(t) == 0 || !json.Valid(t) {
		return 0
	}
	switch t[0] {
	case '{':
		var obj map[string]json.RawMessage
		if json.Unmarshal(t, &obj) == nil && len(obj) > 0 {
			return autoObject
		}
	case '[':
		if _, items, err := (listCodec{id: "id"}).items(t); err == nil && len(items) > 0 && autoListIDs(t, len(items)) {
			return autoList
		}
	}
	return 0
}

// autoListIDs reports whether every item of the list has a string id and
// no id comes twice (n is the number of distinct ids).
func autoListIDs(blob []byte, n int) bool {
	var list []struct {
		ID *string `json:"id"`
	}
	if json.Unmarshal(blob, &list) != nil || len(list) != n {
		return false
	}
	for _, it := range list {
		if it.ID == nil || *it.ID == "" {
			return false
		}
	}
	return true
}

func (autoCodec) split(blob []byte) (map[string][]byte, error) {
	if len(blob) == 0 {
		return map[string][]byte{}, nil
	}
	switch autoShape(blob) {
	case autoObject:
		in, err := (objectCodec{depth: 1}).split(blob)
		if err != nil {
			return nil, err
		}
		out := make(map[string][]byte, len(in))
		for k, v := range in {
			out[string(rune(autoObject))+k] = v
		}
		return out, nil
	case autoList:
		in, err := (listCodec{id: "id"}).split(blob)
		if err != nil {
			return nil, err
		}
		out := make(map[string][]byte, len(in))
		for k, v := range in {
			out[string(rune(autoList))+k] = v
		}
		return out, nil
	}
	return map[string][]byte{"": blob}, nil
}

// part returns the entries of one shape, without the letter.
func autoPart(shape byte, set map[string][]byte, del []string) (map[string][]byte, []string) {
	s := map[string][]byte{}
	for k, v := range set {
		if len(k) > 0 && k[0] == shape {
			s[k[1:]] = v
		}
	}
	var d []string
	for _, k := range del {
		if len(k) > 0 && k[0] == shape {
			d = append(d, k[1:])
		}
	}
	return s, d
}

func (autoCodec) join(blob []byte, set map[string][]byte, del []string) ([]byte, error) {
	if v, ok := set[""]; ok {
		return v, nil
	}
	have := autoShape(blob)
	want := have
	for k := range set {
		if len(k) > 0 && k[0] == autoObject {
			want = autoObject
			break
		}
		if len(k) > 0 && k[0] == autoList {
			want = autoList
		}
	}
	switch want {
	case autoObject:
		s, d := autoPart(autoObject, set, del)
		base := blob
		if have != autoObject {
			base = nil
		}
		return (objectCodec{depth: 1}).join(base, s, d)
	case autoList:
		s, d := autoPart(autoList, set, del)
		base := blob
		if have != autoList {
			base = nil
		}
		return (listCodec{id: "id"}).join(base, s, d)
	}
	// One piece: only its own removal says anything.
	for _, k := range del {
		if k == "" {
			return nil, nil
		}
	}
	return blob, nil
}

// OnSharedKey registers what brings a key of the store into force after
// another node of the group changed it: called with the new value (empty:
// removed) after it was stored. A feature that keeps a value of the store
// in memory calls this once, next to where it reads the key. Without a
// reload the value is in the store all the same.
func (a *App) OnSharedKey(key string, reload func(ctx context.Context, v []byte)) {
	a.sharedHooksMu.Lock()
	defer a.sharedHooksMu.Unlock()
	if a.sharedHooks == nil {
		a.sharedHooks = map[string]func(context.Context, []byte){}
	}
	a.sharedHooks[key] = reload
}

func (a *App) genericThing(id string) sharedThing {
	return a.kvThing(id, autoCodec{}, func(ctx context.Context, v []byte) error {
		if err := a.putKV(ctx, id, v); err != nil {
			return err
		}
		a.sharedHooksMu.Lock()
		reload := a.sharedHooks[id]
		a.sharedHooksMu.Unlock()
		if reload != nil {
			reload(ctx, v)
		}
		return nil
	})
}

// genericThings returns the keys of the store that are shared without
// registration: what the store holds, what another node sent, and what this
// node shared before (a key removed here is removed for the group). Called
// with sharedMu held.
func (a *App) genericThings(ctx context.Context, synced bool) []sharedThing {
	if a.sharedNamed == nil {
		a.sharedNamed = map[string]bool{}
		for _, t := range a.shared {
			a.sharedNamed[t.key()] = true
		}
		a.sharedGeneric = map[string]bool{}
		if raw := a.Cluster.Mark(markGenericThings); raw != "" {
			var ids []string
			if json.Unmarshal([]byte(raw), &ids) == nil {
				for _, id := range ids {
					a.sharedGeneric[id] = true
				}
			}
		}
	}
	before := len(a.sharedGeneric)
	add := func(id string) {
		if a.sharedGeneric[id] || a.sharedNamed[contract.ClassSettings+"/"+id] {
			return
		}
		if !contract.SettingKey(id) {
			if _, perNode := contract.PerNodeSettings[id]; !perNode {
				ratelog.Warn(a.log, "cluster: a key of the store has a name that cannot be shared (lower-case letters, digits and _, at most 64); it holds on this node only", "key", id)
			}
			return
		}
		if len(a.sharedGeneric) >= maxGenericThings {
			ratelog.Warn(a.log, "cluster: too many keys of the store to share; a key holds on this node only", "key", id, "max", maxGenericThings)
			return
		}
		a.sharedGeneric[id] = true
	}
	if keys, err := a.Store.Keys(ctx); err == nil {
		for _, k := range keys {
			add(k)
		}
	}
	prefix := contract.ClassSettings + "/"
	for k := range a.sharedPending {
		if strings.HasPrefix(k, prefix) {
			add(k[len(prefix):])
		}
	}
	// Once in step: what the group holds and this node never heard of.
	if synced && !a.sharedGenericCaught {
		a.sharedGenericCaught = true
		if recs, err := a.Cluster.State(contract.ClassSettings); err == nil {
			for _, rec := range recs {
				if thing, ok := contract.ThingOf(rec.Class, rec.ID); ok {
					add(thing)
				}
			}
		}
	}
	ids := make([]string, 0, len(a.sharedGeneric))
	for id := range a.sharedGeneric {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) != before {
		if raw, err := json.Marshal(ids); err == nil {
			_ = a.Cluster.SetMark(markGenericThings, string(raw))
		}
	}
	out := make([]sharedThing, 0, len(ids))
	for _, id := range ids {
		out = append(out, a.genericThing(id))
	}
	return out
}
