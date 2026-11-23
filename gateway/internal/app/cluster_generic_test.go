//go:build !release

package app_test

import (
	"context"
	"encoding/json"
	"testing"
)

func kvOf(g *groupNode, key string) string {
	v, err := g.h.App.Store.Get(context.Background(), key)
	if err != nil {
		return ""
	}
	return string(v)
}

func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return a == b
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return string(xa) == string(ya)
}

// A key of the store nobody registered is shared all the same: a feature
// that stores a new setting holds on every node of a group without knowing
// the group (initiator 2026-11-22: everything set at runtime is shared).
func TestAKeyNobodyRegisteredIsSharedInAGroup(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	put := func(g *groupNode, key, v string) {
		if err := g.h.App.Store.Put(ctx, key, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	var reloaded string
	b.h.App.OnSharedKey("future_feature_v1", func(_ context.Context, v []byte) { reloaded = string(v) })

	// One piece: it arrives, and the owner on the other node is told.
	put(a, "future_feature_v1", "plain text, no JSON")
	b.h.WaitFor("web-2 holds the value web-1 stored", func() bool { return kvOf(b, "future_feature_v1") == "plain text, no JSON" })
	b.h.WaitFor("the owner of the key on web-2 was told", func() bool { return reloaded == "plain text, no JSON" })

	// An object: two nodes change different fields, both changes stay.
	put(a, "future_object_v1", `{"daily_at":"07:00","tz":"Europe/Berlin"}`)
	b.h.WaitFor("web-2 holds the object", func() bool { return sameJSON(kvOf(b, "future_object_v1"), `{"daily_at":"07:00","tz":"Europe/Berlin"}`) })
	put(a, "future_object_v1", `{"daily_at":"08:30","tz":"Europe/Berlin"}`)
	put(b, "future_object_v1", `{"daily_at":"07:00","tz":"Europe/Berlin","weekly_on":"mon"}`)
	want := `{"daily_at":"08:30","tz":"Europe/Berlin","weekly_on":"mon"}`
	for _, g := range []*groupNode{a, b} {
		g.h.WaitFor(g.name+" holds both changes to the object", func() bool { return sameJSON(kvOf(g, "future_object_v1"), want) })
	}

	// A list of objects with an id: an entry added on each node, both stay; a removed one is gone on both.
	put(a, "future_list_v1", `[{"id":"mail-1","to":"a@example.org"}]`)
	b.h.WaitFor("web-2 holds the list", func() bool { return kvOf(b, "future_list_v1") != "" })
	put(a, "future_list_v1", `[{"id":"mail-1","to":"a@example.org"},{"id":"mail-2","to":"b@example.org"}]`)
	put(b, "future_list_v1", `[{"id":"mail-1","to":"a@example.org"},{"id":"ntfy-1","topic":"x"}]`)
	ids := func(g *groupNode) string {
		var list []struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(kvOf(g, "future_list_v1")), &list)
		seen := map[string]bool{}
		for _, it := range list {
			seen[it.ID] = true
		}
		out := ""
		for _, id := range []string{"mail-1", "mail-2", "ntfy-1"} {
			if seen[id] {
				out += id + " "
			}
		}
		return out
	}
	for _, g := range []*groupNode{a, b} {
		g.h.WaitFor(g.name+" holds the entries of both nodes", func() bool { return ids(g) == "mail-1 mail-2 ntfy-1 " })
	}
	put(b, "future_list_v1", `[{"id":"mail-2","to":"b@example.org"},{"id":"ntfy-1","topic":"x"}]`)
	a.h.WaitFor("the entry removed on web-2 is gone on web-1", func() bool { return ids(a) == "mail-2 ntfy-1 " })

	// A key removed on one node is removed on the other.
	if err := a.h.App.Store.Delete(ctx, "future_feature_v1"); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("the key removed on web-1 is gone on web-2", func() bool { return kvOf(b, "future_feature_v1") == "" })

	// What describes one node stays on it.
	if x, y := kvOf(a, "installed_at_v1"), kvOf(b, "installed_at_v1"); x == "" || y == "" {
		t.Fatal("a node has no installed_at_v1")
	}
	put(a, "dashboard_setup_code_v1", "only-here")
	put(a, "future_marker_v1", "after")
	b.h.WaitFor("web-2 holds the marker written after the per-node key", func() bool { return kvOf(b, "future_marker_v1") == "after" })
	if got := kvOf(b, "dashboard_setup_code_v1"); got == "only-here" {
		t.Fatal("a key that describes one node travelled")
	}
}
