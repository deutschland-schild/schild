//go:build !release

package app_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
)

func sharedStateOf(g *groupNode, member string) map[string]string {
	for _, m := range g.h.App.GroupStatus().Members {
		if m.Name == member {
			return m.SharedState
		}
	}
	return nil
}

func allSame(st map[string]string) bool {
	if len(st) != 4 {
		return false
	}
	for _, v := range st {
		if v != "same" {
			return false
		}
	}
	return true
}

// Two nodes in step tell each other the same hashes of what is in force,
// also after blocks, settings, an allowlist entry and a login changed.
func TestNodesInStepHaveTheSameStateHashes(t *testing.T) {
	defer app.SetStateDiffTimes(2*time.Second, 5*time.Second, 5*time.Second)()
	a, b := pair(t)
	ctx := context.Background()
	a.h.Login()
	a.block("203.0.113.210", "S-HASH", 15*time.Minute)
	if err := a.h.App.Store.Put(ctx, "future_hash_v1", []byte(`{"b":1,"a":[1,2]}`)); err != nil {
		t.Fatal(err)
	}
	if code, body := a.h.API("POST", "/allowlist", map[string]any{"ip": "203.0.113.211", "label": "hash", "level": "no_block"}); code != 201 {
		t.Fatalf("allowlist: %d %s", code, body)
	}
	b.h.WaitFor("web-2 holds what web-1 set", func() bool {
		return b.blocked("203.0.113.210") == "S-HASH" && kvOf(b, "future_hash_v1") != "" && allowed(b, "203.0.113.211")
	})
	for _, g := range []*groupNode{a, b} {
		other := a.name
		if g == a {
			other = b.name
		}
		g.h.WaitFor(g.name+" sees the same state on "+other, func() bool { return allSame(sharedStateOf(g, other)) })
	}
	// It stays that way: no difference is named and nothing is repaired.
	time.Sleep(12 * time.Second)
	for _, g := range []*groupNode{a, b} {
		if g.h.App.StateDiffers() || g.h.App.StateRepairs() != 0 || slices.Contains(g.h.App.ClusterReasons(), "cluster_state_differs") {
			t.Fatalf("%s names a difference or repaired although the nodes are in step (repairs %d)", g.name, g.h.App.StateRepairs())
		}
	}
}

// A node that holds another value than the group and believes it is in
// step is found by the hashes, named on the overview and brought back.
func TestANodeThatDidNotApplyAChangeIsFoundAndRepaired(t *testing.T) {
	defer app.SetStateDiffTimes(2*time.Second, 5*time.Second, 5*time.Second)()
	a, b := pair(t)
	ctx := context.Background()
	if err := a.h.App.Store.Put(ctx, "future_repair_v1", []byte(`{"mode":"group"}`)); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 holds the value of web-1", func() bool { return sameJSON(kvOf(b, "future_repair_v1"), `{"mode":"group"}`) })
	a.h.WaitFor("web-1 sees the same state on web-2", func() bool { return allSame(sharedStateOf(a, b.name)) })

	if err := b.h.App.BreakSharedKey(ctx, "future_repair_v1", []byte(`{"mode":"only-here"}`)); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("web-1 shows that the settings of web-2 differ", func() bool { return sharedStateOf(a, b.name)["settings"] == "differs" })
	if st := sharedStateOf(a, b.name); st["blocks"] != "same" || st["logins"] != "same" {
		t.Errorf("only the settings differ, shown: %v", st)
	}
	b.h.WaitFor("the overview of web-2 names the difference", func() bool { return slices.Contains(b.h.App.ClusterReasons(), "cluster_state_differs") })
	b.h.WaitFor("web-2 holds the group's value again", func() bool { return sameJSON(kvOf(b, "future_repair_v1"), `{"mode":"group"}`) })
	if got := kvOf(a, "future_repair_v1"); !sameJSON(got, `{"mode":"group"}`) {
		t.Fatalf("the repair changed the value of the node that was right: %s", got)
	}
	for _, g := range []*groupNode{a, b} {
		g.h.WaitFor(g.name+" names no difference any more", func() bool {
			return !g.h.App.StateDiffers() && allSame(sharedStateOf(g, map[bool]string{true: b.name, false: a.name}[g == a]))
		})
	}
}
