//go:build !release

package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
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

// Under a steady stream of changes nothing differs: a change is on every
// node within a second, so no node may read another as "differs", name a
// difference on the overview or repair (third lab measurement, S1: with one
// change every 0.6 s a fifth of the member views read "differs" and the
// nodes repaired several times a minute, taking nothing. A node compared a
// member's hashes of up to 5 s ago with its own of now).
func TestSteadyStreamOfChangesIsNoDifference(t *testing.T) {
	defer app.SetStateDiffTimes(2*time.Second, 5*time.Second, 5*time.Second)()
	nodes := trio(t)
	for _, g := range nodes {
		g.h.Login()
	}
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" is in step", func() bool { return g.h.App.InService() })
	}
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed []string
	fail := func(format string, args ...any) {
		mu.Lock()
		failed = append(failed, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	// A block and its lift on another node, and a setting, in turn on the
	// nodes, a change about every 0.3 s.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			set, lift := nodes[i%3], nodes[(i+1)%3]
			ip := fmt.Sprintf("198.51.100.%d", i%200+1)
			code, body := set.h.API("POST", "/blocks", map[string]any{"address": ip, "duration_s": 604800, "reason": "test"})
			if code != 200 {
				fail("block %s: %d %s", ip, code, body)
				return
			}
			var rb struct {
				Incident string `json:"incident"`
			}
			_ = json.Unmarshal([]byte(body), &rb)
			if err := nodes[(i+2)%3].h.App.Store.Put(ctx, "future_stream_v1", []byte(fmt.Sprintf(`{"n":%d}`, i))); err != nil {
				fail("setting: %v", err)
				return
			}
			time.Sleep(300 * time.Millisecond)
			lift.h.WaitFor("the lifting node lists the block", func() bool { return lift.blocked(ip) != "" })
			if code, body := lift.h.API("POST", "/incidents/"+rb.Incident+"/unblock", map[string]any{}); code != 200 {
				fail("unblock %s: %d %s", ip, code, body)
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()
	// Every node is asked once every 250 ms how it sees the others.
	views, differs, seen := 0, map[string]int{}, map[string]int{}
	end := time.Now().Add(20 * time.Second)
	for time.Now().Before(end) {
		for _, g := range nodes {
			for _, m := range g.h.App.GroupStatus().Members {
				if m.Name == g.name {
					continue
				}
				views++
				for class, v := range m.SharedState {
					seen[v]++
					if v == "differs" {
						differs[class]++
					}
				}
			}
			if g.h.App.StateDiffers() || slices.Contains(g.h.App.ClusterReasons(), "cluster_state_differs") {
				differs["overview of "+g.name]++
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if len(failed) > 0 {
		t.Fatalf("the stream failed: %v", failed)
	}
	repairs := int64(0)
	for _, g := range nodes {
		repairs += g.h.App.StateRepairs()
	}
	t.Logf("member views by class during the stream: %v", seen)
	// The nodes could be compared in between: the stream must not turn
	// every view into "unknown" either.
	if seen["same"] < seen["unknown"] {
		t.Errorf("more views read unknown than same during the stream: %v", seen)
	}
	if len(differs) > 0 || repairs != 0 {
		t.Fatalf("under a stream of changes: %v of %d member views read a difference, %d repairs", differs, views, repairs)
	}
	// And when the stream ends every node reads the others as the same.
	for _, g := range nodes {
		g := g
		for _, o := range nodes {
			if o != g {
				o := o
				g.h.WaitFor(g.name+" sees the same state on "+o.name, func() bool { return allSame(sharedStateOf(g, o.name)) })
			}
		}
	}
}
