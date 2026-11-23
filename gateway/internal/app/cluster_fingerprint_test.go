//go:build !release

package app_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/store"
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
			// What an operator sees: the block in the list of the lifting
			// node's dashboard, where "Freigeben" is pressed.
			lift.h.WaitFor("the lifting node lists the block", func() bool {
				code, body := lift.h.API("GET", "/blocks", nil)
				return code == 200 && strings.Contains(string(body), rb.Incident)
			})
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
	// every view into "unknown". How often a comparison finds equal points
	// depends on the speed of the machine (under the race detector in CI
	// "unknown" can outnumber "same"), so only that it happens is checked;
	// the lab measurement reports the shares on real VMs.
	if seen["same"] == 0 {
		t.Errorf("no view read same during the stream: %v", seen)
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

// A node that was not in step with its group for longer than a removed
// entry is remembered (30 days) takes the group's state as it is: an entry
// removed meanwhile, whose tombstone the group has dropped, does not come
// back through the copy the returning node held, neither on that node nor,
// by the repair of a difference, on the others.
func TestNodeAwayLongerThanATombstoneDoesNotBringARemovedEntryBack(t *testing.T) {
	defer app.SetStateDiffTimes(time.Second, 2*time.Second, 2*time.Second)()
	a, b := pair(t)
	ctx := context.Background()
	const gone, kept = "198.51.100.41", "198.51.100.42"
	e := &store.AllowEntry{IP: gone, Label: "removed while web-2 is away", Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}
	if err := b.h.App.Store.AddAllow(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := a.h.App.Store.AddAllow(ctx, &store.AllowEntry{IP: kept, Label: "stays", Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	for _, g := range []*groupNode{a, b} {
		g.h.WaitFor(g.name+" allows both", func() bool { return allowed(g, gone) && allowed(g, kept) })
	}
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := a.h.App.Store.DeleteAllow(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("web-1 published the removal", func() bool { return tombstones(t, a.clusterDir(), "access") > 0 })
	// Thirty days later: the tombstone is gone on web-1 ...
	execCluster(t, a.clusterDir(), `DELETE FROM records WHERE class = 'access' AND deleted = 1`)
	// ... and web-2 was last in step before that.
	execCluster(t, b.clusterDir(), `UPDATE meta SET v = ? WHERE k = 'mark:in_step_at'`, fmt.Sprint(time.Now().Add(-31*24*time.Hour).UnixMilli()))
	b.start(t)
	b.h.WaitFor("web-2 is in service", func() bool { return b.h.App.InService() })
	b.h.WaitFor("web-2 dropped the entry the group removed", func() bool { return !allowed(b, gone) && allowed(b, kept) })
	// Long enough for a difference to be repaired twice.
	time.Sleep(8 * time.Second)
	if allowed(a, gone) || allowed(b, gone) {
		t.Fatalf("the removed entry came back: web-1 %v, web-2 %v", allowed(a, gone), allowed(b, gone))
	}
	if !allowed(a, kept) || !allowed(b, kept) {
		t.Error("the entry the group holds was lost")
	}
}

func execCluster(t *testing.T, dir, query string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "cluster.db")+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		t.Fatalf("%s changed nothing", query)
	}
}

func tombstones(t *testing.T, dir, class string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "cluster.db")+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM records WHERE class = ? AND deleted = 1`, class).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
