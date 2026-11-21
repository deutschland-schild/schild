//go:build !release

package app_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/contract/firewall"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/nftfw"
)

// table stands for the nftables table of the balancer VM.
type table struct {
	mu      sync.Mutex
	held    map[string]time.Duration
	removed bool
}

func (f *table) Ensure() error { return nil }
func (f *table) Replace(els []nftfw.Element) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.held = map[string]time.Duration{}
	for _, e := range els {
		f.held[e.Client] = e.Timeout
	}
	return nil
}
func (f *table) Held() ([]nftfw.Held, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]nftfw.Held, 0, len(f.held))
	for c, d := range f.held {
		out = append(out, nftfw.Held{Client: c, Expires: d})
	}
	return out, nil
}
func (f *table) Remove() error { f.mu.Lock(); f.removed = true; f.mu.Unlock(); return nil }
func (f *table) holds(client string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.held[client]
	return ok
}

// A balancer VM joins as an edge and runs the firewall of D87 fed by the
// gateways: a block set on any gateway is in its table, a release takes it
// out, and an address of the allowlist never gets in.
func TestEdgeFirewallHoldsTheBlocksOfTheGroup(t *testing.T) {
	a, b := pair(t)
	code, _, err := cluster.InviteRole(a.clusterDir(), contract.RoleEdge, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "cluster")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, _, err := cluster.Join(ctx, dir, "lb-1", "", a.addr, code, nil); err != nil {
		t.Fatal(err)
	}
	e, err := cluster.OpenEdge(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	tbl := &table{}
	done := make(chan error, 1)
	var answers []firewall.SyncResponse
	var amu sync.Mutex
	go func() {
		done <- nftfw.Run(ctx, tbl, nftfw.Config{Version: "test", Retry: 200 * time.Millisecond, Call: func(ctx context.Context, req firewall.SyncRequest) (firewall.SyncResponse, error) {
			var ans firewall.SyncResponse
			body, _ := json.Marshal(req)
			raw, err := e.Ask(ctx, "firewall", body, 30*time.Second)
			if err != nil {
				return ans, err
			}
			err = json.Unmarshal(raw, &ans)
			amu.Lock()
			answers = append(answers, ans)
			amu.Unlock()
			return ans, err
		}})
	}()
	// A block on web-2 reaches the table through web-1 or web-2, whichever
	// the edge asks.
	b.block("203.0.113.180", "S-EDGE", 15*time.Minute)
	a.block("192.0.2.10", "S-OWN", 15*time.Minute) // on the allowlist of the harness
	a.h.WaitFor("the edge holds the block of web-2", func() bool { return tbl.holds("203.0.113.180") })
	time.Sleep(time.Second)
	if tbl.holds("192.0.2.10") {
		t.Error("the edge drops an address of the allowlist")
	}
	// The edge learns the client and the end, not the incident.
	amu.Lock()
	for _, ans := range answers {
		for _, blk := range ans.Blocks {
			if blk.Incident != "" {
				t.Errorf("the edge was told an incident: %q", blk.Incident)
			}
		}
	}
	amu.Unlock()
	// A release on web-1 takes the address out of the table.
	a.h.WaitFor("web-1 holds the block", func() bool { return a.blocked("203.0.113.180") != "" })
	a.h.App.Behaviour.Release(mustAddr("203.0.113.180"))
	a.h.WaitFor("the edge let the released address go", func() bool { return !tbl.holds("203.0.113.180") })
	// The gateway it asks knows what the edge applied.
	a.h.WaitFor("a gateway knows what the edge said", func() bool {
		return len(a.h.App.EdgeReports())+len(b.h.App.EdgeReports()) > 0
	})
	// web-1 away: the edge asks web-2.
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	b.block("203.0.113.181", "S-EDGE-2", 15*time.Minute)
	b.h.WaitFor("the edge holds a block set while one gateway is away", func() bool { return tbl.holds("203.0.113.181") })
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the firewall did not stop")
	}
	e.Close()
	tbl.mu.Lock()
	removed := tbl.removed
	tbl.mu.Unlock()
	if !removed {
		t.Error("a clean stop left the table")
	}
}
