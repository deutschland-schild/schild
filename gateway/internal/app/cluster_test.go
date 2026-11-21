//go:build !release

package app_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
)

type groupNode struct {
	dir, addr, name string
	h               *apptest.Harness
}

func (g *groupNode) clusterDir() string { return app.ClusterDir(filepath.Join(g.dir, "data")) }

func (g *groupNode) start(t *testing.T) {
	t.Helper()
	g.h = apptest.New(t, apptest.Options{Dir: g.dir, Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q}\n", g.addr)})
	if g.h.App.Cluster == nil {
		t.Fatalf("%s: no cluster node", g.name)
	}
}

func (g *groupNode) block(ip, incident string, d time.Duration) {
	g.h.App.Behaviour.SetAgentBlock(behaviour.AgentBlock{IP: netip.MustParseAddr(ip), Source: behaviour.DashboardSource, NetClass: "hosting", Duration: d,
		Incident: incident, Time: time.Now()})
}

func (g *groupNode) blocked(ip string) string {
	bi, ok := g.h.App.Behaviour.ActiveBlock(netip.MustParseAddr(ip))
	if !ok {
		return ""
	}
	return bi.Incident
}

// pair: two gateways in one group, web-2 joined through web-1.
func pair(t *testing.T) (a, b *groupNode) {
	t.Helper()
	a = &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1"}
	b = &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2"}
	if _, err := cluster.Init(a.clusterDir(), a.name, a.addr, nil); err != nil {
		t.Fatal(err)
	}
	a.start(t)
	code, _, err := cluster.Invite(a.clusterDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cluster.Join(context.Background(), b.clusterDir(), b.name, b.addr, a.addr, code, nil); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	return a, b
}

func TestGroupBlockActsOnTheOtherNode(t *testing.T) {
	a, b := pair(t)
	const ip = "203.0.113.50"
	if resp := b.h.Visit("GET", "/", ip, "", ""); resp.StatusCode != 200 {
		t.Fatalf("before the block: %d", resp.StatusCode)
	}
	a.block(ip, "S-GROUP-1", 15*time.Minute)
	b.h.WaitFor("web-2 blocks the address web-1 blocked", func() bool { return b.blocked(ip) == "S-GROUP-1" })
	hits := b.h.Hits.Load()
	resp := b.h.Visit("GET", "/", ip, "", "")
	if resp.StatusCode == 200 || b.h.Hits.Load() != hits {
		t.Fatalf("a request of the blocked address on web-2: status %d, reached the app: %v", resp.StatusCode, b.h.Hits.Load() != hits)
	}
	// Another address still passes on web-2.
	if resp := b.h.Visit("GET", "/", "203.0.113.51", "", ""); resp.StatusCode != 200 {
		t.Errorf("another address on web-2: %d", resp.StatusCode)
	}

	// A release on web-2 ends the block on web-1.
	if n := b.h.App.Behaviour.Release(netip.MustParseAddr(ip)); n != 1 {
		t.Fatalf("release on web-2 ended %d blocks", n)
	}
	a.h.WaitFor("web-1 ends the block web-2 released", func() bool { return a.blocked(ip) == "" })
	// And it stays ended: no node tells the group the old block again.
	time.Sleep(700 * time.Millisecond)
	if a.blocked(ip) != "" || b.blocked(ip) != "" {
		t.Errorf("the released block came back: web-1 %q, web-2 %q", a.blocked(ip), b.blocked(ip))
	}
}

func TestGroupBlockNeverBeatsTheOwnAllowlist(t *testing.T) {
	a, b := pair(t)
	// 192.0.2.10 is on the allowlist of the harness. The engine of web-1
	// holds a block of it all the same (set below it); web-2 must not take
	// it over.
	a.block("192.0.2.10", "S-OWN", 15*time.Minute)
	a.block("203.0.113.60", "S-AFTER", 15*time.Minute)
	b.h.WaitFor("web-2 took the later block", func() bool { return b.blocked("203.0.113.60") == "S-AFTER" })
	if got := b.blocked("192.0.2.10"); got != "" {
		t.Errorf("web-2 blocks an address of its own allowlist: %q", got)
	}
}

func TestGroupNodeCatchesUpAndKeepsBlocksOverARestart(t *testing.T) {
	a, b := pair(t)
	a.block("203.0.113.70", "S-BEFORE", 15*time.Minute)
	b.h.WaitFor("web-2 took the block", func() bool { return b.blocked("203.0.113.70") == "S-BEFORE" })
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.block("203.0.113.71", "S-WHILE-AWAY", 15*time.Minute)
	time.Sleep(400 * time.Millisecond)
	b.start(t)
	// A block under 24 h lives in memory only on a single gateway; in a
	// group the node has it again at once, from its copy.
	if got := b.blocked("203.0.113.70"); got != "S-BEFORE" {
		t.Errorf("after the restart web-2 lost the block it had: %q", got)
	}
	b.h.WaitFor("web-2 took the block it missed", func() bool { return b.blocked("203.0.113.71") == "S-WHILE-AWAY" })
}

func TestSingleGatewayHasNoCluster(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	if h.App.Cluster != nil {
		t.Error("a gateway without cluster.enabled runs a node")
	}
	if _, err := os.Stat(app.ClusterDir(filepath.Join(h.Dir, "data"))); !os.IsNotExist(err) {
		t.Errorf("a gateway without cluster.enabled has a cluster directory: %v", err)
	}
}

func TestClusterEnabledWithoutGroupRunsAlone(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q}\n", apptest.FreeAddr(t))})
	if h.App.Cluster != nil {
		t.Error("a node without a group started the mesh")
	}
	if resp := h.Visit("GET", "/", "203.0.113.80", "", ""); resp.StatusCode != 200 {
		t.Errorf("a gateway without a group does not serve: %d", resp.StatusCode)
	}
}
