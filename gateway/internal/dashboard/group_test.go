//go:build !release

package dashboard_test

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

// A gateway without cluster.enabled says that it runs alone, and nothing
// else.
func TestGroupStatusOfASingleGateway(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	expect(t, h, "GET", "/group", nil, 401, "Problem")
	h.Login()
	b := expect(t, h, "GET", "/group", nil, 200, "GroupStatus")
	if got := strings.TrimSpace(string(b)); got != `{"mode":"single"}` {
		t.Errorf("single gateway: %s", got)
	}
	if h.App.Dashboard.Group != nil || h.App.Dashboard.BlockNode != nil || h.App.Dashboard.Erased != nil {
		t.Error("a single gateway carries hooks of the group")
	}
	// No block names a node, no erasure names nodes.
	h.App.Behaviour.SetAgentBlock(behaviour.AgentBlock{IP: netip.MustParseAddr("203.0.113.7"), Source: behaviour.DashboardSource, NetClass: "hosting", Duration: time.Hour, Incident: "AAAA-BBBB", Time: time.Now()})
	l := decode[dashboard.BlockList](t, expect(t, h, "GET", "/blocks", nil, 200, "BlockList"))
	if len(l.Items) != 1 || l.Items[0].Node != "" || l.Items[0].NodeSelf != nil {
		t.Errorf("blocks of a single gateway: %+v", l.Items)
	}
	res := decode[dashboard.PrivacyDeleteResult](t, expect(t, h, "POST", "/privacy/delete", map[string]any{"ip": "203.0.113.7", "confirm": true}, 200, "PrivacyDeleteResult"))
	if res.Nodes != nil {
		t.Errorf("erasure on a single gateway names nodes: %+v", res.Nodes)
	}
}

type member struct {
	dir, addr, name string
	h               *apptest.Harness
	// secretFile and peers: cluster.secret_file and cluster.peers.
	secretFile string
	peers      [2]string
}

func (m *member) clusterDir() string { return app.ClusterDir(filepath.Join(m.dir, "data")) }

func (m *member) start(t *testing.T) {
	t.Helper()
	m.h = apptest.New(t, apptest.Options{Dir: m.dir, Extra: fmt.Sprintf("cluster: {enabled: true, name: %q, listen: %q, secret_file: %q, peers: [%q, %q]}\n",
		m.name, m.addr, m.secretFile, m.peers[0], m.peers[1])})
	if m.h.App.Cluster == nil {
		t.Fatalf("%s: no cluster node", m.name)
	}
}

// status asks the dashboard API on web-1, the node the test signed in to
// (the group shares its logins, a second login would replace the first),
// and the app itself on web-2.
func (m *member) status(t *testing.T) dashboard.GroupStatus {
	t.Helper()
	if m.name != "web-1" {
		return m.h.App.GroupStatus()
	}
	return decode[dashboard.GroupStatus](t, expect(t, m.h, "GET", "/group", nil, 200, "GroupStatus"))
}

func of(st dashboard.GroupStatus, name string) dashboard.GroupMember {
	for _, m := range st.Members {
		if m.Name == name {
			return m
		}
	}
	return dashboard.GroupMember{}
}

func groupPair(t *testing.T) (a, b *member) {
	t.Helper()
	// Set up as a deployment does: the same secret file on both, both
	// addresses in cluster.peers.
	secretFile := filepath.Join(t.TempDir(), "cluster.secret")
	secret, err := cluster.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	a = &member{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1", secretFile: secretFile}
	b = &member{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2", secretFile: secretFile}
	a.peers, b.peers = [2]string{a.addr, b.addr}, [2]string{a.addr, b.addr}
	a.start(t)
	a.h.Login()
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
	b.start(t)
	return a, b
}

// Two real gateways: each dashboard shows the group, the other member with
// its contact, what is shared, and that the configuration differs (the two
// test gateways listen on other ports, which a deployment would not).
func TestGroupStatusOfAPair(t *testing.T) {
	a, b := groupPair(t)
	a.h.WaitFor("web-1 is in step with web-2", func() bool { return a.status(t).State == "active" })
	b.h.WaitFor("web-2 is in step with web-1", func() bool { return b.status(t).State == "active" })
	a.h.WaitFor("web-2 told web-1 its versions", func() bool { return of(a.status(t), "web-2").Config == "differs" })

	st := a.status(t)
	if st.Mode != "group" || st.Group != a.h.App.Cluster.Group() || st.Node == nil || st.Node.Name != "web-1" || st.Node.Role != "gateway" || st.Node.ID != a.h.App.Cluster.ID() {
		t.Fatalf("%+v", st)
	}
	if len(st.Members) != 2 || st.Members[0].Name != "web-1" || st.Members[0].State != "self" || st.Members[0].Version == "" || st.Members[0].Config != "same" {
		t.Fatalf("members: %+v", st.Members)
	}
	other := of(st, "web-2")
	if other.State != "ok" || other.Role != "gateway" || other.Address != b.addr || other.LastOut == nil || other.LastIn == nil || other.Behind == nil || other.Version == "" {
		t.Errorf("web-2 as web-1 sees it: %+v", other)
	}
	if st.Config == nil || len(st.Config.Version) != 12 || !slices.Equal(st.Config.Differing, []string{"web-2"}) {
		t.Errorf("config hint: %+v", st.Config)
	}
	if st.Shared == nil || st.Counters == nil || st.Replaced == nil {
		t.Errorf("shared %+v counters %+v replaced %v", st.Shared, st.Counters, st.Replaced)
	}

	// A block names the node that decided it, on both nodes.
	const ip = "203.0.113.50"
	a.h.App.Behaviour.SetAgentBlock(behaviour.AgentBlock{IP: netip.MustParseAddr(ip), Source: behaviour.DashboardSource, NetClass: "hosting", Duration: 15 * time.Minute, Incident: "S-GROUP-1", Time: time.Now()})
	a.h.WaitFor("web-1 names itself", func() bool {
		l := decode[dashboard.BlockList](t, expect(t, a.h, "GET", "/blocks", nil, 200, "BlockList"))
		return len(l.Items) == 1 && l.Items[0].Node == "web-1" && l.Items[0].NodeSelf != nil && *l.Items[0].NodeSelf
	})
	key, _ := behaviour.KeyOf(netip.MustParseAddr(ip))
	b.h.WaitFor("web-2 names web-1", func() bool {
		name, self, ok := b.h.App.Dashboard.BlockNode(key, "S-GROUP-1")
		return ok && name == "web-1" && !self
	})
	a.h.WaitFor("web-1 counts the block of the group", func() bool { return a.status(t).Shared.Blocks == 1 })

	// An erasure names the nodes it reached.
	res := decode[dashboard.PrivacyDeleteResult](t, expect(t, a.h, "POST", "/privacy/delete", map[string]any{"ip": ip, "confirm": true}, 200, "PrivacyDeleteResult"))
	if res.Nodes == nil || !slices.Equal(res.Nodes.Reached, []string{"web-1", "web-2"}) || len(res.Nodes.Open) != 0 {
		t.Errorf("erasure with both nodes up: %+v", res.Nodes)
	}

	// web-2 away: web-1 says the sync is interrupted, and an erasure stays
	// open for web-2.
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("web-1 says the sync is interrupted", func() bool {
		st := a.status(t)
		return st.State == "interrupted" && of(st, "web-2").State == "unreachable" && of(st, "web-2").Error != ""
	})
	res = decode[dashboard.PrivacyDeleteResult](t, expect(t, a.h, "POST", "/privacy/delete", map[string]any{"ip": "203.0.113.51", "confirm": true}, 200, "PrivacyDeleteResult"))
	if res.Nodes == nil || !slices.Equal(res.Nodes.Reached, []string{"web-1"}) || !slices.Equal(res.Nodes.Open, []string{"web-2"}) {
		t.Errorf("erasure with web-2 away: %+v", res.Nodes)
	}

	// Removed: named apart, without contact times.
	if _, err := cluster.Remove(a.clusterDir(), "web-2", nil); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("web-1 lists web-2 as removed and is active alone", func() bool {
		st := a.status(t)
		return st.State == "active" && of(st, "web-2").State == "removed" && of(st, "web-2").LastOut == nil
	})
}
