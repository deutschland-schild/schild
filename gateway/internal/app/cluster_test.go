//go:build !release

package app_test

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/reqring"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
	"github.com/deutschland-schild/schild/gateway/internal/store"
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
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
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

// The whole group from files a deployment writes: the same secret and the
// same peers on both nodes, no command on either.
func TestGroupFromConfigurationOnly(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "cluster.secret")
	secret, err := cluster.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1"}
	b := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2"}
	start := func(g *groupNode) {
		g.h = apptest.New(t, apptest.Options{Dir: g.dir, Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q, peers: [%q, %q]}\n", g.addr, secretFile, a.addr, b.addr)})
		if g.h.App.Cluster == nil {
			t.Fatalf("%s: no cluster node", g.name)
		}
	}
	start(a)
	start(b)
	a.block("203.0.113.90", "S-CONFIG", 15*time.Minute)
	b.h.WaitFor("web-2 blocks the address web-1 blocked", func() bool { return b.blocked("203.0.113.90") == "S-CONFIG" })
	b.block("203.0.113.91", "S-BACK", 15*time.Minute)
	a.h.WaitFor("web-1 blocks the address web-2 blocked", func() bool { return a.blocked("203.0.113.91") == "S-BACK" })
}

func TestClusterWithUnreadableSecretRunsAlone(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q}\n", apptest.FreeAddr(t), filepath.Join(t.TempDir(), "missing"))})
	if h.App.Cluster != nil {
		t.Error("a node without its secret started the mesh")
	}
	if resp := h.Visit("GET", "/", "203.0.113.80", "", ""); resp.StatusCode != 200 {
		t.Errorf("a gateway without its secret does not serve: %d", resp.StatusCode)
	}
}

func allowed(g *groupNode, ip string) bool {
	lvl, _ := g.h.App.Allow.Match(netip.MustParseAddr(ip), time.Now())
	return lvl != ""
}

func TestGroupSharesSettingsAllowlistAndLogins(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()

	// A scenario mode set in the dashboard of web-1 holds on web-2.
	mode := "observe"
	if b.h.App.Behaviour.Mode("path_probing") == mode {
		mode = "block"
	}
	if _, err := a.h.App.ApplyBehaviour(ctx, map[string]string{"path_probing": mode}, nil, nil); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 took the scenario mode of web-1", func() bool { return b.h.App.Behaviour.Mode("path_probing") == mode })

	// The CRS set to detect on web-2 detects on web-1.
	if _, err := b.h.App.Repos.SetState(ctx, "crs", "detect", false, ruleset.Actor{Kind: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("web-1 took the CRS state of web-2", func() bool { return a.h.App.Config().Rules.CRS.State == "detect" })
	// And the change of web-1 before stands on both: the later value holds
	// the earlier one.
	if a.h.App.Behaviour.Mode("path_probing") != mode || b.h.App.Behaviour.Mode("path_probing") != mode {
		t.Error("the second change took the first one back")
	}

	// An own address added on web-1 passes on web-2.
	if err := a.h.App.Store.AddAllow(ctx, &store.AllowEntry{IP: "198.51.100.77", Label: "office", Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 allows the address web-1 allowed", func() bool { return allowed(b, "198.51.100.77") })

	// The first password is set on web-1; web-2 knows the user and the session.
	a.h.Login()
	b.h.WaitFor("web-2 knows the user of web-1", func() bool { return b.h.App.Store.HasUsers(ctx) })
	b.h.Client, b.h.CSRF = a.h.Client, a.h.CSRF
	b.h.WaitFor("the session of web-1 holds on web-2", func() bool {
		req, _ := http.NewRequest("GET", b.h.Dash.URL+"/api/v0/overview", nil)
		for _, c := range a.h.Client.Jar.Cookies(mustURL(a.h.Dash.URL)) {
			req.AddCookie(c)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
}

func TestGroupErasesAnAddressOnEveryNode(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	const ip = "203.0.113.120"
	if err := b.h.App.Store.AddAllow(ctx, &store.AllowEntry{IP: "198.51.100.88", Label: "stays", Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("web-1 took the allowlist", func() bool { return allowed(a, "198.51.100.88") })
	// web-2 has events of the address, and the block web-1 set.
	b.h.Visit("GET", "/?q=<script>alert(1)</script>", ip, "", "")
	b.h.Flush()
	a.block(ip, "S-ERASE", 15*time.Minute)
	b.h.WaitFor("web-2 blocks the address", func() bool { return b.blocked(ip) == "S-ERASE" })
	if n := eventsOf(t, b, ip); n == 0 {
		t.Fatal("web-2 holds no event of the address before the erasure")
	}

	a.h.Login()
	if code, body := a.h.API("POST", "/privacy/delete", map[string]any{"ip": ip, "confirm": true}); code != 200 {
		t.Fatalf("erasure on web-1: %d %s", code, body)
	}
	b.h.WaitFor("web-2 erased the events of the address", func() bool { return eventsOf(t, b, ip) == 0 })
	b.h.WaitFor("web-2 ended the block of the address", func() bool { return b.blocked(ip) == "" })
	// Nothing else went with it.
	if !allowed(b, "198.51.100.88") || !allowed(a, "198.51.100.88") {
		t.Error("the erasure took an allowlist entry of another address")
	}
	// A node that was away erases when it returns.
	const late = "203.0.113.121"
	b.h.Visit("GET", "/?q=<script>alert(2)</script>", late, "", "")
	b.h.Flush()
	if eventsOf(t, b, late) == 0 {
		t.Fatal("no event of the second address")
	}
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	if code, body := a.h.API("POST", "/privacy/delete", map[string]any{"ip": late, "confirm": true}); code != 200 {
		t.Fatalf("erasure on web-1: %d %s", code, body)
	}
	b.start(t)
	b.h.WaitFor("web-2 erased after its return", func() bool { return eventsOf(t, b, late) == 0 })
}

// A gateway that ran alone brings what it holds into the group it joins:
// its entries are added, the group's stay, nothing is lost on either side.
func TestJoiningNodeAddsWhatItHoldsToTheGroup(t *testing.T) {
	a := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1"}
	b := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2"}
	ctx := context.Background()
	if _, err := cluster.Init(a.clusterDir(), a.name, a.addr, nil); err != nil {
		t.Fatal(err)
	}
	a.start(t)
	if err := a.h.App.Store.AddAllow(ctx, &store.AllowEntry{IP: "198.51.100.1", Label: "of the group", Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	// web-2 ran alone before, with an allowlist of its own.
	solo := apptest.New(t, apptest.Options{Dir: b.dir})
	if err := solo.App.Store.AddAllow(ctx, &store.AllowEntry{IP: "198.51.100.2", Label: "of web-2 alone", Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	if err := solo.Stop(); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
	code, _, err := cluster.Invite(a.clusterDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cluster.Join(ctx, b.clusterDir(), b.name, b.addr, a.addr, code, nil); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	for _, g := range []*groupNode{a, b} {
		g.h.WaitFor(g.name+" allows the address of the group and the one web-2 brought", func() bool {
			return allowed(g, "198.51.100.1") && allowed(g, "198.51.100.2")
		})
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func eventsOf(t *testing.T, g *groupNode, ip string) int {
	t.Helper()
	rows, err := g.h.App.Store.EventsByIP(context.Background(), ip, 50)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// A node of a group answers the balancer's health check with 503 while it
// drains, and still serves the requests that reach it; then it stops.
func TestGroupNodeDrains(t *testing.T) {
	addr := apptest.FreeAddr(t)
	dir := t.TempDir()
	if _, err := cluster.Init(app.ClusterDir(filepath.Join(dir, "data")), "web-1", addr, nil); err != nil {
		t.Fatal(err)
	}
	h := apptest.New(t, apptest.Options{Dir: dir, Listeners: true, Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, drain: {delay_s: 2, grace_s: 5}}\n", addr)})
	ready := func() int {
		resp, err := http.Get("http://" + h.ProxyAddr + "/.schild/readyz")
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	page := func() int {
		req, _ := http.NewRequest("GET", "http://"+h.ProxyAddr+"/", nil)
		req.Host = "shop.example"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	h.WaitFor("the node is in service", func() bool { return ready() == 200 })
	h.App.Drain()
	h.WaitFor("the readiness answer turns to 503", func() bool { return ready() == 503 })
	if got := page(); got != 200 {
		t.Errorf("a request during the drain delay: %d, want it served", got)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- h.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("stop after the drain: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the node did not stop after its drain delay")
	}
	if got := page(); got != 0 {
		t.Errorf("the node still answers after it stopped: %d", got)
	}
}

func TestSingleGatewayStopsWithoutDrainDelay(t *testing.T) {
	h := apptest.New(t, apptest.Options{Listeners: true})
	start := time.Now()
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("a single gateway took %s to stop", d)
	}
}

// A limit counts for the group: a client that takes turns between the
// nodes gets the limit once, not once per node.
func TestGroupLimitCountsAcrossNodes(t *testing.T) {
	limit := "behaviour:\n  rate_limits:\n    - {id: api, route: \"/api/**\", limit: 20, per: 1m, burst: 20, mode: block}\n"
	a := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1"}
	b := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2"}
	if _, err := cluster.Init(a.clusterDir(), a.name, a.addr, nil); err != nil {
		t.Fatal(err)
	}
	start := func(g *groupNode) {
		g.h = apptest.New(t, apptest.Options{Dir: g.dir, Extra: limit + fmt.Sprintf("cluster: {enabled: true, listen: %q}\n", g.addr)})
	}
	start(a)
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
	code, _, err := cluster.Invite(a.clusterDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cluster.Join(context.Background(), b.clusterDir(), b.name, b.addr, a.addr, code, nil); err != nil {
		t.Fatal(err)
	}
	start(b)
	a.h.WaitFor("the nodes reach each other", func() bool { return a.h.App.Cluster.Synced() && b.h.App.Cluster.Synced() })
	time.Sleep(1500 * time.Millisecond)
	const ip = "203.0.113.150"
	passed, limited := 0, 0
	// 4 requests a second for 15 s, taking turns: 60 requests, the limit is 20.
	for i := 0; i < 60; i++ {
		g := a
		if i%2 == 1 {
			g = b
		}
		switch resp := g.h.Visit("GET", "/api/items", ip, "", ""); resp.StatusCode {
		case 200:
			passed++
		case 429:
			limited++
		default:
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
		time.Sleep(250 * time.Millisecond)
	}
	// 20 at the start, 5 more refilled in 15 s, and what two nodes take in
	// the second a count travels.
	if passed > 20+5+8 {
		t.Errorf("%d requests passed, %d were limited: the limit of 20 a minute counted per node", passed, limited)
	}
	if passed < 20 {
		t.Errorf("only %d requests passed: the group is stricter than the limit", passed)
	}
}

const attack = "/?q=<script>alert(document.cookie)</script>"

func requestsOf(t *testing.T, g *groupNode, ip string) int {
	t.Helper()
	if g.h.App.Requests == nil {
		t.Fatal("no request ring")
	}
	g.h.App.Requests.Flush()
	recs, err := g.h.App.Requests.ByIP(context.Background(), netip.MustParseAddr(ip), 50, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return len(recs)
}

// What happens on one node is in the store of the other: events, the
// incident of a stopped request, and the single requests.
func TestGroupSharesEventsIncidentsAndRequests(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	const ip = "203.0.113.160"
	if resp := a.h.Visit("GET", attack, ip, "", ""); resp.StatusCode == 200 {
		t.Fatal("the attack passed on web-1")
	}
	a.h.Visit("GET", "/impressum", ip, "", "")
	a.h.Flush()
	rows, err := a.h.App.Store.EventsByIP(ctx, ip, 50)
	if err != nil || len(rows) == 0 {
		t.Fatalf("web-1 holds no event of its own request: %v", err)
	}
	incident := ""
	for _, r := range rows {
		if r.Incident != "" {
			incident = r.Incident
		}
	}
	if incident == "" {
		t.Fatal("the stopped request has no incident on web-1")
	}
	b.h.WaitFor("web-2 holds the events of web-1", func() bool { return eventsOf(t, b, ip) == len(rows) })
	b.h.WaitFor("web-2 holds the incident of web-1", func() bool {
		in, err := b.h.App.Store.GetIncident(ctx, incident)
		return err == nil && in != nil && in.IP == ip
	})
	b.h.WaitFor("web-2 holds the requests web-1 served", func() bool { return requestsOf(t, b, ip) >= 2 })
	// Nothing comes back to web-1 a second time, and web-2 does not hand
	// the events of web-1 on as its own.
	time.Sleep(2500 * time.Millisecond)
	if n := eventsOf(t, a, ip); n != len(rows) {
		t.Errorf("web-1 holds %d events of the address, wrote %d", n, len(rows))
	}
	if n := requestsOf(t, a, ip); n != 2 {
		t.Errorf("web-1 holds %d requests of the address, served 2", n)
	}

	// web-2 is away while web-1 records; it catches up when it returns.
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	const later = "203.0.113.161"
	a.h.Visit("GET", attack, later, "", "")
	a.h.Flush()
	want := eventsOf(t, a, later)
	if want == 0 {
		t.Fatal("no event of the second address on web-1")
	}
	b.start(t)
	b.h.WaitFor("web-2 caught up with the events it missed", func() bool { return eventsOf(t, b, later) == want })

	// An erased address is gone on both, and does not come back with what
	// the other node holds.
	a.h.Login()
	if code, body := a.h.API("POST", "/privacy/delete", map[string]any{"ip": ip, "confirm": true}); code != 200 {
		t.Fatalf("erasure: %d %s", code, body)
	}
	b.h.WaitFor("web-2 erased events and requests of the address", func() bool { return eventsOf(t, b, ip) == 0 && requestsOf(t, b, ip) == 0 })
	time.Sleep(3 * time.Second)
	if eventsOf(t, a, ip) != 0 || eventsOf(t, b, ip) != 0 || requestsOf(t, a, ip) != 0 {
		t.Error("an erased address came back")
	}
	if eventsOf(t, b, later) != want {
		t.Error("the erasure took the events of another address")
	}
}

func TestGroupKeepsDataPerNodeWhenToldSo(t *testing.T) {
	a := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1"}
	b := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2"}
	if _, err := cluster.Init(a.clusterDir(), a.name, a.addr, nil); err != nil {
		t.Fatal(err)
	}
	start := func(g *groupNode) {
		g.h = apptest.New(t, apptest.Options{Dir: g.dir, Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, share_data: false}\n", g.addr)})
	}
	start(a)
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
	code, _, err := cluster.Invite(a.clusterDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cluster.Join(context.Background(), b.clusterDir(), b.name, b.addr, a.addr, code, nil); err != nil {
		t.Fatal(err)
	}
	start(b)
	const ip = "203.0.113.170"
	a.h.Visit("GET", attack, ip, "", "")
	a.h.Flush()
	a.block("203.0.113.171", "S-STILL-SHARED", 15*time.Minute)
	b.h.WaitFor("blocks are shared all the same", func() bool { return b.blocked("203.0.113.171") == "S-STILL-SHARED" })
	time.Sleep(2 * time.Second)
	if eventsOf(t, b, ip) != 0 || requestsOf(t, b, ip) != 0 {
		t.Error("with share_data false web-2 holds events or requests of web-1")
	}
}

// A flood of blocks leaves in rounds: every one reaches the other node, and
// none is lost on the way.
func TestGroupBlockFloodArrivesInRounds(t *testing.T) {
	a, b := pair(t)
	const n = 180
	for i := 0; i < n; i++ {
		a.block(fmt.Sprintf("198.18.%d.%d", i/200, i%200+1), fmt.Sprintf("S-FLOOD-%d", i), 15*time.Minute)
	}
	b.h.WaitFor("web-2 holds every block of the flood", func() bool {
		for i := 0; i < n; i++ {
			if b.blocked(fmt.Sprintf("198.18.%d.%d", i/200, i%200+1)) == "" {
				return false
			}
		}
		return true
	})
}

// Two entries added to the same list on two nodes at the same moment: both
// stay, on both nodes (the measurement of 2026-11-21 lost the first).
func TestGroupKeepsBothOfTwoChangesToOneList(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		x, y := fmt.Sprintf("198.51.101.%d", i+1), fmt.Sprintf("198.51.102.%d", i+1)
		if err := a.h.App.Store.AddAllow(ctx, &store.AllowEntry{IP: x, Label: "a", Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}); err != nil {
			t.Fatal(err)
		}
		if err := b.h.App.Store.AddAllow(ctx, &store.AllowEntry{IP: y, Label: "b", Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range []*groupNode{a, b} {
		g.h.WaitFor(g.name+" allows all twenty addresses", func() bool {
			for i := 0; i < 10; i++ {
				if !allowed(g, fmt.Sprintf("198.51.101.%d", i+1)) || !allowed(g, fmt.Sprintf("198.51.102.%d", i+1)) {
					return false
				}
			}
			return true
		})
	}
}

// A cut, a change on each side, the cut healed: what either side added
// holds on both, a login of either side holds, and two settings changed on
// different sides both stand (the kill criterion the measurement hit).
func TestGroupMergesBothSidesOfACut(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	a.h.Login()
	b.h.WaitFor("web-2 knows the user", func() bool { return b.h.App.Store.HasUsers(ctx) })
	if err := cluster.Pause(b.clusterDir(), true, nil); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 is cut off", func() bool { return b.h.App.Cluster.Paused() })
	add := func(g *groupNode, ip string) {
		if err := g.h.App.Store.AddAllow(ctx, &store.AllowEntry{IP: ip, Label: g.name, Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}); err != nil {
			t.Fatal(err)
		}
	}
	days := func(g *groupNode, events, summaries *int) {
		if _, err := g.h.App.Apply(ctx, dashboard.SettingsPatch{Retention: &dashboard.RetentionPatch{EventsDays: events, SummariesDays: summaries}}); err != nil {
			t.Fatal(err)
		}
	}
	n := func(v int) *int { return &v }
	add(a, "203.0.113.53")
	days(a, n(11), nil)
	time.Sleep(1200 * time.Millisecond)
	add(b, "203.0.113.54")
	days(b, nil, n(200))
	// A second login, on the side that is cut off.
	b.h.Login()
	if err := cluster.Pause(b.clusterDir(), false, nil); err != nil {
		t.Fatal(err)
	}
	for _, g := range []*groupNode{a, b} {
		g.h.WaitFor(g.name+" allows the addresses of both sides", func() bool { return allowed(g, "203.0.113.53") && allowed(g, "203.0.113.54") })
		g.h.WaitFor(g.name+" holds the settings of both sides", func() bool {
			r := g.h.App.Config().Retention
			return r.EventsDays == 11 && r.SummariesDays == 200
		})
	}
	// Both sessions hold on both nodes.
	for _, who := range []*groupNode{a, b} {
		for _, on := range []*groupNode{a, b} {
			on.h.WaitFor("the session of "+who.name+" holds on "+on.name, func() bool {
				req, _ := http.NewRequest("GET", on.h.Dash.URL+"/api/v0/overview", nil)
				for _, c := range who.h.Client.Jar.Cookies(mustURL(who.h.Dash.URL)) {
					req.AddCookie(c)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return false
				}
				resp.Body.Close()
				return resp.StatusCode == 200
			})
		}
	}
}

// Fresh nodes set up by configuration and started together: the first
// password, set on one of them right away, stays (the measurement saw it
// thrown away a second later).
func TestFreshGroupKeepsAWriteMadeRightAfterStart(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "cluster.secret")
	secret, _ := cluster.NewSecret()
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1"}
	b := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2"}
	start := func(g *groupNode) {
		g.h = apptest.New(t, apptest.Options{Dir: g.dir, Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q, peers: [%q, %q]}\n", g.addr, secretFile, a.addr, b.addr)})
	}
	start(a)
	// Before web-2 exists and before any sync: a node with named peers that
	// reached none does not hold itself for the whole group.
	if a.h.App.Cluster.Synced() {
		t.Error("a node that reached none of its named peers says it is in step with the group")
	}
	a.h.Login()
	start(b)
	ctx := context.Background()
	b.h.WaitFor("web-2 knows the user set on web-1", func() bool { return b.h.App.Store.HasUsers(ctx) })
	time.Sleep(2 * time.Second)
	if !a.h.App.Store.HasUsers(ctx) || !b.h.App.Store.HasUsers(ctx) {
		t.Fatal("the first password is gone")
	}
	if code, body := a.h.API("GET", "/overview", nil); code != 200 {
		t.Errorf("the session of the setup no longer holds on web-1: %d %s", code, body)
	}
}

// A node that joins with nothing of its own must not hand its empty tables
// to the group: the first node may not have told its users and sessions
// yet (it does so once a second), and would take the empty ones as the
// later change.
func TestJoiningNodeWithNothingDoesNotEmptyTheGroup(t *testing.T) {
	a := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1"}
	b := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2"}
	if _, err := cluster.Init(a.clusterDir(), a.name, a.addr, nil); err != nil {
		t.Fatal(err)
	}
	a.start(t)
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
	code, _, err := cluster.Invite(a.clusterDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The login and the join fall into the same second.
	a.h.Login()
	if _, _, err := cluster.Join(context.Background(), b.clusterDir(), b.name, b.addr, a.addr, code, nil); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	ctx := context.Background()
	b.h.WaitFor("web-2 took the users of the group", func() bool { return b.h.App.Store.HasUsers(ctx) })
	time.Sleep(1500 * time.Millisecond) // a round of both nodes
	if !a.h.App.Store.HasUsers(ctx) {
		t.Fatal("web-1 lost its users to the empty table of the node that joined")
	}
	if code, body := a.h.API("GET", "/overview", nil); code != 200 {
		t.Errorf("the session on web-1 is gone after web-2 joined: %d %s", code, body)
	}
}

// A node that was away gets the single requests the others served
// meanwhile, once each, and none of an address that was erased while it was
// away.
func TestGroupNodeCatchesUpOnRequestsAfterAnOutage(t *testing.T) {
	a, b := pair(t)
	const before, missed, erased = "203.0.113.170", "203.0.113.171", "203.0.113.172"
	a.h.Visit("GET", "/a", before, "", "")
	b.h.WaitFor("web-2 holds the request web-1 served", func() bool { return requestsOf(t, b, before) == 1 })

	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		a.h.Visit("GET", fmt.Sprintf("/while-away/%d", i), missed, "", "")
		a.h.Visit("GET", fmt.Sprintf("/erased/%d", i), erased, "", "")
	}
	a.h.WaitFor("web-1 wrote what it served", func() bool { return requestsOf(t, a, missed) == 3 && requestsOf(t, a, erased) == 3 })
	// The address is erased while web-2 is away: web-1 must not hand its
	// requests over when web-2 asks.
	a.h.Login()
	if code, body := a.h.API("POST", "/privacy/delete", map[string]any{"ip": erased, "confirm": true}); code != 200 {
		t.Fatalf("erasure on web-1: %d %s", code, body)
	}

	b.start(t)
	b.h.WaitFor("web-2 caught up with the requests it missed", func() bool { return requestsOf(t, b, missed) == 3 })
	// A few rounds later: nothing came twice, the request from before the
	// outage did not come again, the erased address did not come at all.
	time.Sleep(2500 * time.Millisecond)
	if n := requestsOf(t, b, missed); n != 3 {
		t.Errorf("web-2 holds %d requests of the address, web-1 served 3", n)
	}
	if n := requestsOf(t, b, before); n != 1 {
		t.Errorf("web-2 holds %d requests from before the outage, web-1 served 1", n)
	}
	if n := requestsOf(t, b, erased); n != 0 {
		t.Errorf("web-2 holds %d requests of an address that was erased while it was away", n)
	}
	if n := requestsOf(t, a, missed); n != 3 {
		t.Errorf("web-1 holds %d requests of the address after web-2 returned, served 3", n)
	}
	if n := b.h.App.RequestsMissed(); n != 0 {
		t.Errorf("web-2 counts %d requests as missed", n)
	}

	// And at the receiving end: a request of an erased address that was
	// served before the erasure is not stored, whoever hands it over. One
	// served after it is a new request.
	b.h.WaitFor("web-2 took the erasure", func() bool {
		return !b.h.App.TakesForeignRequest(&reqring.Entry{T: time.Now().Add(-time.Hour).UnixMilli(), Client: netip.MustParseAddr(erased), Host: "shop.example"})
	})
	if !b.h.App.TakesForeignRequest(&reqring.Entry{T: time.Now().Add(-time.Hour).UnixMilli(), Client: netip.MustParseAddr(missed), Host: "shop.example"}) {
		t.Error("web-2 refuses the request of an address that was not erased")
	}
	// What a member hands over is bounded.
	for name, e := range map[string]reqring.Entry{
		"no address":       {T: time.Now().UnixMilli()},
		"from the future":  {T: time.Now().Add(time.Hour).UnixMilli(), Client: netip.MustParseAddr(missed)},
		"older than kept":  {T: time.Now().Add(-100 * 24 * time.Hour).UnixMilli(), Client: netip.MustParseAddr(missed)},
		"a path of 1 MiB":  {T: time.Now().UnixMilli(), Client: netip.MustParseAddr(missed), RawPath: string(make([]byte, 1<<20))},
		"a host too long":  {T: time.Now().UnixMilli(), Client: netip.MustParseAddr(missed), Host: string(make([]byte, 300))},
		"a rule id of 1 k": {T: time.Now().UnixMilli(), Client: netip.MustParseAddr(missed), Rules: [3]string{string(make([]byte, 1024))}},
	} {
		if b.h.App.TakesForeignRequest(&e) {
			t.Errorf("web-2 takes a request with %s", name)
		}
	}
}
