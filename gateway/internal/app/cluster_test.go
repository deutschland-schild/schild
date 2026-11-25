//go:build !release

package app_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	// secretFile and peers: cluster.secret_file and cluster.peers.
	secretFile string
	peers      []string
}

func (g *groupNode) clusterDir() string { return app.ClusterDir(filepath.Join(g.dir, "data")) }

// clusterYAML is the cluster section of the node's schild.yaml; the node
// takes its test name as its name in the group.
func (g *groupNode) clusterYAML() string {
	peers := make([]string, len(g.peers))
	for i, p := range g.peers {
		peers[i] = fmt.Sprintf("%q", p)
	}
	return fmt.Sprintf("cluster: {enabled: true, name: %q, listen: %q, secret_file: %q, peers: [%s]}\n", g.name, g.addr, g.secretFile, strings.Join(peers, ", "))
}

func (g *groupNode) start(t *testing.T) {
	t.Helper()
	g.h = apptest.New(t, apptest.Options{Dir: g.dir, Extra: g.clusterYAML()})
	if g.h.App.Cluster == nil {
		t.Fatalf("%s: no cluster node", g.name)
	}
}

// writeSecret writes a new group secret into a file of its own.
func writeSecret(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cluster.secret")
	secret, err := cluster.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// newGroup makes gateways as a deployment sets them up: the same secret
// file on every one and every address in cluster.peers. None runs yet.
func newGroup(t *testing.T, names ...string) []*groupNode {
	t.Helper()
	secretFile := writeSecret(t)
	var nodes []*groupNode
	var addrs []string
	for _, name := range names {
		g := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: name, secretFile: secretFile}
		nodes = append(nodes, g)
		addrs = append(addrs, g.addr)
	}
	for _, g := range nodes {
		g.peers = addrs
	}
	return nodes
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

// pair: two gateways in one group, set up by their configuration.
func pair(t *testing.T) (a, b *groupNode) {
	t.Helper()
	nodes := newGroup(t, "web-1", "web-2")
	a, b = nodes[0], nodes[1]
	a.start(t)
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
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

// cluster.enabled without cluster.secret_file is no group: the
// configuration is refused, the gateway does not run alone.
func TestClusterEnabledWithoutSecretFileIsRefused(t *testing.T) {
	h := apptest.New(t, apptest.Options{NewFails: true, Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q}\n", apptest.FreeAddr(t))})
	if !strings.Contains(h.NewErr.Error(), "cluster.secret_file") {
		t.Errorf("the error does not name the cause: %v", h.NewErr)
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

// A node of a group that cannot be set up or cannot run does not start:
// it never serves alone while its readiness answer says 200. The error
// names the cause and the fix.
func TestClusterThatCannotRunDoesNotStart(t *testing.T) {
	refused := func(t *testing.T, extra string, want ...string) {
		t.Helper()
		h := apptest.New(t, apptest.Options{NewFails: true, Extra: extra})
		for _, w := range want {
			if !strings.Contains(h.NewErr.Error(), w) {
				t.Errorf("the error does not say %q: %v", w, h.NewErr)
			}
		}
	}
	yaml := func(listen, secretFile string) string {
		return fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q}\n", listen, secretFile)
	}
	t.Run("missing secret file", func(t *testing.T) {
		refused(t, yaml(apptest.FreeAddr(t), filepath.Join(t.TempDir(), "missing")), "cluster.secret_file", "cluster.enabled false")
	})
	t.Run("short secret", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "cluster.secret")
		if err := os.WriteFile(p, []byte("short\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, yaml(apptest.FreeAddr(t), p), "shorter than 32 bytes", "schild cluster secret")
	})
	t.Run("secret others read", func(t *testing.T) {
		p := writeSecret(t)
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
		refused(t, yaml(apptest.FreeAddr(t), p), "chmod 0640")
	})
	t.Run("mesh port taken", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		refused(t, yaml(ln.Addr().String(), writeSecret(t)), "cluster.listen", "free the port")
	})
	t.Run("node key others read", func(t *testing.T) {
		dir := t.TempDir()
		secret := writeSecret(t)
		g := &groupNode{dir: dir, addr: apptest.FreeAddr(t), name: "web-1", secretFile: secret}
		g.start(t)
		if err := g.h.Stop(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(g.clusterDir(), "node.key"), 0o644); err != nil {
			t.Fatal(err)
		}
		h := apptest.New(t, apptest.Options{NewFails: true, Dir: dir, Extra: g.clusterYAML()})
		if !strings.Contains(h.NewErr.Error(), "node.key") || !strings.Contains(h.NewErr.Error(), "cluster.enabled false") {
			t.Errorf("the error does not name the key and the fix: %v", h.NewErr)
		}
	})
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
	nodes := newGroup(t, "web-1", "web-2")
	a, b := nodes[0], nodes[1]
	ctx := context.Background()
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
	h := apptest.New(t, apptest.Options{Listeners: true, Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q, drain: {delay_s: 2, grace_s: 5}}\n", addr, writeSecret(t))})
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
	// Before the stop an answer leaves the connection open, as usual.
	closes := func() bool {
		req, _ := http.NewRequest("GET", "http://"+h.ProxyAddr+"/", nil)
		req.Host = "shop.example"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.Close
	}
	if closes() {
		t.Fatal("an answer of a node in service asks to close the connection")
	}
	h.App.Drain()
	h.WaitFor("the readiness answer turns to 503", func() bool { return ready() == 503 })
	// During the delay every answer asks the client to close: a client
	// that keeps its connection open leaves before the node stops.
	if !closes() {
		t.Fatal("an answer during the drain delay does not carry Connection: close")
	}
	if got := page(); got != 200 {
		t.Errorf("a request during the drain delay: %d, want it served", got)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- h.Stop() }()
	// A client that keeps its connection open and does what the answers ask
	// (close, then connect again) loses no request across the stop: every
	// request is answered until the node refuses new connections.
	kept := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1}, Timeout: 5 * time.Second}
	answered, cut := 0, ""
	// reused: the request that was cut ran on a connection the client had
	// kept; sinceConn: how long that connection existed when it was cut.
	var reused bool
	var sinceConn time.Duration
	for cut == "" {
		req, _ := http.NewRequest("GET", "http://"+h.ProxyAddr+"/", nil)
		req.Host = "shop.example"
		var got httptrace.GotConnInfo
		var gotAt time.Time
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { got, gotAt = i, time.Now() }}))
		resp, err := kept.Do(req)
		switch {
		case err == nil:
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			answered++
			time.Sleep(20 * time.Millisecond)
		case strings.Contains(err.Error(), "connection refused"):
			cut = "refused"
		default:
			cut, reused = err.Error(), got.Reused
			if !gotAt.IsZero() {
				sinceConn = time.Since(gotAt)
			}
		}
		if answered > 2000 {
			cut = "never stopped"
		}
	}
	if cut != "refused" {
		// The one case that is no loss: a connection made in the instant
		// the node closed its listener. The kernel had taken it, the node
		// never did, and every connection after it is refused. That is the
		// end of the node as a client sees it, like a refused connection;
		// behind a balancer no new connection comes at that moment, the
		// node left its pool a delay ago. A connection the client had kept,
		// or one the node held for a while, must never end this way.
		next, _ := http.NewRequest("GET", "http://"+h.ProxyAddr+"/", nil)
		next.Host = "shop.example"
		_, nerr := kept.Do(next)
		atClose := !reused && sinceConn < 500*time.Millisecond && nerr != nil && strings.Contains(nerr.Error(), "connection refused")
		if !atClose {
			t.Errorf("a request on a kept connection was lost across the stop: %s after %d answers (connection reused: %v, %s old; the next request: %v)", cut, answered, reused, sinceConn, nerr)
		} else {
			t.Logf("the last connection was made as the listener closed (%s after %d answers, %s old); the next is refused", cut, answered, sinceConn)
		}
	}
	if answered < 10 {
		t.Errorf("only %d requests were answered during the drain delay", answered)
	}
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
	nodes := newGroup(t, "web-1", "web-2")
	a, b := nodes[0], nodes[1]
	start := func(g *groupNode) {
		g.h = apptest.New(t, apptest.Options{Dir: g.dir, Extra: limit + g.clusterYAML()})
	}
	start(a)
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
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
// different sides both stand (the kill criterion the measurement hit). The
// cut is a stop: web-1 changes while web-2 is down, then web-2 changes
// alone while web-1 is down, then both run again.
func TestGroupMergesBothSidesOfACut(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()
	a.h.Login()
	b.h.WaitFor("web-2 knows the user", func() bool { return b.h.App.Store.HasUsers(ctx) })
	// The sessions as the browsers keep them: a restart makes a new harness.
	sessions := map[string][]*http.Cookie{}
	keep := func(g *groupNode) { sessions[g.name] = g.h.Client.Jar.Cookies(mustURL(g.h.Dash.URL)) }
	keep(a)
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
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	add(a, "203.0.113.53")
	days(a, n(11), nil)
	time.Sleep(1200 * time.Millisecond)
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	add(b, "203.0.113.54")
	days(b, nil, n(200))
	// A second login, on the side that is cut off.
	b.h.Login()
	keep(b)
	a.start(t)
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
				for _, c := range sessions[who.name] {
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
	nodes := newGroup(t, "web-1", "web-2")
	a, b := nodes[0], nodes[1]
	a.start(t)
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
	// The login and the start of web-2 fall into the same second.
	a.h.Login()
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

// A node that was away longer than the log in memory of the others reaches
// gets everything all the same, from their request stores on disk: once
// each, also what a node served before it restarted itself.
func TestGroupNodeCatchesUpFromDiskAfterALongOutage(t *testing.T) {
	defer app.SetRequestsLog(4)() // four requests in memory: the rest has to come from disk
	a, b := pair(t)
	const before, away1, away2, after = "203.0.113.180", "203.0.113.181", "203.0.113.182", "203.0.113.183"
	a.h.Visit("GET", "/before", before, "", "")
	b.h.WaitFor("web-2 holds the request web-1 served", func() bool { return requestsOf(t, b, before) == 1 })

	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		a.h.Visit("GET", fmt.Sprintf("/away/%d", i), away1, "", "")
	}
	a.h.WaitFor("web-1 wrote what it served", func() bool { return requestsOf(t, a, away1) == 20 })
	// web-1 restarts while web-2 is still away: its log in memory is gone,
	// its numbers go on above the old ones.
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.start(t)
	for i := 0; i < 20; i++ {
		a.h.Visit("GET", fmt.Sprintf("/away-again/%d", i), away2, "", "")
	}
	a.h.WaitFor("web-1 wrote what it served after its restart", func() bool { return requestsOf(t, a, away2) == 20 })

	b.start(t)
	b.h.WaitFor("web-2 caught up with all 40 requests it missed", func() bool {
		return requestsOf(t, b, away1) == 20 && requestsOf(t, b, away2) == 20
	})
	a.h.Visit("GET", "/after", after, "", "")
	b.h.WaitFor("web-2 goes on with what web-1 serves now", func() bool { return requestsOf(t, b, after) == 1 })
	// A few rounds later nothing came twice, on either node.
	time.Sleep(2500 * time.Millisecond)
	for ip, want := range map[string]int{before: 1, away1: 20, away2: 20, after: 1} {
		if n := requestsOf(t, b, ip); n != want {
			t.Errorf("web-2 holds %d requests of %s, web-1 served %d", n, ip, want)
		}
		if n := requestsOf(t, a, ip); n != want {
			t.Errorf("web-1 holds %d requests of %s, it served %d", n, ip, want)
		}
	}
	if n := b.h.App.RequestsMissed(); n != 0 {
		t.Errorf("web-2 counts %d numbers as gone for good", n)
	}
}

// Blocks that arrive from another node while this node compares its own
// must never be taken for blocks that ended early here: a node once lifted
// such a block for the whole group (finding of the measurement: an unblock
// on the other node answered "already unblocked").
func TestGroupNeverLiftsABlockThatJustArrived(t *testing.T) {
	a, b := pair(t)
	const n = 300
	for i := 0; i < n; i++ {
		a.block(fmt.Sprintf("198.19.%d.%d", i/200, i%200+1), fmt.Sprintf("S-ARRIVE-%d", i), 15*time.Minute)
		if i%10 == 0 {
			time.Sleep(7 * time.Millisecond) // arrivals spread over many rounds of web-2
		}
	}
	all := func(g *groupNode) int {
		c := 0
		for i := 0; i < n; i++ {
			if g.blocked(fmt.Sprintf("198.19.%d.%d", i/200, i%200+1)) != "" {
				c++
			}
		}
		return c
	}
	b.h.WaitFor("web-2 holds every block", func() bool { return all(b) == n })
	time.Sleep(1500 * time.Millisecond)
	if got := all(a); got != n {
		t.Errorf("web-1 runs %d of the %d blocks it set: another node lifted the rest", got, n)
	}
	if got := all(b); got != n {
		t.Errorf("web-2 runs %d of %d blocks", got, n)
	}
}

// A node of a group makes no keys of the browser check of its own at its
// start: the group rotates them, once, on the node that keeps its tasks,
// and the keys before stay valid next to the new ones. The age is looked at
// every second here, so the test does not depend on when the task first ran
// (it is looked at every hour in production).
func TestGroupNodeDoesNotRotateBrowserCheckKeysAtItsStart(t *testing.T) {
	defer app.SetHumanCheckKeysLook(time.Second)()
	a, b := pair(t)
	b.h.WaitFor("web-2 runs the keys of the group", func() bool {
		x, y := a.h.App.HumanCheck.State(), b.h.App.HumanCheck.State()
		return x != nil && y != nil && string(x.ClearanceKey) == string(y.ClearanceKey) && string(x.ChallengeKey) == string(y.ChallengeKey)
	})
	key := string(a.h.App.HumanCheck.State().ClearanceKey)
	// The keys age two days on both nodes; the group may rotate them at any
	// moment from now on.
	old := time.Now().UTC().Add(-48 * time.Hour)
	if err := a.h.App.AgeHumanCheckKeys(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 holds the aged keys or the group's new ones", func() bool {
		st := b.h.App.HumanCheck.State()
		return st.KeysRotatedAt.Equal(old) || string(st.PrevClearanceKey) == key
	})
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	// At its start web-2 runs the keys it held or the group's, never keys
	// it made itself.
	if got, group := string(b.h.App.HumanCheck.State().ClearanceKey), string(a.h.App.HumanCheck.State().ClearanceKey); got != key && got != group {
		t.Fatal("web-2 rotated the keys at its start, on its own")
	}
	// The group rotated them once: both nodes end with the same new keys,
	// and the keys before stay valid next to them.
	for _, g := range []*groupNode{a, b} {
		g.h.WaitFor(g.name+" runs the keys the group rotated", func() bool {
			st := g.h.App.HumanCheck.State()
			return string(st.ClearanceKey) != key && string(st.PrevClearanceKey) == key
		})
	}
	b.h.WaitFor("both nodes run the same new keys", func() bool {
		return string(a.h.App.HumanCheck.State().ClearanceKey) == string(b.h.App.HumanCheck.State().ClearanceKey)
	})
}

// A group secret that became known is replaced server by server: the new
// secret file and a restart, nothing else. Each server leaves the old group
// and enters the new one with what it held, so nothing the group shared is
// lost on the way, and what a server sets while the others still run the
// old group reaches them when they follow.
func TestNewGroupSecretServerByServerKeepsTheState(t *testing.T) {
	defer app.SetFirstSyncWait(1500 * time.Millisecond)()
	// Two groups run in this process for a while (see OneGroupHashKey).
	t.Cleanup(app.OneGroupHashKey())
	dir := t.TempDir()
	write := func(name string) string {
		secret, err := cluster.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldSecret, newSecret := write("old.secret"), write("new.secret")
	a := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1"}
	b := &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2"}
	start := func(g *groupNode, secretFile string) {
		g.h = apptest.New(t, apptest.Options{Dir: g.dir, Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q, secret_file: %q, peers: [%q, %q]}\n", g.addr, secretFile, a.addr, b.addr)})
		if g.h.App.Cluster == nil {
			t.Fatalf("%s: no cluster node", g.name)
		}
	}
	renew := func(g *groupNode) {
		if err := g.h.Stop(); err != nil {
			t.Fatal(err)
		}
		start(g, newSecret)
	}
	start(a, oldSecret)
	start(b, oldSecret)
	oldGroup := a.h.App.Cluster.Group()
	a.block("203.0.113.180", "S-BEFORE", 15*time.Minute)
	b.h.WaitFor("web-2 holds the block of the old group", func() bool { return b.blocked("203.0.113.180") == "S-BEFORE" })

	b.h.WaitFor("web-2 is in service in the old group", func() bool { return b.h.App.InService() })
	// web-2 goes first. It is alone in the new group and keeps what it held.
	renew(b)
	if g := b.h.App.Cluster.Group(); g == oldGroup {
		t.Fatal("the new secret made no new group")
	}
	// It was in step with the old group and carries that along: alone in
	// the new one it serves after the wait, like a node that finds nobody.
	b.h.WaitFor("web-2 serves alone in the new group", func() bool { return b.h.App.InService() })
	if got := b.blocked("203.0.113.180"); got != "S-BEFORE" {
		t.Fatalf("web-2 lost the block of the old group over the change: %q", got)
	}
	b.block("203.0.113.181", "S-BETWEEN", 15*time.Minute)
	a.block("203.0.113.182", "S-OLD-SIDE", 15*time.Minute)
	// A node of the old group takes nothing of the new one, and the other way round.
	time.Sleep(2 * time.Second)
	if a.blocked("203.0.113.181") != "" || b.blocked("203.0.113.182") != "" {
		t.Fatal("a block crossed between the old and the new group")
	}
	if a.blocked("203.0.113.180") != "S-BEFORE" || a.blocked("203.0.113.182") != "S-OLD-SIDE" {
		t.Fatal("web-1, still in the old group, lost a block when web-2 left")
	}

	// web-1 follows: both are in the new group and hold everything.
	renew(a)
	if a.h.App.Cluster.Group() != b.h.App.Cluster.Group() {
		t.Fatal("the two servers ended in different groups")
	}
	for _, g := range []*groupNode{a, b} {
		for ip, incident := range map[string]string{"203.0.113.180": "S-BEFORE", "203.0.113.181": "S-BETWEEN", "203.0.113.182": "S-OLD-SIDE"} {
			g.h.WaitFor(g.name+" blocks "+ip+" in the new group", func() bool { return g.blocked(ip) == incident })
		}
	}
}

// "Freigeben" on another node works from the moment that node holds the
// block: it does not wait for the incident, which follows with the events of
// the node that blocked (finding F2 of the lab measurement).
func TestUnblockOnAnotherNodeAsSoonAsItHoldsTheBlock(t *testing.T) {
	a, b := pair(t)
	b.h.Login()
	for i, incident := range []string{"K7QM-4XWA", "K7QM-4XWB", "K7QM-4XWC", "K7QM-4XWD", "K7QM-4XWE"} {
		ip := fmt.Sprintf("203.0.113.%d", 210+i)
		a.block(ip, incident, 15*time.Minute)
		b.h.WaitFor("web-2 holds the block "+incident, func() bool { return b.blocked(ip) == incident })
		if code, body := b.h.API("POST", "/incidents/"+incident+"/unblock", map[string]any{}); code != 200 {
			t.Fatalf("unblock of %s on web-2 right after the block arrived: %d %s", incident, code, body)
		}
		a.h.WaitFor("web-1 serves "+ip+" again", func() bool { return a.blocked(ip) == "" })
		if got := b.blocked(ip); got != "" {
			t.Fatalf("web-2 still blocks %s after its own unblock (%s)", ip, got)
		}
	}
}

// The same in the moment the block starts there: its incident is stored by
// then, and the release ends the block on both nodes.
func TestUnblockOnAnotherNodeInTheMomentTheBlockStarts(t *testing.T) {
	a, b := pair(t)
	b.h.Login()
	const ip, incident = "203.0.113.215", "K7QM-4XWF"
	type answer struct {
		code int
		body string
	}
	answers := make(chan answer, 1)
	defer app.SetTestBlockRuns(func(x *app.App, in string) {
		if x != b.h.App || in != incident {
			return
		}
		code, body := b.h.API("POST", "/incidents/"+incident+"/unblock", map[string]any{})
		answers <- answer{code, fmt.Sprintf("%s", body)}
	})()
	a.block(ip, incident, 15*time.Minute)
	select {
	case got := <-answers:
		if got.code != 200 {
			t.Fatalf("unblock on web-2 while the block starts: %d %s", got.code, got.body)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the block did not reach web-2")
	}
	a.h.WaitFor("web-1 serves "+ip+" again", func() bool { return a.blocked(ip) == "" })
	b.h.WaitFor("web-2 serves "+ip+" again", func() bool { return b.blocked(ip) == "" })
}
