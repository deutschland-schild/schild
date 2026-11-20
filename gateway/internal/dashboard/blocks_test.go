//go:build !release

package dashboard_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/firewall"
	"github.com/deutschland-schild/schild/contract/schema"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

const agentListen = "127.0.0.1:8789"

// firewallToken makes a token of scope firewall:sync, as `schild token add`.
func firewallToken(t *testing.T, h *apptest.Harness) string {
	t.Helper()
	tok := contractapi.NewToken()
	now := time.Now().UTC()
	if err := h.App.Store.AddAgentToken(context.Background(), store.AgentToken{ID: contractapi.TokenID(tok), Hash: contractapi.HashToken(tok), Scope: contractapi.ScopeFirewallSync,
		Label: "firewall", Created: now, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return tok
}

// syncFirewall is one call of `schild firewall run`.
func syncFirewall(t *testing.T, h *apptest.Harness, tok string, req firewall.SyncRequest) (int, firewall.SyncResponse) {
	t.Helper()
	b, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/agent/v0/firewall/sync", strings.NewReader(string(b)))
	r.Host = agentListen
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.App.AgentAPI.Handler(agentListen).ServeHTTP(w, r)
	var ans firewall.SyncResponse
	_ = json.Unmarshal(w.Body.Bytes(), &ans)
	return w.Code, ans
}

const agentOn = "agent_api:\n  enabled: true\n  requests_per_minute: 600\n"

// D87: every block that runs is in the list and in the answer for the
// firewall; the list says what the firewall applied.
func TestBlocksListAndFirewallSync(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "autoblock", Extra: agentOn})
	h.Login()
	l := decode[dashboard.BlockList](t, expect(t, h, "GET", "/blocks", nil, 200, "BlockList"))
	if len(l.Items) != 0 || l.Total != 0 || l.Firewall.State != "off" || l.Firewall.Table != firewall.Table {
		t.Fatalf("empty: %+v", l)
	}
	now := time.Now()
	for _, ip := range []string{"203.0.113.7", "2001:db8:1:2::9"} {
		if _, ok := h.App.Behaviour.SetAgentBlock(behaviour.AgentBlock{IP: netip.MustParseAddr(ip), TokenID: "tok_000000000001", NetClass: "hosting", Duration: time.Hour,
			Incident: "AAAA-BBBB", Time: now}); !ok {
			t.Fatalf("%s not blocked", ip)
		}
	}
	tok := firewallToken(t, h)
	code, ans := syncFirewall(t, h, tok, firewall.SyncRequest{Table: firewall.Table, Version: "test"})
	if code != 200 || !ans.Valid() || len(ans.Blocks) != 2 || ans.Blocks[0].Client != "2001:db8:1:2::/64" || ans.Blocks[1].Client != "203.0.113.7" {
		t.Fatalf("first answer: %d %+v", code, ans)
	}
	// Before the firewall applied anything: pending.
	l = decode[dashboard.BlockList](t, expect(t, h, "GET", "/blocks", nil, 200, "BlockList"))
	if l.Firewall.State != "ok" || len(l.Items) != 2 || l.Items[0].Firewall != "pending" || l.Items[0].Source != "agent" {
		t.Fatalf("pending: %+v", l)
	}
	// The firewall applied that revision: banned. The call waits for a change
	// and comes back with the same revision after its wait.
	h.App.AgentAPI.Firewall.Wait = 200 * time.Millisecond
	start := time.Now()
	code, again := syncFirewall(t, h, tok, firewall.SyncRequest{Applied: ans.Revision, Held: 2, Table: firewall.Table, Version: "test"})
	if code != 200 || again.Revision != ans.Revision || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("long poll: %d %s after %s", code, again.Revision, time.Since(start))
	}
	l = decode[dashboard.BlockList](t, expect(t, h, "GET", "/blocks", nil, 200, "BlockList"))
	if l.Firewall.Banned != 2 || l.Items[0].Firewall != "banned" || l.Items[1].Firewall != "banned" {
		t.Fatalf("banned: %+v", l)
	}
	// The firewall's error shows.
	syncFirewall(t, h, tok, firewall.SyncRequest{Applied: ans.Revision, Held: 2, Table: firewall.Table, Version: "test", Error: "netlink: operation not permitted"})
	l = decode[dashboard.BlockList](t, expect(t, h, "GET", "/blocks", nil, 200, "BlockList"))
	if l.Firewall.State != "error" || !strings.Contains(l.Firewall.Error, "not permitted") || l.Items[0].Firewall != "stale" {
		t.Fatalf("error: %+v", l.Firewall)
	}
}

// The firewall's token reads nothing else, and other tokens cannot sync.
func TestFirewallScopeIsNarrow(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "autoblock", Extra: agentOn})
	tok := firewallToken(t, h)
	for _, path := range []string{"/agent/v0/status", "/agent/v0/events", "/agent/v0/websites"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = agentListen
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.App.AgentAPI.Handler(agentListen).ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s with firewall:sync: %d", path, w.Code)
		}
	}
	read := contractapi.NewToken()
	now := time.Now().UTC()
	if err := h.App.Store.AddAgentToken(context.Background(), store.AgentToken{ID: contractapi.TokenID(read), Hash: contractapi.HashToken(read), Scope: contractapi.ScopeAgentRead,
		Created: now, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if code, _ := syncFirewall(t, h, read, firewall.SyncRequest{Table: firewall.Table}); code != 403 {
		t.Fatalf("agent:read synced: %d", code)
	}
}

// Unblocking in the dashboard ends the block for good (D87): it leaves the
// list and the next answer to the firewall, at once.
func TestUnblockTakesTheBlockOutOfTheFirewall(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "review", Extra: agentOn + "behaviour:\n  presets: [wordpress]\n  scenarios:\n    login_bruteforce: {mode: block}\n"})
	h.Login()
	if err := h.App.SetInstalledAt(context.Background(), time.Now().Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	const attacker = "198.51.100.7"
	for i := 0; i < 5; i++ {
		h.Visit("POST", "/wp-login.php", attacker, "application/x-www-form-urlencoded", "log=admin&pwd=x")
	}
	r := h.Visit("GET", "/", attacker, "", "")
	incident := r.Header.Get("X-Schild-Incident")
	if r.StatusCode != 403 || incident == "" {
		t.Fatalf("not blocked: %d", r.StatusCode)
	}
	h.Flush()
	tok := firewallToken(t, h)
	_, ans := syncFirewall(t, h, tok, firewall.SyncRequest{Table: firewall.Table})
	if got := firewall.Running(ans.Blocks, time.Now()); len(got) != 1 || got[0] != attacker {
		t.Fatalf("for the firewall: %v", got)
	}
	// The firewall waits; the unblock answers it within a second.
	type result struct {
		ans firewall.SyncResponse
		at  time.Time
	}
	done := make(chan result, 1)
	go func() {
		_, a := syncFirewall(t, h, tok, firewall.SyncRequest{Applied: ans.Revision, Held: 1, Table: firewall.Table})
		done <- result{a, time.Now()}
	}()
	time.Sleep(100 * time.Millisecond)
	lifted := time.Now()
	expect(t, h, "POST", "/incidents/"+incident+"/unblock", map[string]any{"false_positive": false}, 200, "Incident")
	select {
	case res := <-done:
		if len(res.ans.Blocks) != 0 || res.at.Sub(lifted) > 3*time.Second {
			t.Fatalf("after the unblock: %+v in %s", res.ans, res.at.Sub(lifted))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting firewall did not hear of the unblock")
	}
	if l := decode[dashboard.BlockList](t, expect(t, h, "GET", "/blocks", nil, 200, "BlockList")); len(l.Items) != 0 {
		t.Fatalf("still listed after the unblock: %+v", l)
	}
	if r := h.Visit("GET", "/", attacker, "", ""); r.StatusCode != 200 {
		t.Fatalf("still blocked over HTTP: %d", r.StatusCode)
	}
}

// D88: an address blocked by hand in the dashboard is blocked over HTTP,
// listed, handed to the firewall and recorded; own, private and shared
// addresses are refused, and the unblock frees it again.
func TestBlockByHand(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "autoblock", Extra: agentOn})
	h.Login()
	const attacker = "203.0.113.50"
	body := func(addr string, set map[string]any) map[string]any {
		b := map[string]any{"address": addr, "duration_s": 86400, "reason": "scanner from the access log"}
		for k, v := range set {
			b[k] = v
		}
		return b
	}
	for name, c := range map[string]struct {
		body   map[string]any
		status int
		code   string
	}{
		"own address":     {body("192.0.2.10", nil), 409, "own_address"},
		"private address": {body("10.1.2.3", nil), 409, "private_address"},
		"cgnat":           {body("100.64.3.4", nil), 409, "private_address"},
		"a network":       {body("203.0.113.0/24", nil), 400, "invalid"},
		"a name":          {body("scanner.example", nil), 400, "invalid"},
		"30 days":         {body(attacker, map[string]any{"duration_s": 2592000}), 400, "invalid"},
		"no reason":       {body(attacker, map[string]any{"reason": ""}), 400, "invalid"},
	} {
		p := decode[dashboard.Problem](t, expect(t, h, "POST", "/blocks", c.body, c.status, "Problem"))
		if p.Code != c.code {
			t.Errorf("%s: %+v", name, p)
		}
	}
	// A mobile address needs the confirmation.
	geoOf := h.App.Dashboard.GeoOf
	h.App.Dashboard.GeoOf = func(ip netip.Addr) events.Geo { g := geoOf(ip); g.NetClass = "mobile"; return g }
	if p := decode[dashboard.Problem](t, expect(t, h, "POST", "/blocks", body("198.51.100.77", nil), 409, "Problem")); p.Code != "shared_address" {
		t.Fatalf("shared: %+v", p)
	}
	h.App.Dashboard.GeoOf = geoOf

	if r := h.Visit("GET", "/", attacker, "", ""); r.StatusCode != 200 {
		t.Fatalf("before: %d", r.StatusCode)
	}
	b := decode[dashboard.RunningBlock](t, expect(t, h, "POST", "/blocks", body(attacker, nil), 200, "RunningBlock"))
	if b.Client != attacker || b.Source != "dashboard" || b.DurationS != 86400 || b.Incident == "" || b.NetClass != "hosting" || b.Firewall != "off" {
		t.Fatalf("created: %+v", b)
	}
	if r := h.Visit("GET", "/", attacker, "", ""); r.StatusCode != 403 {
		t.Fatalf("not blocked over HTTP: %d", r.StatusCode)
	}
	if p := decode[dashboard.Problem](t, expect(t, h, "POST", "/blocks", body(attacker, nil), 409, "Problem")); p.Code != "already_blocked" || !strings.Contains(p.Detail, b.Incident) {
		t.Fatalf("twice: %+v", p)
	}
	l := decode[dashboard.BlockList](t, expect(t, h, "GET", "/blocks", nil, 200, "BlockList"))
	if len(l.Items) != 1 || l.Items[0].Source != "dashboard" || l.Items[0].Incident != b.Incident {
		t.Fatalf("listed: %+v", l)
	}
	tok := firewallToken(t, h)
	if _, ans := syncFirewall(t, h, tok, firewall.SyncRequest{Table: firewall.Table}); len(ans.Blocks) != 1 || ans.Blocks[0].Client != attacker {
		t.Fatalf("for the firewall: %+v", ans)
	}
	// Recorded with actor dashboard, valid against the event contract.
	h.Flush()
	rows, _, _ := h.App.Store.ListEvents(context.Background(), store.EventFilter{Type: events.BlockSet}, 0, 10)
	if len(rows) != 1 || !strings.Contains(string(rows[0].Body), `"actor":"dashboard"`) || strings.Contains(string(rows[0].Body), "token_") {
		t.Fatalf("event: %d rows", len(rows))
	}
	var doc any
	if err := json.Unmarshal(rows[0].Body, &doc); err != nil || schema.Validate("events", doc) != nil {
		t.Fatalf("not an event of the contract: %v %s", schema.Validate("events", doc), rows[0].Body)
	}
	// The event list names the address, where it comes from and the result,
	// like a request row.
	var row *dashboard.EventSummary
	for _, e := range decode[dashboard.EventPage](t, expect(t, h, "GET", "/events?limit=100", nil, 200, "EventPage")).Items {
		if e.Type == events.BlockSet {
			row = &e
			break
		}
	}
	if row == nil || row.IP != attacker || row.Outcome != "blocked" || row.Incident != b.Incident || row.Geo == nil || row.Geo.NetClass != "hosting" {
		t.Fatalf("block row in the event list: %+v", row)
	}
	// The incident page knows it, and the unblock frees it at once.
	inc := decode[dashboard.Incident](t, expect(t, h, "GET", "/incidents/"+b.Incident, nil, 200, "Incident"))
	if inc.Block == nil || inc.Block.Source != "dashboard" {
		t.Fatalf("incident: %+v", inc.Block)
	}
	expect(t, h, "POST", "/incidents/"+b.Incident+"/unblock", map[string]any{"false_positive": false}, 200, "Incident")
	if r := h.Visit("GET", "/", attacker, "", ""); r.StatusCode != 200 {
		t.Fatalf("still blocked: %d", r.StatusCode)
	}
	if l := decode[dashboard.BlockList](t, expect(t, h, "GET", "/blocks", nil, 200, "BlockList")); len(l.Items) != 0 {
		t.Fatalf("still listed: %+v", l)
	}
}

// A gateway in the test profile blocks nobody, by hand neither (D89).
func TestBlockByHandObserves(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe"})
	h.Login()
	p := decode[dashboard.Problem](t, expect(t, h, "POST", "/blocks", map[string]any{"address": "203.0.113.50", "duration_s": 3600, "reason": "x"}, 409, "Problem"))
	if p.Code != "test_profile" {
		t.Fatalf("%+v", p)
	}
}
