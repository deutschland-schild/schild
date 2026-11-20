//go:build !release

package agentapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

const (
	blocksPath = "/agent/v0/blocks"
	attacker   = "203.0.113.57" // hosting in the geo fixture
)

func blockAgent(t *testing.T, mode, extra string) *apptestAgent {
	t.Helper()
	h := apptest.New(t, apptest.Options{Mode: mode, Extra: "agent_api:\n  enabled: true\n  requests_per_minute: 600\n" + extra})
	return &apptestAgent{h: h, srv: h.App.AgentAPI.Handler(listen), t: t}
}

// incidentOf has the client send a request the WAF stops and returns its
// incident number.
func incidentOf(t *testing.T, a *apptestAgent, ip string) (incident, eventID string) {
	t.Helper()
	a.h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", ip, "", "")
	a.h.Flush()
	rows, _, err := a.h.App.Store.ListEvents(t.Context(), store.EventFilter{IP: ip}, 0, 10)
	if err != nil || len(rows) == 0 {
		t.Fatalf("no event of %s: %v", ip, err)
	}
	return rows[0].Incident, rows[0].ID
}

func blockBody(field, value string, seconds int) string {
	return fmt.Sprintf(`{"target":{"%s":"%s"},"duration_s":%d,"reason":"scanner, checked by hand"}`, field, value, seconds)
}

func decodeResult(t *testing.T, b []byte) contractapi.BlockResult {
	t.Helper()
	var r contractapi.BlockResult
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return r
}

// In autoblock the block is in force before the answer returns: the very next
// request meets it. No address in the answer.
func TestAgentBlockActsAtOnce(t *testing.T) {
	a := blockAgent(t, "autoblock", "")
	_, ev := incidentOf(t, a, attacker)
	tok := a.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	w := a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev, 3600))
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), attacker) {
		t.Fatalf("address in the answer: %s", w.Body)
	}
	validate(t, "gateway-agent.openapi.yaml", "AgentBlockResult", w.Body.Bytes())
	res := decodeResult(t, w.Body.Bytes())
	if res.Effect != "block" || !res.Changed || res.Incident == "" || res.Until == nil || res.ClientPseudonym == "" {
		t.Fatalf("result %+v", res)
	}
	if r := a.h.Visit("GET", "/produkte", attacker, "", ""); r.StatusCode != 403 {
		t.Fatalf("next request: %d", r.StatusCode)
	}
	// A running block stands: its end does not move, the budget stays.
	w = a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev, 7200))
	again := decodeResult(t, w.Body.Bytes())
	if w.Code != 200 || again.Changed || *again.Until != *res.Until || again.Incident != res.Incident {
		t.Fatalf("second call: %d %s", w.Code, w.Body)
	}
	// The block event and the mark for the dashboard.
	a.h.Flush()
	inc, err := a.h.App.Store.GetIncident(t.Context(), res.Incident)
	if err != nil || len(inc.Sources) != 1 || inc.Sources[0] != "agent:"+contractapi.TokenID(tok) {
		t.Fatalf("incident %+v %v", inc, err)
	}
	b := a.do("GET", "/agent/v0/incidents/"+res.Incident, tok, "", "")
	var got contractapi.Incident
	if err := json.Unmarshal(b.Body.Bytes(), &got); err != nil || got.Block == nil || got.Block.SetBy == nil || got.Block.SetBy.TokenLabel != "Wachdienst" || got.Block.AgentReason == "" {
		t.Fatalf("incident view: %v %s", err, b.Body)
	}
}

// In observe nothing is blocked, the call is recorded and counts.
func TestAgentBlockObserveRecordsWouldBlock(t *testing.T) {
	a := blockAgent(t, "observe", "")
	_, ev := incidentOf(t, a, attacker)
	tok := a.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	w := a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev, 3600))
	res := decodeResult(t, w.Body.Bytes())
	if w.Code != 200 || res.Effect != "would_block" || res.Changed || res.LimitedBy != "gateway_observe" || res.Until != nil || res.Incident != "" || res.EventID == "" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if r := a.h.Visit("GET", "/produkte", attacker, "", ""); r.StatusCode == 403 {
		t.Fatal("observe blocked somebody")
	}
	a.h.Flush()
	if _, err := a.h.App.Store.GetEvent(t.Context(), res.EventID); err != nil {
		t.Fatalf("no record: %v", err)
	}
	if a.h.App.Behaviour.AgentBlocks() != 0 {
		t.Fatal("a block runs in observe")
	}
}

func TestAgentBlockRefusals(t *testing.T) {
	a := blockAgent(t, "autoblock", "")
	_, ev := incidentOf(t, a, attacker)
	inc2, _ := incidentOf(t, a, "198.51.100.9") // no hosting class: cap 24 h
	tok := a.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	read := a.token(contractapi.ScopeAgentRead, "")
	hubTok := a.token(contractapi.ScopeRulesWrite, "Hub")
	for _, c := range []struct {
		name, tok, body string
		status          int
		code            string
	}{
		{"read token", read, blockBody("event_id", ev, 3600), 403, contractapi.CodeScopeRequired},
		{"hub token", hubTok, blockBody("event_id", ev, 3600), 403, contractapi.CodeScopeRequired},
		{"no reason", tok, fmt.Sprintf(`{"target":{"event_id":"%s"},"duration_s":3600,"reason":" "}`, ev), 400, "invalid"},
		{"short", tok, blockBody("event_id", ev, 59), 400, "invalid"},
		{"two targets", tok, fmt.Sprintf(`{"target":{"event_id":"%s","incident":"%s"},"duration_s":3600,"reason":"x"}`, ev, inc2), 400, "invalid"},
		{"an address", tok, `{"target":{"ip":"203.0.113.9"},"duration_s":3600,"reason":"x"}`, 400, "invalid"},
		{"unknown event", tok, blockBody("event_id", "00000000-0000-4000-8000-000000000000", 3600), 404, "not_found"},
		{"unknown pseudonym", tok, blockBody("client_pseudonym", "p1-0000000000000000", 3600), 404, "not_found"},
		{"over the cap", tok, blockBody("incident", inc2, 90000), 400, contractapi.CodeDurationOver},
		{"over the hosting cap", tok, blockBody("event_id", ev, 700000), 400, contractapi.CodeDurationOver},
	} {
		w := a.do("POST", blocksPath, c.tok, "application/json", c.body)
		var p struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &p)
		if w.Code != c.status || p.Code != c.code {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body)
		}
	}
	if w := a.do("POST", blocksPath, tok, "text/plain", blockBody("event_id", ev, 3600)); w.Code != 400 {
		t.Errorf("content type: %d", w.Code)
	}
	// Every call is in the log, refused ones too.
	a.srv = a.h.App.AgentAPI.Handler(listen)
	calls := a.calls(read)
	if len(calls) == 0 || calls[len(calls)-1].Status != 403 {
		t.Fatalf("call log: %+v", calls)
	}
}

func TestAgentBlockOwnAndReleased(t *testing.T) {
	a := blockAgent(t, "autoblock", "")
	tok := a.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	_, ev := incidentOf(t, a, attacker)
	a.h.App.Gate.Exceptions.Add(mustAddr(attacker), []string{"behaviour"}, time.Now().Add(time.Hour))
	w := a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev, 3600))
	if w.Code != 409 || !strings.Contains(w.Body.String(), contractapi.CodeReleased) {
		t.Fatalf("released: %d %s", w.Code, w.Body)
	}
	for ip, code := range map[string]string{"100.64.0.5": contractapi.CodePrivateAddress, "10.0.0.5": contractapi.CodePrivateAddress} {
		_, e := incidentOf(t, a, ip)
		if w := a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", e, 3600)); w.Code != 409 || !strings.Contains(w.Body.String(), code) {
			t.Fatalf("%s: %d %s", ip, w.Code, w.Body)
		}
	}
	a.h.Login()
	_, ev2 := incidentOf(t, a, "198.51.100.9")
	if code, b := a.h.API("POST", "/allowlist", map[string]any{"ip": "198.51.100.9", "label": "Büro", "level": "no_block", "ttl": "30d"}); code != 201 {
		t.Fatalf("allowlist: %d %s", code, b)
	}
	w = a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev2, 3600))
	if w.Code != 409 || !strings.Contains(w.Body.String(), contractapi.CodeOwnAddress) {
		t.Fatalf("own: %d %s", w.Code, w.Body)
	}
}

func TestAgentBlockBudgetAndCap(t *testing.T) {
	a := blockAgent(t, "autoblock", "  block_writes_per_hour: 2\n")
	tok := a.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	for i := 1; i <= 2; i++ {
		_, ev := incidentOf(t, a, fmt.Sprintf("198.51.100.%d", i))
		if w := a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev, 3600)); w.Code != 200 {
			t.Fatalf("write %d: %d %s", i, w.Code, w.Body)
		}
	}
	_, ev := incidentOf(t, a, "198.51.100.3")
	w := a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev, 3600))
	if w.Code != 429 || !strings.Contains(w.Body.String(), contractapi.CodeBlockBudget) || w.Header().Get("Retry-After") == "" {
		t.Fatalf("budget: %d %s", w.Code, w.Body)
	}
	// The budget is per token.
	other := a.token(contractapi.ScopeBlocksWrite, "Zweiter")
	if w := a.do("POST", blocksPath, other, "application/json", blockBody("event_id", ev, 3600)); w.Code != 200 {
		t.Fatalf("second token: %d %s", w.Code, w.Body)
	}

	b := blockAgent(t, "autoblock", "  max_agent_blocks: 1\n")
	btok := b.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	_, e1 := incidentOf(t, b, "198.51.100.1")
	_, e2 := incidentOf(t, b, "198.51.100.2")
	if w := b.do("POST", blocksPath, btok, "application/json", blockBody("event_id", e1, 3600)); w.Code != 200 {
		t.Fatalf("first: %d", w.Code)
	}
	if w := b.do("POST", blocksPath, btok, "application/json", blockBody("event_id", e2, 3600)); w.Code != 429 || !strings.Contains(w.Body.String(), contractapi.CodeBlockCap) {
		t.Fatalf("cap: %d %s", w.Code, w.Body)
	}
}

// A pseudonym names the address it stands for, through the events.
func TestAgentBlockByPseudonym(t *testing.T) {
	a := blockAgent(t, "autoblock", "")
	inc, _ := incidentOf(t, a, attacker)
	tok := a.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	var view contractapi.Incident
	if err := json.Unmarshal(a.do("GET", "/agent/v0/incidents/"+inc, tok, "", "").Body.Bytes(), &view); err != nil || view.ClientPseudonym == "" {
		t.Fatalf("view: %v", err)
	}
	w := a.do("POST", blocksPath, tok, "application/json", blockBody("client_pseudonym", view.ClientPseudonym, 3600))
	if w.Code != 200 || decodeResult(t, w.Body.Bytes()).ClientPseudonym != view.ClientPseudonym {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// Lift ends the block and nothing else: the client stays under every rule, and
// the counters a release would reset stay.
func TestAgentLift(t *testing.T) {
	a := blockAgent(t, "autoblock", "")
	_, ev := incidentOf(t, a, attacker)
	tok := a.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	res := decodeResult(t, a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev, 3600)).Body.Bytes())
	path := "/agent/v0/incidents/" + res.Incident + "/lift"
	if w := a.do("POST", path, a.token(contractapi.ScopeAgentRead, ""), "application/json", `{"reason":"x"}`); w.Code != 403 {
		t.Fatalf("read token: %d", w.Code)
	}
	w := a.do("POST", path, tok, "application/json", `{"reason":"false alarm"}`)
	if w.Code != 200 {
		t.Fatalf("lift: %d %s", w.Code, w.Body)
	}
	var in contractapi.Incident
	if err := json.Unmarshal(w.Body.Bytes(), &in); err != nil || in.Status != "unblocked" {
		t.Fatalf("%v %s", err, w.Body)
	}
	if r := a.h.Visit("GET", "/produkte", attacker, "", ""); r.StatusCode == 403 {
		t.Fatal("still blocked after the lift")
	}
	// It is no exception: the WAF judges the client as before.
	if r := a.h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", attacker, "", ""); r.StatusCode != 403 {
		t.Fatalf("WAF after the lift: %d", r.StatusCode)
	}
	if a.h.App.Gate.Exceptions.Running(mustAddr(attacker), time.Now()) || a.h.App.Behaviour.ReleasedSince(mustAddr(attacker), time.Now().Add(-time.Hour)) {
		t.Fatal("the lift left an exception or a release")
	}
	a.h.Flush()
	// Already unblocked: 200, nothing changes.
	if w := a.do("POST", path, tok, "application/json", `{"reason":"again"}`); w.Code != 200 {
		t.Fatalf("second lift: %d %s", w.Code, w.Body)
	}
	// A single WAF refusal has nothing to lift.
	inc, _ := incidentOf(t, a, "198.51.100.77")
	if w := a.do("POST", "/agent/v0/incidents/"+inc+"/lift", tok, "application/json", `{"reason":"x"}`); w.Code != 409 || !strings.Contains(w.Body.String(), contractapi.CodeNoRunningBlock) {
		t.Fatalf("WAF incident: %d %s", w.Code, w.Body)
	}
	if w := a.do("POST", "/agent/v0/incidents/AAAA-AAAA/lift", tok, "application/json", `{"reason":"x"}`); w.Code != 404 {
		t.Fatalf("unknown: %d", w.Code)
	}
}

// A real agent may lift in the same second it set the block: the block runs in
// memory, its row is only queued. The lift must not answer 404, and the row must
// not come in late and stay blocked for good. The incident writer is held here,
// which is what a busy store does.
func TestAgentLiftRightAfterSet(t *testing.T) {
	a := blockAgent(t, "autoblock", "")
	_, ev := incidentOf(t, a, attacker)
	tok := a.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	var queued []*store.Incident
	a.h.App.AgentAPI.Blocks.Incident = func(in *store.Incident) { queued = append(queued, in) }
	release := func(context.Context) {
		for _, in := range queued {
			if err := a.h.App.Store.InsertIncident(t.Context(), in); err != nil {
				t.Error(err)
			}
		}
		queued = nil
	}
	a.h.App.AgentAPI.Blocks.FlushIncidents = release
	res := decodeResult(t, a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev, 3600)).Body.Bytes())
	w := a.do("POST", "/agent/v0/incidents/"+res.Incident+"/lift", tok, "application/json", `{"reason":"false alarm"}`)
	if w.Code != 200 {
		t.Fatalf("lift: %d %s", w.Code, w.Body)
	}
	if r := a.h.Visit("GET", "/produkte", attacker, "", ""); r.StatusCode == 403 {
		t.Fatal("still blocked after the lift")
	}
	a.h.App.FlushBlocks()
	in, err := a.h.App.Store.GetIncident(t.Context(), res.Incident)
	if err != nil || in.Status != "unblocked" {
		t.Fatalf("row after the lift: %v %+v", err, in)
	}
}

// Without its row, a full queue, the block can still be lifted.
func TestAgentLiftWithoutRow(t *testing.T) {
	a := blockAgent(t, "autoblock", "")
	_, ev := incidentOf(t, a, attacker)
	tok := a.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	a.h.App.AgentAPI.Blocks.Incident = func(*store.Incident) {}
	res := decodeResult(t, a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev, 3600)).Body.Bytes())
	w := a.do("POST", "/agent/v0/incidents/"+res.Incident+"/lift", tok, "application/json", `{"reason":"false alarm"}`)
	if w.Code != 200 {
		t.Fatalf("lift: %d %s", w.Code, w.Body)
	}
	if r := a.h.Visit("GET", "/produkte", attacker, "", ""); r.StatusCode == 403 {
		t.Fatal("still blocked after the lift")
	}
}

// Verified bots are not exempt, and a block over 24 h survives a restart.
func TestAgentBlockKept(t *testing.T) {
	a := blockAgent(t, "autoblock", "")
	_, ev := incidentOf(t, a, attacker)
	tok := a.token(contractapi.ScopeBlocksWrite, "Wachdienst")
	res := decodeResult(t, a.do("POST", blocksPath, tok, "application/json", blockBody("event_id", ev, 200000)).Body.Bytes())
	if !res.Persisted || res.NetClass != "hosting" {
		t.Fatalf("%+v", res)
	}
	a.h.App.FlushBlocks()
	rows, err := a.h.App.Store.ListBlocks(t.Context())
	if err != nil || len(rows) != 1 || rows[0].Source != "agent:"+contractapi.TokenID(tok) || rows[0].DurationS != 200000 {
		t.Fatalf("%v %+v", err, rows)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
