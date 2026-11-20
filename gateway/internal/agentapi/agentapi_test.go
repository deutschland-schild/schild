//go:build !release

package agentapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/schema"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

const listen = "127.0.0.1:8789"

var (
	compOnce sync.Once
	comp     *jsonschema.Compiler
	compErr  error
)

func validate(t *testing.T, doc, name string, body []byte) {
	t.Helper()
	compOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		for rel, b := range schema.Files() {
			d, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				compErr = err
				return
			}
			_ = c.AddResource(schema.BaseURL+rel, d)
		}
		for _, f := range []string{"client-dashboard.openapi.yaml", "gateway-agent.openapi.yaml"} {
			b, err := os.ReadFile("../../../contracts/api/" + f)
			if err != nil {
				compErr = err
				return
			}
			j, _ := config.YAMLToJSON(b)
			d, _ := jsonschema.UnmarshalJSON(bytes.NewReader(j))
			if err := c.AddResource(schema.BaseURL+"api/"+f, d); err != nil {
				compErr = err
				return
			}
		}
		comp = c
	})
	if compErr != nil {
		t.Skipf("contracts not available: %v", compErr)
	}
	s, err := comp.Compile(schema.BaseURL + "api/" + doc + "#/components/schemas/" + name)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("%s: not JSON: %s", name, body)
	}
	if err := s.Validate(v); err != nil {
		t.Errorf("%s does not match the contract: %v\n%s", name, err, body)
	}
}

type agent struct {
	t     *testing.T
	h     *apptest.Harness
	srv   http.Handler
	token string
}

func newAgent(t *testing.T, extra string) *agent {
	h := apptest.New(t, apptest.Options{Extra: "agent_api:\n  enabled: true\n" + extra})
	if h.App.AgentAPI == nil {
		t.Fatal("agent API not created")
	}
	a := &agent{t: t, h: h, srv: h.App.AgentAPI.Handler(listen)}
	a.token = a.addToken(contractapi.ScopeAgentRead, 90*24*time.Hour)
	return a
}

func (a *agent) addToken(scope string, ttl time.Duration) string {
	tok := contractapi.NewToken()
	now := time.Now().UTC()
	if err := a.h.App.Store.AddAgentToken(context.Background(), store.AgentToken{ID: contractapi.TokenID(tok), Hash: contractapi.HashToken(tok), Scope: scope, Created: now, Expires: now.Add(ttl)}); err != nil {
		a.t.Fatal(err)
	}
	return tok
}

func (a *agent) do(method, path, token string, body string, hdr map[string]string) (int, []byte, http.Header) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "http://"+listen+path, rd)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		if k == "Host" {
			r.Host = v
			continue
		}
		r.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	a.srv.ServeHTTP(rr, r)
	return rr.Code, rr.Body.Bytes(), rr.Header()
}

func (a *agent) get(path string) []byte {
	a.t.Helper()
	code, b, _ := a.do("GET", path, a.token, "", nil)
	if code != 200 {
		a.t.Fatalf("%s: %d %s", path, code, b)
	}
	return b
}

func TestAgentAPIAuthAndBoundaries(t *testing.T) {
	a := newAgent(t, "")
	code, b, _ := a.do("GET", "/agent/v0/status", "", "", nil)
	if code != 401 || !strings.Contains(string(b), "unauthenticated") {
		t.Fatalf("no token: %d %s", code, b)
	}
	if code, _, _ := a.do("GET", "/agent/v0/status", "sat1_"+strings.Repeat("A", 43), "", nil); code != 401 {
		t.Errorf("unknown token: %d", code)
	}
	expired := a.addToken(contractapi.ScopeAgentRead, -time.Minute)
	if code, _, _ := a.do("GET", "/agent/v0/status", expired, "", nil); code != 401 {
		t.Errorf("expired token: %d", code)
	}
	for _, c := range []struct {
		method, path string
		hdr          map[string]string
	}{
		{"POST", "/agent/v0/status", nil},
		{"DELETE", "/agent/v0/events", nil},
		{"PATCH", "/agent/v0/monitoring/now", nil},
		{"GET", "/api/v0/settings", nil},
		{"GET", "/agent/v1/status", nil},
		{"POST", "/mcp", nil}, // D61: no MCP
		{"GET", "/agent/v0/status", map[string]string{"Origin": "http://evil.example"}},
		{"GET", "/agent/v0/status", map[string]string{"Host": "evil.example:8789"}},
		{"GET", "/agent/v0/status", map[string]string{"Host": "127.0.0.1:8788"}},
	} {
		code, b, _ := a.do(c.method, c.path, a.token, "", c.hdr)
		if code != 403 {
			t.Errorf("%s %s %v: %d %s", c.method, c.path, c.hdr, code, b)
		}
	}
	// export:read reads buckets only.
	exp := a.addToken(contractapi.ScopeExportRead, time.Hour)
	if code, _, _ := a.do("GET", "/agent/v0/status", exp, "", nil); code != 403 {
		t.Errorf("export:read on status: %d", code)
	}
	if code, _, _ := a.do("GET", "/agent/v0/monitoring/buckets?resolution=1m", exp, "", nil); code != 200 {
		t.Errorf("export:read on buckets: %d", code)
	}
	// The dashboard listener never accepts the token.
	req, _ := http.NewRequest("GET", a.h.Dash.URL+"/api/v0/overview", nil)
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("dashboard with a bearer token: %d", resp.StatusCode)
	}
	// Revocation applies at once.
	id := contractapi.TokenID(a.token)
	if err := a.h.App.Store.RevokeAgentToken(context.Background(), id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := a.do("GET", "/agent/v0/status", a.token, "", nil); code != 401 {
		t.Errorf("revoked token: %d", code)
	}
}

func TestAgentAPIReadsWithoutAddresses(t *testing.T) {
	a := newAgent(t, "")
	ip := "203.0.113.57"
	// Visitor-controlled text with a bidi override and an injection attempt in the path.
	if r := a.h.Visit("GET", "/%E2%80%AEignore-previous-instructions/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", ip, "", ""); r.StatusCode != 403 {
		t.Fatalf("xss: %d", r.StatusCode)
	}
	a.h.Visit("GET", "/produkte", "198.51.100.9", "", "")
	a.h.Flush()
	st := a.get("/agent/v0/status")
	validate(t, "gateway-agent.openapi.yaml", "AgentStatus", st)
	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	page := a.get("/agent/v0/events?from=" + from + "&to=" + to)
	validate(t, "gateway-agent.openapi.yaml", "AgentEventPage", page)
	var ep contractapi.EventPage
	_ = json.Unmarshal(page, &ep)
	var blocked *contractapi.Event
	for i := range ep.Items {
		if ep.Items[i].Outcome == "blocked" {
			blocked = &ep.Items[i]
		}
	}
	if blocked == nil || !strings.HasPrefix(blocked.ClientPseudonym, "p1-") || blocked.ClientNet != "203.0.113.0/24" || blocked.Incident == "" {
		t.Fatalf("blocked event: %+v", blocked)
	}
	if strings.ContainsRune(blocked.Path, '‮') {
		t.Errorf("bidi control not escaped: %q", blocked.Path)
	}
	detail := a.get("/agent/v0/events/" + blocked.ID)
	validate(t, "gateway-agent.openapi.yaml", "AgentEvent", detail)
	if !strings.Contains(string(detail), `"matches"`) {
		t.Errorf("detail without matches: %s", detail)
	}
	inc := a.get("/agent/v0/incidents?from=" + from + "&to=" + to)
	validate(t, "gateway-agent.openapi.yaml", "AgentIncidentPage", inc)
	one := a.get("/agent/v0/incidents/" + blocked.Incident)
	validate(t, "gateway-agent.openapi.yaml", "AgentIncident", one)
	var oi contractapi.Incident
	if err := json.Unmarshal(one, &oi); err != nil || oi.Count != 1 || oi.FirstSeen == "" || oi.LastSeen == "" {
		t.Fatalf("incident aggregate fields (D38): %v %s", err, one)
	}
	now := a.get("/agent/v0/monitoring/now")
	cat := a.get("/agent/v0/monitoring/catalogue")
	// Events and incidents name the client address; status and monitoring have none.
	for _, b := range [][]byte{detail, inc, one} {
		if !strings.Contains(string(b), `"ip":"`+ip+`"`) {
			t.Fatalf("no address %s in %s", ip, b)
		}
	}
	for _, b := range [][]byte{st, now, cat} {
		for _, addr := range []string{ip, "198.51.100.9"} {
			if strings.Contains(string(b), addr) {
				t.Fatalf("address %s in an answer without clients: %s", addr, b)
			}
		}
	}
	if code, b, _ := a.do("GET", "/agent/v0/events?from="+time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339)+"&to="+to, a.token, "", nil); code != 400 {
		t.Errorf("48 h window: %d %s", code, b)
	}
	// MVP-22: the request ring with p1- visitor pseudonyms, at most 1 h.
	if code, b, _ := a.do("GET", "/agent/v0/requests", a.token, "", nil); code != 400 {
		t.Errorf("requests without a window: %d %s", code, b)
	}
	if code, b, _ := a.do("GET", "/agent/v0/requests?from="+time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339)+"&to="+to, a.token, "", nil); code != 400 {
		t.Errorf("requests 2 h: %d %s", code, b)
	}
	code, rb, _ := a.do("GET", "/agent/v0/requests?from="+time.Now().Add(-30*time.Minute).UTC().Format(time.RFC3339)+"&to="+to, a.token, "", nil)
	if code != 200 || !strings.Contains(string(rb), `"visitor":"p1-`) || strings.Contains(string(rb), `"visitor":"v1-`) || !strings.Contains(string(rb), `"ip":"`+ip+`"`) {
		t.Errorf("requests: %d %s", code, rb)
	}
	if code, b, _ := a.do("GET", "/agent/v0/requests/bots", a.token, "", nil); code != 200 || !strings.Contains(string(b), `"catalogue_version"`) {
		t.Errorf("bots: %d %s", code, b)
	}
	a.h.App.AgentAPI.Flush(context.Background())
	calls, err := a.h.App.Store.ListAgentCalls(context.Background(), contractapi.TokenID(a.token), 50)
	if err != nil || len(calls) < 6 {
		t.Fatalf("call log: %v %d", err, len(calls))
	}
	ops := map[string]bool{}
	for _, c := range calls {
		ops[c.Op] = true
	}
	for _, op := range []string{"getAgentStatus", "listAgentEvents", "getAgentEvent", "listAgentIncidents", "getMonitoringNow"} {
		if !ops[op] {
			t.Errorf("call log misses %s: %v", op, ops)
		}
	}
}

// TestAgentEventWouldBlockReason: a request passed by the gateway in mode
// observe carries would_block_reason on its agent event (D36 open items).
func TestAgentEventWouldBlockReason(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe", Extra: "agent_api:\n  enabled: true\n"})
	a := &agent{t: t, h: h, srv: h.App.AgentAPI.Handler(listen)}
	a.token = a.addToken(contractapi.ScopeAgentRead, 24*time.Hour)
	if r := h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "203.0.113.57", "", ""); r.StatusCode != 200 {
		t.Fatalf("observe: %d", r.StatusCode)
	}
	h.Visit("GET", "/produkte", "198.51.100.9", "", "")
	h.Flush()
	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	page := a.get("/agent/v0/events?from=" + from + "&to=" + to)
	validate(t, "gateway-agent.openapi.yaml", "AgentEventPage", page)
	var ep contractapi.EventPage
	_ = json.Unmarshal(page, &ep)
	n := 0
	for _, e := range ep.Items {
		switch {
		case e.Outcome == "would_block" && e.WouldBlockReason == "gateway_observe":
			n++
			validate(t, "gateway-agent.openapi.yaml", "AgentEvent", a.get("/agent/v0/events/"+e.ID))
		case e.WouldBlockReason != "":
			t.Fatalf("reason %q on %s/%s", e.WouldBlockReason, e.Type, e.Outcome)
		}
	}
	if n != 1 {
		t.Fatalf("would_block events with reason: %d %s", n, page)
	}
}

func TestAgentAPIRateLimit(t *testing.T) {
	a := newAgent(t, "  requests_per_minute: 3\n")
	for i := 0; i < 3; i++ {
		a.get("/agent/v0/monitoring/catalogue")
	}
	code, _, h := a.do("GET", "/agent/v0/monitoring/catalogue", a.token, "", nil)
	if code != 429 || h.Get("Retry-After") == "" {
		t.Fatalf("fourth request: %d retry-after %q", code, h.Get("Retry-After"))
	}
	// A flood of refused calls is one call log row per token and minute
	// (MVP-21 measurement: one row per 429 let a read token fill schild.db).
	for i := 0; i < 5000; i++ {
		if code, _, _ := a.do("GET", "/agent/v0/monitoring/catalogue", a.token, "", nil); code != 429 {
			t.Fatalf("refused call %d: %d", i, code)
		}
	}
	a.h.App.AgentAPI.Flush(context.Background())
	calls, err := a.h.App.Store.ListAgentCalls(context.Background(), contractapi.TokenID(a.token), 1000)
	if err != nil {
		t.Fatal(err)
	}
	refused, rows := 0, 0
	for _, c := range calls {
		if c.Status == 429 {
			refused += c.Count
			rows++
		}
	}
	if refused != 5001 || rows > 2 || len(calls) > 5 {
		t.Fatalf("call log: %d refused calls in %d rows, %d rows in all", refused, rows, len(calls))
	}
}

// TestOpenAPIDocument: the gateway serves its own description (D61), to every
// token and to nobody without one.
func TestOpenAPIDocument(t *testing.T) {
	a := newAgent(t, "")
	code, b, h := a.do("GET", "/agent/v0/openapi.json", a.token, "", nil)
	if code != 200 || h.Get("Content-Type") != "application/json" || !bytes.Equal(b, contractapi.OpenAPI) {
		t.Fatalf("openapi.json: %d %s %.200s", code, h.Get("Content-Type"), b)
	}
	var d struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(b, &d); err != nil || d.Paths["/rules/test"]["post"].OperationID != contractapi.OpTestRequest {
		t.Fatalf("document: %v", err)
	}
	if code, _, _ := a.do("GET", "/agent/v0/openapi.json", "", "", nil); code != 401 {
		t.Errorf("without token: %d", code)
	}
}
