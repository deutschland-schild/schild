//go:build !release

package agentapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

func hubAgent(t *testing.T) *apptestAgent {
	t.Helper()
	h := apptest.New(t, apptest.Options{Extra: "agent_api:\n  enabled: true\n  requests_per_minute: 600\n"})
	return &apptestAgent{h: h, srv: h.App.AgentAPI.Handler(listen), t: t}
}

type apptestAgent struct {
	t   *testing.T
	h   *apptest.Harness
	srv http.Handler
}

// token makes a token with a label directly in the store (as `schild token add`).
func (a *apptestAgent) token(scope, label string) string {
	a.t.Helper()
	tok := contractapi.NewToken()
	now := time.Now().UTC()
	if err := a.h.App.Store.AddAgentToken(context.Background(), store.AgentToken{ID: contractapi.TokenID(tok), Hash: contractapi.HashToken(tok), Scope: scope, Label: label,
		Created: now, Expires: now.Add(time.Hour)}); err != nil {
		a.t.Fatal(err)
	}
	return tok
}

func (a *apptestAgent) do(method, path, tok, ctype, body string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = listen
	r.Header.Set("Authorization", "Bearer "+tok)
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	a.srv.ServeHTTP(w, r)
	return w
}

func (a *apptestAgent) calls(tok string) []store.AgentCall {
	a.t.Helper()
	a.h.App.AgentAPI.Flush(context.Background())
	c, err := a.h.App.Store.ListAgentCalls(context.Background(), contractapi.TokenID(tok), 50)
	if err != nil {
		a.t.Fatal(err)
	}
	return c
}

func TestAgentRepositoriesRead(t *testing.T) {
	a := hubAgent(t)
	tok := a.token(contractapi.ScopeAgentRead, "")
	for path, schema := range map[string]string{
		"/agent/v0/rule-repositories":                   "RuleRepositoryList",
		"/agent/v0/rule-repositories/crowdsec":          "RuleRepository",
		"/agent/v0/rule-repositories/crs":               "RuleRepository",
		"/agent/v0/rule-repositories/local":             "RuleRepository",
		"/agent/v0/rules?repository=crs&limit=5":        "RulePage",
		"/agent/v0/rules?repository=crowdsec&limit=200": "RulePage",
		"/agent/v0/rules/crs/942100":                    "RuleDetail",
	} {
		w := a.do("GET", path, tok, "", "")
		if w.Code != 200 {
			t.Fatalf("%s: %d: %s", path, w.Code, w.Body)
		}
		validate(t, "client-dashboard.openapi.yaml", schema, w.Body.Bytes())
	}
	var page ruleset.RulePage
	_ = json.Unmarshal(a.do("GET", "/agent/v0/rules?repository=crowdsec&limit=1", tok, "", "").Body.Bytes(), &page)
	if len(page.Items) != 1 || page.NextCursor == nil || page.Items[0].Crowdsec == nil || page.Items[0].Origin != rules.OriginRelease ||
		page.Items[0].Effect != rules.EffectDetect || page.Items[0].LimitedBy != rules.LimitRepositoryDetect {
		t.Fatalf("%+v", page)
	}
	for path, code := range map[string]int{"/agent/v0/rule-repositories/network": 400, "/agent/v0/rules/crs/1": 404, "/agent/v0/rules?status=suspended": 400,
		"/agent/v0/rules?cursor=x": 400} {
		if w := a.do("GET", path, tok, "", ""); w.Code != code && !(code == 400 && w.Code == 404) {
			t.Errorf("%s: %d, want %d", path, w.Code, code)
		}
	}
}

// Every rule write checks its scope, and every refusal is in the call log.
func TestAgentRuleWritesNeedTheirScope(t *testing.T) {
	a := hubAgent(t)
	writes := []struct{ method, path, body, op string }{
		{"PATCH", "/agent/v0/rule-repositories/crowdsec", `{"state":"off"}`, contractapi.OpUpdateRuleRepository},
		{"POST", "/agent/v0/rule-repositories/local/sync", ``, contractapi.OpSyncRuleRepository},
		{"POST", "/agent/v0/rule-repositories/crowdsec/reset", ``, contractapi.OpResetRuleRepository},
		{"PATCH", "/agent/v0/rules/crs/942100", `{"disabled":true}`, contractapi.OpUpdateRule},
	}
	for _, scope := range []string{contractapi.ScopeAgentRead, contractapi.ScopeExportRead, contractapi.ScopeRulesWrite,
		contractapi.ScopeExceptionsWrite} {
		tok := a.token(scope, "x")
		n := 0
		for _, wr := range writes {
			if contractapi.AllowsWrite(scope, wr.op) {
				continue
			}
			n++
			w := a.do(wr.method, wr.path, tok, "application/json", wr.body)
			if w.Code != 403 || !strings.Contains(w.Body.String(), contractapi.CodeScopeRequired) {
				t.Fatalf("%s %s %s: %d: %s", scope, wr.method, wr.path, w.Code, w.Body)
			}
		}
		if c := a.calls(tok); len(c) != n || n > 0 && c[0].Status != 403 {
			t.Fatalf("%s: call log %+v", scope, c)
		}
	}
	if st := a.h.App.Config().Rules.Crowdsec.State; st != rules.StateDetect {
		t.Fatalf("changed by a token without the scope: %s", st)
	}
	if d, _ := a.h.App.Repos.Rule("crs", "942100"); d.Status != rules.StatusActive {
		t.Fatalf("disabled by a token without the scope: %+v", d)
	}
}

func TestAgentRepositoryWrite(t *testing.T) {
	a := hubAgent(t)
	tok := a.token(contractapi.ScopeRulesWrite, "Local agent")
	id := contractapi.TokenID(tok)
	w := a.do("PATCH", "/agent/v0/rule-repositories/crowdsec", tok, "application/json", `{"state":"block"}`)
	if w.Code != 200 {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	validate(t, "client-dashboard.openapi.yaml", "RuleRepository", w.Body.Bytes())
	var v ruleset.RepositoryView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if v.State != rules.StateBlock || v.StateSource != rules.ByAgent || v.StateSetBy == nil || v.StateSetBy.TokenID != id ||
		v.StateSetBy.Label != "Local agent" || v.StateSetAt == nil || !v.Differs || v.Effect != rules.EffectBlock {
		t.Fatalf("%+v", v)
	}
	a.h.Flush()
	rows, _, err := a.h.App.Store.ListEvents(context.Background(), store.EventFilter{Type: events.RuleRepositorySwitched}, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%v %d", err, len(rows))
	}
	var body struct {
		Data events.RepositorySwitched `json:"data"`
	}
	_ = json.Unmarshal(rows[0].Body, &body)
	if d := body.Data; d.Repository != "crowdsec" || d.Actor != "agent" || d.TokenID != id || d.TokenLabel != "Local agent" || d.From != "detect" || d.To != "block" {
		t.Fatalf("%+v", d)
	}
	// The same value again: no history, but the call is logged.
	if w := a.do("PATCH", "/agent/v0/rule-repositories/crowdsec", tok, "application/json", `{"state":"block"}`); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	a.h.Flush()
	if rows, _, _ := a.h.App.Store.ListEvents(context.Background(), store.EventFilter{Type: events.RuleRepositorySwitched}, 0, 10); len(rows) != 1 {
		t.Fatalf("%d history rows", len(rows))
	}
	if c := a.calls(tok); len(c) != 2 || c[0].Op != contractapi.OpUpdateRuleRepository {
		t.Fatalf("call log %+v", c)
	}
	// Back to schild.yaml; a token of this scope reads as agent:read does.
	if w := a.do("PATCH", "/agent/v0/rule-repositories/crowdsec", tok, "application/json", `{"reset_state":true}`); !strings.Contains(w.Body.String(), `"state_source":"default"`) {
		t.Fatal(w.Body.String())
	}
	if w := a.do("GET", "/agent/v0/status", tok, "", ""); w.Code != 200 {
		t.Fatalf("read with the write scope: %d", w.Code)
	}
	// The CRS in detect: an attack passes and is logged.
	const xss = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	if r := a.h.Visit("GET", xss, "198.51.100.40", "", ""); r.StatusCode != 403 {
		t.Fatalf("crs block: %d", r.StatusCode)
	}
	if w := a.do("PATCH", "/agent/v0/rule-repositories/crs", tok, "application/json", `{"state":"detect"}`); w.Code != 200 {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	if r := a.h.Visit("GET", xss, "198.51.100.41", "", ""); r.StatusCode != 200 {
		t.Fatalf("crs detect: %d", r.StatusCode)
	}
	// Sync and reset where they mean something, not_supported elsewhere.
	for _, c := range []struct {
		path string
		code int
	}{{"/agent/v0/rule-repositories/local/sync", 200}, {"/agent/v0/rule-repositories/crs/sync", 409}, {"/agent/v0/rule-repositories/local/reset", 409},
		{"/agent/v0/rule-repositories/crowdsec/reset", 200}, {"/agent/v0/rule-repositories/network/sync", 404}} {
		w := a.do("POST", c.path, tok, "", "")
		if w.Code != c.code {
			t.Errorf("%s: %d: %s", c.path, w.Code, w.Body)
		}
		if c.code == 409 && !strings.Contains(w.Body.String(), "not_supported") {
			t.Errorf("%s: %s", c.path, w.Body)
		}
	}
}

// A rule disabled through the agent API leaves the WAF at once; one disabled
// in schild.yaml cannot be enabled here; only updates can be approved.
func TestAgentDisableRule(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: "agent_api:\n  enabled: true\n  requests_per_minute: 600\n",
		Rules: "  crs: {disabled_rules: [\"942100\"]}\n"})
	a := &apptestAgent{h: h, srv: h.App.AgentAPI.Handler(listen), t: t}
	tok := a.token(contractapi.ScopeRulesWrite, "Coding-Agent")
	const xss = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	matches := func(id int) bool {
		t.Helper()
		an, _, err := a.h.App.Engine.Current().Probe(httptest.NewRequest("GET", xss, nil), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range an.Matches {
			if m.ID == id {
				return true
			}
		}
		return false
	}
	if !matches(941100) {
		t.Fatal("941100 does not match the probe")
	}
	w := a.do("PATCH", "/agent/v0/rules/crs/941100", tok, "application/json", `{"disabled":true,"note":"test"}`)
	if w.Code != 200 {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	validate(t, "client-dashboard.openapi.yaml", "RuleDetail", w.Body.Bytes())
	var d ruleset.RuleDetail
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	if d.Status != rules.StatusDisabled || d.DisabledBy != rules.ByAgent || len(d.Decisions) != 1 || d.Decisions[0].Token == nil || d.Decisions[0].Note != "test" {
		t.Fatalf("%+v", d)
	}
	if matches(941100) {
		t.Fatal("the disabled rule still runs")
	}
	a.h.Flush()
	rows, _, _ := a.h.App.Store.ListEvents(context.Background(), store.EventFilter{Type: events.RuleDisabled}, 0, 10)
	if len(rows) != 1 || !strings.Contains(string(rows[0].Body), `"token_label":"Coding-Agent"`) {
		t.Fatalf("%d events", len(rows))
	}
	if w := a.do("PATCH", "/agent/v0/rules/crs/941100", tok, "application/json", `{"disabled":false}`); w.Code != 200 || !matches(941100) {
		t.Fatalf("enable: %d %s", w.Code, w.Body)
	}
	if w := a.do("PATCH", "/agent/v0/rules/crs/942100", tok, "application/json", `{"disabled":false}`); w.Code != 409 || !strings.Contains(w.Body.String(), "config_limit") {
		t.Fatalf("config rule: %d %s", w.Code, w.Body)
	}
	if w := a.do("POST", "/agent/v0/rules/crs/941100/approve", tok, "application/json", `{}`); w.Code != 403 && w.Code != 404 {
		t.Fatalf("D89: approving is gone: %d %s", w.Code, w.Body)
	}
	for body, code := range map[string]int{`{}`: 400, `{"disabled":"yes"}`: 400, `{"disabled":true,"x":1}`: 400} {
		if w := a.do("PATCH", "/agent/v0/rules/crs/941100", tok, "application/json", body); w.Code != code {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
}

// An exception names a repository: crs and crowdsec rules, never local.
func TestAgentExceptionRepositories(t *testing.T) {
	a := hubAgent(t)
	a.h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{"shop.example"}}))
	tok := a.token(contractapi.ScopeExceptionsWrite, "Coding-Agent")
	cs := a.h.App.Repos.Rules(ruleset.Filter{Repository: "crowdsec"})
	if len(cs) == 0 {
		t.Fatal("no crowdsec rules in the image")
	}
	req := func(repo, rule string) string {
		b, _ := json.Marshal(contractapi.ExceptionRequest{Website: "shop.example", Path: "/search", Target: "ARGS:q", Repository: repo, Rules: []string{rule}, Reason: "search"})
		return string(b)
	}
	for _, c := range []struct {
		body string
		code int
		in   string
	}{
		{req("crowdsec", cs[0].ID), 200, `"repository":"crowdsec"`},
		{req("crs", "942100"), 200, `"rules":["942100"]`},
		{req("local", "1000001"), 409, "not_supported"},
		{req("crowdsec", "942100"), 400, "invalid"},
		{req("crowdsec", "60000000"), 400, "unknown_rule"},
		{req("", "942100"), 400, "invalid"},
	} {
		w := a.do("POST", "/agent/v0/exceptions", tok, "application/json", c.body)
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.in) {
			t.Errorf("%s: %d %s", c.body, w.Code, w.Body)
		}
	}
}

func TestAgentRepositoryWriteRefusals(t *testing.T) {
	a := hubAgent(t)
	tok := a.token(contractapi.ScopeRulesWrite, "Local agent")
	const path = "/agent/v0/rule-repositories/crowdsec"
	big := `{"state":"off","x":"` + strings.Repeat("a", 2000) + `"}`
	for _, c := range []struct {
		name, ctype, body string
		code              int
	}{
		{"no content type", "", `{"state":"off"}`, 400},
		{"form", "application/x-www-form-urlencoded", `state=off`, 400},
		{"too large", "application/json", big, 400},
		{"not json", "application/json", `off`, 400},
		{"unknown state", "application/json", `{"state":"sometimes"}`, 400},
		{"both", "application/json", `{"state":"off","reset_state":true}`, 400},
		{"neither", "application/json", `{}`, 400},
		{"false reset", "application/json", `{"reset_state":false}`, 400},
		{"unknown field", "application/json", `{"state":"off","mode":"observe"}`, 400},
		{"password is gone", "application/json", `{"state":"off","confirm":{"password":"x"}}`, 400},
	} {
		if w := a.do("PATCH", path, tok, c.ctype, c.body); w.Code != c.code {
			t.Errorf("%s: %d: %s", c.name, w.Code, w.Body)
		}
	}
	// Browsers and other hosts stay out, also for the write.
	if w := a.do("PATCH", path, tok, "application/json", `{"state":"off"}`, "Origin", "https://evil.example"); w.Code != 403 {
		t.Fatalf("origin: %d", w.Code)
	}
	// Nothing else writes, whatever the token.
	for _, c := range [][2]string{{"PATCH", "/agent/v0/status"}, {"POST", path}, {"DELETE", path}, {"PUT", path}, {"PATCH", "/agent/v0/rules/1"},
		{"PATCH", "/agent/v0/crowdsec-hub"}, {"POST", "/agent/v0/rules/crs/942100/suspend"}} {
		if w := a.do(c[0], c[1], tok, "application/json", `{"state":"off"}`); w.Code != 403 {
			t.Errorf("%s %s: %d", c[0], c[1], w.Code)
		}
	}
	if st := a.h.App.Config().Rules.Crowdsec.State; st != rules.StateDetect {
		t.Fatalf("changed: %s", st)
	}
}

// An agent takes single rules out of an exception (D86): the exception stays
// for the others with its id; naming every rule left removes it.
func TestAgentExceptionRulesTakenOut(t *testing.T) {
	a := hubAgent(t)
	a.h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{"shop.example"}}))
	tok := a.token(contractapi.ScopeExceptionsWrite, "Coding-Agent")
	b, _ := json.Marshal(contractapi.ExceptionRequest{Website: "shop.example", Path: "/search", Target: "ARGS:q", Repository: "crs", Rules: []string{"942100", "941100", "932235"}, Reason: "search"})
	w := a.do("POST", "/agent/v0/exceptions", tok, "application/json", string(b))
	var x contractapi.RuleException
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &x) != nil {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	remove := func(body string) *httptest.ResponseRecorder {
		return a.do("POST", "/agent/v0/exceptions/"+strconv.Itoa(x.ID)+"/remove", tok, "application/json", body)
	}
	for body, code := range map[string]int{
		`{"reason":"r","rules":[]}`:                  400,
		`{"reason":"r","rules":["942100","942100"]}`: 400,
		`{"reason":"r","rules":["x"]}`:               400,
		`{"reason":"r","rules":["999999"]}`:          404,
	} {
		if w := remove(body); w.Code != code {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	w = remove(`{"reason":"941100 is needed again","rules":["941100"]}`)
	var l contractapi.ExceptionList
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &l) != nil || len(l.Items) != 1 || l.Items[0].ID != x.ID ||
		strings.Join(l.Items[0].Rules, ",") != "932235,942100" || l.Items[0].Reason != "search" || l.Items[0].Created != x.Created {
		t.Fatalf("one rule out: %d %s", w.Code, w.Body)
	}
	w = remove(`{"reason":"done","rules":["942100","932235"]}`)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &l) != nil || len(l.Items) != 0 {
		t.Fatalf("every rule left out: %d %s", w.Code, w.Body)
	}
	a.h.Flush()
	rows, _, _ := a.h.App.Store.ListEvents(context.Background(), store.EventFilter{Type: events.RuleExceptionRemoved}, 0, 10)
	var got []string
	for _, r := range rows {
		var e struct {
			Data events.RuleExceptionChange `json:"data"`
		}
		_ = json.Unmarshal(r.Body, &e)
		got = append(got, strings.Join(e.Data.Rules, ","))
	}
	slices.Sort(got)
	if strings.Join(got, "|") != "932235,942100|941100" {
		t.Fatalf("removed events name the rules taken out: %v", got)
	}
}
