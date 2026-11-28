//go:build !release

package agentapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/audittest"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// The audit log as the agent API writes and serves it (MVP-36,
// contracts/audit.md), checked by a reader who did not build it: the whole
// log through GET /audit of the dashboard, the view of an agent through
// GET /agent/v0/audit.

type (
	want  = audittest.Want
	field = audittest.Field
)

const (
	auditSite = "shop.example"
	// agentPeer is the address a call of httptest comes from.
	agentPeer = "192.0.2.1"
	auditPath = "/agent/v0/audit"
)

// auditAgent is a gateway with the agent API, one website and a session of
// the dashboard to read the whole log with.
func auditAgent(t *testing.T, extra string) *apptestAgent {
	t.Helper()
	if !strings.Contains(extra, "requests_per_minute") {
		extra += "  requests_per_minute: 600\n"
	}
	h := apptest.New(t, apptest.Options{Extra: "agent_api:\n  enabled: true\n" + extra})
	h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{auditSite}}))
	h.Login()
	return &apptestAgent{h: h, srv: h.App.AgentAPI.Handler(listen), t: t}
}

// wholeLog reads GET /audit of the dashboard: everything.
func wholeLog(t testing.TB, h *apptest.Harness, way string) *audittest.Log {
	return &audittest.Log{T: t, Way: way, Get: func(q string) (int, []byte) { return h.API("GET", "/audit?"+q, nil) }}
}

// agentLog reads GET /agent/v0/audit with a token.
func agentLog(a *apptestAgent, tok string) *audittest.Log {
	return &audittest.Log{T: a.t, Get: func(q string) (int, []byte) {
		w := a.do("GET", auditPath+"?"+q, tok, "", "")
		return w.Code, w.Body.Bytes()
	}}
}

// rawAudit is what the stores of the log hold as bytes.
func rawAudit(t testing.TB, h *apptest.Harness) map[string][]byte {
	t.Helper()
	h.WaitFor("the outbox to be moved to audit.db", func() bool {
		n, _, err := h.App.Store.AuditOutboxLen(context.Background())
		return err == nil && n == 0
	})
	out := map[string][]byte{}
	for _, name := range []string{auditlog.FileName, auditlog.FileName + "-wal"} {
		if b, err := os.ReadFile(filepath.Join(h.Dir, "data", name)); err == nil {
			out[name] = b
		}
	}
	if out[auditlog.FileName] == nil {
		t.Fatalf("no %s in %s", auditlog.FileName, filepath.Join(h.Dir, "data"))
	}
	rows, err := h.App.Store.AuditOutbox(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	var box []byte
	for _, r := range rows {
		box = append(append(box, r.Body...), '\n')
	}
	out["audit_outbox of schild.db"] = box
	return out
}

// agentMatrix runs the writes of the agent API on one gateway.
type agentMatrix struct {
	a       *apptestAgent
	log     *audittest.Log
	covered map[string]bool
	marks   audittest.Markers
}

// token makes a token and notes it as a secret.
func (m *agentMatrix) token(scope, label string) string {
	tok := m.a.token(scope, label)
	m.marks.SecretValue("the token "+label+" ("+scope+")", tok)
	return tok
}

// call sends one call and fails the test on another status.
func (m *agentMatrix) call(t *testing.T, method, path, tok, body string, status int) []byte {
	t.Helper()
	ctype := ""
	if body != "" {
		ctype = "application/json"
	}
	w := m.a.do(method, path, tok, ctype, body)
	if w.Code != status {
		t.Fatalf("%s %s: %d, want %d: %s", method, path, w.Code, status, w.Body)
	}
	return w.Body.Bytes()
}

// entries checks the new entries of an operation: exactly the wanted ones,
// each by the token from the address of the call.
func (m *agentMatrix) entries(t *testing.T, operation, tok, label string, wants ...want) []audittest.Entry {
	t.Helper()
	m.covered[operation] = true
	for i := range wants {
		wants[i].Operation = "agent:" + operation
	}
	got := m.log.Expect(t, wants...)
	for _, e := range got {
		if e == nil {
			continue
		}
		if os.Getenv("SCHILD_AUDIT_DUMP") != "" {
			t.Logf("%s: %s", operation, audittest.JSON(e))
		}
		audittest.CheckAgentActor(t, e, contractapi.TokenID(tok), label, agentPeer)
	}
	return got
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestAuditMatrixAgent: every write of the agent API that the catalogue
// names writes exactly its entry, with the token and its label, the address
// of the call, the subject, the website and the values before and after; a
// call that changes nothing writes none. No token is in the log.
func TestAuditMatrixAgent(t *testing.T) {
	a := auditAgent(t, "")
	m := &agentMatrix{a: a, covered: map[string]bool{}}
	m.log = wholeLog(t, a.h, "agent")
	m.log.Fresh()

	t.Run("setAgentCrawlers", func(t *testing.T) {
		const label = "Site-Agent"
		tok := m.token(contractapi.ScopeCrawlersWrite, label)
		reason := m.marks.Listed("crawlers.reason")
		body := jsonOf(map[string]any{"website": auditSite, "preset": "block_ai_training", "reason": reason})
		m.call(t, "POST", crawlersPath, tok, body, 200)
		m.entries(t, "setAgentCrawlers", tok, label, want{Action: "crawlers.set", Subject: auditSite, Website: auditSite, Reason: reason, Fields: map[string]field{
			"/categories/ai_training": {Change: "added", After: "block"},
			"/preset":                 {Change: "added", After: "block_ai_training"},
		}})
		m.call(t, "POST", crawlersPath, tok, body, 200)
		m.log.None(t, "setAgentCrawlers with the policy that is in force")
		// One category alone, and the same again.
		reason = "open again"
		body = jsonOf(map[string]any{"website": auditSite, "category": "ai_search", "action": "block", "reason": reason})
		m.call(t, "POST", crawlersPath, tok, body, 200)
		m.entries(t, "setAgentCrawlers", tok, label, want{Action: "crawlers.set", Subject: auditSite, Website: auditSite, Reason: reason, Fields: map[string]field{
			"/categories/ai_search": {Change: "added", After: "block"},
		}, Absent: []string{"/categories/ai_training", "/impersonators"}})
		m.call(t, "POST", crawlersPath, tok, body, 200)
		m.log.None(t, "setAgentCrawlers of a category that is set")
	})

	var blocked string
	const guard = "Wachdienst"
	var guardTok string
	t.Run("createAgentBlock", func(t *testing.T) {
		_, ev := incidentOf(t, a, attacker)
		guardTok = m.token(contractapi.ScopeBlocksWrite, guard)
		reason := m.marks.Listed("block.reason")
		body := jsonOf(map[string]any{"target": map[string]string{"event_id": ev}, "duration_s": 3600, "reason": reason})
		res := decodeResult(t, m.call(t, "POST", blocksPath, guardTok, body, 200))
		if !res.Changed || res.Incident == "" || res.Until == nil {
			t.Fatalf("block: %+v", res)
		}
		blocked = res.Incident
		a.h.Flush()
		m.entries(t, "createAgentBlock", guardTok, guard, want{Action: "block.set", Subject: blocked, Event: ev, Reason: reason, Fields: map[string]field{
			"/client":     {Change: "added", After: attacker},
			"/duration_s": {Change: "added", After: 3600},
			"/until":      {Change: "added", After: *res.Until},
			"/effect":     {Change: "added", After: "block"},
		}})
		// A running block stands: nothing changes, no entry.
		if again := decodeResult(t, m.call(t, "POST", blocksPath, guardTok, body, 200)); again.Changed {
			t.Fatalf("second block changed something: %+v", again)
		}
		m.log.None(t, "createAgentBlock of a client that is blocked")
	})

	t.Run("liftAgentBlock", func(t *testing.T) {
		if blocked == "" {
			t.Skip("no block to lift")
		}
		reason := m.marks.Listed("lift.reason")
		path := "/agent/v0/incidents/" + blocked + "/lift"
		m.call(t, "POST", path, guardTok, jsonOf(map[string]any{"reason": reason}), 200)
		m.entries(t, "liftAgentBlock", guardTok, guard, want{Action: "block.lift", Subject: blocked, Incident: blocked, Reason: reason, Fields: map[string]field{
			"/client": {Change: "removed", Before: attacker},
		}})
		// The stored row of the incident follows the lift in the background:
		// a second lift before it is there is answered 409.
		a.h.Flush()
		m.call(t, "POST", path, guardTok, `{"reason":"again"}`, 200)
		m.log.None(t, "liftAgentBlock of a block that is lifted")
	})

	const coder = "Coding-Agent"
	var exception contractapi.RuleException
	var coderTok string
	t.Run("createAgentException", func(t *testing.T) {
		coderTok = m.token(contractapi.ScopeExceptionsWrite, coder)
		req := contractapi.ExceptionRequest{Website: auditSite, Path: "/search", Target: "ARGS:q", Repository: "crs", Rules: []string{"942100", "941100", "932235"},
			Reason: m.marks.Listed("exception.reason")}
		if err := json.Unmarshal(m.call(t, "POST", "/agent/v0/exceptions", coderTok, jsonOf(req), 200), &exception); err != nil {
			t.Fatal(err)
		}
		m.entries(t, "createAgentException", coderTok, coder, want{Action: "rule_exception.set", Subject: fmt.Sprint(exception.ID), Website: auditSite, Reason: req.Reason, Fields: map[string]field{
			"/path":       {Change: "added", After: "/search"},
			"/target":     {Change: "added", After: "ARGS:q"},
			"/repository": {Change: "added", After: "crs"},
			"/rules":      {Change: "added", Added: []string{"932235", "941100", "942100"}},
		}})
		m.call(t, "POST", "/agent/v0/exceptions", coderTok, jsonOf(req), 200)
		m.log.None(t, "createAgentException of the exception that stands")
	})

	t.Run("removeAgentException", func(t *testing.T) {
		if exception.ID == 0 {
			t.Skip("no exception")
		}
		path := fmt.Sprintf("/agent/v0/exceptions/%d/remove", exception.ID)
		reason := m.marks.Listed("exception.remove.reason")
		m.call(t, "POST", path, coderTok, jsonOf(map[string]any{"reason": reason, "rules": []string{"941100"}}), 200)
		m.entries(t, "removeAgentException", coderTok, coder, want{Action: "rule_exception.remove", Subject: fmt.Sprint(exception.ID), Website: auditSite, Reason: reason, Fields: map[string]field{
			"/rules": {Change: "changed", Removed: []string{"941100"}},
		}, Absent: []string{"/path", "/target", "/repository"}})
		m.call(t, "POST", path, coderTok, `{"reason":"done"}`, 200)
		m.entries(t, "removeAgentException", coderTok, coder, want{Action: "rule_exception.remove", Subject: fmt.Sprint(exception.ID), Website: auditSite, Reason: "done", Fields: map[string]field{
			"/path":       {Change: "removed", Before: "/search"},
			"/target":     {Change: "removed", Before: "ARGS:q"},
			"/repository": {Change: "removed", Before: "crs"},
			"/rules":      {Change: "removed", Removed: []string{"932235", "942100"}},
		}})
		m.call(t, "POST", path, coderTok, `{"reason":"again"}`, 404)
		m.log.None(t, "removeAgentException of an exception that is gone")
	})

	const ruler = "Regel-Agent"
	rulerTok := m.token(contractapi.ScopeRulesWrite, ruler)
	t.Run("updateAgentRule", func(t *testing.T) {
		note := m.marks.Listed("rule.note")
		body := jsonOf(map[string]any{"disabled": true, "note": note})
		m.call(t, "PATCH", "/agent/v0/rules/crs/941100", rulerTok, body, 200)
		m.entries(t, "updateAgentRule", rulerTok, ruler, want{Action: "rule.set", Subject: "crs/941100", Reason: note, Fields: map[string]field{
			"/disabled": {Change: "changed", Before: false, After: true},
		}})
		m.call(t, "PATCH", "/agent/v0/rules/crs/941100", rulerTok, body, 200)
		m.log.None(t, "updateAgentRule of a rule that is disabled")
	})

	t.Run("updateAgentRuleRepository", func(t *testing.T) {
		m.call(t, "PATCH", "/agent/v0/rule-repositories/crowdsec", rulerTok, `{"state":"block"}`, 200)
		m.entries(t, "updateAgentRuleRepository", rulerTok, ruler, want{Action: "rule_repository.set", Subject: "crowdsec", Fields: map[string]field{
			"/state": {Change: "changed", Before: "detect", After: "block"},
		}})
		m.call(t, "PATCH", "/agent/v0/rule-repositories/crowdsec", rulerTok, `{"state":"block"}`, 200)
		m.log.None(t, "updateAgentRuleRepository with the state that is set")
		m.call(t, "PATCH", "/agent/v0/rule-repositories/crowdsec", rulerTok, `{"reset_state":true}`, 200)
		m.entries(t, "updateAgentRuleRepository", rulerTok, ruler, want{Action: "rule_repository.set", Subject: "crowdsec", Fields: map[string]field{
			"/state": {Change: "changed", Before: "block", After: "detect"},
		}})
	})

	t.Run("syncAgentRuleRepository", func(t *testing.T) {
		dir := filepath.Join(a.h.Dir, "rules.d")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "10-stop.conf"),
			[]byte(`SecRule REQUEST_URI "@beginsWith /stop-here" "id:1000001,phase:1,deny,status:403,msg:'stop here'"`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		m.call(t, "POST", "/agent/v0/rule-repositories/local/sync", rulerTok, "", 200)
		m.entries(t, "syncAgentRuleRepository", rulerTok, ruler, want{Action: "rule_repository.sync", Subject: "local", Fields: map[string]field{
			"/rules_loaded": {Change: "changed", Before: 0, After: 1},
		}})
		m.call(t, "POST", "/agent/v0/rule-repositories/local/sync", rulerTok, "", 200)
		m.log.None(t, "syncAgentRuleRepository of files that did not change")
	})

	t.Run("resetAgentRuleRepository", func(t *testing.T) {
		m.call(t, "POST", "/agent/v0/rule-repositories/crowdsec/reset", rulerTok, "", 200)
		m.entries(t, "resetAgentRuleRepository", rulerTok, ruler, want{Action: "rule_repository.reset", Subject: "crowdsec"})
	})

	t.Run("not audited", func(t *testing.T) {
		read := m.token(contractapi.ScopeAgentRead, "")
		testSample(t, a, read)
		m.log.None(t, "testAgentRequest")
		for _, path := range []string{"/agent/v0/status", "/agent/v0/exceptions", "/agent/v0/crawlers", auditPath} {
			m.call(t, "GET", path, read, "", 200)
		}
		m.log.None(t, "a reading call")
	})

	t.Run("every operation of the catalogue", func(t *testing.T) {
		for _, op := range audittest.Operations("agent") {
			if op != "any" && !m.covered[op] {
				t.Errorf("operation %s of the catalogue was not called", op)
			}
		}
		// And the other way round: every write the API knows is in the
		// catalogue or was shown to write nothing.
		for op := range contractapi.WriteOperations {
			if !m.covered[op] && op != contractapi.OpTestRequest && op != contractapi.OpSyncFirewall {
				t.Errorf("write operation %s of the agent API was not called", op)
			}
		}
	})

	t.Run("no secret", func(t *testing.T) {
		all := wholeLog(t, a.h, "").All("")
		for _, e := range all {
			audittest.Check(t, e)
		}
		m.marks.Check(t, all, rawAudit(t, a.h))
	})
}

// TestAuditAgentView: a token that may read sees changes and credentials
// and who made them by token; no sign-in, no refused call, no privacy
// entry, no name of a person, no session, no address of a call. A token
// that may not read is refused.
func TestAuditAgentView(t *testing.T) {
	a := auditAgent(t, "")
	h := a.h
	// Entries of every class: the first password (credential, access), a
	// change of the dashboard and one of a token, a privacy entry, a refused
	// call.
	if code, b := h.API("PUT", "/websites/"+auditSite+"/maintenance", map[string]any{"on": true, "message": "Gleich wieder da."}); code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	if code, b := h.API("POST", "/privacy/export", map[string]any{"ip": "203.0.113.57"}); code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	write := a.token(contractapi.ScopeRulesWrite, "Regel-Agent")
	if w := a.do("PATCH", "/agent/v0/rules/crs/941100", write, "application/json", `{"disabled":true,"note":"view test"}`); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := a.do("GET", "/agent/v0/status", contractapi.NewToken(), "", ""); w.Code != 401 {
		t.Fatalf("unknown token: %d", w.Code)
	}
	whole := wholeLog(t, h, "")
	h.WaitFor("the refused call of the unknown token", func() bool { return len(whole.All("class=refused")) > 0 })
	all := whole.All("")
	classes := map[string]int{}
	for _, e := range all {
		classes[audittest.Str(e, "class")]++
	}
	for _, c := range []string{"change", "credential", "access", "privacy", "refused"} {
		if classes[c] == 0 {
			t.Fatalf("the log holds no entry of class %s: the test does not show what it should (%v)", c, classes)
		}
	}

	read := a.token(contractapi.ScopeAgentRead, "Leser")
	view := agentLog(a, read)
	seen := view.All("")
	var wantEntries []audittest.Entry
	for _, e := range all {
		if c := audittest.Str(e, "class"); c == "change" || c == "credential" {
			wantEntries = append(wantEntries, e)
		}
	}
	have := map[string]audittest.Entry{}
	for _, e := range seen {
		have[audittest.Str(e, "id")] = e
	}
	if len(seen) != len(wantEntries) {
		t.Errorf("the agent sees %d entries, the log holds %d changes and credentials", len(seen), len(wantEntries))
	}
	for _, e := range wantEntries {
		got := have[audittest.Str(e, "id")]
		if got == nil {
			t.Errorf("the agent does not see %s", audittest.JSON(e))
			continue
		}
		// What it sees is the entry without the people and the address of
		// the call, and nothing else is another.
		reduced := map[string]any{}
		for k, v := range e {
			if k != "address" {
				reduced[k] = v
			}
		}
		actor := map[string]any{}
		for k, v := range e["actor"].(map[string]any) {
			if k != "user" && k != "session" && k != "account" && k != "on_behalf_of" {
				actor[k] = v
			}
		}
		reduced["actor"] = actor
		if audittest.JSON(got) != audittest.JSON(reduced) {
			t.Errorf("the agent sees %s, want %s", audittest.JSON(got), audittest.JSON(reduced))
		}
	}
	byToken := 0
	for _, e := range seen {
		if c := audittest.Str(e, "class"); c != "change" && c != "credential" {
			t.Errorf("the agent sees an entry of class %s: %s", c, audittest.JSON(e))
		}
		if _, ok := e["address"]; ok {
			t.Errorf("the agent sees the address of a call: %s", audittest.JSON(e))
		}
		actor, _ := e["actor"].(map[string]any)
		for _, k := range []string{"user", "session", "account", "on_behalf_of"} {
			if _, ok := actor[k]; ok {
				t.Errorf("the agent sees %s of the actor: %s", k, audittest.JSON(e))
			}
		}
		if audittest.Str(e, "actor", "id") == contractapi.TokenID(write) && audittest.Str(e, "actor", "label") == "Regel-Agent" {
			byToken++
		}
	}
	if byToken != 1 {
		t.Errorf("the agent sees %d entries of the token that wrote one", byToken)
	}
	// The name of a person is nowhere, also not as the subject of the entry
	// of a password.
	for _, e := range seen {
		if strings.Contains(audittest.JSON(e), `"admin"`) {
			t.Errorf("the agent sees the name of the dashboard user: %s", audittest.JSON(e))
		}
	}
	raw := audittest.JSON(seen)
	for what, text := range map[string]string{"the address of the dashboard call": "127.0.0.1", "the address of the agent call": agentPeer,
		"a sign-in": "session.start", "a privacy entry": "privacy.export", "a refused call": "agent_api.call"} {
		if strings.Contains(raw, text) {
			t.Errorf("the view of the agent holds %s (%s)", what, text)
		}
	}

	// Filters: the classes an agent sees, and nothing that reaches the
	// others.
	for query, n := range map[string]int{"class=change": classes["change"], "class=credential": classes["credential"], "way=agent": 1,
		"actor=" + contractapi.TokenID(write): 1, "way=dashboard&class=change": classes["change"] - 1 - countWay(all, "config:", "system:"),
		"subject=rule&subject_id=crs/941100": 1, "website=" + auditSite: 1, "action=rule.set": 1, "action=session.start": 0, "action=privacy.export": 0} {
		if got := len(view.All(query)); got != n {
			t.Errorf("agent ?%s: %d entries, want %d", query, got, n)
		}
	}
	for _, bad := range []string{"class=access", "class=refused", "class=privacy", "class=x", "way=x", "limit=0", "limit=201", "cursor=x", "from=gestern", "actor=admin", "action=X"} {
		if w := a.do("GET", auditPath+"?"+bad, read, "", ""); w.Code != 400 {
			t.Errorf("agent ?%s: %d, want 400: %.200s", bad, w.Code, w.Body)
		}
	}
	// A session filter would tell an agent which entries one person made.
	if w := a.do("GET", auditPath+"?session="+audittest.Str(pickAction(all, "session.start"), "actor", "session"), read, "", ""); w.Code == 200 {
		var p struct {
			Items []audittest.Entry `json:"items"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &p)
		if len(p.Items) != len(seen) && len(p.Items) != 0 {
			t.Errorf("the agent API filters by the session of a person: %d of %d entries", len(p.Items), len(seen))
		}
	}
	// Pages of two hold every entry once.
	paged := 0
	for _, p := range view.Pages("", 2) {
		paged += len(p)
	}
	if paged != len(seen) {
		t.Errorf("pages of two hold %d entries, the list %d", paged, len(seen))
	}

	// Who may read: every scope that reads; not the two that do not.
	for _, scope := range []string{contractapi.ScopeRulesWrite, contractapi.ScopeBlocksWrite, contractapi.ScopeExceptionsWrite, contractapi.ScopeCrawlersWrite} {
		if w := a.do("GET", auditPath, a.token(scope, "x"), "", ""); w.Code != 200 {
			t.Errorf("a token of scope %s reads the log: %d", scope, w.Code)
		}
	}
	for _, scope := range []string{contractapi.ScopeFirewallSync, contractapi.ScopeExportRead} {
		if w := a.do("GET", auditPath, a.token(scope, "x"), "", ""); w.Code != 403 {
			t.Errorf("a token of scope %s reads the log: %d, want 403: %.200s", scope, w.Code, w.Body)
		}
	}
	if w := a.do("GET", auditPath, contractapi.NewToken(), "", ""); w.Code != 401 {
		t.Errorf("an unknown token reads the log: %d", w.Code)
	}
	// The agent API changes no entry.
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if w := a.do(method, auditPath, write, "application/json", `{}`); w.Code < 400 {
			t.Errorf("%s %s answers %d: the log is append only", method, auditPath, w.Code)
		}
	}
}

func countWay(es []audittest.Entry, prefixes ...string) int {
	n := 0
	for _, e := range es {
		if audittest.Str(e, "class") != "change" {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(audittest.Str(e, "operation"), p) {
				n++
			}
		}
	}
	return n
}

func pickAction(es []audittest.Entry, action string) audittest.Entry {
	for _, e := range es {
		if audittest.Str(e, "action") == action {
			return e
		}
	}
	return nil
}

// refusedOf sums the refused calls of an action, an operation and a token
// in the log: the number of entries and their counts.
func refusedOf(all []audittest.Entry, action, operation, tokenID string) (entries int, count float64, sample audittest.Entry) {
	for _, e := range all {
		if audittest.Str(e, "class") != "refused" || audittest.Str(e, "action") != action || audittest.Str(e, "operation") != operation || audittest.Str(e, "actor", "id") != tokenID {
			continue
		}
		n, _ := e["count"].(float64)
		entries++
		count += n
		sample = e
	}
	return entries, count, sample
}

// TestAuditAgentRefused: a call with an unknown token, a write and a read
// with a token of the wrong scope, and calls over the rate limit each end
// in a refused entry with the action the catalogue says, gathered per
// token, client and minute with their count.
func TestAuditAgentRefused(t *testing.T) {
	a := auditAgent(t, "  requests_per_minute: 5\n")
	h := a.h
	var marks audittest.Markers
	minute := time.Now().UTC().Truncate(time.Minute)

	// An unknown token, seven times: no token id, the call as its action.
	for i := 0; i < 7; i++ {
		unknown := contractapi.NewToken()
		marks.SecretValue(fmt.Sprint("unknown token ", i), unknown)
		path, method := "/agent/v0/status", "GET"
		if i%2 == 1 {
			path, method = crawlersPath, "POST"
		}
		if w := a.do(method, path, unknown, "application/json", `{}`); w.Code != 401 {
			t.Fatalf("unknown token: %d %s", w.Code, w.Body)
		}
	}
	// A write with a token of another scope, three times.
	read := a.token(contractapi.ScopeAgentRead, "Leser")
	marks.SecretValue("the read token", read)
	set := jsonOf(map[string]any{"website": auditSite, "preset": "block_ai_training", "reason": marks.Unlisted("refused.reason")})
	for i := 0; i < 3; i++ {
		if w := a.do("POST", crawlersPath, read, "application/json", set); w.Code != 403 {
			t.Fatalf("write with a read token: %d %s", w.Code, w.Body)
		}
	}
	// A read with a token that may not read, twice.
	fw := a.token(contractapi.ScopeFirewallSync, "Firewall")
	for i := 0; i < 2; i++ {
		if w := a.do("GET", auditPath, fw, "", ""); w.Code != 403 {
			t.Fatalf("read with a firewall token: %d %s", w.Code, w.Body)
		}
	}
	// Over the rate limit: the limit is 5 a minute. The read token made 3
	// calls; 2 more pass, then 4 reads and 6 writes are refused.
	for i := 0; i < 2; i++ {
		if w := a.do("GET", "/agent/v0/status", read, "", ""); w.Code != 200 {
			t.Fatalf("call %d within the limit: %d %s", i, w.Code, w.Body)
		}
	}
	for i := 0; i < 10; i++ {
		method, path := "GET", "/agent/v0/status"
		if i >= 4 {
			method, path = "POST", crawlersPath
		}
		if w := a.do(method, path, read, "application/json", set); w.Code != 429 || !strings.Contains(w.Body.String(), "rate_limited") {
			t.Fatalf("call %d over the limit: %d %s", i, w.Code, w.Body)
		}
	}
	oneMinute := time.Now().UTC().Truncate(time.Minute).Equal(minute)
	whole := wholeLog(t, h, "")
	for _, e := range whole.All("") {
		if audittest.Str(e, "result") == "done" && strings.HasPrefix(audittest.Str(e, "operation"), "agent:") {
			t.Errorf("a refused call wrote an entry that is done: %s", audittest.JSON(e))
		}
	}

	// An entry is written with its first call; its count follows every 10 s
	// and when the gateway stops. Wait for the four entries, then stop the
	// gateway and start it on the same data.
	h.WaitFor("the first write of the four refused entries", func() bool { return len(whole.All("class=refused")) >= 4 })
	dir := h.Dir
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	h2 := apptest.New(t, apptest.Options{Dir: dir, Extra: "agent_api:\n  enabled: true\n"})
	h2.Login()
	all := wholeLog(t, h2, "").All("")
	readID, fwID := contractapi.TokenID(read), contractapi.TokenID(fw)
	if os.Getenv("SCHILD_AUDIT_DUMP") != "" {
		for _, e := range all {
			if audittest.Str(e, "class") == "refused" {
				t.Logf("refused: %s", audittest.JSON(e))
			}
		}
	}
	for _, c := range []struct {
		what, action, operation, token, label string
		count                                 float64
	}{
		{"calls with an unknown token", "agent_api.call", "agent:any", "", "", 7},
		{"writes with a token of the wrong scope", "crawlers.set", "agent:setAgentCrawlers", readID, "Leser", 3 + 6},
		{"reads with a token that may not read", "agent_api.call", "agent:any", fwID, "Firewall", 2},
		{"reads over the rate limit", "agent_api.call", "agent:any", readID, "Leser", 4},
	} {
		entries, count, e := refusedOf(all, c.action, c.operation, c.token)
		if count != c.count {
			t.Errorf("%s: counted %v in %d entries, want %v", c.what, count, entries, c.count)
		}
		if oneMinute && entries != 1 {
			t.Errorf("%s: %d entries in one minute, want 1", c.what, entries)
		}
		if e == nil {
			continue
		}
		audittest.Check(t, e)
		if audittest.Str(e, "result") != "refused" || audittest.Str(e, "class") != "refused" || audittest.Str(e, "address") != agentPeer ||
			audittest.Str(e, "actor", "kind") != "agent" || audittest.Str(e, "actor", "label") != c.label {
			t.Errorf("%s read: %s", c.what, audittest.JSON(e))
		}
		if _, ok := e["change"]; ok {
			t.Errorf("%s: a refused call holds a change: %s", c.what, audittest.JSON(e))
		}
	}
	for _, e := range all {
		if audittest.Str(e, "class") == "refused" {
			if _, err := time.Parse("2006-01-02T15:04:05Z", audittest.Str(e, "last")); err != nil || audittest.Str(e, "last") < audittest.Str(e, "time") {
				t.Errorf("a refused entry with last %q before its time %q", audittest.Str(e, "last"), audittest.Str(e, "time"))
			}
		}
	}
	marks.Check(t, all, rawAudit(t, h2))
	// An agent does not see them.
	a2 := &apptestAgent{h: h2, srv: h2.App.AgentAPI.Handler(listen), t: t}
	for _, e := range agentLog(a2, a2.token(contractapi.ScopeAgentRead, "Leser 2")).All("") {
		if audittest.Str(e, "class") == "refused" || audittest.Str(e, "result") == "refused" {
			t.Errorf("an agent sees a refused call: %s", audittest.JSON(e))
		}
	}
}

// TestAuditRefusedAtStop shows that refused calls are lost when the gateway
// stops while their entries are written for the first time. It depends on
// the moment of the stop, so it runs only when asked:
//
//	SCHILD_AUDIT_STOP_RACE=1 go test -run TestAuditRefusedAtStop ./internal/agentapi/
//
// Twenty tokens of the wrong scope each try one write, then the gateway
// stops at once and starts on the same data: every one of the twenty calls
// must be in the log (contracts/audit.md section 5: a crash loses at most
// 10 s of counting, a stop nothing).
func TestAuditRefusedAtStop(t *testing.T) {
	if os.Getenv("SCHILD_AUDIT_STOP_RACE") == "" {
		t.Skip("depends on the moment of the stop; set SCHILD_AUDIT_STOP_RACE=1 to run it")
	}
	const tokens, rounds = 20, 15
	lostRounds := 0
	for round := 0; round < rounds; round++ {
		a := auditAgent(t, "")
		for i := 0; i < tokens; i++ {
			tok := a.token(contractapi.ScopeAgentRead, fmt.Sprint("Leser ", i))
			if w := a.do("POST", crawlersPath, tok, "application/json", `{"website":"shop.example","preset":"block_ai_training","reason":"x"}`); w.Code != 403 {
				t.Fatalf("write with a read token: %d %s", w.Code, w.Body)
			}
		}
		dir := a.h.Dir
		if err := a.h.Stop(); err != nil {
			t.Fatal(err)
		}
		h2 := apptest.New(t, apptest.Options{Dir: dir, Extra: "agent_api:\n  enabled: true\n"})
		h2.Login()
		count := 0.0
		for _, e := range wholeLog(t, h2, "").All("class=refused") {
			n, _ := e["count"].(float64)
			count += n
		}
		if count != tokens {
			lostRounds++
			t.Errorf("round %d: %d refused calls before the stop, %v in the log after it", round, tokens, count)
		}
		_ = h2.Stop()
	}
	t.Logf("%d of %d rounds lost refused calls", lostRounds, rounds)
}
