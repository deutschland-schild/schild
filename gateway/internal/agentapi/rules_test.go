//go:build !release

package agentapi_test

import (
	"encoding/json"
	"strings"
	"testing"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// A Livewire update as the code of a math app sends it: the text a user types
// sits in json.components.0.updates.text.
const mathUpdate = `{"components":[{"snapshot":"{}","updates":{"text":"Sei $f(x)$ gegeben. Die Lösungen sind $x_{1,2}$."},"calls":[]}]}`

func testSample(t *testing.T, a *apptestAgent, tok string) contractapi.TestResult {
	t.Helper()
	body, _ := json.Marshal(contractapi.TestRequest{Website: "shop.example", Method: "POST", Path: "/livewire/update", ContentType: "application/json", Body: mathUpdate})
	w := a.do("POST", "/agent/v0/rules/test", tok, "application/json", string(body))
	if w.Code != 200 {
		t.Fatalf("test: %d %s", w.Code, w.Body)
	}
	validate(t, "gateway-agent.openapi.yaml", "AgentTestResult", w.Body.Bytes())
	var res contractapi.TestResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// TestAgentFindsExceptionBeforeLive is the case of D55: an agent that knows the
// code reads the rules, tests a sample, sets the suggested exception and tests
// again, before a visitor ever sends such a request. A read token may test.
func TestAgentFindsExceptionBeforeLive(t *testing.T) {
	a := blockAgent(t, "autoblock", "")
	a.h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{"shop.example"}}))
	read := a.token(contractapi.ScopeAgentRead, "")

	w := a.do("GET", "/agent/v0/rules?repository=crs&limit=200&cursor=o0", read, "", "")
	validate(t, "client-dashboard.openapi.yaml", "RulePage", w.Body.Bytes())
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"9`) {
		t.Fatalf("rules: %d %.300s", w.Code, w.Body)
	}

	res := testSample(t, a, read)
	if !res.WouldBlock || len(res.Suggestions) != 1 {
		t.Fatalf("before: %+v", res)
	}
	s := res.Suggestions[0]
	if s.Path != "/livewire/update" || s.Target != "ARGS:json.components.*.updates.text" || len(s.Rules) == 0 {
		t.Fatalf("suggestion %+v", s)
	}
	if r := a.h.Visit("POST", "/livewire/update", "198.51.100.20", "application/json", mathUpdate); r.StatusCode != 403 {
		t.Fatalf("live before: %d", r.StatusCode)
	}

	// The sample changed nothing, and the read token cannot write.
	if s.Repository != "crs" {
		t.Fatalf("suggestion of %s", s.Repository)
	}
	req, _ := json.Marshal(contractapi.ExceptionRequest{Website: s.Website, Path: s.Path, Target: s.Target, Repository: s.Repository, Rules: s.Rules,
		Reason: "LaTeX in the math editor"})
	if w := a.do("POST", "/agent/v0/exceptions", read, "application/json", string(req)); w.Code != 403 {
		t.Fatalf("read token wrote: %d", w.Code)
	}
	write := a.token(contractapi.ScopeExceptionsWrite, "Coding-Agent")
	if w := a.do("POST", "/agent/v0/exceptions", write, "application/json", string(req)); w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}

	after := testSample(t, a, read)
	if after.WouldBlock || len(after.Suggestions) != 0 {
		t.Fatalf("after: %+v", after)
	}
	if r := a.h.Visit("POST", "/livewire/update", "198.51.100.21", "application/json", mathUpdate); r.StatusCode == 403 {
		t.Fatal("live after: still 403")
	}
	// Other fields stay checked.
	xss := strings.Replace(mathUpdate, `"calls":[]`, `"calls":[{"method":"<script>alert(1)</script>"}]`, 1)
	if r := a.h.Visit("POST", "/livewire/update", "198.51.100.22", "application/json", xss); r.StatusCode != 403 {
		t.Fatalf("other field: %d", r.StatusCode)
	}

	// A query argument gets its own suggestion.
	body, _ := json.Marshal(contractapi.TestRequest{Website: "shop.example", Method: "GET", Path: "/suche?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"})
	if w := a.do("POST", "/agent/v0/rules/test", read, "application/json", string(body)); !strings.Contains(w.Body.String(), `"suggestions":[{"website":"shop.example","path":"/suche","target":"ARGS:q","repository":"crs"`) {
		t.Fatalf("query: %.600s", w.Body)
	}
}

func TestAgentRequestTestRefusals(t *testing.T) {
	a := blockAgent(t, "autoblock", "")
	a.h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{"shop.example"}}))
	read := a.token(contractapi.ScopeAgentRead, "")
	for body, code := range map[string]int{
		`{"website":"shop.example","method":"TRACE","path":"/"}`:                                           400,
		`{"website":"shop.example","method":"GET","path":"no-slash"}`:                                      400,
		`{"website":"shop.example","method":"GET","path":"/%zz"}`:                                          400, // panicked in httptest.NewRequest
		`{"website":"shop.example","method":"GET","path":"/","headers":{"Host":"evil.example"}}`:           400,
		`{"website":"shop.example","method":"GET","path":"/","headers":{"X-A":"a\r\nX-B: b"}}`:             400,
		`{"website":"nope.example","method":"GET","path":"/"}`:                                             404,
		`{"website":"shop.example","method":"GET","path":"/","body":"` + strings.Repeat("a", 70000) + `"}`: 400,
	} {
		if w := a.do("POST", "/agent/v0/rules/test", read, "application/json", body); w.Code != code {
			t.Errorf("%.80s: %d, want %d (%s)", body, w.Code, code, w.Body)
		}
	}
}
