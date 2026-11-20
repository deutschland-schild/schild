//go:build !release

package agentapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	cc "github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// D57 (MVP-29): crawler control through the agent API.

const crawlersPath = "/agent/v0/crawlers"

func crawlerAgent(t *testing.T) *apptestAgent {
	t.Helper()
	a := blockAgent(t, "autoblock", "")
	a.h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{"shop.example"}}))
	return a
}

// crawlerVisit sends a request with a user agent through the proxy.
func crawlerVisit(t *testing.T, a *apptestAgent, ua, ip string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", a.h.Proxy.URL+"/blog/hallo", nil)
	req.Host = "shop.example"
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

const uaGPTBot = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"

func TestAgentCrawlersScope(t *testing.T) {
	a := crawlerAgent(t)
	read := a.token(contractapi.ScopeAgentRead, "")
	other := a.token(contractapi.ScopeExceptionsWrite, "Coding-Agent")
	write := a.token(contractapi.ScopeCrawlersWrite, "Site-Agent")

	w := a.do("GET", crawlersPath, read, "", "")
	validate(t, "gateway-agent.openapi.yaml", "AgentCrawlerList", w.Body.Bytes())
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"website":"shop.example"`) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	set := `{"website":"shop.example","preset":"block_ai_training","reason":"The operator wants no AI training crawlers."}`
	for _, tok := range []string{read, other} {
		w := a.do("POST", crawlersPath, tok, "application/json", set)
		if w.Code != 403 || !strings.Contains(w.Body.String(), contractapi.CodeScopeRequired) {
			t.Fatalf("token without crawlers:write: %d %s", w.Code, w.Body)
		}
	}
	if code := crawlerVisit(t, a, uaGPTBot, "198.51.100.30"); code != 200 {
		t.Fatalf("before: %d", code)
	}
	w = a.do("POST", crawlersPath, write, "application/json", set)
	validate(t, "gateway-agent.openapi.yaml", "AgentCrawlerPolicy", w.Body.Bytes())
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"categories":{"ai_training":"block"}`) {
		t.Fatalf("set: %d %s", w.Code, w.Body)
	}
	// In force before the answer returned.
	if code := crawlerVisit(t, a, uaGPTBot, "198.51.100.31"); code != 403 {
		t.Fatalf("after: %d", code)
	}
	if code := crawlerVisit(t, a, "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0", "198.51.100.32"); code != 200 {
		t.Fatalf("browser: %d", code)
	}
	w = a.do("GET", crawlersPath+"?site=shop.example", read, "", "")
	var list cc.AgentList
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("list: %s %v", w.Body, err)
	}
	found := false
	for _, c := range list.Items[0].Crawlers {
		if c.Bot == "gptbot" {
			found = c.Blocked == 1 && c.Rule == cc.Block
		}
	}
	if !found {
		t.Fatalf("gptbot count: %+v", list.Items[0].Crawlers)
	}
	// History: the event with token and reason, and the call log.
	a.h.Flush()
	rows, _, err := a.h.App.Store.ListEvents(t.Context(), store.EventFilter{Type: events.CrawlerPolicySet}, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("events: %d %v", len(rows), err)
	}
	ev, err := a.h.App.Store.GetEvent(t.Context(), rows[0].ID)
	if err != nil || !strings.Contains(string(ev.Body), `"token_label":"Site-Agent"`) || !strings.Contains(string(ev.Body), `"reason":"The operator wants no AI training crawlers."`) ||
		!strings.Contains(string(ev.Body), `"preset":"block_ai_training"`) {
		t.Fatalf("event: %s %v", ev.Body, err)
	}
	calls := a.calls(read)
	refused := false
	for _, c := range calls {
		refused = refused || c.Op == contractapi.OpSetCrawlers && c.Status == 403
	}
	if !refused {
		t.Fatalf("refused write not in the call log: %+v", calls)
	}

	// The write token switches impersonators on, the read token sees it.
	if w := a.do("POST", "/agent/v0/crawlers", write, "application/json", `{"website":"shop.example","impersonators":"block","reason":"spoofed googlebots"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"impersonators":"block"`) {
		t.Fatalf("write token: %d %.400s", w.Code, w.Body)
	}
	if w := a.do("GET", "/agent/v0/crawlers?site=shop.example", read, "", ""); !strings.Contains(w.Body.String(), `"impersonators":"block"`) {
		t.Fatalf("read: %.400s", w.Body)
	}
	// The stored policy survives as the app keeps it in schild.db.
	if e := a.h.App.Crawlers.Entry("shop.example"); e == nil || e.Policy.Impersonators != cc.Block || e.TokenLabel != "Site-Agent" {
		t.Fatalf("entry %+v", e)
	}
}

func TestAgentCrawlersRefusals(t *testing.T) {
	a := crawlerAgent(t)
	write := a.token(contractapi.ScopeCrawlersWrite, "Site-Agent")
	for body, code := range map[string]int{
		`{"website":"shop.example","bot":"nosuchbot","action":"block","reason":"x"}`:                             400,
		`{"website":"shop.example","category":"likely_browser","action":"block","reason":"x"}`:                   400,
		`{"website":"shop.example","category":"ai_training","action":"inherit","reason":"x"}`:                    400,
		`{"website":"shop.example","category":"ai_training","bot":"gptbot","action":"block","reason":"x"}`:       400,
		`{"website":"shop.example","bot":"gptbot","action":"block"}`:                                             400,
		`{"website":"shop.example","bot":"gptbot","action":"block","reason":"a\u0007b"}`:                         400,
		`{"website":"shop.example","bot":"gptbot","action":"block","reason":"x","charge":"1 EUR"}`:               400,
		`{"website":"nope.example","bot":"gptbot","action":"block","reason":"x"}`:                                404,
		`{"website":"shop.example","bot":"gptbot","action":"block","reason":"` + strings.Repeat("a", 301) + `"}`: 400,
	} {
		if w := a.do("POST", crawlersPath, write, "application/json", body); w.Code != code {
			t.Errorf("%.90s: %d, want %d (%s)", body, w.Code, code, w.Body)
		}
	}
	if w := a.do("GET", crawlersPath+"?site=nope.example", write, "", ""); w.Code != 404 {
		t.Errorf("unknown site: %d", w.Code)
	}
	if e := a.h.App.Crawlers.Entry("shop.example"); e != nil {
		t.Fatalf("a refused write stored %+v", e)
	}
	// A bot rule set and taken back with inherit.
	if w := a.do("POST", crawlersPath, write, "application/json", `{"website":"shop.example","bot":"gptbot","action":"block","reason":"x"}`); w.Code != 200 {
		t.Fatalf("bot block: %d %s", w.Code, w.Body)
	}
	if w := a.do("POST", crawlersPath, write, "application/json", `{"website":"shop.example","bot":"gptbot","action":"inherit","reason":"x"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"bots":{}`) {
		t.Fatalf("bot inherit: %d %s", w.Code, w.Body)
	}
	if code := crawlerVisit(t, a, uaGPTBot, "198.51.100.40"); code != 200 {
		t.Fatalf("after inherit: %d", code)
	}
}
