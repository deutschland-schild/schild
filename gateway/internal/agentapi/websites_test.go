//go:build !release

package agentapi_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// TestAgentWebsites: listWebsites and getWebsite answer like the client
// dashboard and the site filter works on events and incidents (v0.5, D36).
func TestAgentWebsites(t *testing.T) {
	a := newAgent(t, "")
	a.h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{"shop.example", "www.shop.example"}}))
	if r := a.h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "203.0.113.5", "", ""); r.StatusCode != 403 {
		t.Fatalf("xss: %d", r.StatusCode)
	}
	a.h.Flush()
	b := a.get("/agent/v0/websites")
	validate(t, "client-dashboard.openapi.yaml", "WebsiteList", b)
	var l websites.List
	_ = json.Unmarshal(b, &l)
	if len(l.Websites) != 1 || l.Websites[0].ID != "shop.example" || l.Websites[0].Source != websites.SourceProxy {
		t.Fatalf("websites: %s", b)
	}
	b = a.get("/agent/v0/websites/shop.example")
	validate(t, "client-dashboard.openapi.yaml", "WebsiteDetail", b)
	if !strings.Contains(string(b), `"traffic_24h_partial":true`) || !strings.Contains(string(b), `"traffic_24h_since":`) {
		t.Fatalf("detail of a fresh start without traffic_24h_partial/_since: %s", b)
	}
	if code, _, _ := a.do("GET", "/agent/v0/websites/nope.example", a.token, "", nil); code != 404 {
		t.Fatalf("unknown website: %d", code)
	}
	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	b = a.get("/agent/v0/events?site=shop.example&from=" + from + "&to=" + to)
	validate(t, "gateway-agent.openapi.yaml", "AgentEventPage", b)
	if !strings.Contains(string(b), `"site":"shop.example"`) {
		t.Fatalf("events without site: %s", b)
	}
	b = a.get("/agent/v0/incidents?site=shop.example&from=" + from + "&to=" + to)
	validate(t, "gateway-agent.openapi.yaml", "AgentIncidentPage", b)
	if !strings.Contains(string(b), `"sites_affected":{"sites":["shop.example"],"count":1,"total":1}`) {
		t.Fatalf("incident without site: %s", b)
	}
	if code, _, _ := a.do("GET", "/agent/v0/events?site=nope.example&from="+from+"&to="+to, a.token, "", nil); code != 400 {
		t.Fatalf("unknown site filter: %d", code)
	}
	code, out, _ := a.do("GET", "/agent/v0/websites/shop.example", a.token, "", nil)
	if code != 200 || !strings.Contains(string(out), `"id":"shop.example"`) {
		t.Fatalf("getWebsite: %d %s", code, out)
	}
	code, out, _ = a.do("GET", "/agent/v0/websites", a.token, "", nil)
	if code != 200 || !strings.Contains(string(out), `"websites"`) {
		t.Fatalf("listWebsites: %d %s", code, out)
	}
}
