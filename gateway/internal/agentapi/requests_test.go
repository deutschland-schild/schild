//go:build !release

package agentapi_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
)

// TestAgentRequests: queryRequests, getRequestContext and getBotOverview
// for agents (v0.5, MVP-22): p1- pseudonyms instead of visitor keys, the
// client address as the ring holds it, the ip filter and the agent bounds.
func TestAgentRequests(t *testing.T) {
	a := newAgent(t, "")
	ip := "203.0.113.77"
	a.h.Visit("GET", "/", ip, "", "")
	if r := a.h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", ip, "", ""); r.StatusCode != 403 {
		t.Fatalf("xss: %d", r.StatusCode)
	}
	a.h.Flush()
	from := time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	b := a.get("/agent/v0/requests?from=" + from + "&to=" + to)
	validate(t, "gateway-agent.openapi.yaml", "AgentRequestPage", b)
	var p contractapi.RequestPage
	_ = json.Unmarshal(b, &p)
	if len(p.Items) != 2 || p.Items[0].IP != ip || strings.Contains(string(b), `"v1-`) {
		t.Fatalf("requests: %s", b)
	}
	var ev string
	for _, it := range p.Items {
		if it.Outcome == "blocked_waf" {
			ev = it.EventID
		}
		if !strings.HasPrefix(it.Visitor, "p1-") {
			t.Fatalf("visitor %q", it.Visitor)
		}
	}
	if p.Items[0].Visitor != p.Items[1].Visitor {
		t.Fatal("one visitor, two pseudonyms")
	}
	b = a.get("/agent/v0/requests/context/" + ev)
	validate(t, "gateway-agent.openapi.yaml", "AgentRequestContext", b)
	var c contractapi.RequestContext
	_ = json.Unmarshal(b, &c)
	if c.Anchor == nil || c.Anchor.EventID != ev || len(c.VisitorRequests) != 2 || c.Anchor.IP != ip {
		t.Fatalf("context: %s", b)
	}
	b = a.get("/agent/v0/requests/bots")
	validate(t, "client-dashboard.openapi.yaml", "BotOverview", b)
	code, out, _ := a.do("GET", "/agent/v0/requests?from="+from+"&to="+to+"&outcome=blocked_waf", a.token, "", nil)
	if code != 200 || !strings.Contains(string(out), `blocked_waf`) {
		t.Fatalf("queryRequests: %d %s", code, out)
	}
	// The ip filter: this client's requests, nobody else's, and an address only.
	a.h.Visit("GET", "/other", "198.51.100.9", "", "")
	a.h.Flush()
	for q, want := range map[string]int{"&ip=" + ip: 2, "&ip=198.51.100.9": 1, "&ip=192.0.2.1": 0} {
		b = a.get("/agent/v0/requests?from=" + from + "&to=" + to + q)
		_ = json.Unmarshal(b, &p)
		if len(p.Items) != want {
			t.Errorf("requests%s: %d items, want %d", q, len(p.Items), want)
		}
		var ev contractapi.EventPage
		_ = json.Unmarshal(a.get("/agent/v0/events?from="+from+"&to="+to+q), &ev)
		for _, e := range ev.Items {
			if e.IP != q[4:] {
				t.Errorf("events%s: event of %s", q, e.IP)
			}
		}
		if want == 2 && len(ev.Items) == 0 {
			t.Errorf("events%s: none", q)
		}
	}
	for _, path := range []string{"/requests", "/events"} {
		if code, out, _ := a.do("GET", "/agent/v0"+path+"?from="+from+"&to="+to+"&ip=nope", a.token, "", nil); code != 400 {
			t.Errorf("%s with a bad ip: %d %s", path, code, out)
		}
	}
}
