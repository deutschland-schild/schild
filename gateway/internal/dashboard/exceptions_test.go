//go:build !release

package dashboard_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/schema"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The exceptions of the agent API are readable in the dashboard (D83).
func TestRuleExceptionsList(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	if h.App.Dashboard.Exceptions == nil {
		t.Fatal("the app does not hand its exceptions to the dashboard")
	}
	l := decode[agentapi.ExceptionList](t, expect(t, h, "GET", "/rule-exceptions", nil, 200, "RuleExceptionList"))
	if l.Items == nil || len(l.Items) != 0 || l.Max != agentapi.MaxExceptions {
		t.Fatalf("empty: %+v", l)
	}
	one := agentapi.RuleException{ID: agentapi.ExceptionIDMin, Website: "verein.example", Hosts: []string{"verein.example"}, Path: "/livewire/update",
		Target: "ARGS:json.components.*.updates.body", Repository: "crs", Rules: []string{"932235"}, Reason: "code samples in a text field",
		SetBy: agentapi.SetByAgent, TokenID: "tok_000000000001", TokenLabel: "maintenance-agent", Created: "2026-10-28T08:40:00Z"}
	h.App.Dashboard.Exceptions = func(context.Context) []agentapi.RuleException { return []agentapi.RuleException{one} }
	l = decode[agentapi.ExceptionList](t, expect(t, h, "GET", "/rule-exceptions", nil, 200, "RuleExceptionList"))
	if len(l.Items) != 1 || l.Items[0].ID != one.ID || l.Items[0].Rules[0] != "932235" {
		t.Fatalf("one: %+v", l)
	}
}

const sqlText = "message=1%27+OR+%271%27%3D%271"

func contact(h *apptest.Harness, field string) int {
	body := sqlText
	if field != "message" {
		body = strings.Replace(sqlText, "message", field, 1)
	}
	return h.Visit("POST", "/kontakt", "198.51.100.20", "application/x-www-form-urlencoded", body).StatusCode
}

// The operator sets and removes an exception in the dashboard (D84): it holds
// for the named field only, is listed for agents too and leaves an audit event.
func TestRuleExceptionSetAndRemovedInTheDashboard(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "autoblock"})
	h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{"shop.example"}}))
	h.Login()
	if got := contact(h, "message"); got != 403 {
		t.Fatalf("before: %d", got)
	}
	req := agentapi.ExceptionRequest{Website: "shop.example", Path: "/kontakt", Target: "ARGS:message", Repository: "crs", Rules: []string{"942100"},
		Reason: "SQL examples in the contact form"}
	x := decode[agentapi.RuleException](t, expect(t, h, "POST", "/rule-exceptions", req, 200, "RuleException"))
	if x.ID != agentapi.ExceptionIDMin || x.SetBy != agentapi.SetByDashboard || x.TokenID != "" || x.TokenLabel != "" || x.Reason != req.Reason {
		t.Fatalf("created: %+v", x)
	}
	if got := contact(h, "message"); got != 200 {
		t.Fatalf("the named field after the exception: %d", got)
	}
	if got := contact(h, "other"); got != 403 {
		t.Fatalf("another field after the exception: %d", got)
	}
	// The same again stands, and the list knows one.
	again := decode[agentapi.RuleException](t, expect(t, h, "POST", "/rule-exceptions", req, 200, "RuleException"))
	l := decode[agentapi.ExceptionList](t, expect(t, h, "GET", "/rule-exceptions", nil, 200, "RuleExceptionList"))
	if again.ID != x.ID || len(l.Items) != 1 {
		t.Fatalf("again %+v, list %+v", again, l)
	}

	l = decode[agentapi.ExceptionList](t, expect(t, h, "DELETE", fmt.Sprintf("/rule-exceptions/%d", x.ID), nil, 200, "RuleExceptionList"))
	if len(l.Items) != 0 {
		t.Fatalf("after the removal: %+v", l)
	}
	if got := contact(h, "message"); got != 403 {
		t.Fatalf("after the removal: %d", got)
	}
	expect(t, h, "DELETE", fmt.Sprintf("/rule-exceptions/%d", x.ID), nil, 404, "Problem")

	h.Flush()
	for _, typ := range []string{events.RuleExceptionSet, events.RuleExceptionRemoved} {
		rows, _, _ := h.App.Store.ListEvents(context.Background(), store.EventFilter{Type: typ}, 0, 10)
		if len(rows) != 1 || !strings.Contains(string(rows[0].Body), `"actor":"dashboard"`) || strings.Contains(string(rows[0].Body), "token_") {
			t.Fatalf("%s: %d events", typ, len(rows))
		}
		var doc any
		if err := json.Unmarshal(rows[0].Body, &doc); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate("events", doc); err != nil {
			t.Fatalf("%s is not an event of the contract: %v", typ, err)
		}
	}
}

// One rule comes out of an exception in the dashboard (D86): the field is
// checked with that rule again, the exception stands for the others.
func TestRuleExceptionRuleTakenOutInTheDashboard(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "autoblock"})
	h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{"shop.example"}}))
	h.Login()
	req := agentapi.ExceptionRequest{Website: "shop.example", Path: "/kontakt", Target: "ARGS:message", Repository: "crs", Rules: []string{"932235", "942100"},
		Reason: "SQL examples in the contact form"}
	x := decode[agentapi.RuleException](t, expect(t, h, "POST", "/rule-exceptions", req, 200, "RuleException"))
	if got := contact(h, "message"); got != 200 {
		t.Fatalf("with the exception: %d", got)
	}
	expect(t, h, "DELETE", fmt.Sprintf("/rule-exceptions/%d/rules/941100", x.ID), nil, 404, "Problem")
	expect(t, h, "DELETE", fmt.Sprintf("/rule-exceptions/%d/rules/942100", x.ID+1), nil, 404, "Problem")
	l := decode[agentapi.ExceptionList](t, expect(t, h, "DELETE", fmt.Sprintf("/rule-exceptions/%d/rules/942100", x.ID), nil, 200, "RuleExceptionList"))
	if len(l.Items) != 1 || l.Items[0].ID != x.ID || strings.Join(l.Items[0].Rules, ",") != "932235" || l.Items[0].Reason != req.Reason || l.Items[0].Created != x.Created {
		t.Fatalf("after taking 942100 out: %+v", l)
	}
	if got := contact(h, "message"); got != 403 {
		t.Fatalf("942100 checks the field again: %d", got)
	}
	l = decode[agentapi.ExceptionList](t, expect(t, h, "DELETE", fmt.Sprintf("/rule-exceptions/%d/rules/932235", x.ID), nil, 200, "RuleExceptionList"))
	if len(l.Items) != 0 {
		t.Fatalf("the last rule out removes the exception: %+v", l)
	}
	h.Flush()
	rows, _, _ := h.App.Store.ListEvents(context.Background(), store.EventFilter{Type: events.RuleExceptionRemoved}, 0, 10)
	if len(rows) != 2 {
		t.Fatalf("%d removed events", len(rows))
	}
	for _, r := range rows {
		var doc any
		if err := json.Unmarshal(r.Body, &doc); err != nil || schema.Validate("events", doc) != nil {
			t.Fatalf("not an event of the contract: %s", r.Body)
		}
		if !strings.Contains(string(r.Body), `"rules":["942100"]`) && !strings.Contains(string(r.Body), `"rules":["932235"]`) {
			t.Fatalf("names more than the rule taken out: %s", r.Body)
		}
	}
}

// What the dashboard refuses, with the field named.
func TestRuleExceptionRefusedInTheDashboard(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "autoblock"})
	h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{"shop.example"}}))
	h.Login()
	good := agentapi.ExceptionRequest{Website: "shop.example", Path: "/kontakt", Target: "ARGS:message", Repository: "crs", Rules: []string{"942100"}, Reason: "why"}
	for name, c := range map[string]struct {
		change  func(*agentapi.ExceptionRequest)
		status  int
		code    string
		pointer string
	}{
		"no reason":        {func(r *agentapi.ExceptionRequest) { r.Reason = "" }, 400, "invalid", "/reason"},
		"whole collection": {func(r *agentapi.ExceptionRequest) { r.Target = "ARGS" }, 400, "invalid", "/target"},
		"only wildcards":   {func(r *agentapi.ExceptionRequest) { r.Target = "ARGS:*" }, 400, "invalid", "/target"},
		"relative path":    {func(r *agentapi.ExceptionRequest) { r.Path = "kontakt" }, 400, "invalid", "/path"},
		"no rules":         {func(r *agentapi.ExceptionRequest) { r.Rules = nil }, 400, "invalid", "/rules"},
		"not a crs rule":   {func(r *agentapi.ExceptionRequest) { r.Rules = []string{"1000001"} }, 400, "invalid", "/rules"},
		"a rule not here":  {func(r *agentapi.ExceptionRequest) { r.Rules = []string{"942999"} }, 400, agentapi.CodeUnknownRule, ""},
		"local":            {func(r *agentapi.ExceptionRequest) { r.Repository = "local" }, 409, agentapi.CodeNotSupported, ""},
		"unknown website":  {func(r *agentapi.ExceptionRequest) { r.Website = "nowhere.example" }, 404, "not_found", ""},
	} {
		req := good
		c.change(&req)
		p := decode[dashboard.Problem](t, expect(t, h, "POST", "/rule-exceptions", req, c.status, "Problem"))
		if p.Code != c.code || (c.pointer != "" && (len(p.Errors) != 1 || p.Errors[0].Pointer != c.pointer)) {
			t.Fatalf("%s: %+v", name, p)
		}
	}
	if l := decode[agentapi.ExceptionList](t, expect(t, h, "GET", "/rule-exceptions", nil, 200, "RuleExceptionList")); len(l.Items) != 0 {
		t.Fatalf("a refused exception stands: %+v", l)
	}
}
