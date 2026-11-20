package events

import (
	"regexp"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func client() Client {
	return Client{IP: "198.51.100.23", Port: 40000, Attribution: "tcp_peer", Geo: Geo{Country: "DE", City: "Berlin", ASN: 64496, ASOrg: "Example Net", NetClass: "residential"}}
}

func TestRequestEvents(t *testing.T) {
	req := Request{
		RequestID: "req-0001aaaa", Client: client(), Method: "GET", Host: "verein.example", Path: "/", Status: 200,
		Rules: []MatchedRule{}, Score: 0, Outcome: "passed", Mode: "observe", DurationMS: 1.1, WAFMS: 0.2, Sampled: true,
	}
	if err := New(RequestEvaluated, "web-1", now, req).Validate(); err != nil {
		t.Fatal(err)
	}
	req.Outcome, req.Status = "blocked", 403
	if err := New(RequestBlocked, "web-1", now, req).Validate(); contract.CodeOf(err) != contract.CodeSchema {
		t.Fatalf("blocked without incident must fail: %v", err)
	}
	req.Incident = NewIncident()
	req.Client.IP = "2001:db8::abcd"
	if err := New(RequestBlocked, "web-1", now, req).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOtherEvents(t *testing.T) {
	c := client()
	cases := []*Event{
		New(RequestUnblocked, "web-1", now, Unblocked{Incident: "K7QM-4XWD", RequestID: "req-0001aaaa", By: "operator", FalsePositive: true}),
		New(SessionFlagged, "web-1", now, SessionFlaggedData{SessionID: "s_abcdefgh", Client: client(), Reason: "rate", Requests: 500, WindowS: 60}),
		New(EnvironmentChanged, "web-1", now, EnvironmentChangedData{Kind: "runtime", Name: "php", FromVersion: "8.2.10", ToVersion: "8.2.11"}),
		New(EnvironmentAnomaly, "web-1", now, EnvironmentAnomalyData{Level: "elevated", Index: 42, Factors: []Factor{{Name: "cpu_without_load", Points: 30}}}),
		New(AdvisoryAssessed, "web-1", now, AdvisoryAssessedData{AdvisoryID: "CVE-2026-12345", Result: "unclear"}),
		New(BehaviourTriggered, "web-1", now, BehaviourTriggeredData{Scenario: "login_bruteforce", Scope: "client", Client: &c, KeyBits: 32, Route: "/wp-login.php", Preset: "wordpress",
			Count: 6, Threshold: 5, WindowS: 60, Mode: "block", Action: "block", WouldAction: "block", Level: 1, DurationS: 900, Until: "2026-10-26T12:15:00Z", Incident: "K7QM-4XWD"}),
		New(BehaviourTriggered, "web-1", now, BehaviourTriggeredData{Scenario: "credential_stuffing", Scope: "site", Count: 120, Threshold: 50, WindowS: 600, Mode: "observe", Action: "observe", Reason: "site_scope"}),
		New(DashboardAccessReset, "web-1", now, AccessReset{Via: "host_cli", UsersRemoved: 1, SessionsEnded: 2}),
		New(IncidentExported, "web-1", now, IncidentExportedData{Incident: "K7QM-4XWD", By: "admin", Events: 3}),
		New(RateLimitExceeded, "web-1", now, RateLimitExceededData{LimitID: "preset-wordpress-login", Source: "preset", Route: "/wp-login.php", Methods: []string{"POST"}, Client: c, KeyBits: 32,
			Limit: 10, PerS: 60, Burst: 10, Count: 3, Mode: "block", Action: "block", RetryAfterS: 6}),
	}
	for _, e := range cases {
		if err := e.Validate(); err != nil {
			t.Errorf("%s: %v", e.Type, err)
		}
	}
	if len(Types) != 28 { // D72: rule.received, rule.adopted, rule.dropped, rule.suspended, signal.sent removed; D73: rule.repository_updated, rule.repository_switched, rule.disabled, rule.enabled, rule.approved, rule.rejected; D42: block.set, block.lifted; D51: incident.exported; D54: rule.exception_set, rule.exception_removed; D56: access.protection_set, access.protection_removed, access.login, access.prefix_locked; D57: crawler.policy_set
		t.Fatal("type list")
	}
}

func TestIncident(t *testing.T) {
	re := regexp.MustCompile(`^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		s := NewIncident()
		if !re.MatchString(s) {
			t.Fatalf("bad incident %q", s)
		}
		seen[s] = true
	}
	if len(seen) < 990 {
		t.Fatal("incident numbers repeat too often")
	}
}

// v0.4: a block needs until, duration, level and incident; a site-wide hit
// has no client.
func TestBehaviourEventRules(t *testing.T) {
	c := client()
	block := BehaviourTriggeredData{Scenario: "path_probing", Scope: "client", Client: &c, KeyBits: 32, Count: 25, Threshold: 20, WindowS: 60, Mode: "block", Action: "block"}
	if err := New(BehaviourTriggered, "web-1", now, block).Validate(); contract.CodeOf(err) != contract.CodeSchema {
		t.Fatalf("block without until must fail: %v", err)
	}
	site := BehaviourTriggeredData{Scenario: "credential_stuffing", Scope: "site", Client: &c, KeyBits: 32, Count: 60, Threshold: 50, WindowS: 600, Mode: "observe", Action: "observe"}
	if err := New(BehaviourTriggered, "web-1", now, site).Validate(); contract.CodeOf(err) != contract.CodeSchema {
		t.Fatalf("site scope with client must fail: %v", err)
	}
}
