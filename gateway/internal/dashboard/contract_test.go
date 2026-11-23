//go:build !release

package dashboard_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/contract/schema"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/hosts"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
)

const apiDoc = "../../../contracts/api/client-dashboard.openapi.yaml"

var (
	compOnce sync.Once
	comp     *jsonschema.Compiler
	compErr  error
	compiled sync.Map
)

func compiler(t testing.TB) *jsonschema.Compiler {
	compOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		for rel, b := range schema.Files() {
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				compErr = err
				return
			}
			if err := c.AddResource(schema.BaseURL+rel, doc); err != nil {
				compErr = err
				return
			}
		}
		b, err := os.ReadFile(apiDoc)
		if err != nil {
			compErr = err
			return
		}
		j, err := config.YAMLToJSON(b)
		if err != nil {
			compErr = err
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(j))
		if err != nil {
			compErr = err
			return
		}
		compErr = c.AddResource(schema.BaseURL+"api/client-dashboard.openapi.yaml", doc)
		comp = c
	})
	if compErr != nil {
		t.Skipf("contracts/api not available: %v", compErr)
	}
	return comp
}

func validate(t testing.TB, name string, body []byte) {
	t.Helper()
	var s *jsonschema.Schema
	if v, ok := compiled.Load(name); ok {
		s = v.(*jsonschema.Schema)
	} else {
		var err error
		s, err = compiler(t).Compile(schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/" + name)
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		compiled.Store(name, s)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("%s: not JSON: %v: %s", name, err, body)
	}
	if err := s.Validate(v); err != nil {
		t.Errorf("response does not match %s: %v\n%s", name, err, trunc(body))
	}
}

func trunc(b []byte) string {
	if len(b) > 1500 {
		return string(b[:1500]) + "..."
	}
	return string(b)
}

// TestFixturesRoundTrip: every client fixture decodes into the Go type of
// its schema without unknown fields and encodes back to the same JSON.
func TestFixturesRoundTrip(t *testing.T) {
	// Fixtures are named <operationId>[.variant].json (contracts v0.1).
	types := map[string]struct {
		schema string
		proto  any
	}{
		"getOverview": {"Overview", dashboard.Overview{}}, "listEvents": {"EventPage", dashboard.EventPage{}}, "getEvent": {"EventDetail", dashboard.EventDetail{}},
		"getIncident": {"Incident", dashboard.Incident{}}, "exportIncident": {"IncidentExport", dashboard.IncidentExport{}}, "listRules": {"RulePage", dashboard.RulePage{}}, "getRule": {"RuleDetail", dashboard.RuleDetail{}},
		"listAllowlist": {"AllowlistPage", dashboard.AllowlistPage{}}, "getMyIP": {"MyIP", dashboard.MyIP{}},
		"getSettings": {"Settings", dashboard.Settings{}}, "getSession": {"Session", dashboard.Session{}}, "privacySearch": {"PrivacySummary", dashboard.PrivacySummary{}},
		"privacyDelete": {"PrivacyDeleteResult", dashboard.PrivacyDeleteResult{}},
		// v0.3 (MVP-11): types of the hosts package, served unchanged.
		"listHosts": {"HostPage", hosts.HostPage{}}, "getHost": {"HostDetail", hosts.HostDetail{}}, "acceptHostFinding": {"HostDetail", hosts.HostDetail{}}, "reopenHostFinding": {"HostDetail", hosts.HostDetail{}},
		"runLocalCheck": {"LocalCheckRun", hosts.LocalCheckRun{}},
		"listAgents":    {"AgentPage", hosts.AgentPage{}}, "createEnrolment": {"Enrolment", hosts.Enrolment{}}, "confirmAgent": {"Agent", hosts.Agent{}},
		"revokeAgent": {"Agent", hosts.Agent{}},
		// v0.4 (MVP-17)
		"listBehaviourHits": {"BehaviourHitPage", dashboard.BehaviourHitPage{}}, "getBehaviourHit": {"BehaviourHitDetail", dashboard.BehaviourHitDetail{}},
		"getBehaviourSettings": {"BehaviourSettings", dashboard.BehaviourSettings{}}, "listRateLimits": {"RateLimitPage", dashboard.RateLimitPage{}},
		"createRateLimit": {"RateLimit", dashboard.RateLimit{}}, "dryRunRateLimit": {"RateLimitDryRun", dashboard.RateLimitDryRun{}},
		"releaseClient": {"ReleaseResult", dashboard.ReleaseResult{}},
		"listWaves":     {"WavePage", dashboard.WavePage{}}, "getWave": {"WaveDetail", dashboard.WaveDetail{}}, "endWave": {"Wave", dashboard.Wave{}},
		"getDistributedSettings": {"DistributedSettings", dashboard.DistributedSettings{}},
		// v0.5 (D36): website-first dashboard; contract types served unchanged
		// except incidents and the agent call log.
		"listWebsites": {"WebsiteList", websites.List{}}, "getWebsite": {"WebsiteDetail", websites.Detail{}},
		"getWebsiteKpis": {"WebsiteKpis", websites.Kpis{}}, "getWebsiteRealtime": {"WebsiteRealtime", websites.Realtime{}},
		"listAnnotations": {"AnnotationList", websites.AnnotationList{}}, "listAlerts": {"AlertFeed", websites.AlertFeed{}},
		"listIncidents": {"IncidentPage", dashboard.IncidentPage{}}, "listAgentCalls": {"AgentCallLog", dashboard.AgentCallLog{}},
		"getAgentAPI": {"AgentAPIState", dashboard.AgentAPIState{}}, "setAgentAPI": {"AgentAPIState", dashboard.AgentAPIState{}},
		// v0.5 D36 fix round 1: served by the monitoring package.
		"getTrafficBreakdown": {"TrafficBreakdown", monitoring.TrafficBreakdown{}},
		// v0.5 (D39, MVP-26)
		// D73: rule repositories and rules.
		"listRuleRepositories": {"RuleRepositoryList", dashboard.RuleRepositoryList{}}, "getRuleRepository": {"RuleRepository", dashboard.RuleRepository{}},
		"updateRuleRepositorySettings": {"RuleRepository", dashboard.RuleRepository{}},
		"updateRuleRepository":         {"RuleRepository", dashboard.RuleRepository{}}, "syncRuleRepository": {"RuleRepository", dashboard.RuleRepository{}},
		"resetRuleRepository": {"RuleRepository", dashboard.RuleRepository{}}, "updateRule": {"RuleDetail", dashboard.RuleDetail{}},

		// D83: the exceptions of the agent API, read only.
		"listRuleExceptions":  {"RuleExceptionList", agentapi.ExceptionList{}},
		"createRuleException": {"RuleException", agentapi.RuleException{}}, "removeRuleException": {"RuleExceptionList", agentapi.ExceptionList{}},
		"removeRuleExceptionRule": {"RuleExceptionList", agentapi.ExceptionList{}},
		// D87: the address blocks that run.
		"listBlocks": {"BlockList", dashboard.BlockList{}},
		// D105: the group of gateways.
		"getGroupStatus": {"GroupStatus", dashboard.GroupStatus{}},
		"createBlock":    {"RunningBlock", dashboard.RunningBlock{}},
		// D56 (MVP-14 step 1)
		"getAccessProtection": {"AccessProtectionState", dashboard.AccessProtectionState{}}, "setAccessProtection": {"AccessProtectionState", dashboard.AccessProtectionState{}},
		// D98
		"setMaintenance": {"AccessProtectionState", dashboard.AccessProtectionState{}},
		// D57 (MVP-29)
		"getCrawlerPolicy": {"CrawlerPolicyState", crawlers.State{}}, "setCrawlerPolicy": {"CrawlerPolicyState", crawlers.State{}},
	}
	files, _ := filepath.Glob("../../../contracts/api/fixtures/client/*.json")
	if len(files) == 0 {
		t.Skip("no fixtures")
	}
	for _, f := range files {
		op, variant, _ := strings.Cut(strings.TrimSuffix(filepath.Base(f), ".json"), ".")
		entry, ok := types[op]
		if strings.HasPrefix(variant, "problem") {
			entry, ok = struct {
				schema string
				proto  any
			}{"Problem", dashboard.Problem{}}, true
		}
		if !ok {
			t.Errorf("no Go type for fixture %s", f)
			continue
		}
		name, proto := entry.schema, entry.proto
		raw, _ := os.ReadFile(f)
		validate(t, name, raw)
		v := reflect.New(reflect.TypeOf(proto)).Interface()
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		out, _ := json.Marshal(v)
		validate(t, name, out)
		if !jsonEqual(raw, out) {
			t.Errorf("%s: round trip differs\nfixture: %s\ngo:      %s", filepath.Base(f), compact(raw), out)
		}
	}
}

func compact(b []byte) string {
	var buf bytes.Buffer
	_ = json.Compact(&buf, b)
	return buf.String()
}

// jsonEqual compares semantically; nulls and empty arrays in the fixture
// may be omitted by Go and vice versa only where the schema allows it
// (checked by validate above).
func jsonEqual(a, b []byte) bool {
	var x, y any
	_ = json.Unmarshal(a, &x)
	_ = json.Unmarshal(b, &y)
	return reflect.DeepEqual(strip(x), strip(y))
}

func strip(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			if x == nil {
				continue
			}
			if arr, ok := x.([]any); ok && len(arr) == 0 {
				continue
			}
			out[k] = strip(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = strip(x)
		}
		return out
	}
	return v
}

func decode[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return v
}

func expect(t *testing.T, h *apptest.Harness, method, path string, body any, status int, schemaName string) []byte {
	t.Helper()
	code, b := h.API(method, path, body)
	if code != status {
		t.Fatalf("%s %s: got %d want %d: %s", method, path, code, status, trunc(b))
	}
	if schemaName != "" {
		validate(t, schemaName, b)
	}
	return b
}

func TestAuthAndSecurity(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	sess := decode[dashboard.Session](t, expect(t, h, "GET", "/auth/session", nil, 200, "Session"))
	if !sess.FirstRun || sess.Authenticated {
		t.Fatalf("%+v", sess)
	}
	expect(t, h, "GET", "/overview", nil, 401, "Problem")
	// The first password always needs the setup code (D40), also from
	// loopback, which this test client is.
	req, _ := http.NewRequest("POST", h.Dash.URL+"/api/v0/auth/setup", strings.NewReader(`{"password":"korrekt-pferd-batterie"}`))
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("setup from loopback without code: %d", resp.StatusCode)
	}
	resp.Body.Close()
	req, _ = http.NewRequest("POST", h.Dash.URL+"/api/v0/auth/setup", strings.NewReader(`{"password":"korrekt-pferd-batterie"}`))
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("remote setup without code: %d", resp.StatusCode)
	}
	resp.Body.Close()
	req, _ = http.NewRequest("POST", h.Dash.URL+"/api/v0/auth/setup", strings.NewReader(`{"password":"short","setup_code":"`+h.App.SetupCode()+`"}`))
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 400 {
		t.Fatalf("short password: %d", resp.StatusCode)
	}
	resp.Body.Close()
	h.Login()
	// Cookie flags and headers.
	req, _ = http.NewRequest("POST", h.Dash.URL+"/api/v0/auth/login", strings.NewReader(`{"password":"korrekt-pferd-batterie"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	sc := resp.Header.Get("Set-Cookie")
	if !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "SameSite=Strict") || !strings.Contains(sc, "schild_session=") {
		t.Fatalf("cookie flags: %s", sc)
	}
	for _, hd := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"} {
		if resp.Header.Get(hd) == "" {
			t.Errorf("missing %s", hd)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") && strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Fatalf("csp: %s", csp)
	}
	expect(t, h, "POST", "/auth/setup", map[string]string{"password": "korrekt-pferd-batterie-2"}, 409, "Problem")
	// CSRF: missing or wrong token.
	good := h.CSRF
	h.CSRF = ""
	expect(t, h, "POST", "/allowlist/mine", map[string]string{"label": "x"}, 403, "Problem")
	h.CSRF = strings.Repeat("0", 32)
	expect(t, h, "POST", "/allowlist/mine", map[string]string{"label": "x"}, 403, "Problem")
	h.CSRF = good
	// Login rate limit: at most 5 failures (the failed setup above counts too).
	limited := false
	for i := 0; i < 6 && !limited; i++ {
		req, _ := http.NewRequest("POST", h.Dash.URL+"/api/v0/auth/login", strings.NewReader(`{"password":"wrong"}`))
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		switch resp.StatusCode {
		case 401:
		case 429:
			limited = true
		default:
			t.Fatalf("wrong password %d: %d", i, resp.StatusCode)
		}
	}
	if !limited {
		t.Fatal("no rate limit after 6 wrong passwords")
	}
	req, _ = http.NewRequest("POST", h.Dash.URL+"/api/v0/auth/login", strings.NewReader(`{"password":"korrekt-pferd-batterie"}`))
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("rate limit: %d", resp.StatusCode)
	}
	// Password change ends other sessions and keeps this one.
	expect(t, h, "POST", "/auth/password", map[string]string{"current_password": "wrong", "new_password": "neues-langes-passwort"}, 401, "Problem")
	expect(t, h, "POST", "/auth/password", map[string]string{"current_password": h.Password, "new_password": "neues-langes-passwort"}, 204, "")
	s2 := decode[dashboard.Session](t, expect(t, h, "GET", "/auth/session", nil, 200, "Session"))
	if !s2.Authenticated {
		t.Fatal("session lost after password change")
	}
	h.CSRF = s2.CSRFToken
	expect(t, h, "POST", "/auth/logout", nil, 204, "")
	expect(t, h, "GET", "/settings", nil, 401, "Problem")
	expect(t, h, "GET", "/nope", nil, 404, "Problem")
	// UI: placeholder or app, never a third-party URL.
	resp, _ = http.Get(h.Dash.URL + "/")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || bytes.Contains(b, []byte("https://")) {
		t.Fatalf("ui: %d", resp.StatusCode)
	}
}

func TestAPIContract(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	// Traffic.
	if r := h.Visit("GET", "/", "198.51.100.23", "", ""); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	blocked := h.Visit("GET", "/?id=1%27%20OR%20%271%27%3D%271%27--", "203.0.113.42", "", "")
	if blocked.StatusCode != 403 {
		t.Fatalf("sqli: %d", blocked.StatusCode)
	}
	incident := blocked.Header.Get("X-Schild-Incident")
	if r := h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "2001:db8::17", "", ""); r.StatusCode != 403 {
		t.Fatalf("xss: %d", r.StatusCode)
	}
	h.Visit("POST", "/wp-login.php", "203.0.113.43", "application/x-www-form-urlencoded", "log=admin&pwd=%27%20or%201%3D1--")
	h.Flush()

	// Overview, events, detail.
	ov := decode[dashboard.Overview](t, expect(t, h, "GET", "/overview", nil, 200, "Overview"))
	if ov.Counters24h.Blocked < 2 || ov.Rules.CRSVersion == "" {
		t.Fatalf("%+v", ov)
	}
	page := decode[dashboard.EventPage](t, expect(t, h, "GET", "/events?limit=2", nil, 200, "EventPage"))
	if len(page.Items) != 2 || page.NextCursor == nil {
		t.Fatalf("paging: %+v", page)
	}
	expect(t, h, "GET", "/events?cursor="+*page.NextCursor+"&limit=500", nil, 200, "EventPage")
	for _, q := range []string{"?ip=203.0.113.42", "?ip=203.0.113.0/24", "?country=NL", "?asn=64500", "?outcome=blocked", "?rule=942100",
		"?type=schild.request.blocked.v1", "?path=/wp", "?q=wp-login", "?from=2020-01-01T00:00:00Z&to=2099-01-01T00:00:00Z"} {
		p := decode[dashboard.EventPage](t, expect(t, h, "GET", "/events"+q, nil, 200, "EventPage"))
		if len(p.Items) == 0 {
			t.Errorf("filter %s returned nothing", q)
		}
	}
	for _, q := range []string{"?limit=0", "?limit=501", "?outcome=nope", "?ip=nope", "?country=nl", "?asn=-1", "?from=yesterday", "?cursor=xyz", "?type=bad"} {
		expect(t, h, "GET", "/events"+q, nil, 400, "Problem")
	}
	all := decode[dashboard.EventPage](t, expect(t, h, "GET", "/events?outcome=blocked", nil, 200, "EventPage"))
	det := expect(t, h, "GET", "/events/"+all.Items[0].ID, nil, 200, "EventDetail")
	if !bytes.Contains(det, []byte(`"ip":"`)) {
		t.Fatal("local event without the full IP (E7)")
	}
	expect(t, h, "GET", "/events/00000000-0000-4000-8000-000000000000", nil, 404, "Problem")

	// Incident lookup and unblock with allowlist.
	inc := decode[dashboard.Incident](t, expect(t, h, "GET", "/incidents/"+incident, nil, 200, "Incident"))
	if inc.Status != "blocked" || inc.Request.IP != "203.0.113.42" {
		t.Fatalf("%+v", inc)
	}
	expect(t, h, "GET", "/incidents/AAAA-AAAA", nil, 404, "Problem")
	// D38: two blocks of one client, rule and minute are one incident with
	// count 2 (a pair straddling a minute boundary is retried once).
	for try := 0; ; try++ {
		sqli := "/?id=1%27%20OR%20%271%27%3D%271%27--"
		a1 := h.Visit("GET", sqli, "203.0.113.44", "", "").Header.Get("X-Schild-Incident")
		a2 := h.Visit("GET", sqli, "203.0.113.44", "", "").Header.Get("X-Schild-Incident")
		if a1 == "" || a2 == "" || (a1 != a2 && try > 0) {
			t.Fatalf("aggregated block pages: %q %q", a1, a2)
		}
		if a1 != a2 {
			continue
		}
		// The incident writer stores the row and folds the second hit in
		// its next flush (every 500 ms): flush it now.
		h.Flush()
		var agg dashboard.Incident
		h.WaitFor("aggregated incident count 2", func() bool {
			if code, _ := h.API("GET", "/incidents/"+a1, nil); code == 404 {
				return false
			}
			agg = decode[dashboard.Incident](t, expect(t, h, "GET", "/incidents/"+a1, nil, 200, "Incident"))
			return agg.Count == 2
		})
		if agg.FirstSeen == "" || agg.LastSeen < agg.FirstSeen || agg.Request.IP != "203.0.113.44" {
			t.Fatalf("aggregate: %+v", agg)
		}
		break
	}
	if inc.Count != 1 || inc.FirstSeen != inc.Time || inc.LastSeen != inc.Time {
		t.Fatalf("single-request incident: %+v", inc)
	}
	un := decode[dashboard.Incident](t, expect(t, h, "POST", "/incidents/"+incident+"/unblock", map[string]any{"false_positive": true, "allow_ip": true, "allow_ttl": "7d"}, 200, "Incident"))
	if un.Status != "unblocked" || un.AllowlistEntry == nil {
		t.Fatalf("%+v", un)
	}
	expect(t, h, "POST", "/incidents/"+incident+"/unblock", map[string]any{"false_positive": true}, 409, "Problem")
	if r := h.Visit("GET", "/?id=1%27%20OR%20%271%27%3D%271%27--", "203.0.113.42", "", ""); r.StatusCode != 200 {
		t.Fatalf("after unblock + allowlist: %d", r.StatusCode)
	}
	expect(t, h, "POST", "/incidents/"+incident+"/unblock", map[string]any{"false_positive": true, "send_feedback": true}, 400, "Problem")

	// Rules.
	rp := decode[dashboard.RulePage](t, expect(t, h, "GET", "/rules", nil, 200, "RulePage"))
	if len(rp.Items) < 3 {
		t.Fatalf("rules: %+v", rp.Items)
	}
	expect(t, h, "GET", "/rules?repository=crs&status=active", nil, 200, "RulePage")
	expect(t, h, "GET", "/rules?repository=crs&limit=1", nil, 200, "RulePage")
	expect(t, h, "GET", "/rules?status=shadow", nil, 400, "Problem")
	expect(t, h, "GET", "/rules?repository=crowdsec_hub", nil, 400, "Problem")
	expect(t, h, "GET", "/rules/crs/942100", nil, 200, "RuleDetail")
	expect(t, h, "GET", "/rules/crs/1", nil, 404, "Problem")
	expect(t, h, "GET", "/rule-repositories", nil, 200, "RuleRepositoryList")
	expect(t, h, "GET", "/rule-repositories/crs", nil, 200, "RuleRepository")

	// D89: there is no mode to set; a password field is unknown too.
	expect(t, h, "PATCH", "/settings", map[string]any{"mode": "autoblock"}, 400, "Problem")
	expect(t, h, "PATCH", "/settings", map[string]any{"confirm": map[string]string{"password": h.Password}}, 400, "Problem")

	// Settings validation.
	expect(t, h, "GET", "/settings", nil, 200, "Settings")
	expect(t, h, "PATCH", "/settings", map[string]any{"min_independent_operators": 3}, 400, "Problem")
	expect(t, h, "PATCH", "/settings", map[string]any{"retention": map[string]any{"raw_ip_days": 3}}, 200, "Settings")
	expect(t, h, "PATCH", "/settings", map[string]any{"bogus": 1}, 400, "Problem")

	// Allowlist.
	al := decode[dashboard.AllowlistPage](t, expect(t, h, "GET", "/allowlist", nil, 200, "AllowlistPage"))
	if len(al.Items) < 2 {
		t.Fatalf("allowlist %+v", al)
	}
	expect(t, h, "GET", "/allowlist?limit=1", nil, 200, "AllowlistPage")
	expect(t, h, "GET", "/allowlist/mine", nil, 200, "MyIP")
	mine := decode[dashboard.AllowlistEntry](t, expect(t, h, "POST", "/allowlist/mine", map[string]any{"label": "Mein Laptop", "ttl": "7d"}, 201, "AllowlistEntry"))
	expect(t, h, "POST", "/allowlist", map[string]any{"cidr": "0.0.0.0/0", "label": "alle", "level": "no_block"}, 400, "Problem")
	expect(t, h, "POST", "/allowlist", map[string]any{"ip": "198.51.100.200", "label": "Monitoring", "level": "bypass_waf"}, 400, "Problem")
	expect(t, h, "POST", "/allowlist", map[string]any{"ip": "198.51.100.200", "label": "Monitoring", "level": "bypass_waf", "confirm_bypass": true, "ttl": "30d"}, 201, "AllowlistEntry")
	expect(t, h, "POST", "/allowlist", map[string]any{"host": "home.dyndns.example", "label": "Zuhause", "level": "no_block"}, 201, "AllowlistEntry")
	expect(t, h, "DELETE", "/allowlist/"+mine.ID, nil, 204, "")
	expect(t, h, "DELETE", "/allowlist/"+mine.ID, nil, 404, "Problem")
	expect(t, h, "DELETE", "/allowlist/cfg-1", nil, 409, "Problem")

	// Privacy: search, export, delete. Events of the requests above are written in the background; wait until they are
	// stored, otherwise one arriving after the delete shows up in the search afterwards.
	h.Flush()
	ps := decode[dashboard.PrivacySummary](t, expect(t, h, "GET", "/privacy/search?ip=203.0.113.42", nil, 200, "PrivacySummary"))
	if ps.Events == 0 || len(ps.Incidents) != 1 {
		t.Fatalf("%+v", ps)
	}
	expect(t, h, "GET", "/privacy/search?ip=nope", nil, 400, "Problem")
	ex := decode[dashboard.PrivacyExport](t, expect(t, h, "POST", "/privacy/export", map[string]string{"ip": "203.0.113.42"}, 200, "PrivacyExport"))
	if len(ex.Events) != ps.Events {
		t.Fatalf("export %d events, summary %d", len(ex.Events), ps.Events)
	}
	expect(t, h, "POST", "/privacy/delete", map[string]any{"ip": "203.0.113.42", "confirm": false}, 400, "Problem")
	del := decode[dashboard.PrivacyDeleteResult](t, expect(t, h, "POST", "/privacy/delete", map[string]any{"ip": "203.0.113.42", "confirm": true}, 200, "PrivacyDeleteResult"))
	if del.DeletedEvents != ps.Events || del.DeletedAllowlistEntries != 1 {
		t.Fatalf("%+v", del)
	}
	ps2 := decode[dashboard.PrivacySummary](t, expect(t, h, "GET", "/privacy/search?ip=203.0.113.42", nil, 200, "PrivacySummary"))
	if ps2.Events != 0 || len(ps2.Incidents) != 0 || ps2.Allowlisted {
		t.Fatalf("after delete: %+v", ps2)
	}
	expect(t, h, "GET", "/incidents/"+incident, nil, 404, "Problem")
	// Every local event written during this test matched events.schema.json
	// (the harness validates each one; invalid events would be dropped).
	h.Flush()
	if n := testutil.ToFloat64(h.App.Metrics.EventsDropped); n != 0 {
		t.Fatalf("%v local events failed validation or were dropped", n)
	}
}

func TestEventStream(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe"})
	h.Login()
	h.Visit("GET", "/one", "198.51.100.1", "", "")
	h.Flush()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", h.Dash.URL+"/api/v0/events/stream?outcome=would_block", nil)
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal(resp.Header.Get("Content-Type"))
	}
	lines := make(chan string, 100)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	h.Visit("GET", "/clean", "198.51.100.2", "", "")                                  // filtered out
	h.Visit("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "198.51.100.3", "", "") // would_block in observe
	var id string
	for id == "" {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatal("stream closed")
			}
			if strings.HasPrefix(l, "data: ") {
				validate(t, "EventSummary", []byte(strings.TrimPrefix(l, "data: ")))
				ev := decode[dashboard.EventSummary](t, []byte(strings.TrimPrefix(l, "data: ")))
				if ev.Outcome != "would_block" || ev.IP != "198.51.100.3" {
					t.Fatalf("filter: %+v", ev)
				}
				id = ev.ID
			}
		case <-ctx.Done():
			t.Fatal("no live event")
		}
	}
	resp.Body.Close()
	// Reconnect with Last-Event-ID: the missed event is replayed.
	h.Visit("GET", "/?q=%3Cscript%3Ealert(2)%3C%2Fscript%3E", "198.51.100.4", "", "")
	h.Flush()
	req, _ = http.NewRequestWithContext(ctx, "GET", h.Dash.URL+"/api/v0/events/stream?outcome=would_block", nil)
	req.Header.Set("Last-Event-ID", id)
	resp, err = h.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if l := sc.Text(); strings.HasPrefix(l, "data: ") {
			ev := decode[dashboard.EventSummary](t, []byte(strings.TrimPrefix(l, "data: ")))
			if ev.IP != "198.51.100.4" {
				t.Fatalf("replay: %+v", ev)
			}
			return
		}
	}
	t.Fatal("no replay")
}

// D89: the test profile observes on its own, whatever schild.yaml says.
func TestTestProfileStaysObserve(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "autoblock", Profile: "test"})
	h.Login()
	ov := decode[dashboard.Overview](t, expect(t, h, "GET", "/overview", nil, 200, "Overview"))
	if h.App.Gate.Settings().Mode != "observe" || ov.Profile != "test" {
		t.Fatalf("%+v", ov)
	}
}
