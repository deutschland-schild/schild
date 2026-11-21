//go:build !release

package dashboard_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// A rule of the shipped snapshot and a request that matches it and that the
// CRS lets through, so only the crowdsec rule decides.
const (
	hubName   = "crowdsecurity/vpatch-CVE-2007-0885"
	hubAttack = "/jira/secure/BrowseProject.jspa?id=%3C"
	hubOther  = "crowdsecurity/vpatch-CVE-2014-5181"
)

func repo(t *testing.T, h *apptest.Harness, id string) dashboard.RuleRepository {
	t.Helper()
	code, body := h.API("GET", "/rule-repositories/"+id, nil)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	validate(t, "RuleRepository", body)
	var v dashboard.RuleRepository
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func setState(t *testing.T, h *apptest.Harness, id string, body map[string]any) dashboard.RuleRepository {
	t.Helper()
	code, b := h.API("PATCH", "/rule-repositories/"+id, body)
	if code != 200 {
		t.Fatalf("switch %v: %d: %s", body, code, b)
	}
	validate(t, "RuleRepository", b)
	var v dashboard.RuleRepository
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func ruleOf(t *testing.T, h *apptest.Harness, method, path string, body any, want int) dashboard.RuleDetail {
	t.Helper()
	code, b := h.API(method, path, body)
	if code != want {
		t.Fatalf("%s %s: %d: %s", method, path, code, b)
	}
	var d dashboard.RuleDetail
	if want == 200 {
		validate(t, "RuleDetail", b)
		_ = json.Unmarshal(b, &d)
	}
	return d
}

func TestRepositoriesList(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	code, body := h.API("GET", "/rule-repositories", nil)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	validate(t, "RuleRepositoryList", body)
	var l dashboard.RuleRepositoryList
	_ = json.Unmarshal(body, &l)
	if len(l.Items) != 3 || l.Items[0].ID != "crs" || l.Items[1].ID != "crowdsec" || l.Items[2].ID != "local" {
		t.Fatalf("%+v", l)
	}
	if c := l.Items[0]; c.State != rules.StateBlock || c.CRS == nil || c.Counts.Rules < 200 || c.Effect != rules.EffectBlock {
		t.Fatalf("crs %+v", c)
	}
	if c := l.Items[2]; c.State != rules.StateBlock || c.Local == nil || c.Local.Dir == "" || c.Origin != "operator" {
		t.Fatalf("local %+v", c)
	}
	if code, _ := h.API("GET", "/rule-repositories/network", nil); code != 404 {
		t.Fatalf("network: %d", code)
	}
}

// The standalone gateway is the case the crowdsec repository exists for.
func TestCrowdsecDefaultAndSwitch(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	v := repo(t, h, "crowdsec")
	if v.State != rules.StateDetect || v.StateSource != rules.ByDefault || v.Crowdsec.SetSource != crowdsec.SetImage || v.Counts.Rules < 150 || v.Differs {
		t.Fatalf("default: %+v", v)
	}
	// detect in autoblock: the request passes, the event names the rule.
	if r := h.Visit("GET", hubAttack, "203.0.113.5", "", ""); r.StatusCode != 200 {
		t.Fatalf("detect answered %d", r.StatusCode)
	}
	h.Flush()
	code, body := h.API("GET", "/events?rule="+strconv.Itoa(crowdsec.BaseID(hubName)), nil)
	if code != 200 || !strings.Contains(string(body), `"outcome":"would_block"`) || !strings.Contains(string(body), `"would_block_reason":"source_detect"`) {
		t.Fatalf("event list %d: %s", code, body)
	}
	validate(t, "EventPage", body)

	// No password on any transition. Session and CSRF stay.
	if code, _ := h.API("PATCH", "/rule-repositories/crowdsec", map[string]any{"state": "block", "confirm": map[string]any{"password": "x"}}); code != 400 {
		t.Fatalf("confirm accepted: %d", code)
	}
	v = setState(t, h, "crowdsec", map[string]any{"state": "block"})
	if v.State != rules.StateBlock || v.StateSource != rules.ByDashboard || !v.Differs || v.ConfigState != rules.StateDetect ||
		v.StateSetAt == nil || v.StateSetBy != nil || v.Effect != rules.EffectBlock {
		t.Fatalf("block: %+v", v)
	}
	if r := h.Visit("GET", hubAttack, "203.0.113.6", "", ""); r.StatusCode != 403 {
		t.Fatalf("block answered %d", r.StatusCode)
	}
	v = setState(t, h, "crowdsec", map[string]any{"state": "off"})
	if v.State != rules.StateOff || v.Crowdsec.SetSource != crowdsec.SetNone || v.Counts.Rules != 0 || v.Crowdsec.UpdateState != "off" {
		t.Fatalf("off: %+v", v)
	}
	if n := len(h.App.Engine.Current().Hub); n != 0 {
		t.Fatalf("%d hub ids in the WAF after off", n)
	}
	v = setState(t, h, "crowdsec", map[string]any{"reset_state": true})
	if v.State != rules.StateDetect || v.StateSource != rules.ByDefault || v.Differs || v.Counts.Rules == 0 {
		t.Fatalf("reset: %+v", v)
	}
	if n := len(h.App.Engine.Current().Hub); n == 0 {
		t.Fatal("no hub ids in the WAF after the reset")
	}
}

func TestRepositorySwitchRefusals(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	for _, body := range []map[string]any{{}, {"state": "sometimes"}, {"state": "off", "reset_state": true}, {"reset_state": false}} {
		if code, b := h.API("PATCH", "/rule-repositories/crowdsec", body); code != 400 {
			t.Fatalf("%v: %d: %s", body, code, b)
		}
	}
	csrf := h.CSRF
	h.CSRF = ""
	for _, c := range [][2]string{{"PATCH", "/rule-repositories/crowdsec"}, {"POST", "/rule-repositories/crowdsec/reset"}, {"POST", "/rule-repositories/local/sync"},
		{"PATCH", "/rules/crs/942100"}} {
		if code, _ := h.API(c[0], c[1], map[string]any{"state": "off"}); code != 403 {
			t.Fatalf("%s %s without CSRF: %d", c[0], c[1], code)
		}
	}
	h.CSRF = csrf
	if v := repo(t, h, "crowdsec"); v.State != rules.StateDetect {
		t.Fatalf("%+v", v)
	}
	if code, b := h.API("POST", "/rule-repositories/crs/sync", nil); code != 409 || !strings.Contains(string(b), "not_supported") {
		t.Fatalf("crs sync: %d %s", code, b)
	}
	if code, b := h.API("POST", "/rule-repositories/local/reset", nil); code != 409 || !strings.Contains(string(b), "not_supported") {
		t.Fatalf("local reset: %d %s", code, b)
	}
}

func TestCrowdsecRulesAndDisabling(t *testing.T) {
	h := apptest.New(t, apptest.Options{Rules: "  crowdsec: {auto_update: false, disabled_rules: [crowdsecurity/vpatch-CVE-2014-5181]}\n"})
	h.Login()
	code, body := h.API("GET", "/rules?repository=crowdsec&limit=500", nil)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	validate(t, "RulePage", body)
	var page dashboard.RulePage
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) < 150 {
		t.Fatalf("%d rules", len(page.Items))
	}
	for _, it := range page.Items {
		if it.Crowdsec == nil || it.Repository != "crowdsec" || it.Crowdsec.Licence != "MIT" || it.Origin != rules.OriginRelease {
			t.Fatalf("%+v", it)
		}
	}
	id := strconv.Itoa(crowdsec.BaseID(hubName))
	if d := ruleOf(t, h, "GET", "/rules/crowdsec/"+id, nil, 200); d.SecLang == "" || d.Name != hubName {
		t.Fatalf("%+v", d)
	}
	d := ruleOf(t, h, "PATCH", "/rules/crowdsec/"+id, map[string]any{"disabled": true, "note": "false positive"}, 200)
	if d.Status != rules.StatusDisabled || d.DisabledBy != rules.ByDashboard || len(d.Decisions) != 1 || d.Decisions[0].Note != "false positive" {
		t.Fatalf("%+v", d)
	}
	// The same again changes nothing; enabling needs no body but disabled.
	ruleOf(t, h, "PATCH", "/rules/crowdsec/"+id, map[string]any{"disabled": true}, 200)
	if d := ruleOf(t, h, "PATCH", "/rules/crowdsec/"+id, map[string]any{"disabled": false}, 200); d.Status != rules.StatusActive {
		t.Fatalf("%+v", d)
	}
	conf := strconv.Itoa(crowdsec.BaseID(hubOther))
	code, body = h.API("PATCH", "/rules/crowdsec/"+conf, map[string]any{"disabled": false})
	if code != 409 || !strings.Contains(string(body), "config_limit") {
		t.Fatalf("config rule: %d: %s", code, body)
	}
	ruleOf(t, h, "PATCH", "/rules/crowdsec/"+id, map[string]any{"confirm": map[string]any{"password": h.Password}}, 400)
	ruleOf(t, h, "PATCH", "/rules/crowdsec/1", map[string]any{"disabled": true}, 404)
	ruleOf(t, h, "POST", "/rules/crowdsec/"+id+"/approve", map[string]any{}, 404) // D89: no approvals
	h.Flush()
	code, body = h.API("GET", "/events?type=schild.rule.disabled.v1", nil)
	if code != 200 || !strings.Contains(string(body), "schild.rule.disabled.v1") {
		t.Fatalf("%d: %s", code, body)
	}
}

// D89: an old mode review in schild.yaml means nothing; the rules of the
// image block as soon as the repository does.
func TestOldReviewModeIsIgnored(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: "mode: review\n"})
	h.Login()
	v := setState(t, h, "crowdsec", map[string]any{"state": "block"})
	if v.Effect != rules.EffectBlock || v.LimitedBy != "" || v.Counts.Settling != 0 {
		t.Fatalf("%+v", v)
	}
	if r := h.Visit("GET", hubAttack, "203.0.113.5", "", ""); r.StatusCode != 403 {
		t.Fatalf("review: %d", r.StatusCode)
	}
	if d := ruleOf(t, h, "GET", "/rules/crowdsec/"+strconv.Itoa(crowdsec.BaseID(hubName)), nil, 200); d.Effect != rules.EffectBlock || d.Status != rules.StatusActive {
		t.Fatalf("%+v", d)
	}
}

func TestCrowdsecBlockIncidentAndOverlaySurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	h := apptest.New(t, apptest.Options{Dir: dir})
	h.Login()
	setState(t, h, "crowdsec", map[string]any{"state": "block"})
	if r := h.Visit("GET", hubAttack, "203.0.113.6", "", ""); r.StatusCode != 403 {
		t.Fatalf("block answered %d", r.StatusCode)
	}
	h.Flush()
	code, body := h.API("GET", "/events?outcome=blocked", nil)
	if code != 200 || !strings.Contains(string(body), strconv.Itoa(crowdsec.BaseID(hubName))) {
		t.Fatalf("%d: %s", code, body)
	}
	var page dashboard.EventPage
	_ = json.Unmarshal(body, &page)
	if len(page.Items) != 1 || page.Items[0].Incident == "" {
		t.Fatalf("%+v", page.Items)
	}
	code, body = h.API("GET", "/incidents/"+page.Items[0].Incident, nil)
	if code != 200 || !strings.Contains(string(body), strconv.Itoa(crowdsec.BaseID(hubName))) {
		t.Fatalf("%d: %s", code, body)
	}
	validate(t, "Incident", body)
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	r := apptest.New(t, apptest.Options{Dir: dir})
	if got := r.App.Config().Rules.Crowdsec.State; got != rules.StateBlock {
		t.Fatalf("overlay lost: %s", got)
	}
	if v, _ := r.App.Repos.Repository("crowdsec"); v.StateSource != rules.ByDashboard || !v.Differs {
		t.Fatalf("%+v", v)
	}
}

// Every change of the effective state, and only such a change, is history.
func TestRepositorySwitchHistory(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	start := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	setState(t, h, "crowdsec", map[string]any{"state": "block"})
	setState(t, h, "crowdsec", map[string]any{"state": "block"}) // nothing changes
	setState(t, h, "crowdsec", map[string]any{"reset_state": true})
	setState(t, h, "crs", map[string]any{"state": "detect"})
	h.Flush()
	code, body := h.API("GET", "/events?type=schild.rule.repository_switched.v1", nil)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var page dashboard.EventPage
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 3 {
		t.Fatalf("%d history entries: %s", len(page.Items), body)
	}
	end := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	code, body = h.API("GET", "/websites/default/annotations?from="+start+"&to="+end, nil)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	validate(t, "AnnotationList", body)
	if n := strings.Count(string(body), `"kind":"rule_repository_changed"`); n != 3 {
		t.Fatalf("%d annotations: %s", n, body)
	}
	if !strings.Contains(string(body), `"state_to":"block"`) || !strings.Contains(string(body), `"repository":"crs"`) || !strings.Contains(string(body), `"actor":"dashboard"`) {
		t.Fatalf("%s", body)
	}
}

// Back to the image (D43): session and CSRF, no password, nothing but the
// stored set changes.
func TestCrowdsecResetToTheImage(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	ctx := context.Background()
	before := repo(t, h, "crowdsec")
	if err := h.App.Store.Put(ctx, crowdsec.StoreKey, []byte(`{"set":{}}`)); err != nil {
		t.Fatal(err)
	}
	code, b := h.API("POST", "/rule-repositories/crowdsec/reset", nil)
	if code != 200 {
		t.Fatalf("%d: %s", code, b)
	}
	validate(t, "RuleRepository", b)
	var v dashboard.RuleRepository
	_ = json.Unmarshal(b, &v)
	if v.Crowdsec.SetSource != crowdsec.SetImage || v.State != before.State || v.Counts.Rules != before.Counts.Rules {
		t.Fatalf("%+v", v)
	}
	if _, err := h.App.Store.Get(ctx, crowdsec.StoreKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stored set still there: %v", err)
	}
}

// Local rules: a sync loads rules.d, a disabled rule leaves the WAF, the
// repository in detect never blocks (D73).
func TestLocalRepository(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	dir := filepath.Join(h.Dir, "rules.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "10-stop.conf"),
		[]byte(`SecRule REQUEST_URI "@beginsWith /stop-here" "id:1000001,phase:1,deny,status:403,msg:'stop here'"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, b := h.API("POST", "/rule-repositories/local/sync", nil)
	if code != 200 {
		t.Fatalf("%d: %s", code, b)
	}
	var v dashboard.RuleRepository
	_ = json.Unmarshal(b, &v)
	if v.Counts.Rules != 1 || len(v.Local.Files) != 1 || v.Local.Files[0].Name != "10-stop.conf" {
		t.Fatalf("%+v", v)
	}
	d := ruleOf(t, h, "GET", "/rules/local/1000001", nil, 200)
	if d.Msg != "stop here" || d.File != "10-stop.conf" || d.Origin != rules.OriginOperator || !strings.Contains(d.SecLang, "/stop-here") {
		t.Fatalf("%+v", d)
	}
	// A CRS rule shows the text of the embedded file (D82).
	c := ruleOf(t, h, "GET", "/rules/crs/942100", nil, 200)
	if !strings.HasPrefix(c.File, "REQUEST-942-") || !strings.HasPrefix(c.SecLang, "SecRule ") || !strings.Contains(c.SecLang, "id:942100,") {
		t.Fatalf("crs rule: file %q, text %q", c.File, c.SecLang)
	}
	if r := h.Visit("GET", "/stop-here", "203.0.113.7", "", ""); r.StatusCode != 403 {
		t.Fatalf("local rule: %d", r.StatusCode)
	}
	ruleOf(t, h, "PATCH", "/rules/local/1000001", map[string]any{"disabled": true}, 200)
	if r := h.Visit("GET", "/stop-here", "203.0.113.7", "", ""); r.StatusCode != 200 {
		t.Fatalf("disabled local rule: %d", r.StatusCode)
	}
	ruleOf(t, h, "PATCH", "/rules/local/1000001", map[string]any{"disabled": false}, 200)
	setState(t, h, "local", map[string]any{"state": "detect"})
	if r := h.Visit("GET", "/stop-here", "203.0.113.8", "", ""); r.StatusCode != 200 {
		t.Fatalf("local in detect: %d", r.StatusCode)
	}
	setState(t, h, "local", map[string]any{"state": "off"})
	if strings.Contains(h.App.Engine.Current().Config.LocalRules, "1000001") {
		t.Fatal("local off still builds the rules")
	}
}

// D101: paranoia level and blocking threshold of the CRS are set in the
// dashboard, effective without a restart, and an empty body gives them back
// to schild.yaml.
func TestCRSSettings(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	const xss = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	set := func(body map[string]any) dashboard.RuleRepository {
		t.Helper()
		b := expect(t, h, "PATCH", "/rule-repositories/crs/settings", body, 200, "RuleRepository")
		return decode[dashboard.RuleRepository](t, b)
	}
	before := repo(t, h, "crs")
	if c := before.CRS; c.ParanoiaLevel != 1 || c.InboundAnomalyThreshold != 5 || c.ConfigParanoiaLevel != 1 || c.ConfigInboundAnomalyThreshold != 5 {
		t.Fatalf("default: %+v", c)
	}
	if r := h.Visit("GET", xss, "203.0.113.20", "", ""); r.StatusCode != 403 {
		t.Fatalf("threshold 5 answered %d", r.StatusCode)
	}

	// A threshold above the score of the request lets it through; the values
	// of schild.yaml stay visible next to the ones that run.
	v := set(map[string]any{"inbound_anomaly_threshold": 100})
	if c := v.CRS; c.InboundAnomalyThreshold != 100 || c.ConfigInboundAnomalyThreshold != 5 || c.ParanoiaLevel != 1 || v.State != rules.StateBlock {
		t.Fatalf("threshold 100: %+v", v)
	}
	if r := h.Visit("GET", xss, "203.0.113.21", "", ""); r.StatusCode != 200 {
		t.Fatalf("threshold 100 answered %d", r.StatusCode)
	}

	// The body replaces what was set: the threshold falls back, the stricter
	// level loads more rules.
	v = set(map[string]any{"paranoia_level": 2})
	if c := v.CRS; c.ParanoiaLevel != 2 || c.ConfigParanoiaLevel != 1 || c.InboundAnomalyThreshold != 5 || v.Counts.Rules <= before.Counts.Rules {
		t.Fatalf("level 2: %+v (rules before: %d)", v, before.Counts.Rules)
	}
	if r := h.Visit("GET", xss, "203.0.113.22", "", ""); r.StatusCode != 403 {
		t.Fatalf("threshold back at 5 answered %d", r.StatusCode)
	}

	// The state switch and the settings do not touch each other.
	if s := setState(t, h, "crs", map[string]any{"state": "detect"}); s.CRS.ParanoiaLevel != 2 {
		t.Fatalf("the switch dropped the level: %+v", s.CRS)
	}
	if v = set(map[string]any{"paranoia_level": 2, "inbound_anomaly_threshold": 7}); v.State != rules.StateDetect || v.CRS.InboundAnomalyThreshold != 7 {
		t.Fatalf("the settings dropped the state: %+v", v)
	}

	// An empty body: schild.yaml and the defaults hold again.
	v = set(map[string]any{})
	if c := v.CRS; c.ParanoiaLevel != 1 || c.InboundAnomalyThreshold != 5 || v.Counts.Rules != before.Counts.Rules || v.State != rules.StateDetect {
		t.Fatalf("reset: %+v", v)
	}

	for name, body := range map[string]map[string]any{
		"level 0": {"paranoia_level": 0}, "level 5": {"paranoia_level": 5}, "threshold 0": {"inbound_anomaly_threshold": 0},
		"threshold 101": {"inbound_anomaly_threshold": 101}, "unknown field": {"state": "off"},
	} {
		if code, b := h.API("PATCH", "/rule-repositories/crs/settings", body); code != 400 {
			t.Errorf("%s: %d: %s", name, code, b)
		}
	}
	if code, b := h.API("PATCH", "/rule-repositories/crs/settings", map[string]any{"paranoia_level": 5}); !strings.Contains(string(b), `/paranoia_level`) {
		t.Errorf("no pointer: %d: %s", code, b)
	}
	for id, want := range map[string]int{"crowdsec": 409, "local": 409, "network": 404} {
		if code, b := h.API("PATCH", "/rule-repositories/"+id+"/settings", map[string]any{"paranoia_level": 2}); code != want {
			t.Errorf("%s: %d, want %d: %s", id, code, want, b)
		}
	}
}
