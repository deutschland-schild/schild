package gate

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// The local exceptions of the MVP-19 measurement (runbook pattern 9.4) and
// the runbook's chained form. They are matched (nolog rules are still
// recorded by Coraza) but they are exceptions, not findings.
const measurementExceptions = `SecRule REQUEST_FILENAME "@streq /livewire/update" "id:1000101,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=941100;ARGS:json.components.0.snapshot,ctl:ruleRemoveTargetById=941160;ARGS:json.components.0.snapshot,ctl:ruleRemoveTargetById=942270;ARGS:json.components.0.snapshot,ctl:ruleRemoveTargetById=941100;ARGS:json.components.0.updates.body,ctl:ruleRemoveTargetById=941160;ARGS:json.components.0.updates.body"
SecRule REQUEST_FILENAME "@streq /login" "id:1000102,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:password"
SecRule REQUEST_HEADERS:Host "@streq shop.example" "id:1000103,phase:1,pass,nolog,t:none,chain"
  SecRule REQUEST_FILENAME "@streq /login" "t:none,ctl:ruleRemoveTargetById=942100;ARGS:password"
SecRule ARGS:probe "@contains localattack" "id:1000200,phase:2,pass,log,msg:'Local detection'"
SecRule ARGS:probe "@contains localblock" "id:1000201,phase:2,deny,status:403,msg:'Local block'"
SecRule ARGS:probe "@contains quietattack" "id:1000202,phase:2,pass,nolog,setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecRule ARGS:probe "@contains quietblock" "id:1000203,phase:2,deny,nolog,status:403"
`

func analyseWith(t *testing.T, inst *waf.Instance, target, body string) *waf.Analysis {
	t.Helper()
	r := httptest.NewRequest("POST", target, strings.NewReader(body))
	r.Host = "shop.example"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	r.Header.Set("Accept", "text/html")
	tx, c := inst.NewTransaction()
	defer func() { c.Finish(); _ = tx.Close() }()
	waf.ProcessHeaders(tx, r, "198.51.100.77", 40000)
	if _, _, err := waf.ReadBody(tx, r, waf.DefaultLimits); err != nil {
		t.Fatal(err)
	}
	_, _ = tx.ProcessRequestBody()
	a := inst.Analyze(tx.MatchedRules())
	// The gate's decision marks which matches may count (every repository
	// blocks here).
	(&Gate{Exceptions: NewExceptions()}).applyRules(&reqInfo{analysis: a, start: time.Now()}, &Settings{Mode: "autoblock"})
	return a
}

func ids(a *waf.Analysis) map[int]bool {
	out := map[int]bool{}
	for _, m := range a.Matches {
		out[m.ID] = true
	}
	return out
}

// MVP-19 measurement, finding 3b: a Livewire request and a login that hit
// only the operator's exceptions must not count towards waf_repeat; real
// findings (CRS points, local detection and blocking rules) still do.
func TestLocalExceptionsAreNoWAFHits(t *testing.T) {
	inst, err := waf.Build(waf.Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5, LocalRules: measurementExceptions})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[int]bool{1000101: true, 1000102: true, 1000103: true, 1000200: false, 1000201: false, 1000202: false, 1000203: false} {
		if inst.LocalException[id] != want {
			t.Errorf("rule %d: exception %v, want %v", id, inst.LocalException[id], want)
		}
	}

	// Login with a password CRS 942100 would flag: the exceptions match,
	// 942100 is removed for the password, nothing counts.
	a := analyseWith(t, inst, "/login", "email=kunde%40example.de&password=p%40ss%27word%22--&_token=abc")
	if m := ids(a); !m[1000102] || !m[1000103] || m[942100] {
		t.Fatalf("login matches: %v", m)
	}
	if got := wafRuleIDs(&reqInfo{analysis: a}); len(got) != 0 {
		t.Fatalf("exceptions counted as WAF hits: %v", got)
	}

	// Local detection and blocking rules and CRS points still count.
	a = analyseWith(t, inst, "/login", "probe=localattack+localblock&password=x")
	got := map[int]bool{}
	for _, id := range wafRuleIDs(&reqInfo{analysis: a}) {
		got[id] = true
	}
	if !got[1000200] || !got[1000201] || got[1000102] || got[1000103] {
		t.Fatalf("findings: %v", got)
	}
	// Detections with nolog are findings too (MVP-19 re-measurement).
	a = analyseWith(t, inst, "/login", "probe=quietattack+quietblock&password=x")
	got = map[int]bool{}
	for _, id := range wafRuleIDs(&reqInfo{analysis: a}) {
		got[id] = true
	}
	if !got[1000202] || !got[1000203] {
		t.Fatalf("nolog detections not counted: %v", got)
	}
	a = analyseWith(t, inst, "/contact", "msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
	if len(wafRuleIDs(&reqInfo{analysis: a})) == 0 {
		t.Fatal("CRS findings no longer count")
	}
}
