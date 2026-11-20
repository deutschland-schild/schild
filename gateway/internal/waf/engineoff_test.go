package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func formPost(path, body string) *http.Request {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// Operator rules that switch the engine or the body access off would make
// Coraza buffer nothing, and the backend would get an empty body. Build
// refuses them, so a start and a reload of rules.d do too.
func TestOperatorRulesCannotTakeTheBodyAway(t *testing.T) {
	for _, rule := range []string{
		`SecRule REQUEST_URI "@beginsWith /hook" "id:1001,phase:1,pass,nolog,ctl:ruleEngine=Off"`,
		`SecRule REQUEST_URI "@beginsWith /hook" "id:1001,phase:1,pass,nolog,Ctl:RuleEngine=DetectionOnly"`,
		`SecRule REQUEST_URI "@beginsWith /hook" "id:1001,phase:1,pass,nolog,ctl:requestBodyAccess=Off"`,
		`SecRule REQUEST_URI "@beginsWith /hook" "id:1001,phase:1,pass,nolog,ctl:requestBodyLimit=10"`,
		"SecRule REQUEST_URI \"@beginsWith /hook\" \\\n  \"id:1001,phase:1,pass,nolog,ctl:ruleEngine=Off\"",
		"SecRule REQUEST_URI \"@beginsWith /hook\" \"id:1001,phase:1,pass,nolog,chain\"\nSecRule REQUEST_METHOD \"@streq POST\" \"ctl:ruleEngine=Off\"",
		`SecRuleEngine Off`,
		`secruleengine On`,
		`SecRequestBodyAccess Off`,
		`SecRequestBodyLimit 1024`,
		`SecRequestBodyNoFilesLimit 1024`,
		`SecRequestBodyLimitAction ProcessPartial`,
		`SecRequestBodyInMemoryLimit 1024`,
		`Include /etc/schild/more.conf`,
		`include /etc/schild/more/*.conf`,
	} {
		if _, err := Build(Config{LocalRules: rule}); err == nil || !strings.Contains(err.Error(), "not allowed in operator rules") {
			t.Errorf("%s: built, err = %v", rule, err)
		}
		if _, err := Build(Config{Exceptions: rule}); err == nil {
			t.Errorf("as an exception: %s: built", rule)
		}
	}
}

// What the refusal points to instead: the body still reaches the backend.
func TestLeavingAPathOutKeepsTheBody(t *testing.T) {
	inst, err := Build(Config{CRS: true, LocalRules: "# not SecRuleEngine Off and not ctl:ruleEngine=Off\n" +
		`SecRule REQUEST_URI "@beginsWith /hook" "id:1001,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS"`})
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := inst.NewTransaction()
	defer tx.Close()
	const body = "q=1' OR '1'='1"
	r := formPost("/hook", body)
	ProcessHeaders(tx, r, "192.0.2.1", 40000)
	rd, n, err := ReadBody(tx, r, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rd)
	if string(got) != body || n != int64(len(body)) {
		t.Fatalf("forwarded %q (%d bytes), want %q", got, n, body)
	}
	if it, _ := tx.ProcessRequestBody(); it != nil {
		t.Fatalf("blocked by rule %d on a path left out of the CRS", it.RuleID)
	}
	// The flow control rules of the CRS carry no message, its detections do.
	for _, m := range tx.MatchedRules() {
		if id := m.Rule().ID(); id >= 910000 && id < 1000000 && m.Message() != "" {
			t.Errorf("CRS rule %d matched on a path left out of the CRS", id)
		}
	}
}

// Without the operator rule the same request is a finding, so the test above
// measures the rule and not a harmless body.
func TestTheSameBodyIsAFindingWithTheCRS(t *testing.T) {
	inst, err := Build(Config{CRS: true})
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := inst.NewTransaction()
	defer tx.Close()
	r := formPost("/hook", "q=1' OR '1'='1")
	ProcessHeaders(tx, r, "192.0.2.1", 40000)
	if _, _, err := ReadBody(tx, r, DefaultLimits); err != nil {
		t.Fatal(err)
	}
	_, _ = tx.ProcessRequestBody()
	for _, m := range tx.MatchedRules() {
		if id := m.Rule().ID(); id >= 942000 && id < 943000 && m.Message() != "" {
			return
		}
	}
	t.Fatal("no SQL injection finding without the operator rule")
}

// The net behind the refusal: a transaction without engine or body access
// never yields an empty body for the backend.
func TestNoEmptyBodyWithoutBodyAccess(t *testing.T) {
	for _, directives := range []string{"SecRuleEngine Off", "SecRuleEngine DetectionOnly\nSecRequestBodyAccess Off"} {
		w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
		if err != nil {
			t.Fatal(err)
		}
		tx := w.NewTransaction()
		r := formPost("/hook", "a=1")
		ProcessHeaders(tx, r, "192.0.2.1", 40000)
		if rd, _, err := ReadBody(tx, r, DefaultLimits); err != ErrBodyBusy || rd != nil {
			t.Errorf("%q: reader %v, err %v", directives, rd, err)
		}
		_ = tx.Close()
	}
}
