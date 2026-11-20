package waf

import (
	"fmt"
	"testing"

	"github.com/deutschland-schild/schild/contract/websites"
)

// An exception of an agent (D54) ends at its website, page and field, is no finding
// and leaves the other rules on.
func TestAgentExceptionIsNarrow(t *testing.T) {
	rule, err := websites.RuleExceptionRule(websites.RuleExceptionInput{Hosts: []string{"app.example"}, Path: "/livewire/update",
		Target: "ARGS:json.components.*.updates.bodyText", Rules: []string{"932130", "932280", "933160", "933180", "942100", "942151"}, ID: 1900000})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := Build(Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5, Livewire: true, Exceptions: rule})
	if err != nil {
		t.Fatal(err)
	}
	if !inst.LocalException[1900000] {
		t.Fatal("not classed as an exception")
	}
	for _, text := range livewireMath {
		a := anomaly(t, inst, "/livewire/update", livewireJSON, mixedCaseField(t, text))
		if a.CRSBlock {
			t.Errorf("%q blocked in the excepted field: %v", text, a.MatchedIDs)
		}
		if got := anomalyOn(t, inst, "other.example", "/livewire/update", livewireJSON, mixedCaseField(t, text)); !got.CRSBlock {
			t.Errorf("%q passed on another website", text)
		}
	}
	if a := anomaly(t, inst, "/livewire/update", livewireJSON, mixedCaseField(t, `<script>alert(1)</script>`)); !a.CRSBlock {
		t.Error("another rule stopped checking the field")
	}
}

// A wrong id must not take the gateway down at a later reload: a duplicate fails the build.
func TestAgentExceptionIDClash(t *testing.T) {
	rule, err := websites.RuleExceptionRule(websites.RuleExceptionInput{Hosts: []string{"app.example"}, Path: "/a", Target: "ARGS:body", Rules: []string{"933180"}, ID: 1900000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(Config{Exceptions: rule, LocalRules: rule}); err == nil {
		t.Fatal("a clash with rules.d built")
	}
}

// An exception for a crowdsec rule (D73) takes the target off every group of
// the hub rule with one id range in ctl:ruleRemoveTargetById, also when the
// field sits in a chained line, and only on its website.
func TestAgentExceptionCrowdsecRange(t *testing.T) {
	r := hubRule(t)
	ids := fmt.Sprintf("%d-%d", r.BaseID, r.BaseID+7)
	match := func(inst *Instance, host, target string) bool {
		req := browserReq("GET", target, "", "")
		req.Host = host
		a, err := eval(t, inst, req)
		if err != nil {
			t.Fatal(err)
		}
		return a.HasHub
	}
	for _, field := range []string{"cmd", "run"} { // group 0 and group 1
		rule, err := websites.RuleExceptionRule(websites.RuleExceptionInput{Hosts: []string{"app.example"}, Path: "/vulnerable/one", Target: "ARGS:" + field,
			Rules: []string{ids}, ID: 1900000, SplitArgs: true})
		if err != nil {
			t.Fatal(err)
		}
		inst, err := Build(Config{Hub: []HubRule{r}, Exceptions: rule})
		if err != nil {
			t.Fatal(err)
		}
		if match(inst, "app.example", "/vulnerable/one?"+field+"=pwn") {
			t.Errorf("%s: the excepted field still matches", field)
		}
		if !match(inst, "other.example", "/vulnerable/one?"+field+"=pwn") {
			t.Errorf("%s: the exception holds on another website", field)
		}
		other := map[string]string{"cmd": "run", "run": "cmd"}[field]
		if !match(inst, "app.example", "/vulnerable/one?"+other+"=pwn") {
			t.Errorf("%s: the other field stopped matching", field)
		}
	}
}
