package agentapi

import (
	"strconv"
	"testing"
)

func TestValidException(t *testing.T) {
	ok := ExceptionRequest{Website: "app.example", Path: "/livewire/update", Target: "ARGS:json.components.*.updates.body", Repository: "crs", Rules: []string{"933180", "942100"}, Reason: "math"}
	if !ValidException(ok) {
		t.Fatal("valid request refused")
	}
	for name, change := range map[string]func(*ExceptionRequest){
		"no website": func(r *ExceptionRequest) { r.Website = "" },
		"no rules":   func(r *ExceptionRequest) { r.Rules = nil },
		"too many": func(r *ExceptionRequest) {
			r.Rules = nil
			for i := range MaxExceptionRules + 1 {
				r.Rules = append(r.Rules, strconv.Itoa(933100+i))
			}
		},
		"twice":           func(r *ExceptionRequest) { r.Rules = []string{"933180", "933180"} },
		"not crs":         func(r *ExceptionRequest) { r.Rules = []string{"200002"} },
		"blocking score":  func(r *ExceptionRequest) { r.Rules = []string{"949110"} },
		"crs as crowdsec": func(r *ExceptionRequest) { r.Repository = "crowdsec" },
		"local":           func(r *ExceptionRequest) { r.Repository = "local" },
		"no repository":   func(r *ExceptionRequest) { r.Repository = "" },
		"not a number":    func(r *ExceptionRequest) { r.Rules = []string{"9331a0"} },
		"leading zero":    func(r *ExceptionRequest) { r.Rules = []string{"0933180"} },
		"collection":      func(r *ExceptionRequest) { r.Target = "ARGS" },
		"all values":      func(r *ExceptionRequest) { r.Target = "ARGS:*" },
		"all parts":       func(r *ExceptionRequest) { r.Target = "ARGS:*.*" },
		"all cookies":     func(r *ExceptionRequest) { r.Target = "REQUEST_COOKIES:*" },
		"other variable":  func(r *ExceptionRequest) { r.Target = "REQUEST_BODY:x" },
		"second ctl":      func(r *ExceptionRequest) { r.Target = "ARGS:a,ctl:ruleEngine=Off" },
		"quote in path":   func(r *ExceptionRequest) { r.Path = `/a" "id:1` },
		"relative path":   func(r *ExceptionRequest) { r.Path = "livewire" },
	} {
		r := ok
		change(&r)
		if ValidException(r) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCrowdsecException(t *testing.T) {
	r := ExceptionRequest{Website: "app.example", Path: "/search", Target: "ARGS:q", Repository: "crowdsec", Rules: []string{"62846312"}, Reason: "search"}
	if !ValidException(r) {
		t.Fatal("crowdsec base id refused")
	}
	r.Rules = []string{"7700001"}
	if ValidException(r) {
		t.Fatal("an id outside the crowdsec range accepted")
	}
}

func TestExceptionScope(t *testing.T) {
	if !ValidScope(ScopeExceptionsWrite) || !CanRead(ScopeExceptionsWrite) || !NeedsLabel(ScopeExceptionsWrite) {
		t.Fatal("scope")
	}
	if !AllowsWrite(ScopeExceptionsWrite, OpCreateException) || !AllowsWrite(ScopeExceptionsWrite, OpRemoveException) {
		t.Fatal("may not write")
	}
	if AllowsWrite(ScopeExceptionsWrite, OpCreateBlock) || AllowsWrite(ScopeBlocksWrite, OpCreateException) {
		t.Fatal("a write scope carries another write")
	}
}
