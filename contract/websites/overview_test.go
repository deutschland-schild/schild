package websites

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/schema"
)

func compiler(t *testing.T) (*jsonschema.Compiler, map[string]any) {
	t.Helper()
	b, err := os.ReadFile("../../contracts/api/client-dashboard.openapi.yaml")
	if err != nil {
		t.Skipf("contracts/api not present: %v", err)
	}
	j, err := config.YAMLToJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	_ = json.Unmarshal(j, &d)
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	for rel, f := range schema.Files() {
		doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(f))
		if err := c.AddResource(schema.BaseURL+rel, doc); err != nil {
			t.Fatal(err)
		}
	}
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(j))
	if err := c.AddResource(schema.BaseURL+"api/client-dashboard.openapi.yaml", doc); err != nil {
		t.Fatal(err)
	}
	return c, d
}

func TestRuleCategory(t *testing.T) {
	c, d := compiler(t)
	_ = c
	enum := map[string]bool{}
	for _, x := range d["components"].(map[string]any)["schemas"].(map[string]any)["RuleCategory"].(map[string]any)["enum"].([]any) {
		enum[x.(string)] = true
	}
	for id, want := range map[string]string{"942100": "sqli", "930120": "lfi", "941100": "xss", "949110": "anomaly", "913100": "scanner",
		"7700012": "local", "100001": "local", "1000001": "local", "x": "local", "920350": "protocol"} {
		got := RuleCategory(id)
		if got != want || !enum[got] {
			t.Errorf("RuleCategory(%s) = %s, want %s (in enum: %v)", id, got, want, enum[got])
		}
	}
	for _, v := range crsFamilies {
		if !enum[v] {
			t.Errorf("%s not in the RuleCategory enum", v)
		}
	}
}

func TestOverviewWireTypes(t *testing.T) {
	c, _ := compiler(t)
	f := func(x float64) *float64 { return &x }
	i := func(x int64) *int64 { return &x }
	set := KpiSet{Visitors: KpiValue{Value: f(1830), ErrorBound: 0.033}, PageViews: KpiValue{Value: f(5120), Exact: true}, Requests: KpiValue{Value: f(48000), Exact: true},
		Stopped: KpiValue{Value: f(310), Exact: true}, WouldBlock: KpiValue{Value: f(12), Exact: true}, LatencyP95MS: KpiValue{Value: f(91.3), ErrorBound: 0.25},
		ErrorRate: KpiValue{Value: f(0.002), Exact: true}}
	noLatency := set
	noLatency.LatencyP95MS = KpiValue{Unavailable: "filter_needs_requests"}
	for _, c0 := range []struct {
		name  string
		v     any
		proto any
	}{
		{"WebsiteKpis", Kpis{Site: "verein.example", From: "2026-10-28T12:00:00Z", To: "2026-10-29T12:00:00Z", PreviousFrom: "2026-10-27T12:00:00Z", PreviousTo: "2026-10-28T12:00:00Z",
			Source: "rings", Current: set, Previous: set}, Kpis{}},
		{"WebsiteKpis", Kpis{Site: "verein.example", From: "2026-10-28T12:00:00Z", To: "2026-10-29T12:00:00Z", PreviousFrom: "2026-10-27T12:00:00Z", PreviousTo: "2026-10-28T12:00:00Z",
			Filters: []string{"country:DE"}, Source: "rings", Current: noLatency, Previous: noLatency}, Kpis{}},
		{"WebsiteRealtime", Realtime{Site: "verein.example", GeneratedAt: "2026-10-29T12:00:30Z", Visitors5m: i(14), Requests5m: 840, Stopped5m: 3,
			Points: []RealtimePoint{{T: "2026-10-29T11:31:00Z", Requests: 160, Visitors: i(6)}, {T: "2026-10-29T12:00:00Z", Requests: 80, Partial: true}}}, Realtime{}},
		{"AnnotationList", AnnotationList{Site: "verein.example", From: "2026-10-28T12:00:00Z", To: "2026-10-29T12:00:00Z", Items: []Annotation{
			{T: "2026-10-28T13:10:00Z", Until: "2026-10-28T13:40:00Z", Kind: AnnWaveDetected, Ref: "0c1a5c6e-8f0b-4e6a-9d55-2f6d7c1e4b11", Detector: "route_wave", Count: 380},
			{T: "2026-10-28T14:02:11Z", Kind: AnnBlockLong, Ref: "K7QM-4XWD", NetClass: "hosting", DurationS: 604800},
			{T: "2026-10-29T08:00:00Z", Kind: AnnConfigChanged, ConfigSHA256: "4f2c9a1b7e3d5f6a8b0c2d4e6f8a0b1c3d5e7f9a1b3c5d7e9f0a2b4c6d8e0f1a"},
			{T: "2026-10-29T08:00:02Z", Kind: AnnModeChanged, ModeFrom: "observe", ModeTo: "autoblock"},
			{T: "2026-10-29T09:00:00Z", Until: "2026-10-29T09:03:00Z", Kind: AnnMonitoringGap}}}, AnnotationList{}},
		{"AlertFeed", AlertFeed{Site: "verein.example", Filters: []string{"net_class:hosting"}, Items: []AlertItem{
			{T: "2026-10-29T11:59:58Z", EventID: "f2064730-835b-4d96-b173-d92534ccd620", Kind: "waf", Outcome: "blocked", Category: RuleCategory("930120"), Rules: []string{"930120"},
				Path: "/wp-login.php", Country: "NL", NetClass: "hosting", ClientPseudonym: "p1-0011223344556677", Incident: "K7QM-4XWD"},
			{T: "2026-10-29T11:58:00Z", EventID: "0c1a5c6e-8f0b-4e6a-9d55-2f6d7c1e4b11", Kind: "behaviour", Outcome: "would_block", Category: "behaviour", Scenario: "login_bruteforce",
				Path: "/wp-login.php", Country: "DE", NetClass: "residential"}}}, AlertFeed{}},
	} {
		sch, err := c.Compile(schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/" + c0.name)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(c0.v)
		inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err := sch.Validate(inst); err != nil {
			t.Errorf("%s: %v\n%s", c0.name, err, b)
			continue
		}
		v := reflect.New(reflect.TypeOf(c0.proto)).Interface()
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Errorf("%s: %v", c0.name, err)
		}
	}
}
