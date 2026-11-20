package requests

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/geo"
	"github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/schema"
)

const apiDoc = "../../contracts/api/client-dashboard.openapi.yaml"

func openAPI(t *testing.T) (map[string]any, *jsonschema.Compiler) {
	t.Helper()
	b, err := os.ReadFile(apiDoc)
	if err != nil {
		t.Skipf("contracts/api not present: %v", err)
	}
	j, err := config.YAMLToJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(j, &d); err != nil {
		t.Fatal(err)
	}
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
	return d, c
}

func comp(d map[string]any, name string) map[string]any {
	return d["components"].(map[string]any)["schemas"].(map[string]any)[name].(map[string]any)
}

func enum(d map[string]any, name string) []string {
	var out []string
	for _, x := range comp(d, name)["enum"].([]any) {
		out = append(out, x.(string))
	}
	return out
}

// TestEnums: the Go value sets equal the OpenAPI enums and the catalogue
// schema; the geo providers equal geo.provider in schild.yaml.
func TestEnums(t *testing.T) {
	d, _ := openAPI(t)
	for name, want := range map[string][]string{"RequestOutcome": Outcomes, "VisitorPattern": Patterns, "BotVerification": bots.Verifications} {
		if got := enum(d, name); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: openapi %v, go %v", name, got, want)
		}
	}
	if got := enum(d, "BotCategory"); !reflect.DeepEqual(got[:len(bots.Categories)], bots.Categories) || !reflect.DeepEqual(got, monitoring.BotCategories) {
		t.Errorf("BotCategory %v vs bots.Categories %v", got, bots.Categories)
	}
	var cat map[string]any
	b, _ := os.ReadFile("../../contracts/bot-catalogue.schema.json")
	_ = json.Unmarshal(b, &cat)
	var catEnum []string
	for _, x := range cat["$defs"].(map[string]any)["category"].(map[string]any)["enum"].([]any) {
		catEnum = append(catEnum, x.(string))
	}
	if !reflect.DeepEqual(catEnum, bots.Categories) {
		t.Errorf("catalogue categories %v vs %v", catEnum, bots.Categories)
	}
	var site map[string]any
	b, _ = os.ReadFile("../../contracts/config/schild.schema.json")
	_ = json.Unmarshal(b, &site)
	var prov []string
	for _, x := range site["properties"].(map[string]any)["geo"].(map[string]any)["properties"].(map[string]any)["provider"].(map[string]any)["enum"].([]any) {
		prov = append(prov, x.(string))
	}
	if !reflect.DeepEqual(prov, geo.Providers) {
		t.Errorf("geo providers %v vs %v", prov, geo.Providers)
	}
	geoDB := comp(d, "Overview")["properties"].(map[string]any)["geo_db"].(map[string]any)["properties"].(map[string]any)
	var opt []string
	for _, x := range geoDB["optional_fields"].(map[string]any)["items"].(map[string]any)["enum"].([]any) {
		opt = append(opt, x.(string))
	}
	if !reflect.DeepEqual(opt, geo.OptionalFields) {
		t.Errorf("optional geo fields %v vs %v", opt, geo.OptionalFields)
	}
}

func TestVisitorKey(t *testing.T) {
	day1 := bytes.Repeat([]byte{1}, 32)
	day2 := bytes.Repeat([]byte{2}, 32)
	a := netip.MustParseAddr("203.0.113.7")
	k := VisitorKey(day1, a)
	if !ValidVisitorKey(k) || k != VisitorKey(day1, netip.MustParseAddr("::ffff:203.0.113.7")) {
		t.Fatalf("format or unmapping: %s", k)
	}
	if k == VisitorKey(day2, a) {
		t.Fatal("a new daily key must unlink the visitor")
	}
	if k == VisitorKey(day1, netip.MustParseAddr("203.0.113.8")) {
		t.Fatal("IPv4 addresses are keyed one by one")
	}
	v6 := VisitorKey(day1, netip.MustParseAddr("2001:db8:1:2::7"))
	if v6 != VisitorKey(day1, netip.MustParseAddr("2001:db8:1:2:ffff::1")) || v6 == VisitorKey(day1, netip.MustParseAddr("2001:db8:1:3::7")) {
		t.Fatal("IPv6 is keyed per /64")
	}
	if regexp.MustCompile(`203|113|2001|db8`).MatchString(k + v6) {
		t.Fatal("key looks like an address")
	}
}

func s(v string) *string { return &v }
func f(v float64) *float64 {
	return &v
}
func i(v int64) *int64 { return &v }

func record() Record {
	return Record{T: "2026-10-29T10:15:02.120Z", Site: "default", Host: "verein.example", Path: "/wp-login.php", PathKind: "template", Method: "POST", Status: 403,
		Outcome: BlockedWAF, AnomalyScore: 10, Rules: []string{"942100", "949110"}, EventID: "6f1c2b7e-1d4a-4c8e-9b2f-6a5d4e3c2b16", Country: "DE", ASN: 64496,
		NetClass: "residential", Browser: "none", OS: "none", Device: "unknown", BotCategory: bots.LikelyAutomated, Referrer: monitoring.ReferrerDirect,
		DurationMS: monitoring.BucketBound(20), BytesOut: 512, Visitor: VisitorKey(bytes.Repeat([]byte{7}, 32), netip.MustParseAddr("198.51.100.7"))}
}

// TestWireTypes: Go values encode to documents the OpenAPI schemas accept
// and decode back without unknown fields; broken values are rejected.
func TestWireTypes(t *testing.T) {
	_, c := openAPI(t)
	r := record()
	browse := Record{T: "2026-10-29T10:14:40Z", Site: "default", Host: "verein.example", Path: "/", PathKind: "template", Method: "GET", Status: 200,
		Outcome: Passed, Country: "DE", ASN: 64496, Browser: "firefox", OS: "linux", Device: "desktop", BotCategory: bots.LikelyBrowser,
		Referrer: "ai:perplexity", DurationMS: 12.3, BytesOut: 18000, PageView: true, Visitor: r.Visitor}
	bot := browse
	bot.Bot, bot.BotCategory, bot.Verification, bot.Browser, bot.OS, bot.Device, bot.PageView = "gptbot", "ai_training", bots.Mismatch, "none", "none", "unknown", false
	cursor := "r.1761732902.42"
	ok := []struct {
		name  string
		v     any
		proto any
	}{
		{"RequestRecord", r, Record{}},
		{"RequestPage", Page{From: "2026-10-29T10:00:00Z", To: "2026-10-29T11:00:00Z", Items: []Record{r, browse, bot}, NextCursor: &cursor, Scanned: 3, SampleRate: 1}, Page{}},
		{"RequestPage", Page{From: "2026-10-29T10:00:00Z", To: "2026-10-29T11:00:00Z", Items: []Record{}, SampleRate: 0.25, ScanCapped: true}, Page{}},
		{"RequestContext", Context{EventID: r.EventID, State: "complete", From: "2026-10-29T10:10:02Z", To: "2026-10-29T10:20:02Z", Anchor: &r,
			VisitorRequests: []Record{r}, VisitorSummary: &VisitorSummary{Requests: 1, Alerts: 1, Pattern: "alert_only"},
			SiteStrip: []StripPoint{{T: "2026-10-29T10:10:00Z", Requests: 40, Stopped: 1, Detections: 1}}}, Context{}},
		{"RequestContext", Context{EventID: r.EventID, State: "expired", From: "2026-10-26T10:10:02Z", To: "2026-10-26T10:20:02Z", VisitorRequests: []Record{}, SiteStrip: []StripPoint{}}, Context{}},
		{"BotOverview", BotOverview{From: "2026-10-28T11:00:00Z", To: "2026-10-29T11:00:00Z", CatalogueVersion: "2026-10-29.1", Verification: VerificationSettings{Ranges: true},
			Ranges:     []RangeInfo{{ID: "googlebot", Operator: "Google", FetchedAt: "2026-10-27T00:00:00Z", Source: "release"}},
			Categories: []CategoryEntry{{Category: "ai_training", Requests: 900, BytesOut: 4.2e7, Bots: 3}},
			Bots: []BotEntry{{ID: "gptbot", Name: "GPTBot", Operator: "OpenAI", Category: "ai_training", Requests: 600, BytesOut: 3e7, LastSeen: "2026-10-29T10:58:00Z",
				Verification: BotCounts{Verified: 590, Mismatch: 10}, Robots: &Robots{Token: "GPTBot", ReadAt: s("2026-10-29T06:00:00Z"), Respects: "yes"}}}, SampleRate: 1}, BotOverview{}},
		{"RuleAlerts", RuleAlerts{From: "2026-10-15T11:00:00Z", To: "2026-10-29T11:00:00Z", Resolution: "10m", RingFrom: s("2026-10-27T11:00:00Z"),
			Items: []RuleAlert{{RuleID: "942100", Detections: 410, Blocked: 0, WouldBlock: 410, Pages: []RulePage{{Path: "/kontakt/", Detections: 380, Requests: 1200, Rate: 0.32}},
				Clients: RuleClients{Hit: 140, AlertOnly: 3, InSession: 137}, PossibleFalsePositive: true}}}, RuleAlerts{}},
		{"PageAlerts", PageAlerts{From: "2026-10-28T11:00:00Z", To: "2026-10-29T11:00:00Z", Resolution: "1m", Items: []PageAlert{{Path: "/kontakt/", Requests: 1200, Detections: 380, Rate: 0.32,
			WouldBlock: 380, Status: &StatusClasses{S2xx: 1150, S4xx: 50}, LatencyP95MS: f(180), ObserveFollowedBy2xx: i(371), Rules: []RuleCount{{"942100", 380}}, Review: true}}}, PageAlerts{}},
		{"FalsePositiveHintList", FalsePositiveHintList{From: "2026-10-28T11:00:00Z", To: "2026-10-29T11:00:00Z", Items: []FalsePositiveHint{{RuleID: "942100", Path: "/kontakt/",
			Target: "ARGS:nachricht", Detections: 380, ClientsHit: 140, ClientsInSession: 137, Since: "2026-10-27T12:00:00Z",
			Exception: Exception{Language: "seclang", File: "rules.d/90-exceptions.conf", Snippet: `SecRule REQUEST_FILENAME "@streq /kontakt/" "id:1000301,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:nachricht"`}}}}, FalsePositiveHintList{}},
	}
	for _, tc := range ok {
		sch, err := c.Compile(schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/" + tc.name)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(tc.v)
		inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err := sch.Validate(inst); err != nil {
			t.Errorf("%s: %v\n%s", tc.name, err, b)
			continue
		}
		v := reflect.New(reflect.TypeOf(tc.proto)).Interface()
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	sch, _ := c.Compile(schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/RequestRecord")
	for name, mut := range map[string]func(m map[string]any){
		"four rules":    func(m map[string]any) { m["rules"] = []string{"1", "2", "3", "4"} },
		"query string":  func(m map[string]any) { m["query"] = "a=b" },
		"user agent":    func(m map[string]any) { m["user_agent"] = "Mozilla\n5.0" },
		"full referrer": func(m map[string]any) { m["referrer"] = "https://example.org/page?x=1" },
		"city":          func(m map[string]any) { m["city"] = "Berlin" },
		"long visitor":  func(m map[string]any) { m["visitor"] = "v1-00112233445566778899" },
		"outcome":       func(m map[string]any) { m["outcome"] = "challenged" },
		"control":       func(m map[string]any) { m["path"] = "/a\nb" },
		"verification":  func(m map[string]any) { m["verification"] = "fake" },
	} {
		b, _ := json.Marshal(record())
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mut(m)
		b, _ = json.Marshal(m)
		inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if sch.Validate(inst) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestNoAddressFields: no request schema has a property that could carry an
// address, a long-lived key or what the ring never stores.
func TestNoAddressFields(t *testing.T) {
	d, _ := openAPI(t)
	forbidden := regexp.MustCompile(`(?i)^(ips|client_ip|ip_key|ip_hash|client_key|address|cidr|remote_addr|prefix|query|query_string|city|region|cookies?|accept_language|ja4|headers?)$`)
	for _, name := range []string{"RequestRecord", "RequestPage", "RequestContext", "BotOverview", "RuleAlerts", "RuleAlert", "PageAlerts", "PageAlert", "FalsePositiveHint", "FalsePositiveHintList", "SiteStripPoint"} {
		var walk func(v any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				if p, ok := x["properties"].(map[string]any); ok {
					for k := range p {
						if forbidden.MatchString(k) {
							t.Errorf("%s: property %s", name, k)
						}
					}
				}
				for _, y := range x {
					walk(y)
				}
			case []any:
				for _, y := range x {
					walk(y)
				}
			}
		}
		walk(comp(d, name))
	}
}
