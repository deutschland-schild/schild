package apispec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/schema"
)

const apiDir = "../../contracts/api"

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(apiDir, name))
	if err != nil {
		t.Skipf("contracts/api not present: %v", err)
	}
	j, err := config.YAMLToJSON(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var v map[string]any
	if err := json.Unmarshal(j, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func pointer(doc any, ptr string) (any, bool) {
	cur := doc
	if ptr == "" || ptr == "/" {
		return cur, true
	}
	for _, p := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
		p = strings.ReplaceAll(strings.ReplaceAll(p, "~1", "/"), "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[p]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func walkRefs(v any, f func(string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if k == "$ref" {
				if s, ok := x.(string); ok {
					f(s)
				}
				continue
			}
			walkRefs(x, f)
		}
	case []any:
		for _, x := range t {
			walkRefs(x, f)
		}
	}
}

func TestDocuments(t *testing.T) {
	docs := map[string]map[string]any{}
	for name := range Docs {
		docs[name] = load(t, name)
	}
	for name, d := range docs {
		if d["openapi"] != "3.1.0" {
			t.Errorf("%s: openapi must be 3.1.0", name)
		}
		// $ref resolution.
		walkRefs(d, func(ref string) {
			file, frag, _ := strings.Cut(ref, "#")
			target := d
			if file != "" {
				if strings.HasSuffix(file, ".schema.json") {
					if _, err := os.Stat(filepath.Join(apiDir, file)); err != nil {
						t.Errorf("%s: $ref %s: %v", name, ref, err)
					}
					return
				}
				var ok bool
				if target, ok = docs[file]; !ok {
					t.Errorf("%s: $ref to unknown document %s", name, ref)
					return
				}
			}
			if _, ok := pointer(target, frag); !ok {
				t.Errorf("%s: $ref %s does not resolve", name, ref)
			}
		})
		// Operations.
		ids := map[string]bool{}
		paths, _ := d["paths"].(map[string]any)
		if len(paths) == 0 {
			t.Errorf("%s: no paths", name)
		}
		for p, item := range paths {
			for method, op := range item.(map[string]any) {
				o, ok := op.(map[string]any)
				if !ok {
					continue
				}
				id, _ := o["operationId"].(string)
				if id == "" || ids[id] {
					t.Errorf("%s %s %s: missing or duplicate operationId %q", name, method, p, id)
				}
				ids[id] = true
				if _, ok := o["responses"].(map[string]any); !ok {
					t.Errorf("%s %s %s: no responses", name, method, p)
				}
				for _, m := range regexp.MustCompile(`\{([a-z_]+)\}`).FindAllStringSubmatch(p, -1) {
					if !hasPathParam(d, o, m[1]) {
						t.Errorf("%s %s %s: path parameter %s not declared", name, method, p, m[1])
					}
				}
			}
		}
	}
}

func hasPathParam(doc map[string]any, op map[string]any, name string) bool {
	params, _ := op["parameters"].([]any)
	for _, p := range params {
		pm, _ := p.(map[string]any)
		if ref, ok := pm["$ref"].(string); ok && strings.HasPrefix(ref, "#") {
			if r, ok := pointer(doc, strings.TrimPrefix(ref, "#")); ok {
				pm, _ = r.(map[string]any)
			}
		}
		if pm["name"] == name && pm["in"] == "path" {
			return true
		}
	}
	return false
}

func compiler(t *testing.T) *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	for rel, b := range schema.Files() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource(schema.BaseURL+rel, doc); err != nil {
			t.Fatal(err)
		}
	}
	for name := range Docs {
		b, _ := os.ReadFile(filepath.Join(apiDir, name))
		j, err := config.YAMLToJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(j))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource(schema.BaseURL+"api/"+name, doc); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestComponentSchemasCompile(t *testing.T) {
	c := compiler(t)
	for name := range Docs {
		d := load(t, name)
		comps, _ := d["components"].(map[string]any)
		schemas, _ := comps["schemas"].(map[string]any)
		for s := range schemas {
			if _, err := c.Compile(schema.BaseURL + "api/" + name + "#/components/schemas/" + s); err != nil {
				t.Errorf("%s %s: %v", name, s, err)
			}
		}
	}
}

var ipv4 = regexp.MustCompile(`\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b`)

func docAddress(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return true
		}
	}
	return false
}

// successSchema returns the JSON pointer of the 200/201/202 response schema of
// an operation, or "" when it has none.
func successSchema(d map[string]any, opID string) (string, bool) {
	paths, _ := d["paths"].(map[string]any)
	for p, item := range paths {
		for method, op := range item.(map[string]any) {
			o, ok := op.(map[string]any)
			if !ok || o["operationId"] != opID {
				continue
			}
			for _, code := range []string{"200", "201", "202"} {
				r, _ := pointer(o, "/responses/"+code+"/content/application~1json/schema")
				if m, ok := r.(map[string]any); ok {
					if ref, ok := m["$ref"].(string); ok {
						return ref, true
					}
					return "#/paths/" + strings.ReplaceAll(strings.ReplaceAll(p, "~", "~0"), "/", "~1") + "/" + method + "/responses/" + code + "/content/application~1json/schema", true
				}
			}
			return "", true
		}
	}
	return "", false
}

// TestFixtures validates every fixture (v0.1 naming: <app>/<operationId>[.variant].json,
// so the app-kit mock finds them) against the success response schema of its
// operation; variants starting with "problem" validate against Problem.
func TestFixtures(t *testing.T) {
	c := compiler(t)
	total := 0
	for name, dir := range Docs {
		d := load(t, name)
		files, _ := filepath.Glob(filepath.Join(apiDir, "fixtures", dir, "*.json"))
		sort.Strings(files)
		if len(files) < 10 {
			t.Errorf("%s: only %d fixtures", name, len(files))
		}
		// fixtures/pending/<app>: operations no component serves yet. Checked
		// here; the builder moves them next to the others (D39).
		pending, _ := filepath.Glob(filepath.Join(apiDir, "fixtures", "pending", dir, "*.json"))
		files = append(files, pending...)
		for _, f := range files {
			total++
			base := strings.TrimSuffix(filepath.Base(f), ".json")
			opID, variant, _ := strings.Cut(base, ".")
			ref, found := successSchema(d, opID)
			if !found {
				t.Errorf("%s: no operation %q in %s (fixtures are named <operationId>[.variant].json)", f, opID, name)
				continue
			}
			url := schema.BaseURL + "api/" + name + ref
			if ref != "" && !strings.HasPrefix(ref, "#") {
				url = schema.BaseURL + "api/" + ref // v0.4: a schema of another API document
			}
			if strings.HasPrefix(variant, "problem") {
				url = schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/Problem"
			} else if ref == "" {
				t.Errorf("%s: operation %s has no JSON success response", f, opID)
				continue
			}
			sch, err := c.Compile(url)
			if err != nil {
				t.Errorf("%s: schema %s: %v", f, url, err)
				continue
			}
			b, _ := os.ReadFile(f)
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				t.Errorf("%s: %v", f, err)
				continue
			}
			if err := sch.Validate(inst); err != nil {
				t.Errorf("%s: %v", f, err)
			}
			// Documentation addresses only (RFC 5737, RFC 3849).
			for _, m := range ipv4.FindAllString(string(b), -1) {
				if !docAddress(m) {
					t.Errorf("%s: %s is not a documentation address", f, m)
				}
			}
			var v any
			_ = json.Unmarshal(b, &v)
			checkIPFields(t, f, v)
		}
	}
	if total == 0 {
		t.Skip("no fixtures")
	}
}

func checkIPFields(t *testing.T, f string, v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			if s, ok := y.(string); ok && (k == "ip") && !docAddress(s) {
				t.Errorf("%s: ip %q is not a documentation address", f, s)
			}
			if k == "resolved" {
				for _, r := range y.([]any) {
					if !docAddress(r.(string)) {
						t.Errorf("%s: resolved %q is not a documentation address", f, r)
					}
				}
			}
			checkIPFields(t, f, y)
		}
	case []any:
		for _, y := range x {
			checkIPFields(t, f, y)
		}
	}
}

// TestConventions checks the dashboard API conventions (DECISIONS D20) on
// every operation, so both dashboards can rely on them without exceptions.
func TestConventions(t *testing.T) {
	ipNames := map[string]bool{"ip": true, "ips": true, "client_ip": true, "remote_addr": true, "ip_address": true, "ip_prefix": true, "ip_hash": true, "cidr": true, "x_forwarded_for": true}
	for name := range Docs {
		d := load(t, name)
		walk(d, func(k string, v any) {
			if k == "format" {
				t.Errorf("%s: format keyword (implementations differ, D09): %v", name, v)
			}
		})
		paths, _ := d["paths"].(map[string]any)
		for p, item := range paths {
			for method, op := range item.(map[string]any) {
				o, ok := op.(map[string]any)
				if !ok {
					continue
				}
				id, _ := o["operationId"].(string)
				where := name + " " + strings.ToUpper(method) + " " + p
				params := map[string]bool{}
				for _, x := range asSlice(o["parameters"]) {
					m := x.(map[string]any)
					if ref, ok := m["$ref"].(string); ok {
						params[ref[strings.LastIndex(ref, "/")+1:]] = true
					} else {
						params[m["name"].(string)] = true
					}
				}
				resp, _ := o["responses"].(map[string]any)
				if def, _ := resp["default"].(map[string]any); def["$ref"] != "#/components/responses/Problem" {
					t.Errorf("%s: no default RFC 9457 problem response", where)
				}
				if method != "get" && id != "setupPassword" && id != "login" && agentapi.WriteOperations[id] == "" && id != agentapi.OpTestRequest && !params["CSRF"] {
					t.Errorf("%s: state change without X-CSRF-Token", where)
				}
				for _, code := range []string{"200", "201", "202"} {
					r, _ := resp[code].(map[string]any)
					b, _ := json.Marshal(r)
					if strings.Contains(string(b), `Page"`) && (!params["Cursor"] || !params["Limit"]) {
						t.Errorf("%s: page response without cursor and limit parameters", where)
					}
					if strings.Contains(string(b), "text/event-stream") && !params["Last-Event-ID"] {
						t.Errorf("%s: SSE without Last-Event-ID", where)
					}
				}
				if name == "lab-dashboard.openapi.yaml" {
					for pn := range params {
						if ipNames[strings.ToLower(pn)] {
							t.Errorf("%s: takes an IP parameter %s (labs never see visitor IPs)", where, pn)
						}
					}
				}
			}
		}
		if name == "lab-dashboard.openapi.yaml" {
			walk(d["components"], func(k string, v any) {
				if k != "properties" {
					return
				}
				for pn := range v.(map[string]any) {
					if ipNames[strings.ToLower(pn)] {
						t.Errorf("%s: schema has an IP property %s", name, pn)
					}
				}
			})
		}
	}
}

func asSlice(v any) []any { s, _ := v.([]any); return s }

func walk(v any, f func(k string, v any)) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			f(k, x)
			walk(x, f)
		}
	case []any:
		for _, x := range t {
			walk(x, f)
		}
	}
}

// TestNoNetwork checks D72: the gateway API has no network fields any more,
// a document that still carries one is invalid.
func TestNoNetwork(t *testing.T) {
	c := compiler(t)
	base := schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/"
	overview := `{"generated_at":"2026-10-28T12:00:00Z","profile":"production",
			"baseline":{"state":"active","reasons":[]},
			"counters_24h":{"requests":9120,"evaluated":9120,"blocked":37,"would_block":0,"incidents":37},
			"rules":{"crs_version":"4.8.0"}%s}`
	for _, tc := range []struct {
		schema string
		doc    string
		valid  bool
	}{
		{"RulePage", `{"items":[],"next_cursor":null}`, true},
		{"RulePage", `{"items":[],"next_cursor":null,"network":"off"}`, false},
		{"Rule", `{"repository":"network","id":"7700001","origin":"update","status":"active","effect":"block","hits_24h":0}`, false},
		{"Rule", `{"repository":"crs","id":"930120","origin":"release","status":"shadow","effect":"block","hits_24h":0}`, false},
		{"Rule", `{"repository":"crs","id":"930120","origin":"release","status":"active","effect":"block","hits_24h":0}`, true},
		{"RuleRepositoryId", `"network"`, false},
		{"Overview", fmt.Sprintf(overview, ""), true},
		{"Overview", fmt.Sprintf(overview, `,"network":"off"`), false},
		{"Overview", fmt.Sprintf(overview, `,"labs":[],"relays":[]`), false},
		{"SettingsPatch", `{"remote_rules":{"enabled":false}}`, false},
		{"SettingsPatch", `{"signals":{"enabled":false}}`, false},
	} {
		sch, err := c.Compile(base + tc.schema)
		if err != nil {
			t.Fatal(err)
		}
		inst, err := jsonschema.UnmarshalJSON(strings.NewReader(tc.doc))
		if err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(inst); (err == nil) != tc.valid {
			t.Errorf("%s %s: valid=%v, got %v", tc.schema, tc.doc, tc.valid, err)
		}
	}
}

// TestMonitoring checks the v0.4 (MVP-21) monitoring schemas the Go package
// contract/monitoring does not cover, with valid and invalid documents. The
// client adds fixtures once its dashboard serves these operations.
func TestMonitoring(t *testing.T) {
	c := compiler(t)
	base := schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/"
	now := `{"generated_at":"2026-10-28T12:00:00Z","started_at":"2026-10-28T08:00:00Z",
		"traffic":{"window_s":60,"requests_per_s":42.5,"requests_per_s_10s":40.1,"stopped_share":0.008,"would_block_share":0,"fail_closed":0,
			"upstream_error_share":0.001,"latency_total_p50_ms":18.6,"latency_total_p95_ms":91.3,"latency_overhead_p95_ms":1.2,"latency_upstream_p95_ms":89.9,
			"bytes_in_per_s":3100,"bytes_out_per_s":2400000,"clients_unique":180},
		"server":{"sampled_at":"2026-10-28T11:59:58Z","scope":"host","cpu_usage":0.23,"cores":4,"load1":0.9,"memory_used_ratio":0.61,
			"memory_available_bytes":3221225472,"swap_used_bytes":0,"disk":{"mount":"/","used_ratio":0.72},"net_rx_bytes_per_s":180000,"net_tx_bytes_per_s":2600000,"uptime_s":864000},
		"hints":[{"code":"disk_full_soon","level":"notice","since":"2026-10-28T09:00:00Z","value":0.91,"threshold":0.9,"object":"/var/lib/docker"}]%s}`
	idle := `{"generated_at":"2026-10-28T12:00:00Z","started_at":"2026-10-28T11:59:55Z",
		"traffic":{"window_s":60,"requests_per_s":0,"requests_per_s_10s":0,"stopped_share":null,"would_block_share":null,"fail_closed":0,
			"upstream_error_share":null,"latency_total_p50_ms":null,"latency_total_p95_ms":null,"latency_overhead_p95_ms":null,"latency_upstream_p95_ms":null,
			"bytes_in_per_s":0,"bytes_out_per_s":0},"server":null,"hints":[]}`
	breakdown := `{"by":"%s","from":"2026-10-28T11:00:00Z","to":"2026-10-28T12:00:00Z","resolution":"1m","exact":%s,
		"total":{"requests":1000,"stopped":12,"would_block":3},
		"items":[{"key":"%s","requests":400,"stopped":10,"would_block":0,"error":%d}],"other":{"requests":600,"stopped":2,"would_block":3}}`
	snapshot := `{"generated_at":"2026-10-28T12:00:00Z","sampled_at":"2026-10-28T11:59:58Z","interval_s":10,
		"environment":{"os_family":"linux","container":true,"cgroup":"v2","net_namespace":"%s","lxcfs":false},
		"os":{"source":"host_report","name":"Debian GNU/Linux 12 (bookworm)","kernel":"6.1.0-26-amd64","arch":"x86_64","eol":"2026-06-10","report_at":"2026-10-28T03:00:00Z"},
		"uptime_s":864000,
		"cpu":{"scope":"host","cores":4,"usage":0.23,"user":0.15,"system":0.06,"iowait":0.01,"steal":0.01,"per_core":[0.3,0.2,0.2,0.22],"load1":0.9,"load5":0.8,"load15":0.7},
		"memory":{"scope":"host","total_bytes":8589934592,"available_bytes":3221225472,"used_bytes":5368709120,"cached_bytes":2147483648,"swap_total_bytes":0,"swap_used_bytes":0,"oom_kills_24h":0},
		"container":{"cpu_limit_cores":null,"cpu_usage":0.05,"cpu_throttled":0,"memory_used_bytes":95000000,"memory_limit_bytes":null,"oom_kills":0},
		"mounts":[{"mount":"/","device":"sda1","fs_type":"ext4","size_bytes":80000000000,"used_bytes":57600000000,"avail_bytes":22400000000,"used_ratio":0.72,
			"inodes_total":5000000,"inodes_used":900000,"read_bytes_per_s":12000,"write_bytes_per_s":340000,"reads_per_s":2,"writes_per_s":30,"busy":0.03}],
		"interfaces":[{"name":"eth0","rx_bytes_per_s":180000,"tx_bytes_per_s":2600000,"rx_packets_per_s":900,"tx_packets_per_s":1900,"errors_per_s":0,"drops_per_s":0}],
		"tcp":{"source":"netlink","established":212,"syn_sent":0,"syn_recv":1,"fin_wait":3,"time_wait":480,"close_wait":0,"last_ack":0,"closing":0,"listen":9,"inuse":230,"orphan":0,"listen_drops_per_s":0,"retransmits_per_s":0.2},
		"conntrack":%s,
		"files":{"open":3200,"max":9223372036854775807},
		"process":{"started_at":"2026-10-28T08:00:00Z","version":"0.4.0","cpu_usage":0.02,"rss_bytes":91000000,"heap_bytes":40000000,"goroutines":180,"threads":14,"gc_pause_p99_ms":0.4,"open_files":96,"open_files_limit":1048576},
		"schild":{"event_queue_used":0,"event_queue_capacity":8192,"events_dropped_1h":0,"eval_slots_used":1,"eval_slots_max":4,"store_bytes":52428800,"store_max_bytes":104857600,
			"metrics_store_bytes":16777216,"sampler_ms":2.1,"sampler_budget_ms":50},
		"unavailable":%s}`
	for _, tc := range []struct {
		schema string
		doc    string
		valid  bool
	}{
		{"MonitoringNow", fmt.Sprintf(now, ""), true},
		{"MonitoringNow", fmt.Sprintf(now, `,"sites":[{"site":"verein","label":"Verein","requests_per_s":30,"stopped_share":0.01},{"site":"_other","requests_per_s":12.5,"stopped_share":null}]`), true},
		{"MonitoringNow", idle, true},
		{"MonitoringNow", fmt.Sprintf(now, `,"ip":"203.0.113.7"`), false},
		{"MonitoringNow", strings.Replace(idle, `"hints":[]`, `"hints":[{"code":"under_attack","level":"warning","since":"2026-10-28T12:00:00Z"}]`, 1), false},
		{"MonitoringNow", strings.Replace(idle, `"hints":[]`, `"hints":[{"code":"cpu_high","level":"critical","since":"2026-10-28T12:00:00Z"}]`, 1), false},
		{"MonitoringNow", strings.Replace(idle, `"stopped_share":null`, `"stopped_share":1.5`, 1), false},
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "path", "false", "/wp-json/wp/v2/users/{n}", 4), true},
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "country", "true", "DE", 0), true},
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "ua_class", "true", "bot_unverified", 0), true},
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "ip", "true", "203.0.113.7", 0), true}, // D65: from the request ring
		{"TrafficBreakdown", strings.Replace(fmt.Sprintf(breakdown, "path", "false", "/", 0), `"1m"`, `"10s"`, 1), false},
		{"ServerSnapshot", fmt.Sprintf(snapshot, "host", `{"count":1200,"max":262144}`, `[]`), true},
		{"ServerSnapshot", fmt.Sprintf(snapshot, "own", `null`, `[{"area":"conntrack","reason":"container_hidden"}]`), true},
		{"ServerSnapshot", fmt.Sprintf(snapshot, "bridge", `null`, `[]`), false},
		{"ServerSnapshot", fmt.Sprintf(snapshot, "own", `null`, `[{"area":"conntrack","reason":"forbidden"}]`), false},
		{"MetricQuery", `"traffic.requests:rate"`, true},
		{"MetricQuery", `"server.cpu_usage"`, true},
		{"MetricQuery", `"traffic.requests:median"`, false},
		{"MetricQuery", `"ip.requests"`, false},
		{"LatencyHistogram", `{"scheme":"exp1.25-0.05ms","counts":{"0":1,"57":2}}`, true},
		{"LatencyHistogram", `{"scheme":"exp1.25-0.05ms","counts":{"58":1}}`, false},
		{"LatencyHistogram", `{"scheme":"exp1.25-0.05ms","counts":{"3":0}}`, false},
		{"MetricValues", `{"gauges":{"server.cpu_usage":{"avg":0.2,"min":0.1,"max":0.4}}}`, true},
		{"MetricValues", `{"gauges":{"server.cpu":{"avg":0.2,"min":0.1,"max":0.4}}}`, false},
		{"SiteKey", `"_other"`, true},
		{"SiteKey", `"_all"`, false},
		// v0.4 addendum (2026-10-28): behaviour reason learning.
		{"BehaviourReason", `"learning"`, true},
		// Addendum 2026-10-29 (MVP-22 MVP-21 addendum): new dimensions, detections, page views.
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "referrer", "false", "ai:perplexity", 0), true},
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "referrer", "false", "_intern", 0), true},
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "browser", "true", "firefox", 0), true},
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "os", "true", "android", 0), true},
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "device", "true", "tablet", 0), true},
		{"TrafficBreakdown", strings.Replace(fmt.Sprintf(breakdown, "bot_category", "true", "ai_training", 0), `"exact":true`, `"exact":true,"bot_verification":false`, 1), true},
		{"TrafficBreakdown", strings.Replace(fmt.Sprintf(breakdown, "path", "false", "/kontakt/", 0), `"error":0`, `"detections":7,"error":0`, 1), true},
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "rule", "false", "942100", 1), true},
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "user_agent", "true", "Mozilla/5.0", 0), true}, // D65
		{"TrafficBreakdown", fmt.Sprintf(breakdown, "referrer_url", "false", "https://example.org/a?b=c", 0), false},
		{"TrafficBreakdown", strings.Replace(fmt.Sprintf(breakdown, "path", "false", "/", 0), `"error":0`, `"detections":-1,"error":0`, 1), false},
		{"ReferrerKey", `"_direct"`, true},
		{"ReferrerKey", `"example.co.uk"`, true},
		{"ReferrerKey", `"ai:chatgpt"`, true},
		{"ReferrerKey", `"https://example.org/page"`, false},
		{"ReferrerKey", `"Example.org"`, false},
		{"ReferrerKey", `"localhost"`, false},
		{"BrowserFamily", `"chrome"`, true},
		{"BrowserFamily", `"chrome 129"`, false},
		{"OSFamily", `"ios"`, true},
		{"OSFamily", `"ios 18"`, false},
		{"DeviceClass", `"unknown"`, true},
		{"DeviceClass", `"iphone"`, false},
		{"BotCategory", `"likely_automated"`, true},
		{"BotCategory", `"ai_crawler"`, false},
		{"MetricQuery", `"traffic.page_views:sum"`, true},
	} {
		sch, err := c.Compile(base + tc.schema)
		if err != nil {
			t.Fatal(err)
		}
		inst, err := jsonschema.UnmarshalJSON(strings.NewReader(tc.doc))
		if err != nil {
			t.Fatalf("%s: %v\n%s", tc.schema, err, tc.doc)
		}
		if err := sch.Validate(inst); (err == nil) != tc.valid {
			t.Errorf("%s %.200s: valid=%v, got %v", tc.schema, tc.doc, tc.valid, err)
		}
	}
}

// TestAgentAPI checks the v0.4 (MVP-21, D33) agent API: GET only apart from
// the writes, every operation tells an agent what it is for (D61) and attacker-controlled properties are
// marked x-untrusted with a length cap. Fixtures carry documentation addresses only (TestFixtures).
func TestAgentAPI(t *testing.T) {
	const name = "gateway-agent.openapi.yaml"
	d := load(t, name)
	agentWrites := map[string]string{"patch /rule-repositories/{repository}": agentapi.OpUpdateRuleRepository,
		"post /rule-repositories/{repository}/sync": agentapi.OpSyncRuleRepository, "post /rule-repositories/{repository}/reset": agentapi.OpResetRuleRepository,
		"patch /rules/{repository}/{rule}": agentapi.OpUpdateRule, "post /blocks": agentapi.OpCreateBlock, "post /incidents/{incident}/lift": agentapi.OpLiftBlock, "post /exceptions": agentapi.OpCreateException, "post /exceptions/{id}/remove": agentapi.OpRemoveException, "post /crawlers": agentapi.OpSetCrawlers,
		// D87: the firewall says what it applied and gets the blocks.
		"post /firewall/sync": agentapi.OpSyncFirewall}
	ops, writes := map[string]bool{}, map[string]bool{}
	for p, item := range d["paths"].(map[string]any) {
		for method, op := range item.(map[string]any) {
			id := op.(map[string]any)["operationId"].(string)
			if d, _ := op.(map[string]any)["description"].(string); len(d) < 20 {
				t.Errorf("%s: no description for agents", id)
			}
			// The writes, by name: nothing else may write.
			// The request test posts a sample and changes nothing (D55).
			if method == "post" && p == "/rules/test" && id == agentapi.OpTestRequest {
				ops[id] = true
				continue
			}
			if method != "get" && agentWrites[method+" "+p] != id {
				t.Errorf("%s %s %s: the agent API reads, except the writes named here", name, method, p)
			}
			if method != "get" {
				writes[id] = true
			}
			ops[id] = true
		}
	}
	if len(writes) != len(agentapi.WriteOperations) {
		t.Errorf("writes in the document %v, agentapi.WriteOperations %v", writes, agentapi.WriteOperations)
	}
	untrusted := map[string]bool{"host": true, "path": true, "user_agent": true, "msg": true, "reason": true, "query": true, "referrer": true} // v0.5: referrer
	schemas := d["components"].(map[string]any)["schemas"].(map[string]any)
	walk(d["components"], func(k string, v any) {
		if k != "properties" {
			return
		}
		for pn, ps := range v.(map[string]any) {
			if !untrusted[pn] {
				continue
			}
			m := ps.(map[string]any)
			if m["type"] == "boolean" {
				continue
			}
			if ref, ok := m["$ref"].(string); ok && strings.HasPrefix(ref, "#/components/schemas/") {
				m = schemas[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any)
			}
			if m["x-untrusted"] != true || m["maxLength"] == nil {
				t.Errorf("%s: property %s is not marked x-untrusted with maxLength", name, pn)
			}
		}
	})
}

// TestAgentBundle: the document the gateway serves (D61) is the bundle of
// gateway-agent.openapi.yaml as it is now, and every reference stays inside it.
func TestAgentBundle(t *testing.T) {
	b, err := Bundle(filepath.Join("..", "..", "contracts", "api"), AgentDoc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, agentapi.OpenAPI) {
		t.Fatal("contract/agentapi/openapi.json is stale: make contracts-sync")
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	n := 0
	walkRefs(d, func(ref string) {
		n++
		if !strings.HasPrefix(ref, "#/") {
			t.Errorf("reference outside the bundle: %s", ref)
			return
		}
		if _, ok := pointer(d, ref[1:]); !ok {
			t.Errorf("unresolved %s", ref)
		}
	})
	if n < 100 {
		t.Errorf("%d references", n)
	}
	if len(b) > agentapi.MaxBytes/2 {
		t.Errorf("bundle %d bytes", len(b))
	}
}

// TestAuditActions: every writing operation of the dashboard and the agent
// API writes an audit entry or stands in not_audited with its reason
// (contracts/audit.md), and the catalogue names no operation that is gone.
func TestAuditActions(t *testing.T) {
	listed := map[string]bool{}
	for _, a := range audit.Actions.Actions {
		for _, o := range a.Operations {
			listed[o] = true
		}
	}
	for _, o := range audit.Actions.NotAudited {
		listed[o.Operation] = true
	}
	known := map[string]bool{"agent:any": true}
	for _, o := range audit.Actions.Undocumented {
		known[o.Operation] = true
	}
	for way, name := range map[string]string{"dashboard": "client-dashboard.openapi.yaml", "agent": "gateway-agent.openapi.yaml"} {
		paths, _ := load(t, name)["paths"].(map[string]any)
		routes := map[string]bool{}
		for p, item := range paths {
			for method, op := range item.(map[string]any) {
				o, ok := op.(map[string]any)
				if !ok {
					continue
				}
				routes[strings.ToUpper(method)+" "+p] = true
				if method == "get" {
					continue
				}
				id := way + ":" + o["operationId"].(string)
				known[id] = true
				if !listed[id] {
					t.Errorf("%s %s (%s): no action in contracts/audit-actions.json", strings.ToUpper(method), p, id)
				}
			}
		}
		for _, o := range audit.Actions.Undocumented {
			if strings.HasPrefix(o.Operation, way+":") && routes[o.Route] {
				t.Errorf("%s is documented now: take it out of undocumented", o.Operation)
			}
		}
	}
	for o := range listed {
		if (strings.HasPrefix(o, "dashboard:") || strings.HasPrefix(o, "agent:")) && !known[o] {
			t.Errorf("%s: no such operation", o)
		}
	}
}
