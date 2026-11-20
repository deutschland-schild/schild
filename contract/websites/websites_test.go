package websites

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/schema"
)

func TestPunycode(t *testing.T) {
	for u, a := range map[string]string{"bücher": "bcher-kva", "münchen-verein": "mnchen-verein-wob", "ü": "tda", "例え": "r8jz45g"} {
		got, err := punyEncode(u)
		if err != nil || got != a {
			t.Errorf("encode %s: %q %v, want %q", u, got, err, a)
		}
		back, err := punyDecode(a)
		if err != nil || back != u {
			t.Errorf("decode %s: %q %v", a, back, err)
		}
	}
	if _, err := punyDecode("99999999999999"); err == nil {
		t.Error("overflow accepted")
	}
}

func TestServerStatus(t *testing.T) {
	for _, c := range []struct {
		s    Server
		want string
	}{
		{Server{Node: "web-1", State: "ok", Baseline: "active"}, StatusOK},
		{Server{Node: "web-1", State: "ok", Baseline: "active", Hints: []Hint{{Code: "disk_full_soon", Level: "notice"}}}, StatusAttention},
		{Server{Node: "web-1", State: "ok", Baseline: "degraded"}, StatusAttention},
		{Server{Node: "web-1", State: "ok", Baseline: "off"}, StatusDisrupted},
		{Server{Node: "web-1", State: "not_ready", Baseline: "active"}, StatusDisrupted},
	} {
		if got := ServerStatus(c.s); got != c.want {
			t.Errorf("%+v: %s, want %s", c.s, got, c.want)
		}
	}
}

func TestDeriveResolve(t *testing.T) {
	s, err := Derive(Input{Mode: ModeIngress, Blocks: []Block{
		{Addresses: []string{"example.org", "www.example.org"}, Schild: true, Proxies: true},
		{Addresses: []string{"*.example.org"}, Schild: true, Proxies: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{"WWW.example.org:443": "example.org", "shop.example.org": "_.example.org", "example.net": ""} {
		if got := s.Resolve(host); got != want {
			t.Errorf("Resolve(%s) = %q, want %q", host, got, want)
		}
	}
}

// TestHostFold: hostFold names every non-ASCII rune that strings.EqualFold or
// strings.ToLower (Caddy's host matcher) takes for an ASCII letter (D69).
func TestHostFold(t *testing.T) {
	n := 0
	for r := rune(utf8.RuneSelf); r <= unicode.MaxRune; r++ {
		want := ""
		for c := 'a'; c <= 'z'; c++ {
			if strings.EqualFold(string(r), string(c)) || strings.ToLower(string(r)) == string(c) {
				want = string(c)
			}
		}
		if want == "" {
			continue
		}
		n++
		if got := foldHost(string(r)); got != want {
			t.Errorf("foldHost(%U) = %q, want %q", r, got, want)
		}
	}
	if n != 3 {
		t.Errorf("%d runes fold to ASCII, hostFold has 3", n)
	}
}

func TestRouteWebsite(t *testing.T) {
	s, err := Derive(Input{Mode: ModeIngress, Blocks: []Block{
		{Addresses: []string{"secret.example.org", "www.secret.example.org"}, Schild: true, Proxies: true},
		{Addresses: []string{"*.kunden.example.org"}, Schild: true, Proxies: true},
		{Addresses: []string{"[2001:db8::1]"}, Schild: true, Proxies: true},
		{Addresses: []string{"bücher.example"}, Schild: true, Proxies: true},
		{Addresses: []string{":8080"}, Schild: true, Proxies: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		hosts []string
		want  string
	}{
		{[]string{"secret.example.org", "www.secret.example.org"}, "secret.example.org"},
		{[]string{"Secret.Example.ORG."}, "secret.example.org"},
		{[]string{"*.kunden.example.org"}, "_.kunden.example.org"},
		{[]string{"2001:db8::1"}, "ipv6-2001-db8--1"},
		{[]string{"[2001:0db8::1]"}, "ipv6-2001-db8--1"},
		{[]string{"bücher.example"}, "xn--bcher-kva.example"},
		{nil, ""},                              // no host matcher: left to Resolve
		{[]string{"a.kunden.example.org"}, ""}, // a request host, not an address
		{[]string{"secret.example.org", "*.kunden.example.org"}, ""}, // two websites
		{[]string{"other.example.org"}, ""},
	} {
		if got := s.RouteWebsite(c.hosts); got != c.want {
			t.Errorf("RouteWebsite(%q) = %q, want %q", c.hosts, got, c.want)
		}
	}
}

// TestWireTypes: the Go wire types encode to documents the OpenAPI schemas
// accept and decode back without unknown fields.
func TestWireTypes(t *testing.T) {
	b, err := os.ReadFile("../../contracts/api/client-dashboard.openapi.yaml")
	if err != nil {
		t.Skipf("contracts/api not present: %v", err)
	}
	j, err := config.YAMLToJSON(b)
	if err != nil {
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
	// The example documents of the v0.5 (D36) operations are client
	// fixtures named after their operation (contracts/api/fixtures/client,
	// moved there from testdata by the D36 amendment). Those served with a
	// type of this package decode into it without unknown fields and encode
	// back to the same document; the others are checked by their schema
	// only (contract/apispec TestFixtures checks every fixture too).
	for op, x := range map[string]struct {
		schema string
		proto  any
	}{
		"listWebsites": {"WebsiteList", List{}}, "getWebsite": {"WebsiteDetail", Detail{}},
		"getWebsiteKpis": {"WebsiteKpis", Kpis{}}, "getWebsiteRealtime": {"WebsiteRealtime", Realtime{}},
		"listAnnotations": {"AnnotationList", AnnotationList{}}, "listAlerts": {"AlertFeed", AlertFeed{}},
		"listIncidents": {"IncidentPage", nil}, "listAgentCalls": {"AgentCallLog", nil},
	} {
		dir := "../../contracts/api/fixtures/client"
		variants, _ := filepath.Glob(filepath.Join(dir, op+".*.json")) // e.g. getWebsiteKpis.partial
		for _, f := range append([]string{filepath.Join(dir, op+".json")}, variants...) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Errorf("fixture %s: %v", f, err)
				continue
			}
			sch, err := c.Compile(schema.BaseURL + "api/client-dashboard.openapi.yaml#/components/schemas/" + x.schema)
			if err != nil {
				t.Fatal(err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if err := sch.Validate(inst); err != nil {
				t.Errorf("%s: %v", f, err)
			}
			if x.proto == nil {
				continue
			}
			v := reflect.New(reflect.TypeOf(x.proto)).Interface()
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(v); err != nil {
				t.Errorf("%s: %v", f, err)
				continue
			}
			out, _ := json.Marshal(v)
			var a, b any
			_ = json.Unmarshal(raw, &a)
			_ = json.Unmarshal(out, &b)
			if !reflect.DeepEqual(dropEmpty(a), dropEmpty(b)) {
				t.Errorf("%s: round trip differs\n%s", f, out)
			}
		}
	}
	p95, share := 91.3, 0.008
	now := &monitoring.TrafficNow{WindowS: 60, RequestsPerS: 42.5, StoppedShare: &share, LatencyTotalP95MS: &p95}
	srv := ServerHealth{Node: "web-1", This: true, Status: StatusAttention, Baseline: "active",
		Hints: []monitoring.HealthHint{{Code: monitoring.HintDiskFullSoon, Level: "notice", Since: "2026-10-29T09:00:00Z", Object: "/var/lib/docker"}}}
	site := Summary{ID: "xn--bcher-kva.example", Label: "bücher.example", Hosts: []string{"xn--bcher-kva.example", "www.xn--bcher-kva.example"}, HostsTotal: 2,
		Source: SourceCaddyfile, Protection: Protected, Tracked: true, Status: StatusAttention,
		Reasons: []Reason{{Code: ReasonServerHint, Node: "web-1", Hint: monitoring.HintDiskFullSoon, Object: "/var/lib/docker"}}, Now: now, RunsOn: []ServerHealth{srv}}
	legacy := Summary{ID: "legacy.example.org", Label: "legacy.example.org", Hosts: []string{"legacy.example.org"}, HostsTotal: 1, Source: SourceCaddyfile,
		Protection: Unprotected, Status: StatusUnknown, Reasons: []Reason{{Code: ReasonUnprotected}}, RunsOn: []ServerHealth{srv}}
	var tr monitoring.TrafficCounters
	for _, c0 := range []struct {
		name  string
		v     any
		proto any
	}{
		{"WebsiteList", List{GeneratedAt: "2026-10-29T12:00:00Z", Node: "web-1", Server: &srv, Websites: []Summary{site, legacy}, Other: &Other{Websites: 3, Now: now}}, List{}},
		{"WebsiteDetail", Detail{GeneratedAt: "2026-10-29T12:00:00Z", Website: site, Traffic24h: &tr, Incidents24h: 2}, Detail{}},
		{"WebsiteDetail", Detail{GeneratedAt: "2026-10-29T12:00:00Z", Website: legacy}, Detail{}},
		{"SitesAffected", SitesAffected{Sites: []string{"verein.example", "shop.example.org", "_any"}, Count: 3, Total: 4}, SitesAffected{}},
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

// dropEmpty removes nulls, false and empty arrays from objects: Go omits
// them where the schema allows it (omitempty) and fixtures may spell them.
func dropEmpty(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			if a, ok := x.([]any); x == nil || x == false || ok && len(a) == 0 {
				continue
			}
			out[k] = dropEmpty(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = dropEmpty(x)
		}
		return out
	}
	return v
}
