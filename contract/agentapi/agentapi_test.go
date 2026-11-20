package agentapi

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/schema"
)

const apiDir = "../../contracts/api"

func doc(t *testing.T) (map[string]any, *jsonschema.Compiler) {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	for rel, f := range schema.Files() {
		d, _ := jsonschema.UnmarshalJSON(bytes.NewReader(f))
		if err := c.AddResource(schema.BaseURL+rel, d); err != nil {
			t.Fatal(err)
		}
	}
	var agent map[string]any
	for _, name := range []string{"client-dashboard.openapi.yaml", "gateway-agent.openapi.yaml"} {
		b, err := os.ReadFile(filepath.Join(apiDir, name))
		if err != nil {
			t.Skipf("contracts/api not present: %v", err)
		}
		j, err := config.YAMLToJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		d, _ := jsonschema.UnmarshalJSON(bytes.NewReader(j))
		if err := c.AddResource(schema.BaseURL+"api/"+name, d); err != nil {
			t.Fatal(err)
		}
		if name == "gateway-agent.openapi.yaml" {
			_ = json.Unmarshal(j, &agent)
		}
	}
	return agent, c
}

func TestTokens(t *testing.T) {
	a, b := NewToken(), NewToken()
	if !ValidToken(a) || a == b || len(HashToken(a)) != 64 || !strings.HasPrefix(TokenID(a), "tok_") || len(TokenID(a)) != 16 {
		t.Fatal(a, TokenID(a))
	}
	for _, bad := range []string{"", "sat1_", "sat0_" + a[5:], a + "x", "Bearer " + a} {
		if ValidToken(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if d, err := ParseTTL("90d"); err != nil || d != 90*24*time.Hour {
		t.Fatal(d, err)
	}
	for _, bad := range []string{"0d", "366d", "never", "90", "12h", "-1d"} {
		if _, err := ParseTTL(bad); err == nil {
			t.Errorf("ttl %q accepted", bad)
		}
	}
	if !ValidScope(ScopeAgentRead) || !ValidScope(ScopeExportRead) || !ValidScope(ScopeBlocksWrite) || ValidScope("admin") || ValidScope("agent:write") {
		t.Fatal("scopes")
	}
	// Each write scope has its own operations; reading stays with every
	// scope but export:read; only write scopes need a label.
	if !AllowsWrite(ScopeBlocksWrite, OpCreateBlock) || !AllowsWrite(ScopeBlocksWrite, OpLiftBlock) || AllowsWrite(ScopeBlocksWrite, OpUpdateRuleRepository) ||
		AllowsWrite(ScopeRulesWrite, OpCreateBlock) || AllowsWrite(ScopeAgentRead, OpCreateBlock) || AllowsWrite(ScopeExportRead, OpLiftBlock) {
		t.Fatal("write scopes")
	}
	// D89: rules:write tunes; approving is gone, rules:approve with it.
	if !AllowsWrite(ScopeRulesWrite, OpUpdateRule) || AllowsWrite(ScopeRulesWrite, "approveAgentRule") || AllowsWrite("rules:approve", OpUpdateRule) || ValidScope("rules:approve") {
		t.Fatal("rule scopes")
	}
	if !CanRead(ScopeAgentRead) || !CanRead(ScopeBlocksWrite) || !CanRead(ScopeRulesWrite) || CanRead("rules:approve") || CanRead(ScopeExportRead) {
		t.Fatal("read scopes")
	}
	if !NeedsLabel(ScopeBlocksWrite) || !NeedsLabel(ScopeRulesWrite) || NeedsLabel(ScopeAgentRead) || NeedsLabel(ScopeExportRead) {
		t.Fatal("labels")
	}
	for _, sc := range Scopes {
		if !ValidScope(sc) || ScopeHelp[sc] == "" {
			t.Errorf("%s in Scopes but not valid or without help", sc)
		}
	}
	if len(ScopeHelp) != len(Scopes) {
		t.Error("ScopeHelp names a scope Scopes does not have")
	}
	for _, sc := range WriteOperations {
		if !slices.Contains(Scopes, sc) {
			t.Errorf("%s of a write not in Scopes", sc)
		}
	}
}

// The Go defaults of the block limits are the schema defaults (D42).
func TestBlockLimitDefaults(t *testing.T) {
	var doc struct {
		Properties struct {
			AgentAPI struct {
				Properties map[string]struct {
					Default any `json:"default"`
				} `json:"properties"`
			} `json:"agent_api"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema.Files()["config/schild.schema.json"], &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Properties.AgentAPI.Properties
	if p["block_writes_per_hour"].Default != float64(DefaultBlockWritesPerHour) || p["max_agent_blocks"].Default != float64(DefaultMaxAgentBlocks) {
		t.Fatalf("schema defaults %+v", p)
	}
}

func TestPseudonyms(t *testing.T) {
	k1, k2 := []byte("0123456789abcdef0123456789abcdef"), []byte("fedcba9876543210fedcba9876543210")
	a := netip.MustParseAddr("203.0.113.42")
	if ClientPseudonym(k1, a) != ClientPseudonym(k1, a) || ClientPseudonym(k1, a) == ClientPseudonym(k2, a) || ClientPseudonym(k1, a) == ClientPseudonym(k1, netip.MustParseAddr("203.0.113.43")) {
		t.Fatal("keyed pseudonym")
	}
	if ClientPseudonym(k1, a) != ClientPseudonym(k1, netip.MustParseAddr("::ffff:203.0.113.42")) {
		t.Fatal("mapped IPv4")
	}
	// IPv6: one /64 is one client key (behaviour engine), the next /64 another.
	if ClientPseudonym(k1, netip.MustParseAddr("2001:db8:1:2::17")) != ClientPseudonym(k1, netip.MustParseAddr("2001:db8:1:2:ffff::1")) ||
		ClientPseudonym(k1, netip.MustParseAddr("2001:db8:1:2::17")) == ClientPseudonym(k1, netip.MustParseAddr("2001:db8:1:3::17")) {
		t.Fatal("IPv6 /64")
	}
	if !strings.HasPrefix(ClientPseudonym(k1, a), "p1-") || len(ClientPseudonym(k1, a)) != 19 || strings.Contains(ClientPseudonym(k1, a), "203") {
		t.Fatal(ClientPseudonym(k1, a))
	}
	if ClientNet(a) != "203.0.113.0/24" || ClientNet(netip.MustParseAddr("2001:db8:1:2::17")) != "2001:db8:1::/48" {
		t.Fatal(ClientNet(a), ClientNet(netip.MustParseAddr("2001:db8:1:2::17")))
	}
	// v0.5: visitor keys of the request ring are re-keyed in their own domain.
	v := "v1-3a9f0c51d2e47b86"
	vp := VisitorPseudonym(k1, v)
	if vp != VisitorPseudonym(k1, v) || vp == VisitorPseudonym(k2, v) || vp == VisitorPseudonym(k1, "v1-3a9f0c51d2e47b87") ||
		!regexp.MustCompile(`^p1-[0-9a-f]{16}$`).MatchString(vp) || strings.Contains(vp, "3a9f0c51") {
		t.Fatal(vp)
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"/wp-login.php":           "/wp-login.php",
		"a\nb\x00c\x7fd":          "a�b�c�d",
		"x\u202eevil\u2066":       "x\ufffdevil\ufffd",
		"line\u2028sep":           "line\ufffdsep",
		string([]byte{0xff, 'a'}): "�a",
	} {
		if got := Sanitize(in, 512); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("ä", 400)
	got := Sanitize(long, MaxUserAgent)
	if len(got) > MaxUserAgent || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Fatalf("cut: %d %q", len(got), got[len(got)-8:])
	}
}

// TestFixturesRoundTrip: the agent fixtures of events and incidents decode
// into the Go types without unknown fields and encode back to valid documents.
func TestFixturesRoundTrip(t *testing.T) {
	_, c := doc(t)
	for file, tc := range map[string]struct {
		schema string
		proto  any
	}{
		"listAgentEvents": {"AgentEventPage", EventPage{}}, "getAgentEvent": {"AgentEvent", Event{}},
		"listAgentIncidents": {"AgentIncidentPage", IncidentPage{}}, "getAgentIncident": {"AgentIncident", Incident{}},
		// v0.5 (MVP-22)
		"queryRequests": {"AgentRequestPage", RequestPage{}}, "getRequestContext": {"AgentRequestContext", RequestContext{}},
		// D42
		"createAgentBlock": {"AgentBlockResult", BlockResult{}}, "createAgentBlock.would-block": {"AgentBlockResult", BlockResult{}},
	} {
		raw, err := os.ReadFile(filepath.Join(apiDir, "fixtures", "agent", file+".json"))
		if err != nil {
			t.Fatal(err)
		}
		v := reflect.New(reflect.TypeOf(tc.proto)).Interface()
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		out, _ := json.Marshal(v)
		sch, err := c.Compile(schema.BaseURL + "api/gateway-agent.openapi.yaml#/components/schemas/" + tc.schema)
		if err != nil {
			t.Fatal(err)
		}
		inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(out))
		if err := sch.Validate(inst); err != nil {
			t.Errorf("%s: %v", file, err)
		}
		var a, b any
		_ = json.Unmarshal(raw, &a)
		_ = json.Unmarshal(out, &b)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: round trip differs\n%s\n%s", file, raw, out)
		}
	}
	// Generated values validate too.
	key := []byte("0123456789abcdef0123456789abcdef")
	ip := netip.MustParseAddr("198.51.100.7")
	ev := Event{ID: "6f1c2b7e-1d4a-4c8e-9b2f-6a5d4e3c2b16", Time: "2026-10-28T12:00:00Z", Type: "schild.request.evaluated.v1", Outcome: "would_block",
		ClientPseudonym: ClientPseudonym(key, ip), ClientNet: ClientNet(ip), Path: Sanitize("/?q=<script>\n", MaxPath), Host: Sanitize("verein.example", MaxHost)}
	b, _ := json.Marshal(ev)
	sch, _ := c.Compile(schema.BaseURL + "api/gateway-agent.openapi.yaml#/components/schemas/AgentEvent")
	inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err := sch.Validate(inst); err != nil {
		t.Errorf("generated event: %v\n%s", err, b)
	}
	ev.Path = "/a\nb"
	b, _ = json.Marshal(ev)
	inst, _ = jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if sch.Validate(inst) == nil {
		t.Error("unsanitised control character accepted")
	}
}
