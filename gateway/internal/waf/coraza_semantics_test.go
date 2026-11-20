package waf

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The SecLang subset (contracts/seclang-subset.md, DECISIONS D21) rejects
// several rules because of how Coraza parses and evaluates them. These tests
// pin those semantics for the Coraza version the client ships, so that a
// Coraza upgrade that changes them fails here (re-verified for v3.8.1, D24).

var vecID = regexp.MustCompile(`id:(\d+)`)

// rejectedVector loads an invalid SecLang vector straight into Coraza,
// bypassing the contract validator.
func rejectedVector(t *testing.T, name string) *Instance {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../../contracts/vectors/seclang/invalid", name))
	if os.IsNotExist(err) {
		t.Skip("contracts/vectors not present")
	}
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		InputRaw string `json:"input_raw"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	m := vecID.FindStringSubmatch(v.InputRaw)
	if m == nil {
		t.Fatalf("%s: no id", name)
	}
	inst, err := Build(Config{LocalRules: asLocal(v.InputRaw)})
	if err != nil {
		t.Fatalf("%s: Coraza rejects: %v", name, err)
	}
	return inst
}

func fires(t *testing.T, inst *Instance, r *http.Request) bool {
	t.Helper()
	r.Header.Set("Referer", "https://shop.example/")
	r.Header.Set("Cookie", "session=0123456789abcdef")
	a, err := eval(t, inst, r)
	if err != nil {
		t.Fatal(err)
	}
	return len(a.Matches) > 0
}

// asLocal moves a rule of the reserved network range (7700000..7799999) to
// the local range 1700000..1799999: the gateway loads no network rules (D72),
// the semantics pinned here are the same for any rule id.
func asLocal(text string) string {
	return networkID.ReplaceAllString(text, "${1}17$2")
}

var networkID = regexp.MustCompile(`(id:)77([0-9]{5})`)

// Rejected because Coraza turns them into catch-alls: they fire on every
// ordinary request.
func TestCorazaCatchAllVectors(t *testing.T) {
	for _, name := range []string{
		"016-catch-all-rx.json",
		"017-unconditional.json",
		"044-rx-leading-space.json",  // Coraza trims the argument: "@rx  .*" is ".*"
		"045-rx-trailing-space.json", // same, trailing
		"046-pm-double-space.json",   // "a  b" adds the empty phrase
		"051-rx-dot-catch-all.json",
		"052-rx-root-catch-all.json",
		"053-beginswith-slash.json",
	} {
		inst := rejectedVector(t, name)
		for _, b := range benign {
			if !fires(t, inst, browserReq(b.method, b.uri, b.ctype, b.body)) {
				t.Errorf("%s: no longer fires on %s %s (Coraza semantics changed, review seclang-subset.md)", name, b.method, b.uri)
			}
		}
	}
}

// "@within abc" on an empty value: the empty string is within every argument.
func TestCorazaWithinEmptyValue(t *testing.T) {
	inst := rejectedVector(t, "050-within-empty-catch-all.json")
	if !fires(t, inst, browserReq("GET", "/", "", "")) {
		t.Error("@within no longer matches an empty QUERY_STRING")
	}
	if fires(t, inst, browserReq("GET", "/?x=zzz", "", "")) {
		t.Error("@within matches an unrelated value")
	}
}

// Coraza expands macros in operator arguments, so "%{...}" would let a rule
// of the SecLang subset use the client address or the site's host.
func TestCorazaOperatorMacros(t *testing.T) {
	inst := rejectedVector(t, "047-streq-macro-remote-addr.json")
	if !fires(t, inst, browserReq("GET", "/?a=203.0.113.7", "", "")) { // eval uses client 203.0.113.7
		t.Error("@streq %{REMOTE_ADDR} is no longer expanded to the client address")
	}
	if fires(t, inst, browserReq("GET", "/?a=198.51.100.1", "", "")) {
		t.Error("@streq %{REMOTE_ADDR} matches another address")
	}
	inst = rejectedVector(t, "048-contains-macro-host.json")
	if !fires(t, inst, browserReq("GET", "/go/shop.example", "", "")) { // browserReq sets Host shop.example
		t.Error("@contains %{REQUEST_HEADERS.host} is no longer expanded to the host")
	}
	if fires(t, inst, browserReq("GET", "/go/other.example", "", "")) {
		t.Error("@contains %{REQUEST_HEADERS.host} matches another host")
	}
}

// Operator semantics the catch-all check in contract/seclang assumes
// (seclang-subset.md, "Operator semantics for the check are Coraza's").
func TestCorazaOperatorSemantics(t *testing.T) {
	cases := []struct {
		op, value string
		want      bool
	}{
		{"@rx b[0-9]c", "aab1cc", true}, // search anywhere
		{"@rx ^b", "ab", false},
		{"@pm union sleep", "x UNION y", true}, // ASCII case-insensitive substring
		{"@pm union sleep", "x unio y", false},
		{"@streq abc", "abc", true},
		{"@streq abc", "abcd", false},
		{"@contains Abc", "xAbcx", true}, // case-sensitive
		{"@contains Abc", "xabcx", false},
		{"@beginsWith Abc", "Abcx", true},
		{"@beginsWith Abc", "abcx", false},
		{"@endsWith Abc", "xAbc", true},
		{"@endsWith Abc", "xabc", false},
		{"@within alpha beta", "alpha", true}, // value occurs in the argument
		{"@within alpha beta", "gamma", false},
	}
	for i, c := range cases {
		id := 1700900 + i
		rule := `SecRule ARGS:q "` + c.op + `" "id:` + strconv.Itoa(id) + `,phase:2,deny,severity:CRITICAL,msg:'x',t:none"`
		inst, err := Build(Config{LocalRules: rule})
		if err != nil {
			t.Fatalf("%s: %v", c.op, err)
		}
		body := "q=" + url.QueryEscape(c.value)
		got := fires(t, inst, browserReq("POST", "/s", "application/x-www-form-urlencoded", body))
		if got != c.want {
			t.Errorf("%s on %q: fires=%v, want %v", c.op, c.value, got, c.want)
		}
	}
}
