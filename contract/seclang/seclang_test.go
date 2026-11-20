package seclang

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract"
)

func TestCases(t *testing.T) {
	valid, invalid := 0, 0
	names := map[string]bool{}
	for _, c := range Cases {
		if names[c.Name] {
			t.Fatalf("duplicate case name %s", c.Name)
		}
		names[c.Name] = true
		r, err := Validate(c.Text, Options{MaxAction: c.MaxAction})
		if c.Valid {
			valid++
			if err != nil {
				t.Errorf("%s: want valid, got %v", c.Name, err)
			} else if r.ID < contract.RemoteRuleIDMin {
				t.Errorf("%s: id not parsed", c.Name)
			}
		} else {
			invalid++
			if err == nil {
				t.Errorf("%s: want invalid, got valid", c.Name)
			} else if contract.CodeOf(err) != contract.CodeSecLang {
				t.Errorf("%s: wrong code %v", c.Name, err)
			}
		}
	}
	if valid < 5 || invalid < 10 {
		t.Fatalf("need >= 5 valid and >= 10 invalid cases, have %d/%d", valid, invalid)
	}
}

func TestParsedHead(t *testing.T) {
	r, err := Validate(Cases[1].Text, Options{MaxAction: "challenge"})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != 7700002 || r.Phase != 1 || r.Disruptive != "block" || r.Lines != 2 {
		t.Fatalf("got %+v", r)
	}
}

func TestLimits(t *testing.T) {
	long := `SecRule ARGS "@rx ` + strings.Repeat("a", MaxRegexLen+1) + `" "id:7700001,phase:2,deny,severity:CRITICAL,msg:'x'"`
	if _, err := Validate(long, Options{}); err == nil {
		t.Fatal("long regex accepted")
	}
	if _, err := Validate(strings.Repeat("x", contract.MaxSecLangBytes+1), Options{}); err == nil {
		t.Fatal("oversize accepted")
	}
	if _, err := Validate("", Options{}); err == nil {
		t.Fatal("empty accepted")
	}
	many := `SecRule ` + strings.TrimSuffix(strings.Repeat("ARGS|", MaxVariables+1), "|") + ` "@detectSQLi" "id:7700001,phase:2,deny,severity:CRITICAL,msg:'x'"`
	if _, err := Validate(many, Options{}); err == nil {
		t.Fatal("too many variables accepted")
	}
}

// Every regexp escape outside the allowlist is rejected (Go RE2 and Python
// re disagree on many of them).
func TestRegexEscapes(t *testing.T) {
	ok := []string{`\.`, `\d`, `\w`, `\s`, `\x41`, `[\]a]`, `\bword\b`, `(?i:abc)`, `(?:a|b)c`}
	bad := []string{`\z`, `\Z`, `\Q.\E`, `\pL`, `\x{41}`, `[\b]`, `\k<a>`, `(?P<n>a)`, `(?U)a`, `a{,3}b`, `[[:alpha:]]`, `a++`, `[]a]`, `a\`}
	for _, p := range ok {
		if err := validateRegex(p); err != nil {
			t.Errorf("%s rejected: %v", p, err)
		}
	}
	for _, p := range bad {
		if err := validateRegex(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

func FuzzValidate(f *testing.F) {
	for _, c := range Cases {
		f.Add(c.Text)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Validate(s, Options{MaxAction: "block"})
		if err != nil {
			return
		}
		// Invariants of every accepted rule.
		if r.ID < contract.RemoteRuleIDMin || r.ID > contract.RemoteRuleIDMax {
			t.Fatalf("accepted id %d", r.ID)
		}
		for _, bad := range []string{"ctl:", "REMOTE_ADDR", "@ipMatch", "@geoLookup", "SERVER_NAME", "allow", "skipAfter", "exec:"} {
			if strings.Contains(s, bad) && !strings.Contains(s, "'") {
				t.Fatalf("accepted rule containing %q: %s", bad, s)
			}
		}
	})
}

// Review v0: each bypass is rejected for the intended reason, not by accident.
func TestBypassReasons(t *testing.T) {
	want := map[string]string{
		"rx-leading-space":        "start or end with a space",
		"rx-trailing-space":       "start or end with a space",
		"pm-double-space":         "exactly one space",
		"pm-empty-trailing":       "start or end with a space",
		"streq-macro-remote-addr": "%{",
		"contains-macro-host":     "%{",
		"within-empty-catch-all":  "catch-all",
		"rx-dot-catch-all":        "catch-all",
		"rx-root-catch-all":       "catch-all",
		"beginswith-slash":        "catch-all",
		"pm-browser":              "catch-all",
		"streq-get":               "catch-all",
		"negated-chain-catch-all": "catch-all",
		"numeric-chain-catch-all": "catch-all",
		"count-with-rx":           "& (count)",
		"length-with-rx":          "t:length",
		"referer-targets-site":    "carries the site's host name",
		"origin-targets-site":     "carries the site's host name",
		"x-forwarded-server":      "identifies the site",
		"client-ip-header":        "identifies the site",
		"escaped-quote":           "backslash",
		"even-backslashes":        "backslash",
		"nested-quantifier":       "nested quantifier",
		"quantified-alternation":  "nested quantifier",
		"nested-group-quantifier": "nested quantifier",
		"repeat-sum":              "sum to",
		"msg-comma-smuggle":       "static text",
		"action-backslash":        "backslash",
		"setvar-threshold":        "setvar",
		"ctl-mixed-case":          "not allowed",
	}
	for _, c := range Cases {
		sub, ok := want[c.Name]
		if !ok {
			continue
		}
		delete(want, c.Name)
		_, err := Validate(c.Text, Options{MaxAction: c.MaxAction})
		if err == nil || !strings.Contains(err.Error(), sub) {
			t.Errorf("%s: want error containing %q, got %v", c.Name, sub, err)
		}
	}
	for n := range want {
		t.Errorf("case %s missing", n)
	}
}

func TestBenignCorpus(t *testing.T) {
	for i, v := range BenignCorpus {
		for j := 0; j < len(v); j++ {
			if v[j] < 0x20 || v[j] > 0x7e {
				t.Fatalf("corpus value %d has a non-printable byte", i)
			}
		}
	}
	cases := []struct {
		op, arg string
		want    bool
	}{
		{"rx", ".", true}, {"rx", "^/", true}, {"rx", "(?i)union\\s+select", false}, {"rx", "^GET$", true},
		{"pm", "MOZILLA", true}, {"pm", "sqlmap nikto", false}, {"streq", "POST", true}, {"streq", "PUT", false},
		{"within", "anything", true}, {"contains", "../", false}, {"beginsWith", "/wp-admin", false},
		{"endsWith", ".php", true}, {"endsWith", "/xmlrpc.php", false},
	}
	for _, c := range cases {
		if got := MatchesBenign(c.op, c.arg); got != c.want {
			t.Errorf("MatchesBenign(%s, %q) = %v, want %v", c.op, c.arg, got, c.want)
		}
	}
}

// The Go copy of the benign corpus equals contracts/seclang-benign-corpus.json,
// which the Python cross-check loads.
func TestBenignCorpusInSync(t *testing.T) {
	b, err := os.ReadFile("../../contracts/seclang-benign-corpus.json")
	if err != nil {
		t.Skipf("contracts not present: %v", err)
	}
	var f struct {
		Values []string `json:"values"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.Values, BenignCorpus) {
		t.Fatalf("contract/seclang/benign.go and contracts/seclang-benign-corpus.json differ (%d vs %d values)", len(BenignCorpus), len(f.Values))
	}
}
