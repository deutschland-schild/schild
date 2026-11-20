package crowdsec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/seclang"
)

func TestBaseIDStableAndInRange(t *testing.T) {
	// A change of this value moves every rule: it is part of the contract.
	if got := BaseID("crowdsecurity/vpatch-CVE-2026-1207"); got != 62846312 {
		t.Fatalf("BaseID = %d", got)
	}
	for _, n := range []string{"crowdsecurity/vpatch-a", "crowdsecurity/vpatch-b", "crowdsecurity/vpatch-CVE-2099-99999999"} {
		id := BaseID(n)
		if id < contract.HubRuleIDMin || id+MaxGroups-1 > contract.HubRuleIDMax || (id-contract.HubRuleIDMin)%MaxGroups != 0 {
			t.Fatalf("%s: %d", n, id)
		}
	}
}

func TestIDRangeApart(t *testing.T) {
	if contract.HubRuleIDMin <= contract.RemoteRuleIDMax {
		t.Fatal("hub range overlaps the network range")
	}
	if contract.HubRuleIDMax > 99999999 {
		t.Fatal("hub range leaves events.schema.json matchedRule.id")
	}
}

func TestNetworkSubsetNotWidened(t *testing.T) {
	head := func(id, vars, op, ts string) string {
		return `SecRule REQUEST_FILENAME "@contains /wp-json/example/v1/" "id:` + id + `,phase:2,pass,t:none,severity:CRITICAL,msg:'x',chain"` + "\n" +
			`SecRule ` + vars + ` "` + op + `" "t:none` + ts + `"`
	}
	for _, c := range []struct{ name, text string }{
		{"hub id", head("62846312", "ARGS_GET:a", "@contains x", "")},
		{"uppercase", head("7700001", "ARGS_GET:a", "@contains x", ",t:uppercase")},
		{"tx", head("7700001", seclang.HubJSONBody, "@contains x", "")},
		{"bracket", head("7700001", "ARGS_GET:a[]", "@contains x", "")},
		{"regex selector", head("7700001", "ARGS_GET:/a/", "@contains x", "")},
	} {
		if _, err := seclang.Validate(c.text, seclang.Options{MaxAction: "observe"}); err == nil {
			t.Errorf("%s: accepted by the network subset", c.name)
		}
		if _, err := seclang.Validate(strings.ReplaceAll(c.text, "7700001", "62846312"), seclang.Options{MaxAction: "observe", Hub: true}); err != nil {
			t.Errorf("%s: refused by the hub profile: %v", c.name, err)
		}
	}
}

func TestHubProfileKeepsPassOnly(t *testing.T) {
	text := `SecRule REQUEST_FILENAME "@contains /wp-json/example/v1/" "id:62846312,phase:2,deny,status:403,t:none,severity:CRITICAL,msg:'x'"`
	if _, err := seclang.Validate(text, seclang.Options{MaxAction: "observe", Hub: true}); err == nil {
		t.Fatal("deny accepted")
	}
}

func TestCatchAllSentinel(t *testing.T) {
	text := `SecRule REQUEST_FILENAME "@contains /" "id:62846312,phase:2,pass,t:none,severity:CRITICAL,msg:'x'"`
	_, err := seclang.Validate(text, seclang.Options{MaxAction: "observe", Hub: true})
	if !errors.Is(err, seclang.ErrCatchAll) || contract.CodeOf(err) != contract.CodeSecLang {
		t.Fatalf("err = %v", err)
	}
}

func TestParseSetOversize(t *testing.T) {
	// Not a vector: the file would be 8 MiB.
	if _, err := ParseSet(make([]byte, MaxSetFileBytes+1)); contract.CodeOf(err) != contract.CodeOversize {
		t.Fatalf("err = %v", err)
	}
}

func TestSetTime(t *testing.T) {
	const fetched, commit = "2026-10-30T08:00:00Z", "2026-10-25T09:00:00Z"
	for _, c := range []struct {
		s    Set
		want string
	}{
		{Set{FetchedAt: fetched}, fetched},                                     // master: the head at that moment
		{Set{FetchedAt: fetched, HubCommit: "c", HubCommitAt: commit}, commit}, // snapshot
		{Set{FetchedAt: fetched, HubCommit: "c"}, ""},                          // pinned: may be old
	} {
		if got := c.s.Time(); got != c.want {
			t.Errorf("%+v: %q", c.s, got)
		}
	}
}

func TestCheckRegexCost(t *testing.T) {
	if err := CheckRegexCost(`^/api/(a|b)+$`); err != nil {
		t.Fatal(err)
	}
	if err := CheckRegexCost(`(?:[a-z]{500}){9}`); err == nil {
		t.Fatal("expensive pattern accepted")
	}
	if err := CheckRegexCost(`(`); err == nil {
		t.Fatal("broken pattern accepted")
	}
}

func TestNoRuleText(t *testing.T) {
	// Hub free text never reaches a rule: only the checked name, operators
	// and selectors do.
	y := "name: crowdsecurity/vpatch-x\ndescription: \"evil',ctl:ruleEngine=Off\"\nrules:\n  - zones:\n      - URI\n    match:\n      type: contains\n      value: /wp-json/example/v1/\nlabels:\n  label: \"evil',deny\"\n"
	r, sk := Convert("crowdsecurity/vpatch-x", "0.1", "d", []byte(y), "")
	if sk != nil {
		t.Fatal(sk)
	}
	if strings.Contains(r.SecLang[0], "evil") || strings.Contains(r.SecLang[0], "ctl:") {
		t.Fatalf("hub text in rule: %s", r.SecLang[0])
	}
}

func TestEnumsMatchOpenAPI(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "api", "client-dashboard.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Enum []string `yaml:"enum"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]string{"CrowdsecHubSkipCode": RuleRefusals, "CrowdsecHubRefusalCode": UpdateRefusals} {
		got := doc.Components.Schemas[name].Enum
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s:\n got %v\nwant %v", name, got, want)
		}
	}
}
