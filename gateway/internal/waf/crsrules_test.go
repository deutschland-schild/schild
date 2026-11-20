package waf

import (
	"strconv"
	"strings"
	"testing"
)

func TestCRSRulesUpToTheParanoiaLevel(t *testing.T) {
	has := func(rs []CRSRule, id int) bool {
		for _, r := range rs {
			if r.ID == id {
				return true
			}
		}
		return false
	}
	one, four := CRSRules(1), CRSRules(4)
	if len(one) < 100 || len(four) <= len(one) {
		t.Fatalf("rules at level 1: %d, at level 4: %d", len(one), len(four))
	}
	if !has(one, 942100) {
		t.Fatal("942100 runs at level 1")
	}
	if has(one, 942131) || !has(four, 942131) {
		t.Fatal("942131 runs from level 2 on")
	}
	if has(one, 901001) {
		t.Fatal("flow control is no finding")
	}
	for _, r := range four {
		if r.Msg == "" {
			t.Fatalf("rule %d without a text", r.ID)
		}
	}
}

func TestParseCRSRules(t *testing.T) {
	got := parseCRSRules(`# SecRule ARGS "@rx a" "id:1,msg:'comment'"
SecRule ARGS "@rx a" \
    "id:949110,\
    phase:2,\
    msg:'Inbound Anomaly Score Exceeded (Total Score: %{TX.SCORE})',\
    tag:'paranoia-level/2',\
    chain"
    SecRule ARGS "@rx b" "t:none"
SecRule TX:X "@lt 1" "id:7,phase:1,pass,nolog"
`)
	if len(got) != 1 || got[0].ID != 949110 || got[0].Paranoia != 2 || got[0].Msg != "Inbound Anomaly Score Exceeded" {
		t.Fatalf("parsed %+v", got)
	}
	// The text is the rule as written, with the rule chained to it and nothing else.
	want := "SecRule ARGS \"@rx a\" \\\n    \"id:949110,\\\n    phase:2,\\\n    msg:'Inbound Anomaly Score Exceeded (Total Score: %{TX.SCORE})',\\\n    tag:'paranoia-level/2',\\\n    chain\"\n    SecRule ARGS \"@rx b\" \"t:none\""
	if got[0].Text != want {
		t.Fatalf("text:\n%s\nwant:\n%s", got[0].Text, want)
	}
}

// Every rule of the embedded CRS has its own text and file: the text starts
// with the directive, names its id once and holds no other rule's id.
func TestCRSRulesCarryTheirText(t *testing.T) {
	for _, r := range CRSRules(4) {
		if !strings.HasPrefix(strings.TrimSpace(r.Text), "Sec") || !strings.HasSuffix(r.File, ".conf") {
			t.Fatalf("rule %d: file %q, text %q", r.ID, r.File, r.Text)
		}
		ids := crsActionID.FindAllStringSubmatch(r.Text, -1)
		if len(ids) != 1 || ids[0][1] != strconv.Itoa(r.ID) {
			t.Fatalf("rule %d: ids in its text: %v", r.ID, ids)
		}
		if len(r.Text) > 65536 {
			t.Fatalf("rule %d: %d bytes", r.ID, len(r.Text))
		}
	}
}
