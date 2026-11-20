package waf

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/deutschland-schild/schild/contract/crowdsec"
)

const hubYAML = `name: crowdsecurity/vpatch-CVE-2026-0001
description: Two ways in, two AND-groups
rules:
  - and:
      - zones: [URI]
        transform: [lowercase]
        match: { type: contains, value: /vulnerable/one }
      - zones: [ARGS]
        variables: [cmd]
        match: { type: contains, value: pwn }
  - and:
      - zones: [URI]
        transform: [lowercase]
        match: { type: contains, value: /vulnerable/one }
      - zones: [ARGS]
        variables: [run]
        match: { type: contains, value: pwn }
labels:
  label: Test rule
  classification:
    - cve.CVE-2026-0001
`

func hubRule(t testing.TB) HubRule {
	t.Helper()
	sum := sha256.Sum256([]byte(hubYAML))
	r, sk := crowdsec.Convert("crowdsecurity/vpatch-CVE-2026-0001", "0.1", hex.EncodeToString(sum[:]), []byte(hubYAML), "")
	if sk != nil {
		t.Fatal(sk)
	}
	if len(r.SecLang) != 2 {
		t.Fatalf("groups: %d", len(r.SecLang))
	}
	return HubRule{Name: r.Name, Version: r.Version, Label: r.Label, CVEs: r.CVEs, BaseID: r.BaseID, Groups: r.SecLang}
}

func hubOnly(t testing.TB, local string) *Instance {
	t.Helper()
	inst, err := Build(Config{Hub: []HubRule{hubRule(t)}, LocalRules: local})
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

func TestAnalyzeHubMatchIsItsOwnKind(t *testing.T) {
	inst := hubOnly(t, "")
	a, err := eval(t, inst, browserReq("GET", "/vulnerable/one?cmd=pwn", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	r := hubRule(t)
	if !a.HasHub || len(a.Matches) != 1 {
		t.Fatalf("matches %+v", a.Matches)
	}
	m := a.Matches[0]
	if m.Source != SourceCrowdsec || m.ID != r.BaseID || m.Hub == nil || m.Hub.Name != r.Name || m.Key() != r.Key() {
		t.Fatalf("match %+v", m)
	}
	if m.Points != 0 || a.Score != 0 || a.CRSAnomaly != 0 || a.LocalBlock || a.CRSBlock || len(a.MatchedIDs) != 0 {
		t.Fatalf("a hub match counted: %+v", a)
	}
	if a.Category != "" {
		t.Fatalf("category %q", a.Category)
	}
	if m.Msg == "" || a.TopMsg != m.Msg {
		t.Fatalf("msg %q, top %q", m.Msg, a.TopMsg)
	}
}

func TestAnalyzeSeveralGroupsCountOnce(t *testing.T) {
	inst := hubOnly(t, "")
	a, err := eval(t, inst, browserReq("GET", "/vulnerable/one?cmd=pwn&run=pwn", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Matches) != 1 {
		t.Fatalf("two groups counted %d times: %+v", len(a.Matches), a.Matches)
	}
}

func TestAnalyzeNoMatchOnTheFirstLineAlone(t *testing.T) {
	inst := hubOnly(t, "")
	a, err := eval(t, inst, browserReq("GET", "/vulnerable/one?cmd=harmless", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if a.HasHub || len(a.Matches) != 0 {
		t.Fatalf("%+v", a.Matches)
	}
}

// The CRS score of an attack is the same with and without hub rules.
func TestCRSScoreUnchangedByHubRules(t *testing.T) {
	with, err := Build(Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5, Hub: []HubRule{hubRule(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer with.Close()
	target := "/vulnerable/one?cmd=pwn&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	a, err := eval(t, with, browserReq("GET", target, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	b, err := eval(t, crs(t), browserReq("GET", target, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasHub {
		t.Fatal("the hub rule did not match")
	}
	if a.CRSAnomaly != b.CRSAnomaly || a.Score != b.Score || a.CRSBlock != b.CRSBlock || a.Category != b.Category || len(a.MatchedIDs) != len(b.MatchedIDs) {
		t.Fatalf("with hub %d/%d/%v/%s, without %d/%d/%v/%s", a.CRSAnomaly, a.Score, a.CRSBlock, a.Category, b.CRSAnomaly, b.Score, b.CRSBlock, b.Category)
	}
	for i, id := range a.MatchedIDs {
		if id >= 60000000 || id != b.MatchedIDs[i] {
			t.Fatalf("hub id in MatchedIDs: %v", a.MatchedIDs)
		}
	}
}

func TestLocalRuleInTheHubRangeStaysLocal(t *testing.T) {
	inst := hubOnly(t, `SecRule ARGS:x "@contains boom" "id:60000001,phase:2,deny,status:403,msg:'mine'"`)
	a, err := eval(t, inst, browserReq("GET", "/?x=boom", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Matches) != 1 || a.Matches[0].Source != "local" || !a.LocalBlock {
		t.Fatalf("%+v", a.Matches)
	}
}

func TestBuildRefusesHubIDProblems(t *testing.T) {
	r := hubRule(t)
	r2 := r
	r2.BaseID = 7700001
	if _, err := Build(Config{Hub: []HubRule{r2}}); err == nil {
		t.Fatal("id outside the range built")
	}
	if _, err := Build(Config{Hub: []HubRule{r, r}}); err == nil {
		t.Fatal("duplicate built")
	}
	local := `SecRule ARGS:x "@contains boom" "id:` + r.Key() + `,phase:2,pass,msg:'mine'"`
	if _, err := Build(Config{Hub: []HubRule{r}, LocalRules: local}); err == nil {
		t.Fatal("a local rule on a hub id built")
	}
}

func TestCheckHub(t *testing.T) {
	if err := CheckHub([]HubRule{hubRule(t)}); err != nil {
		t.Fatal(err)
	}
	if err := CheckHub([]HubRule{{Name: "x", BaseID: 60000000, Groups: []string{`SecRule NOPE "@rx a" "id:60000000,phase:2,pass"`}}}); err == nil {
		t.Fatal("a broken rule passed")
	}
}
