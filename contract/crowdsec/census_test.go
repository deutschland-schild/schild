package crowdsec

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestRealIndex runs the update rules over a real .index.json when
// SCHILD_HUB_INDEX points at one. Never part of a normal run: no network and
// no vendored index. It prints the coverage the spec asks for; with
// SCHILD_HUB_OUT it writes the converted rules for a Coraza load test.
func TestRealIndex(t *testing.T) {
	p := os.Getenv("SCHILD_HUB_INDEX")
	if p == "" {
		t.Skip("SCHILD_HUB_INDEX not set")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	u := CheckIndex(raw, nil, DefaultLimits, "2026-10-30T00:00:00Z")
	t.Logf("outcome=%s code=%s loaded=%d skipped=%d not_selected=%d", u.Outcome, u.Code, len(u.Rules), len(u.Skipped), u.NotSelected)
	codes := map[string]int{}
	for _, s := range u.Skipped {
		codes[s.Code]++
		t.Logf("skipped %s %s", s.Name, s.Code)
	}
	ks := make([]string, 0, len(codes))
	for k := range codes {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		t.Logf("%s: %d", k, codes[k])
	}
	re := regexp.MustCompile(`@rx (.*?)" "`)
	notes, groups, lines, maxProg := 0, 0, 0, 0
	for _, r := range u.Rules {
		notes += len(r.Notes)
		groups += len(r.SecLang)
		for _, s := range r.SecLang {
			lines += strings.Count(s, "\n") + 1
			for _, m := range re.FindAllStringSubmatch(s, -1) {
				if err := CheckRegexCost(m[1]); err != nil {
					t.Errorf("%s: %v", r.Name, err)
				}
				if n := programSize(m[1]); n > maxProg {
					maxProg = n
				}
			}
		}
	}
	t.Logf("rules with notes=%d groups=%d lines=%d largest regex program=%d", notes, groups, lines, maxProg)
	if out := os.Getenv("SCHILD_HUB_OUT"); out != "" {
		b, _ := json.Marshal(u.Rules)
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
