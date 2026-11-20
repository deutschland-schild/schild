//go:build !release

package dashboard_test

import (
	"encoding/json"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

// D48: the rule list shows what runs, also without a hit, and a rule with hits first.
func TestRuleListShowsEveryRunningCRSRule(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	h.Visit("GET", "/?q=%27%20or%201=1--", "203.0.113.9", "", "")
	h.Flush()
	code, body := h.API("GET", "/rules?repository=crs&limit=500", nil)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	validate(t, "RulePage", body)
	var page dashboard.RulePage
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	crs, zero := 0, false
	var quiet *dashboard.Rule
	for i, r := range page.Items {
		if r.Repository != "crs" {
			continue
		}
		crs++
		if r.Hits24h == 0 {
			zero = true
		} else if zero {
			t.Fatalf("rule %s with hits after a rule without", r.ID)
		}
		if r.ID == "942100" {
			quiet = &page.Items[i]
		}
	}
	if crs < 200 {
		t.Fatalf("%d CRS rules listed", crs)
	}
	if quiet == nil || quiet.Status != "active" || quiet.Msg == "" {
		t.Fatalf("942100 %+v", quiet)
	}
	if code, body := h.API("GET", "/rules/crs/942131", nil); code != 404 {
		t.Fatalf("a rule of paranoia level 2 does not run at level 1: %d %s", code, body)
	}
}
