package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
)

func siteWith(t *testing.T, behaviour string) (*Site, error) {
	t.Helper()
	b, err := os.ReadFile(examples + "schild.production.yaml")
	if err != nil {
		t.Skip(err)
	}
	return ParseSite([]byte(string(b) + "\n" + behaviour))
}

func TestBehaviourDefaults(t *testing.T) {
	s, err := siteWith(t, "")
	if err != nil {
		t.Fatal(err)
	}
	b := s.Behaviour
	if len(b.Presets) != len(BehaviourPresets) || b.PresetLimits != "" || b.PresetLimitModes != nil {
		t.Fatalf("defaults: %+v", b)
	}
	for _, id := range ScenarioIDs {
		if m := b.Scenarios.Get(id).Mode; m != ScenarioRecommended[id] {
			t.Fatalf("%s: default %q, want the recommended mode %q", id, m, ScenarioRecommended[id])
		}
	}
	if b.Scenarios.PathProbing.Mode != BehaviourBlock || b.Scenarios.AggressiveCrawl.Mode != BehaviourObserve || s.ChallengeWarning() != "" {
		t.Fatalf("D92 defaults: %+v", b.Scenarios)
	}
}

// D92: the old mode challenge loads as observe and is named in a warning.
func TestBehaviourLegacyChallenge(t *testing.T) {
	s, err := siteWith(t, `behaviour:
  scenarios:
    path_probing: {mode: challenge}
    aggressive_crawl: {mode: challenge}
`)
	if err != nil {
		t.Fatal(err)
	}
	if s.Behaviour.Scenarios.PathProbing.Mode != BehaviourObserve || s.Behaviour.Scenarios.AggressiveCrawl.Mode != BehaviourObserve {
		t.Fatalf("challenge not read as observe: %+v", s.Behaviour.Scenarios)
	}
	w := s.ChallengeWarning()
	if !strings.Contains(w, "path_probing, aggressive_crawl") || len(s.Warnings()) != 1 {
		t.Fatalf("warning %q, all %q", w, s.Warnings())
	}
}

func TestBehaviourRateLimits(t *testing.T) {
	s, err := siteWith(t, `behaviour:
  scenarios:
    login_bruteforce: {mode: block}
  rate_limits:
    - {route: /wp-login.php, methods: [POST], limit: 10, per: 1m}
    - {id: search, route: /search, limit: 30, per: 1m, burst: 60, mode: block}
`)
	if err != nil {
		t.Fatal(err)
	}
	l := s.Behaviour.RateLimits
	if l[0].ID != "config-1" || l[0].Burst != 10 || l[0].Mode != BehaviourObserve || l[1].ID != "search" || l[1].Burst != 60 {
		t.Fatalf("limits: %+v", l)
	}
	if s.Behaviour.Scenarios.LoginBruteforce.Mode != BehaviourBlock || s.Behaviour.Scenarios.AggressiveCrawl.Mode != BehaviourObserve {
		t.Fatal("scenario modes")
	}
	// A generated id that collides with an explicit one is a config error.
	_, err = siteWith(t, `behaviour:
  rate_limits:
    - {route: /a, limit: 1, per: 1s}
    - {id: config-1, route: /b, limit: 1, per: 1s}
`)
	if contract.CodeOf(err) != contract.CodeConfig {
		t.Fatalf("generated id collision: %v", err)
	}
	_, err = siteWith(t, "behaviour:\n  rate_limits:\n    - {route: /**, limit: 1, per: 1s}\n")
	if err == nil || !strings.Contains(err.Error(), "confirm_site_wide") {
		t.Fatalf("site-wide limit without confirm: %v", err)
	}
}

func TestSiteWideRouteAndPer(t *testing.T) {
	for r, want := range map[string]bool{"/**": true, "/*": true, "/*/**": true, "/": false, "/api/**": false, "/*.php": false} {
		if SiteWideRoute(r) != want {
			t.Errorf("SiteWideRoute(%q) != %v", r, want)
		}
	}
	for p, want := range map[string]time.Duration{"1s": time.Second, "10m": 10 * time.Minute, "24h": 24 * time.Hour} {
		if d, err := ParsePer(p); err != nil || d != want {
			t.Errorf("ParsePer(%q) = %v, %v", p, d, err)
		}
	}
	for _, p := range []string{"", "0s", "25h", "1d", "m"} {
		if _, err := ParsePer(p); err == nil {
			t.Errorf("ParsePer(%q) accepted", p)
		}
	}
}
