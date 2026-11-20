package gate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
)

func TestLoginUserHashHandlesSemicolons(t *testing.T) {
	inst := crsInstance(t)
	tx, _ := inst.NewTransaction()
	defer tx.Close()

	body := "a=1;b=2&username=Alice@Example.Org&password=secret"
	r := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, _, err := tx.ReadRequestBodyFrom(r.Body); err != nil {
		t.Fatal(err)
	}

	want := behaviour.HashUser("alice@example.org")
	got, ok := loginUserHash(r, tx, []string{"username", "log"})
	if !ok {
		t.Fatal("loginUserHash failed on form body containing semicolon")
	}
	if got != want {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestTrustedProxyFallbackNotAutoBlocked(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	b := config.Behaviour{
		Presets: []string{"wordpress"},
	}
	b.Scenarios.Get(config.ScenarioLoginBruteforce).Mode = config.BehaviourBlock
	eng := behaviour.New(behaviour.Config{Behaviour: b, InstalledAt: time.Now().Add(-60 * 24 * time.Hour)})
	e.g.Behaviour = eng

	// Requests come from 127.0.0.1 (a trusted proxy in newEnv) without X-Forwarded-For,
	// so clientip falls back to 127.0.0.1 itself. Behaviour must never auto-block it.
	for i := 0; i < 15; i++ {
		r := e.do(t, "POST", "/wp-login.php", "application/x-www-form-urlencoded", "log=admin&pwd=wrong", nil)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("trusted proxy fallback blocked on request %d: status %d", i, r.StatusCode)
		}
	}
	if blocks := eng.RunningBlocks(); len(blocks) != 0 {
		t.Fatalf("trusted proxy acquired active block: %+v", blocks)
	}

	// Sanity check: an untrusted external IP sending the same failed logins IS blocked.
	blocked := false
	for i := 0; i < 15; i++ {
		r := e.do(t, "POST", "/wp-login.php", "application/x-www-form-urlencoded", "log=admin&pwd=wrong", map[string]string{
			"X-Forwarded-For": otherIP,
		})
		if r.StatusCode == http.StatusForbidden {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("external IP was not blocked by login_bruteforce")
	}
}

func TestSpoofedSearchBotNotExemptFromAggressiveCrawl(t *testing.T) {
	e, _, _ := crawlerEnv(t, decide.ModeAutoblock, nil)
	b := config.Behaviour{}
	b.Scenarios.Get(config.ScenarioAggressiveCrawl).Mode = config.BehaviourBlock
	eng := behaviour.New(behaviour.Config{Behaviour: b, InstalledAt: time.Now().Add(-60 * 24 * time.Hour)})
	e.g.Behaviour = eng

	// Spoofed Googlebot from non-Google IP (VerMismatch) must get blocked by aggressive_crawl.
	blocked := false
	for i := 0; i < 240; i++ {
		r := e.do(t, "GET", fmt.Sprintf("/item/%d", i), "", "", map[string]string{
			"User-Agent":      uaGooglebot,
			"X-Forwarded-For": otherIP,
		})
		if r.StatusCode == http.StatusForbidden {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("spoofed Googlebot (VerMismatch) was not blocked by aggressive_crawl")
	}

	// Real Googlebot from Google range (VerRange) is still exempt.
	for i := 0; i < 240; i++ {
		r := e.do(t, "GET", fmt.Sprintf("/real/%d", i), "", "", map[string]string{
			"User-Agent":      uaGooglebot,
			"X-Forwarded-For": googleIP,
		})
		if r.StatusCode != http.StatusOK {
			t.Fatalf("real Googlebot was blocked on request %d: status %d", i, r.StatusCode)
		}
	}
}
