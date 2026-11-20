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

func TestLoginUserHashOfOddForms(t *testing.T) {
	inst := crsInstance(t)
	for _, tc := range []struct{ name, body, user string }{
		{"semicolon in another field", "a=1;b=2&username=Alice@Example.Org&password=secret", "alice@example.org"},
		{"bad escape in another field", "a=%zz&username=alice@example.org", "alice@example.org"},
		// PHP takes the last of two: the attempt is on victim, not on decoy.
		{"field sent twice", "log=decoy&log=victim&pwd=x", "victim"},
		{"second field name", "pwd=x&log=victim", "victim"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, _ := inst.NewTransaction()
			defer tx.Close()
			r := httptest.NewRequest("POST", "/login", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if _, _, err := tx.ReadRequestBodyFrom(r.Body); err != nil {
				t.Fatal(err)
			}
			got, ok := loginUserHash(r, tx, []string{"username", "log"})
			if !ok {
				t.Fatal("no user name found")
			}
			if want := behaviour.HashUser(tc.user); got != want {
				t.Fatalf("got %x, want the hash of %q (%x)", got, tc.user, want)
			}
		})
	}
}

// wp-login.php reads the action from the body too and takes what it does
// not know as "login": attempts behind "?action=register" count, a real
// registration form does not, and a body the gate cannot read as a form
// (multipart) is on the careful side. ("?action=lostpassword" would end at
// the preset limit of the password reset after three requests.)
func TestWPLoginActionThroughGate(t *testing.T) {
	const form = "application/x-www-form-urlencoded"
	multipart := "--b\r\nContent-Disposition: form-data; name=\"log\"\r\n\r\nadmin\r\n" +
		"--b\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nlogin\r\n--b--\r\n"
	for _, tc := range []struct {
		name, ip, path, ct, body string
		blocked                  bool
	}{
		{"action in the body", "203.0.113.31", "/wp-login.php?action=register", form, "log=admin&pwd=wrong&action=login", true},
		{"unknown action", "203.0.113.32", "/wp-login.php?action=nothing", form, "log=admin&pwd=wrong", true},
		{"multipart body", "203.0.113.33", "/wp-login.php?action=register", "multipart/form-data; boundary=b", multipart, true},
		{"registration form", "203.0.113.34", "/wp-login.php?action=register", form, "user_login=admin&user_email=a%40b.example&wp-submit=x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, decide.ModeAutoblock)
			b := config.Behaviour{Presets: []string{"wordpress"}}
			b.Scenarios.Get(config.ScenarioLoginBruteforce).Mode = config.BehaviourBlock
			eng := behaviour.New(behaviour.Config{Behaviour: b, InstalledAt: time.Now().Add(-60 * 24 * time.Hour)})
			e.g.Behaviour = eng
			for i := 0; i < 15; i++ {
				e.do(t, "POST", tc.path, tc.ct, tc.body, map[string]string{"X-Forwarded-For": tc.ip})
			}
			if got := len(eng.RunningBlocks()) == 1; got != tc.blocked {
				t.Fatalf("blocked %v, want %v (%+v)", got, tc.blocked, eng.RunningBlocks())
			}
		})
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
