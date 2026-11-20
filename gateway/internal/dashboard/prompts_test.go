//go:build !release

package dashboard_test

import (
	"testing"

	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
)

// No write of this API asks for the password again (D74): no write takes a
// confirm field, the decoder refuses it as unknown.
func TestNoPasswordPrompt(t *testing.T) {
	if keys.Release {
		t.Skip("app servers with schild-agent need the test switch " + app.HostAgentsEnv + ", which release builds ignore (D77)")
	}
	t.Setenv(app.HostAgentsEnv, "1") // agents are not part of the first version (D60b)
	h := apptest.New(t, apptest.Options{Extra: "host_check:\n  report_dir: " + t.TempDir() + "\n  agents:\n    enabled: true\n    listen: \"0.0.0.0:0\"\n"})
	h.Login()
	confirm := map[string]string{"password": h.Password}
	for _, c := range []struct {
		method, path string
		body         map[string]any
	}{
		{"PATCH", "/settings", map[string]any{"retention": map[string]any{"raw_ip_days": 3}, "confirm": confirm}},
		{"POST", "/agents/enrolments", map[string]any{"confirm": confirm}},
		{"POST", "/agents/x/confirm", map[string]any{"fingerprint": "sha256:x", "confirm": confirm}},
		{"POST", "/agents/x/revoke", map[string]any{"confirm": confirm}},
		{"PATCH", "/behaviour/settings", map[string]any{"confirm": confirm}},
		{"POST", "/behaviour/rate-limits", map[string]any{"route": "/x", "limit": 3, "per": "1m", "confirm": confirm}},
		{"PATCH", "/behaviour/rate-limits/x", map[string]any{"route": "/x", "limit": 3, "per": "1m", "confirm": confirm}},
		{"POST", "/behaviour/release", map[string]any{"ip": "198.51.100.9", "confirm": confirm}},
		{"PATCH", "/distributed/settings", map[string]any{"confirm": confirm}},
	} {
		if code, b := h.API(c.method, c.path, c.body); code != 400 {
			t.Errorf("%s %s with confirm: %d: %s", c.method, c.path, code, b)
		}
	}
	// privacyDelete keeps its dialog flag, which is no password.
	if code, b := h.API("POST", "/privacy/delete", map[string]any{"ip": "198.51.100.9", "confirm": false}); code != 400 {
		t.Fatalf("privacy delete without the flag: %d: %s", code, b)
	}
	if code, b := h.API("POST", "/privacy/delete", map[string]any{"ip": "198.51.100.9", "confirm": true}); code != 200 {
		t.Fatalf("privacy delete: %d: %s", code, b)
	}
}
