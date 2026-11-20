//go:build !release

package dashboard_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

func getHost(t *testing.T, h *apptest.Harness, path, host string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", h.Dash.URL+path, nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestDashboardHostCheck: the dashboard answers localhost, IP addresses, the
// host of listen.dashboard and the names of dashboard.allowed_hosts. Any
// other name gets a 403 that names the config key (D76, DNS rebinding).
func TestDashboardHostCheck(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe", Extra: "dashboard:\n  allowed_hosts: [\"Gateway.VPN.example\", schild-host]\n"})
	for _, host := range []string{
		"localhost", "localhost:8788", "LOCALHOST:8788", "127.0.0.1:8788", "[::1]:8788", "10.8.0.1:8788", "192.0.2.7", "[2001:db8::1]:8788",
		"gateway.vpn.example", "gateway.vpn.example:8788", "GATEWAY.vpn.example.:8788", "schild-host:8788",
	} {
		if code, b := getHost(t, h, "/api/v0/auth/session", host); code != 200 {
			t.Errorf("Host %q: %d %s", host, code, b)
		}
	}
	for _, host := range []string{
		"attacker.example", "attacker.example:8788", "localhost.attacker.example", "127.0.0.1.attacker.example:8788",
		"gateway.vpn.example.attacker.example", "xgateway.vpn.example", "vpn.example",
	} {
		for _, path := range []string{"/api/v0/auth/session", "/", "/assets/x.js"} {
			code, b := getHost(t, h, path, host)
			if code != 403 {
				t.Errorf("Host %q %s: %d, want 403", host, path, code)
				continue
			}
			if !strings.Contains(b, dashboard.AllowedHostsKey) || !strings.Contains(b, "restart") {
				t.Errorf("Host %q: the answer does not name the config key:\n%s", host, b)
			}
		}
	}
	// A login for a foreign name sets no cookie.
	body, _ := json.Marshal(map[string]string{"password": h.Password, "setup_code": h.App.SetupCode()})
	req, _ := http.NewRequest("POST", h.Dash.URL+"/api/v0/auth/setup", bytes.NewReader(body))
	req.Host = "attacker.example"
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 || len(resp.Cookies()) != 0 {
		t.Fatalf("setup for a foreign host: %d, cookies %v", resp.StatusCode, resp.Cookies())
	}
	// Probes may send any name.
	for _, path := range []string{"/healthz", "/readyz"} {
		if code, _ := getHost(t, h, path, "schild.internal:8788"); code != 200 {
			t.Errorf("%s with a foreign host: %d", path, code)
		}
	}
}

// TestDashboardHostCheckDefault: without dashboard.allowed_hosts only
// localhost, addresses and the host of listen.dashboard pass.
func TestDashboardHostCheckDefault(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe"})
	if code, _ := getHost(t, h, "/api/v0/auth/session", "gateway.vpn.example"); code != 403 {
		t.Fatalf("a name without an entry: %d", code)
	}
	if code, _ := getHost(t, h, "/api/v0/auth/session", h.Dash.Listener.Addr().String()); code != 200 {
		t.Fatalf("the listen address: %d", code)
	}
	h.App.Dashboard.Listen = "dash.internal:8788"
	if code, _ := getHost(t, h, "/api/v0/auth/session", "dash.internal:8788"); code != 200 {
		t.Fatalf("the host of listen.dashboard: %d", code)
	}
}

// TestLoginOverPlainHTTPKeepsItsSession: a browser on a VPN address over
// plain HTTP gets a session cookie without Secure (it would drop a Secure
// one and be logged out with the next request); behind HTTPS the cookie is
// Secure (D76).
func TestLoginOverPlainHTTPKeepsItsSession(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "observe"})
	h.Login()
	login := func(host, origin, proto string) *http.Cookie {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"password": h.Password})
		req, _ := http.NewRequest("POST", h.Dash.URL+"/api/v0/auth/login", bytes.NewReader(body))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("login as %s from %s: %d", host, origin, resp.StatusCode)
		}
		for _, c := range resp.Cookies() {
			if c.Name == "schild_session" {
				if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
					t.Fatalf("cookie lost HttpOnly or SameSite=Strict: %+v", c)
				}
				return c
			}
		}
		t.Fatal("no session cookie")
		return nil
	}
	if c := login("10.8.0.1:8788", "http://10.8.0.1:8788", ""); c.Secure {
		t.Error("plain HTTP on a VPN address: Secure cookie, the browser drops it")
	}
	if c := login("10.8.0.1:8788", "https://10.8.0.1:8788", ""); !c.Secure {
		t.Error("https origin: cookie without Secure")
	}
	if c := login("10.8.0.1:8788", "http://10.8.0.1:8788", "https"); !c.Secure {
		t.Error("X-Forwarded-Proto https: cookie without Secure")
	}
	if c := login("10.8.0.1:8788", "", ""); !c.Secure {
		t.Error("no browser, not loopback: cookie without Secure")
	}
	if c := login("127.0.0.1:8788", "http://127.0.0.1:8788", ""); c.Secure {
		t.Error("loopback: Secure cookie")
	}
}
