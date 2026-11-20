//go:build !release

package dashboard_test

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

func websiteID(t *testing.T, h *apptest.Harness) string {
	t.Helper()
	code, body := h.API("GET", "/websites", nil)
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"websites"`
	}
	if code != 200 || json.Unmarshal(body, &page) != nil || len(page.Items) == 0 {
		t.Fatalf("websites %d: %s", code, body)
	}
	return page.Items[0].ID
}

func TestAccessProtectionDashboard(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	id := websiteID(t, h)
	path := "/websites/" + id + "/access"
	code, body := h.API("GET", path, nil)
	if code != 200 || !strings.Contains(string(body), `"protection":null`) {
		t.Fatalf("get none: %d %s", code, body)
	}
	validate(t, "AccessProtectionState", body)

	// Invalid: an end (D58: on or off).
	code, body = h.API("PUT", path, map[string]any{"scope": "site", "password": "korrekt-pferd", "own_networks": false, "until": "2026-11-04T12:00:00Z"})
	if code != 400 || !strings.Contains(string(body), `"pointer":"/until"`) {
		t.Fatalf("end: %d %s", code, body)
	}
	// Invalid: no way in.
	if code, body = h.API("PUT", path, map[string]any{"scope": "site", "own_networks": false}); code != 400 || !strings.Contains(string(body), `"/password"`) {
		t.Fatalf("no way in: %d %s", code, body)
	}

	code, body = h.API("PUT", path, map[string]any{"scope": "site", "password": "korrekt-pferd", "own_networks": true, "except": []string{"/hooks/*"}})
	if code != 200 {
		t.Fatalf("set: %d %s", code, body)
	}
	validate(t, "AccessProtectionState", body)
	var st dashboard.AccessProtectionState
	_ = json.Unmarshal(body, &st)
	if st.Protection == nil || !st.Protection.Password || st.Protection.Actor != "dashboard" {
		t.Fatalf("state: %s", body)
	}
	if strings.Contains(string(body), "korrekt-pferd") || strings.Contains(string(body), "argon2") {
		t.Fatal("password or hash in the answer")
	}

	before := h.Hits.Load()
	if r := h.Visit("GET", "/", "203.0.113.5", "", ""); r.StatusCode != 503 {
		t.Fatalf("locked: %d", r.StatusCode)
	}
	if r := h.Visit("POST", "/wp-login.php", "203.0.113.5", "application/x-www-form-urlencoded", "log=a&pwd=b"); r.StatusCode != 503 {
		t.Fatalf("locked post: %d", r.StatusCode)
	}
	if n := h.Hits.Load() - before; n != 0 {
		t.Fatalf("%d requests reached the app", n)
	}
	// D58: password and own networks: the allowlisted test admin still
	// needs the password.
	if r := h.Visit("GET", "/", "192.0.2.10", "", ""); r.StatusCode != 503 {
		t.Fatalf("own network without session: %d", r.StatusCode)
	}
	if r := h.Visit("GET", "/hooks/x", "203.0.113.5", "", ""); r.StatusCode != 200 {
		t.Fatalf("except: %d", r.StatusCode)
	}
	a, err := access.ReadActive(filepath.Join(h.Dir, "data"))
	if err != nil || !a.InForce() {
		t.Fatalf("active file: %+v %v", a, err)
	}
	if _, err := os.Stat(filepath.Join(h.Dir, "data", access.ActiveDir, access.ActiveMarker)); err != nil {
		t.Fatalf("marker: %v", err)
	}

	// Change without a new password keeps the stored one.
	if code, body = h.API("PUT", path, map[string]any{"scope": "paths", "paths": []string{"/wp-admin/*"}, "own_networks": false}); code != 200 || !strings.Contains(string(body), `"password":true`) {
		t.Fatalf("keep password: %d %s", code, body)
	}
	if r := h.Visit("GET", "/", "203.0.113.5", "", ""); r.StatusCode != 200 {
		t.Fatalf("public path: %d", r.StatusCode)
	}
	if r := h.Visit("GET", "/WP-Admin/", "203.0.113.5", "", ""); r.StatusCode != 403 {
		t.Fatalf("protected path: %d", r.StatusCode)
	}

	if code, body = h.API("DELETE", path, nil); code != 204 {
		t.Fatalf("remove: %d %s", code, body)
	}
	if r := h.Visit("GET", "/wp-admin/", "203.0.113.5", "", ""); r.StatusCode != 200 {
		t.Fatalf("after remove: %d", r.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(h.Dir, "data", access.ActiveDir, access.ActiveMarker)); !os.IsNotExist(err) {
		t.Fatalf("marker after remove: %v", err)
	}
	h.Flush()
	code, body = h.API("GET", "/events?type=schild.access.protection_set.v1", nil)
	if code != 200 || strings.Count(string(body), "schild.access.protection_set.v1") < 2 {
		t.Fatalf("events: %d %s", code, body)
	}
	if code, _ = h.API("GET", "/websites/nope.example/access", nil); code != 404 {
		t.Fatalf("unknown website: %d", code)
	}
}

// A protection survives a restart, and its sessions stay valid (same key and epoch).
func TestAccessProtectionRestart(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	id := websiteID(t, h)
	if code, body := h.API("PUT", "/websites/"+id+"/access", map[string]any{"scope": "site", "addresses": []string{"198.51.100.0/24"}, "own_networks": false}); code != 200 {
		t.Fatalf("set: %d %s", code, body)
	}
	dir := h.Dir
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	h2 := apptest.New(t, apptest.Options{Dir: dir})
	if r := h2.Visit("GET", "/", "203.0.113.5", "", ""); r.StatusCode != 503 {
		t.Fatalf("after restart: %d", r.StatusCode)
	}
	if r := h2.Visit("GET", "/", "198.51.100.7", "", ""); r.StatusCode != 200 {
		t.Fatalf("listed address after restart: %d", r.StatusCode)
	}
}

// D98: the maintenance mode is a switch of its own. It closes the whole
// website for everyone outside the own networks, also with a protection of
// single paths in force, and leaves that protection as it is.
func TestMaintenanceMode(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	id := websiteID(t, h)
	accessPath, path := "/websites/"+id+"/access", "/websites/"+id+"/maintenance"
	const visitor, own = "203.0.113.5", "192.0.2.10"
	if code, body := h.API("PUT", accessPath, map[string]any{"scope": "paths", "paths": []string{"/wp-admin/*"}, "password": "korrekt-pferd", "own_networks": false}); code != 200 {
		t.Fatalf("protection: %d %s", code, body)
	}
	state := func(b []byte) dashboard.AccessProtectionState {
		t.Helper()
		validate(t, "AccessProtectionState", b)
		var st dashboard.AccessProtectionState
		if err := json.Unmarshal(b, &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	code, body := h.API("PUT", path, map[string]any{"on": true, "message": "Wir ziehen gerade um."})
	if st := state(body); code != 200 || !st.Maintenance.On || st.Maintenance.Message != "Wir ziehen gerade um." || st.Maintenance.Actor != "dashboard" ||
		st.Protection == nil || st.Protection.Scope != "paths" || !st.Protection.Password {
		t.Fatalf("on: %d %s", code, body)
	}
	closed := func(hh *apptest.Harness, when string) {
		t.Helper()
		for _, p := range []string{"/", "/wp-admin/", "/.schild/access/login"} {
			r := hh.Visit("GET", p, visitor, "", "")
			b, _ := io.ReadAll(r.Body)
			if r.StatusCode != 503 || !strings.Contains(string(b), "Wir ziehen gerade um.") {
				t.Fatalf("%s: visitor at %s: %d", when, p, r.StatusCode)
			}
		}
		// An own address passes the maintenance mode and still meets the protection.
		if r := hh.Visit("GET", "/", own, "", ""); r.StatusCode != 200 {
			t.Fatalf("%s: own address at /: %d", when, r.StatusCode)
		}
		if r := hh.Visit("GET", "/wp-admin/", own, "", ""); r.StatusCode != 403 {
			t.Fatalf("%s: own address at the protected path: %d", when, r.StatusCode)
		}
	}
	closed(h, "on")
	if a, err := access.ReadActive(filepath.Join(h.Dir, "data")); err != nil || len(a.Protections) != 2 {
		t.Fatalf("active file: %+v %v", a, err)
	}
	if code, body = h.API("PUT", path, map[string]any{"on": true, "message": strings.Repeat("x", 501)}); code != 400 {
		t.Fatalf("long message: %d %s", code, body)
	}

	dir := h.Dir
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	h2 := apptest.New(t, apptest.Options{Dir: dir})
	h2.Login()
	closed(h2, "after a restart")

	code, body = h2.API("PUT", path, map[string]any{"on": false})
	if st := state(body); code != 200 || st.Maintenance.On || st.Protection == nil {
		t.Fatalf("off: %d %s", code, body)
	}
	if r := h2.Visit("GET", "/", visitor, "", ""); r.StatusCode != 200 {
		t.Fatalf("open again: %d", r.StatusCode)
	}
	if r := h2.Visit("GET", "/wp-admin/", visitor, "", ""); r.StatusCode != 403 {
		t.Fatalf("the protection is gone with the maintenance mode: %d", r.StatusCode)
	}

	// What the switch stored as a protection before D98 becomes the
	// maintenance mode at the next start.
	if code, body = h2.API("PUT", accessPath, map[string]any{"scope": "site", "own_networks": true, "remove_password": true, "message": "Gleich wieder da."}); code != 200 {
		t.Fatalf("old shape: %d %s", code, body)
	}
	if err := h2.Stop(); err != nil {
		t.Fatal(err)
	}
	h3 := apptest.New(t, apptest.Options{Dir: dir})
	h3.Login()
	code, body = h3.API("GET", accessPath, nil)
	if st := state(body); code != 200 || st.Protection != nil || !st.Maintenance.On || st.Maintenance.Message != "Gleich wieder da." {
		t.Fatalf("migrated: %d %s", code, body)
	}
	if r := h3.Visit("GET", "/", visitor, "", ""); r.StatusCode != 503 {
		t.Fatalf("migrated maintenance mode: %d", r.StatusCode)
	}
}
