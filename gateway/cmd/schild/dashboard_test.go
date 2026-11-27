//go:build !release

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/control"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// shortDir keeps the control socket path below the unix socket limit (104
// bytes on macOS).
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "sd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// snapshot is what a reset must not touch.
type snapshot struct {
	events   int
	overlay  string
	blocks   int
	allow    int
	firstEvt string
}

func takeSnapshot(t *testing.T, st *store.Store) snapshot {
	t.Helper()
	ctx := context.Background()
	var s snapshot
	if err := st.DB().QueryRow("SELECT COUNT(*) FROM events WHERE type != ?", events.DashboardAccessReset).Scan(&s.events); err != nil {
		t.Fatal(err)
	}
	_ = st.DB().QueryRow("SELECT id FROM events ORDER BY seq LIMIT 1").Scan(&s.firstEvt)
	ov, _ := st.Get(ctx, "settings_overlay_v1")
	s.overlay = string(ov)
	bs, err := st.ListBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.blocks = len(bs)
	as, _ := st.ListAllow(ctx)
	s.allow = len(as)
	return s
}

// seed logs in (one user, one session) and stores an event, a settings
// overlay and a kept block.
func seed(t *testing.T, h *apptest.Harness) {
	t.Helper()
	h.Login()
	if code, b := h.API("GET", "/overview", nil); code != 200 {
		t.Fatalf("overview before reset: %d %s", code, b)
	}
	h.Visit("GET", "/?q=%27%20OR%201%3D1--", "203.0.113.50", "", "")
	h.Flush()
	ctx := context.Background()
	if err := h.App.Store.Put(ctx, "settings_overlay_v1", []byte(`{"retention":{"events_days":14}}`)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := h.App.Store.PutBlock(ctx, events.ActiveBlock{ClientKey: "203.0.113.51", KeyBits: 32, NetClass: "unknown", Source: "behaviour:login_bruteforce",
		Level: 1, DurationS: 600, Since: now.Format(time.RFC3339), Until: now.Add(10 * time.Minute).Format(time.RFC3339), Incident: "K7QM-4XWD"}); err != nil {
		t.Fatal(err)
	}
}

// auditEvents returns the stored access reset events, each validated
// against events.schema.json.
func auditEvents(t *testing.T, st *store.Store) []events.AccessReset {
	t.Helper()
	rows, err := st.DB().Query("SELECT body FROM events WHERE type = ? ORDER BY seq", events.DashboardAccessReset)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []events.AccessReset
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			t.Fatal(err)
		}
		if _, err := verify.Document(verify.DocEvent, body, &verify.Context{}); err != nil {
			t.Fatalf("audit event does not match events.schema.json: %v\n%s", err, body)
		}
		var ev struct {
			Data events.AccessReset `json:"data"`
		}
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"password", "hash", "setup_code", "session_id", "token"} {
			if strings.Contains(string(body), bad) {
				t.Fatalf("audit event contains %q: %s", bad, body)
			}
		}
		out = append(out, ev.Data)
	}
	return out
}

// setupRemote sets the first password as a non-local client.
func setupRemote(t *testing.T, h *apptest.Harness, code string) int {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"password": "neues-pferd-batterie", "setup_code": code})
	req, _ := http.NewRequest("POST", h.Dash.URL+"/api/v0/auth/setup", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func firstRun(t *testing.T, h *apptest.Harness) bool {
	t.Helper()
	resp, err := http.Get(h.Dash.URL + "/api/v0/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var s dashboard.Session
	_ = json.NewDecoder(resp.Body).Decode(&s)
	return s.FirstRun
}

// TestResetPasswordRunningGateway: through the control path the running
// gateway ends old sessions at once, needs the new code from a remote
// client exactly once and keeps events, settings and blocks.
func TestResetPasswordRunningGateway(t *testing.T) {
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	seed(t, h)
	data := filepath.Dir(h.App.Store.Path())
	before := takeSnapshot(t, h.App.Store)
	if before.events == 0 || before.blocks != 1 || before.overlay == "" {
		t.Fatalf("seed: %+v", before)
	}
	release, err := control.Lock(data) // as schild run
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := h.App.ServeControl(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	for p, want := range map[string]os.FileMode{filepath.Dir(srv.Path()): 0o700, srv.Path(): 0o600} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s: mode %v, want %v (%v)", p, fi.Mode().Perm(), want, err)
		}
	}

	r, err := resetPassword(context.Background(), "test-node", data, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if r.Via != dashboard.ViaControlPath || r.Users != 1 || r.Sessions < 1 || r.Code == "" {
		t.Fatalf("result %+v", r)
	}
	// Old session invalid at once, first-run setup again.
	if code, _ := h.API("GET", "/overview", nil); code != 401 {
		t.Fatalf("old session after reset: %d", code)
	}
	if !firstRun(t, h) {
		t.Fatal("no first-run setup after reset")
	}
	// Remote setup: no code, the old logged code and a wrong code fail.
	for _, c := range []string{"", h.App.SetupCode(), "AAAA-BBBB-CCCC"} {
		if got := setupRemote(t, h, c); got != 403 {
			t.Fatalf("setup with code %q: %d, want 403", c, got)
		}
	}
	if got := setupRemote(t, h, strings.ToLower(r.Code)); got != 200 {
		t.Fatalf("setup with the new code: %d", got)
	}
	if got := setupRemote(t, h, r.Code); got != 409 {
		t.Fatalf("second setup with the same code: %d, want 409", got)
	}
	if h.App.Store.PendingSetupHash(context.Background()) != nil {
		t.Fatal("pending setup hash kept after setup")
	}
	h.Flush()
	if after := takeSnapshot(t, h.App.Store); after != before {
		t.Fatalf("reset touched events, settings or blocks:\nbefore %+v\nafter  %+v", before, after)
	}
	as := auditEvents(t, h.App.Store)
	if len(as) != 1 || as[0] != (events.AccessReset{Via: "control_path", UsersRemoved: 1, SessionsEnded: r.Sessions, HostUser: "deploy"}) {
		t.Fatalf("audit %+v", as)
	}
}

// TestResetPasswordStopped: with schild stopped the CLI writes the store
// itself; the code it printed works after the next start (and is not
// replaced by a new logged one).
func TestResetPasswordStopped(t *testing.T) {
	dir := shortDir(t)
	h := apptest.New(t, apptest.Options{Dir: dir})
	seed(t, h)
	data := filepath.Dir(h.App.Store.Path())
	before := takeSnapshot(t, h.App.Store)
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_USER", "")
	r, err := resetPassword(context.Background(), "test-node", data, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Via != dashboard.ViaHostCLI || r.Users != 1 || r.Sessions < 1 {
		t.Fatalf("result %+v", r)
	}
	st, err := store.Open(filepath.Join(data, "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	after := takeSnapshot(t, st)
	audit := auditEvents(t, st)
	users, _ := st.GetUser(context.Background(), "admin")
	st.Close()
	if after != before {
		t.Fatalf("reset touched events, settings or blocks:\nbefore %+v\nafter  %+v", before, after)
	}
	if users != nil {
		t.Fatal("user kept")
	}
	if len(audit) != 1 || audit[0] != (events.AccessReset{Via: "host_cli", UsersRemoved: 1, SessionsEnded: r.Sessions}) {
		t.Fatalf("audit %+v", audit)
	}
	var out bytes.Buffer
	printReset(&out, r)
	if strings.Count(out.String(), r.Code) != 1 {
		t.Fatalf("code not printed exactly once:\n%s", out.String())
	}

	h2 := apptest.New(t, apptest.Options{Dir: dir})
	if h2.App.SetupCode() != "" {
		t.Fatal("a new setup code was generated (and logged) although a reset code is pending")
	}
	if !firstRun(t, h2) {
		t.Fatal("no first-run setup after reset")
	}
	if got := setupRemote(t, h2, ""); got != 403 {
		t.Fatalf("remote setup without code: %d", got)
	}
	if got := setupRemote(t, h2, r.Code); got != 200 {
		t.Fatalf("setup with the printed code: %d", got)
	}
	if got := setupRemote(t, h2, r.Code); got != 409 {
		t.Fatalf("code used twice: %d", got)
	}
}

// TestResetPasswordRefused: a gateway holds the data directory but its
// control path does not answer: nothing changes.
func TestResetPasswordRefused(t *testing.T) {
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	seed(t, h)
	data := filepath.Dir(h.App.Store.Path())
	release, err := control.Lock(data)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_, err = resetPassword(context.Background(), "test-node", data, "deploy")
	if !errors.Is(err, errGatewayUnreachable) {
		t.Fatalf("err %v, want refused", err)
	}
	if code, _ := h.API("GET", "/overview", nil); code != 200 {
		t.Fatalf("session ended although refused: %d", code)
	}
	if !h.App.Store.HasUsers(context.Background()) || len(auditEvents(t, h.App.Store)) != 0 {
		t.Fatal("store changed although refused")
	}
}

func TestResetPasswordNoStore(t *testing.T) {
	if _, err := resetPassword(context.Background(), "n", filepath.Join(shortDir(t), "missing"), ""); err == nil || !strings.Contains(err.Error(), "no store") {
		t.Fatalf("err %v", err)
	}
}

func TestHostUser(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cur := func() string { return "root" }
	for _, c := range []struct {
		env map[string]string
		// account is what the audit entry names, event what the event
		// takes of it: names outside the contract pattern are left out there.
		account, event string
	}{
		{map[string]string{"SUDO_USER": "deploy", "USER": "root"}, "deploy", "deploy"},
		{map[string]string{"USER": "martin"}, "martin", "martin"},
		{map[string]string{"USER": "Not Valid"}, "Not Valid", ""},
		{map[string]string{}, "root", "root"},
	} {
		got := hostAccount(env(c.env), cur)
		if got != c.account || dashboard.HostUser(got) != c.event {
			t.Errorf("%v: account %q (event %q), want %q (%q)", c.env, got, dashboard.HostUser(got), c.account, c.event)
		}
	}
}

// TestSetupCodeCommand: `schild dashboard setup-code` prints the code of
// the first start through the control path, changes nothing, and has no
// code once a password is set or after a reset.
func TestSetupCodeCommand(t *testing.T) {
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	data := filepath.Dir(h.App.Store.Path())
	// Not running (no control path): a clear error, nothing created.
	if _, err := setupCode(context.Background(), data, "deploy"); err == nil || !strings.Contains(err.Error(), "start schild") {
		t.Fatalf("without a control path: %v", err)
	}
	release, err := control.Lock(data)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := h.App.ServeControl(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	for range 2 { // asking does not use the code up
		code, err := setupCode(context.Background(), data, "deploy")
		if err != nil || code == "" || code != h.App.SetupCode() {
			t.Fatalf("setup code %q, %v; want the code of the start log", code, err)
		}
	}
	var out bytes.Buffer
	printSetupCode(&out, h.App.SetupCode(), "0.0.0.0:8788")
	if !strings.Contains(out.String(), h.App.SetupCode()) || !strings.Contains(out.String(), "http://127.0.0.1:8788") {
		t.Fatalf("output:\n%s", out.String())
	}
	h.Login()
	if _, err := setupCode(context.Background(), data, "deploy"); err == nil || !strings.Contains(err.Error(), "already set") {
		t.Fatalf("with a password set: %v", err)
	}
	r, err := resetPassword(context.Background(), "test-node", data, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	// The reset code is shown once and kept as a hash only.
	if code, err := setupCode(context.Background(), data, "deploy"); err == nil || code != "" || strings.Contains(err.Error(), r.Code) {
		t.Fatalf("after a reset: %q, %v", code, err)
	}
}
