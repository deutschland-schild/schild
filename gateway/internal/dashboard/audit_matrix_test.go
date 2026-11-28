//go:build !release

package dashboard_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/audittest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/hostagent"
	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
	"github.com/deutschland-schild/schild/gateway/internal/hosts"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The audit log as the dashboard API writes and serves it (MVP-36,
// contracts/audit.md), checked by a reader of GET /audit who did not build
// it. A failure here names a place where a `must` of the spec does not hold.

type (
	want  = audittest.Want
	field = audittest.Field
)

const (
	auditSite = "shop.example"
	loopback  = "127.0.0.1"
	xssPath   = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
)

// dashLog reads GET /audit with the session of the harness.
func dashLog(t testing.TB, h *apptest.Harness) *audittest.Log {
	return &audittest.Log{T: t, Way: "dashboard", Get: func(q string) (int, []byte) { return h.API("GET", "/audit?"+q, nil) }}
}

// oneSite makes the gateway know one website with a fixed id.
func oneSite(h *apptest.Harness) {
	h.App.Sites.Store(sites.NewView(websites.Input{Mode: websites.ModeProxy, SiteHosts: []string{auditSite}}))
}

// rawAudit is what the stores of the log hold as bytes: audit.db with its
// WAL, and the bodies of the outbox in schild.db.
func rawAudit(t testing.TB, h *apptest.Harness) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	found := false
	for _, name := range []string{auditlog.FileName, auditlog.FileName + "-wal"} {
		b, err := os.ReadFile(filepath.Join(h.Dir, "data", name))
		if err == nil {
			out[name] = b
			found = found || name == auditlog.FileName
		}
	}
	if !found {
		t.Fatalf("no %s in %s", auditlog.FileName, filepath.Join(h.Dir, "data"))
	}
	rows, err := h.App.Store.AuditOutbox(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	var box []byte
	for _, r := range rows {
		box = append(append(box, r.Body...), '\n')
	}
	out["audit_outbox of schild.db"] = box
	return out
}

// storedBodies reads the body of every entry in audit.db by id, as the
// bytes that are stored.
func storedBodies(t testing.TB, h *apptest.Harness) map[string]string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(h.Dir, "data", auditlog.FileName)+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, body FROM entries`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id string
		var body []byte
		if err := rows.Scan(&id, &body); err != nil {
			t.Fatal(err)
		}
		out[id] = string(body)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// moved waits until the outbox is empty: every entry is in audit.db.
func moved(h *apptest.Harness) {
	h.T.Helper()
	h.WaitFor("the outbox to be moved to audit.db", func() bool {
		n, _, err := h.App.Store.AuditOutboxLen(context.Background())
		return err == nil && n == 0
	})
}

// dumpEntries logs entries when SCHILD_AUDIT_DUMP is set.
func dumpEntries(t testing.TB, what string, es []audittest.Entry) {
	if os.Getenv("SCHILD_AUDIT_DUMP") == "" {
		return
	}
	for _, e := range es {
		t.Logf("%s: %s", what, audittest.JSON(e))
	}
}

// matrix runs the operations of the dashboard API one after the other on
// one gateway and checks the entries of each.
type matrix struct {
	t       *testing.T
	h       *apptest.Harness
	log     *audittest.Log
	session string
	covered map[string]bool
	marks   audittest.Markers
}

// call sends one call of the dashboard API and fails the test on another
// status.
func (m *matrix) call(t *testing.T, method, path string, body any, status int) []byte {
	t.Helper()
	code, b := m.h.API(method, path, body)
	if code != status {
		t.Fatalf("%s %s: %d, want %d: %s", method, path, code, status, b)
	}
	return b
}

// entries checks the new entries of an operation: exactly the wanted ones,
// each by the session of the harness from loopback.
func (m *matrix) entries(t *testing.T, operation string, wants ...want) []audittest.Entry {
	t.Helper()
	m.covered[operation] = true
	for i := range wants {
		wants[i].Operation = "dashboard:" + operation
	}
	got := m.log.Expect(t, wants...)
	dumpEntries(t, operation, got)
	for _, e := range got {
		if e != nil {
			audittest.CheckDashboardActor(t, e, "admin", m.session, loopback)
		}
	}
	return got
}

// TestAuditMatrixDashboard: every operation of the dashboard API that the
// catalogue names writes exactly its entries, with the action, the actor,
// the address, the subject, the website and the values before and after; a
// setting that is set to what it is writes none. No secret is in the log.
func TestAuditMatrixDashboard(t *testing.T) {
	if keys.Release {
		t.Skip("app servers with schild-agent need the test switch " + app.HostAgentsEnv + ", which release builds ignore")
	}
	t.Setenv(app.HostAgentsEnv, "1")
	reports := t.TempDir()
	h := apptest.New(t, apptest.Options{Extra: "host_check:\n  report_dir: " + reports + "\n  agents:\n    enabled: true\n    listen: \"0.0.0.0:8790\"\n" +
		"behaviour:\n  presets: [wordpress]\n"})
	oneSite(h)
	m := &matrix{t: t, h: h, covered: map[string]bool{}}
	ctx := context.Background()

	// The first password and its session.
	h.Password = m.marks.Secret("setup.password")
	m.marks.SecretValue("setup.setup_code", h.App.SetupCode())
	h.Login()
	m.log = dashLog(t, h)
	t.Run("setupPassword", func(t *testing.T) {
		m.covered["setupPassword"] = true
		got := m.log.Expect(t,
			want{Action: "password.setup", Operation: "dashboard:setupPassword", Fields: map[string]field{"/password": {Change: "added", Hidden: "secret"}}},
			want{Action: "session.start", Operation: "dashboard:setupPassword"})
		dumpEntries(t, "setupPassword", got)
		for _, e := range got {
			if e == nil {
				t.Fatal("the first sign-in has no entry: the session of the following checks is unknown")
			}
			audittest.CheckDashboardActor(t, e, "admin", "", loopback)
		}
		m.session = audittest.Str(got[1], "actor", "session")
		if s := audittest.Str(got[0], "actor", "session"); s != m.session {
			t.Errorf("password.setup names session %q, session.start %q", s, m.session)
		}
	})
	if m.session == "" {
		t.Fatal("no session id")
	}
	m.marks.SecretValue("the session cookie", sessionCookie(t, h))
	m.marks.SecretValue("the CSRF token", h.CSRF)

	site := "/websites/" + auditSite

	t.Run("setAccessProtection", func(t *testing.T) {
		body := map[string]any{"scope": "site", "except": []string{"/hooks/*"},
			"password": m.marks.Secret("access.password"), "addresses": []string{"198.51.100.0/24"}, "own_networks": false,
			"message": m.marks.Listed("access.message")}
		m.call(t, "PUT", site+"/access", body, 200)
		m.entries(t, "setAccessProtection", want{Action: "access_lock.set", Subject: auditSite, Website: auditSite, Fields: map[string]field{
			"/scope":     {Change: "added", After: "site"},
			"/except":    {Change: "added", Added: []string{"/hooks/*"}},
			"/addresses": {Change: "added", Added: []string{"198.51.100.0/24"}},
			"/message":   {Change: "added", After: m.marks.Listed("access.message")},
			"/password":  {Change: "added", Hidden: "secret"},
		}})
		// The same protection without a new password: nothing changes.
		delete(body, "password")
		m.call(t, "PUT", site+"/access", body, 200)
		m.log.None(t, "setAccessProtection with the protection that is in force")
		// A change of two fields names those fields alone.
		body["scope"], body["paths"] = "paths", []string{"/wp-admin/*"}
		delete(body, "except")
		m.call(t, "PUT", site+"/access", body, 200)
		m.entries(t, "setAccessProtection", want{Action: "access_lock.set", Subject: auditSite, Website: auditSite, Fields: map[string]field{
			"/scope":  {Change: "changed", Before: "site", After: "paths"},
			"/paths":  {Change: "added", Added: []string{"/wp-admin/*"}},
			"/except": {Change: "removed", Removed: []string{"/hooks/*"}},
		}, Absent: []string{"/message", "/addresses", "/password"}})
	})

	t.Run("setMaintenance", func(t *testing.T) {
		body := map[string]any{"on": true, "message": m.marks.Listed("maintenance.message")}
		m.call(t, "PUT", site+"/maintenance", body, 200)
		m.entries(t, "setMaintenance", want{Action: "maintenance.set", Subject: auditSite, Website: auditSite, Fields: map[string]field{
			"/on":      {Change: "changed", Before: false, After: true},
			"/message": {Change: "added", After: m.marks.Listed("maintenance.message")},
		}})
		m.call(t, "PUT", site+"/maintenance", body, 200)
		m.log.None(t, "setMaintenance with the mode that is on")
		m.call(t, "PUT", site+"/maintenance", map[string]any{"on": false}, 200)
		m.entries(t, "setMaintenance", want{Action: "maintenance.set", Subject: auditSite, Website: auditSite, Fields: map[string]field{
			"/on":      {Change: "changed", Before: true, After: false},
			"/message": {Change: "removed", Before: m.marks.Listed("maintenance.message")},
		}})
		m.call(t, "PUT", site+"/maintenance", map[string]any{"on": false}, 200)
		m.log.None(t, "setMaintenance off while it is off")
	})

	t.Run("removeAccessProtection", func(t *testing.T) {
		m.call(t, "DELETE", site+"/access", nil, 204)
		m.entries(t, "removeAccessProtection", want{Action: "access_lock.remove", Subject: auditSite, Website: auditSite, Fields: map[string]field{
			"/scope":     {Change: "removed", Before: "paths"},
			"/paths":     {Change: "removed", Removed: []string{"/wp-admin/*"}},
			"/addresses": {Change: "removed", Removed: []string{"198.51.100.0/24"}},
			"/message":   {Change: "removed", Before: m.marks.Listed("access.message")},
			"/password":  {Change: "removed", Hidden: "secret"},
		}})
		m.call(t, "DELETE", site+"/access", nil, 204)
		m.log.None(t, "removeAccessProtection without a protection")
	})

	t.Run("setCrawlerPolicy", func(t *testing.T) {
		body := map[string]any{"categories": map[string]string{"ai_training": "block"}, "impersonators": "block"}
		m.call(t, "PUT", site+"/crawlers", body, 200)
		m.entries(t, "setCrawlerPolicy", want{Action: "crawlers.set", Subject: auditSite, Website: auditSite, Fields: map[string]field{
			"/categories/ai_training": {Change: "added", After: "block"},
			"/impersonators":          {Change: "changed", Before: "allow", After: "block"},
		}})
		m.call(t, "PUT", site+"/crawlers", body, 200)
		m.log.None(t, "setCrawlerPolicy with the policy that is in force")
	})

	t.Run("setHumanCheck", func(t *testing.T) {
		body := map[string]any{"mode": "always", "except": []string{"/api/*"}, "clearance_ttl_s": 1800, "difficulty": 5000}
		m.call(t, "PUT", site+"/human-check", body, 200)
		m.entries(t, "setHumanCheck", want{Action: "human_check.set", Subject: auditSite, Website: auditSite, Fields: map[string]field{
			"/mode":            {Change: "added", After: "always"},
			"/except":          {Change: "added", Added: []string{"/api/*"}},
			"/clearance_ttl_s": {Change: "added", After: 1800},
			"/difficulty":      {Change: "added", After: 5000},
		}})
		m.call(t, "PUT", site+"/human-check", body, 200)
		m.log.None(t, "setHumanCheck with the policy that is in force")
		body["mode"] = "findings"
		m.call(t, "PUT", site+"/human-check", body, 200)
		m.entries(t, "setHumanCheck", want{Action: "human_check.set", Subject: auditSite, Website: auditSite, Fields: map[string]field{
			"/mode": {Change: "changed", Before: "always", After: "findings"},
		}, Absent: []string{"/except", "/clearance_ttl_s", "/difficulty"}})
	})

	t.Run("removeHumanCheck", func(t *testing.T) {
		m.call(t, "DELETE", site+"/human-check", nil, 200)
		m.entries(t, "removeHumanCheck", want{Action: "human_check.remove", Subject: auditSite, Website: auditSite, Fields: map[string]field{
			"/mode":            {Change: "removed", Before: "findings"},
			"/except":          {Change: "removed", Removed: []string{"/api/*"}},
			"/clearance_ttl_s": {Change: "removed", Before: 1800},
			"/difficulty":      {Change: "removed", Before: 5000},
		}})
		m.call(t, "DELETE", site+"/human-check", nil, 200)
		m.log.None(t, "removeHumanCheck without a policy")
	})

	// A block by hand, and the two ways a person ends one.
	block := func(t *testing.T, ip, reason string) string {
		t.Helper()
		b := m.call(t, "POST", "/blocks", map[string]any{"address": ip, "duration_s": 3600, "reason": reason}, 200)
		var rb struct {
			Incident string `json:"incident"`
			Until    string `json:"until"`
		}
		if err := json.Unmarshal(b, &rb); err != nil || rb.Incident == "" {
			t.Fatalf("createBlock: %v %s", err, b)
		}
		h.Flush()
		m.entries(t, "createBlock", want{Action: "block.set", Subject: rb.Incident, Reason: reason, Fields: map[string]field{
			"/client":     {Change: "added", After: ip},
			"/duration_s": {Change: "added", After: 3600},
			"/until":      {Change: "added", After: rb.Until},
			"/effect":     {Change: "added", After: "block"},
		}})
		return rb.Incident
	}
	var blocked string
	t.Run("createBlock", func(t *testing.T) {
		blocked = block(t, "203.0.113.57", m.marks.Listed("block.reason"))
		// A block that runs stands: the second call is refused and writes
		// nothing.
		m.call(t, "POST", "/blocks", map[string]any{"address": "203.0.113.57", "duration_s": 3600, "reason": "again"}, 409)
		m.log.None(t, "createBlock of an address that is blocked")
	})

	t.Run("unblockIncident", func(t *testing.T) {
		if blocked == "" {
			t.Skip("no block to end")
		}
		note := m.marks.Listed("unblock.note")
		m.call(t, "POST", "/incidents/"+blocked+"/unblock", map[string]any{"false_positive": true, "allow_ip": true, "allow_ttl": "24h", "note": note}, 200)
		got := m.entries(t, "unblockIncident",
			want{Action: "block.lift", Subject: blocked, Incident: blocked, Reason: note, Fields: map[string]field{
				"/client":         {Change: "removed", Before: "203.0.113.57"},
				"/false_positive": {Change: "added", After: true},
			}},
			want{Action: "client.release", Incident: blocked, Reason: note, Fields: map[string]field{
				"/client": {Change: "added", After: "203.0.113.57"},
				"/until":  {Change: "added", After: audittest.Any},
			}},
			want{Action: "allowlist.add", Subject: "*", Incident: blocked, Fields: map[string]field{
				"/ip":      {Change: "added", After: "203.0.113.57"},
				"/label":   {Change: "added", After: "Vorfall " + blocked},
				"/level":   {Change: "added", After: "no_block"},
				"/expires": {Change: "added", After: audittest.Any},
			}})
		if got[2] != nil && !strings.HasPrefix(audittest.Str(got[2], "subject", "id"), "al_") {
			t.Errorf("allowlist.add: the subject is not the id of the own IP: %s", audittest.JSON(got[2]["subject"]))
		}
		m.call(t, "POST", "/incidents/"+blocked+"/unblock", map[string]any{}, 409)
		m.log.None(t, "unblockIncident of an incident that is unblocked")
	})

	t.Run("releaseClient", func(t *testing.T) {
		incident := block(t, "203.0.113.58", "release test")
		label := m.marks.Listed("release.label")
		b := m.call(t, "POST", "/behaviour/release", map[string]any{"ip": "203.0.113.58", "allow": "permanent", "label": label}, 200)
		var res dashboard.ReleaseResult
		_ = json.Unmarshal(b, &res)
		if res.BlocksEnded != 1 {
			t.Errorf("release: %d blocks ended, want 1: %s", res.BlocksEnded, b)
		}
		m.entries(t, "releaseClient",
			want{Action: "block.lift", Subject: incident, Incident: incident, Fields: map[string]field{"/client": {Change: "removed", Before: "203.0.113.58"}}},
			want{Action: "client.release", Fields: map[string]field{
				"/client": {Change: "added", After: "203.0.113.58"},
				"/allow":  {Change: "added", After: "permanent"},
			}},
			want{Action: "allowlist.add", Subject: "*", Fields: map[string]field{
				"/ip":      {Change: "added", After: "203.0.113.58"},
				"/label":   {Change: "added", After: label},
				"/level":   {Change: "added", After: "no_block"},
				"/expires": {Change: "added", After: "never"},
			}})
		// A release for a while, of one scenario: no block runs, so the
		// release alone.
		m.call(t, "POST", "/behaviour/release", map[string]any{"ip": "203.0.113.59", "allow": "exception", "scenario": "path_probing", "ttl": "24h"}, 200)
		m.entries(t, "releaseClient", want{Action: "client.release", Fields: map[string]field{
			"/client":   {Change: "added", After: "203.0.113.59"},
			"/allow":    {Change: "added", After: "exception"},
			"/scenario": {Change: "added", After: "path_probing"},
			"/until":    {Change: "added", After: audittest.Any},
		}})
	})

	var allowID string
	t.Run("addAllowlistEntry", func(t *testing.T) {
		label := m.marks.Listed("allowlist.label")
		b := m.call(t, "POST", "/allowlist", map[string]any{"ip": "203.0.113.52", "label": label, "level": "no_block", "ttl": "24h"}, 201)
		var e dashboard.AllowlistEntry
		_ = json.Unmarshal(b, &e)
		allowID = e.ID
		m.entries(t, "addAllowlistEntry", want{Action: "allowlist.add", Subject: e.ID, Fields: map[string]field{
			"/ip":      {Change: "added", After: "203.0.113.52"},
			"/label":   {Change: "added", After: label},
			"/level":   {Change: "added", After: "no_block"},
			"/expires": {Change: "added", After: audittest.Any},
		}})
		// A network and a host name are recorded as what they are.
		b = m.call(t, "POST", "/allowlist", map[string]any{"cidr": "198.51.100.0/28", "label": "Netz", "level": "no_block", "ttl": "never"}, 201)
		_ = json.Unmarshal(b, &e)
		m.entries(t, "addAllowlistEntry", want{Action: "allowlist.add", Subject: e.ID, Fields: map[string]field{
			"/cidr":    {Change: "added", After: "198.51.100.0/28"},
			"/expires": {Change: "added", After: "never"},
		}})
	})

	t.Run("allowMyIP", func(t *testing.T) {
		label := m.marks.Listed("allowmine.label")
		code, b := h.API("POST", "/allowlist/mine", map[string]any{"label": label, "ttl": "24h"})
		if code != 201 {
			t.Fatalf("allowMyIP: %d %s", code, b)
		}
		var e dashboard.AllowlistEntry
		_ = json.Unmarshal(b, &e)
		m.entries(t, "allowMyIP", want{Action: "allowlist.add", Subject: e.ID, Fields: map[string]field{
			"/ip":    {Change: "added", After: loopback},
			"/label": {Change: "added", After: label},
			"/level": {Change: "added", After: "no_block"},
		}})
		m.call(t, "DELETE", "/allowlist/"+e.ID, nil, 204)
		m.entries(t, "deleteAllowlistEntry", want{Action: "allowlist.remove", Subject: e.ID, Fields: map[string]field{
			"/ip": {Change: "removed", Before: loopback},
		}})
	})

	t.Run("deleteAllowlistEntry", func(t *testing.T) {
		if allowID == "" {
			t.Skip("no own IP to delete")
		}
		m.call(t, "DELETE", "/allowlist/"+allowID, nil, 204)
		m.entries(t, "deleteAllowlistEntry", want{Action: "allowlist.remove", Subject: allowID, Fields: map[string]field{
			"/ip":      {Change: "removed", Before: "203.0.113.52"},
			"/label":   {Change: "removed", Before: m.marks.Listed("allowlist.label")},
			"/level":   {Change: "removed", Before: "no_block"},
			"/expires": {Change: "removed", Before: audittest.Any},
		}})
		m.call(t, "DELETE", "/allowlist/"+allowID, nil, 404)
		m.log.None(t, "deleteAllowlistEntry of an own IP that is gone")
	})

	var exception contractapi.RuleException
	t.Run("createRuleException", func(t *testing.T) {
		req := contractapi.ExceptionRequest{Website: auditSite, Path: "/kontakt", Target: "ARGS:message", Repository: "crs", Rules: []string{"942100", "941100"},
			Reason: m.marks.Listed("exception.reason")}
		exception = decode[contractapi.RuleException](t, m.call(t, "POST", "/rule-exceptions", req, 200))
		m.entries(t, "createRuleException", want{Action: "rule_exception.set", Subject: fmt.Sprint(exception.ID), Website: auditSite, Reason: req.Reason, Fields: map[string]field{
			"/path":       {Change: "added", After: "/kontakt"},
			"/target":     {Change: "added", After: "ARGS:message"},
			"/repository": {Change: "added", After: "crs"},
			"/rules":      {Change: "added", Added: []string{"941100", "942100"}},
		}})
		m.call(t, "POST", "/rule-exceptions", req, 200)
		m.log.None(t, "createRuleException of the exception that stands")
	})

	t.Run("removeRuleExceptionRule", func(t *testing.T) {
		if exception.ID == 0 {
			t.Skip("no exception")
		}
		m.call(t, "DELETE", fmt.Sprintf("/rule-exceptions/%d/rules/941100", exception.ID), nil, 200)
		m.entries(t, "removeRuleExceptionRule", want{Action: "rule_exception.remove", Subject: fmt.Sprint(exception.ID), Website: auditSite, Fields: map[string]field{
			"/rules": {Change: "changed", Removed: []string{"941100"}},
		}, Absent: []string{"/path", "/target", "/repository"}})
		m.call(t, "DELETE", fmt.Sprintf("/rule-exceptions/%d/rules/941100", exception.ID), nil, 404)
		m.log.None(t, "removeRuleExceptionRule of a rule that is out")
	})

	t.Run("removeRuleException", func(t *testing.T) {
		if exception.ID == 0 {
			t.Skip("no exception")
		}
		m.call(t, "DELETE", fmt.Sprintf("/rule-exceptions/%d", exception.ID), nil, 200)
		m.entries(t, "removeRuleException", want{Action: "rule_exception.remove", Subject: fmt.Sprint(exception.ID), Website: auditSite, Fields: map[string]field{
			"/path":       {Change: "removed", Before: "/kontakt"},
			"/target":     {Change: "removed", Before: "ARGS:message"},
			"/repository": {Change: "removed", Before: "crs"},
			"/rules":      {Change: "removed", Removed: []string{"942100"}},
		}})
		m.call(t, "DELETE", fmt.Sprintf("/rule-exceptions/%d", exception.ID), nil, 404)
		m.log.None(t, "removeRuleException of an exception that is gone")
	})

	t.Run("updateRule", func(t *testing.T) {
		note := m.marks.Listed("rule.note")
		body := map[string]any{"disabled": true, "note": note}
		m.call(t, "PATCH", "/rules/crs/941100", body, 200)
		m.entries(t, "updateRule", want{Action: "rule.set", Subject: "crs/941100", Reason: note, Fields: map[string]field{
			"/disabled": {Change: "changed", Before: false, After: true},
		}})
		m.call(t, "PATCH", "/rules/crs/941100", body, 200)
		m.log.None(t, "updateRule of a rule that is disabled")
		m.call(t, "PATCH", "/rules/crs/941100", map[string]any{"disabled": false}, 200)
		m.entries(t, "updateRule", want{Action: "rule.set", Subject: "crs/941100", Fields: map[string]field{
			"/disabled": {Change: "changed", Before: true, After: false},
		}})
	})

	t.Run("updateRuleRepository", func(t *testing.T) {
		body := map[string]any{"state": "block"}
		m.call(t, "PATCH", "/rule-repositories/crowdsec", body, 200)
		m.entries(t, "updateRuleRepository", want{Action: "rule_repository.set", Subject: "crowdsec", Fields: map[string]field{
			"/state": {Change: "changed", Before: "detect", After: "block"},
		}})
		m.call(t, "PATCH", "/rule-repositories/crowdsec", body, 200)
		m.log.None(t, "updateRuleRepository with the state that is set")
	})

	t.Run("updateRuleRepositorySettings", func(t *testing.T) {
		body := map[string]any{"paranoia_level": 2, "inbound_anomaly_threshold": 7}
		m.call(t, "PATCH", "/rule-repositories/crs/settings", body, 200)
		m.entries(t, "updateRuleRepositorySettings", want{Action: "rule_repository.set", Subject: "crs", Fields: map[string]field{
			"/paranoia_level":            {Change: "changed", Before: 1, After: 2},
			"/inbound_anomaly_threshold": {Change: "changed", Before: 5, After: 7},
		}, Absent: []string{"/state"}})
		m.call(t, "PATCH", "/rule-repositories/crs/settings", body, 200)
		m.log.None(t, "updateRuleRepositorySettings with the values that are set")
	})

	t.Run("syncRuleRepository", func(t *testing.T) {
		dir := filepath.Join(h.Dir, "rules.d")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "10-stop.conf"),
			[]byte(`SecRule REQUEST_URI "@beginsWith /stop-here" "id:1000001,phase:1,deny,status:403,msg:'stop here'"`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		m.call(t, "POST", "/rule-repositories/local/sync", nil, 200)
		m.entries(t, "syncRuleRepository", want{Action: "rule_repository.sync", Subject: "local", Fields: map[string]field{
			"/rules_loaded": {Change: "changed", Before: 0, After: 1},
		}})
		m.call(t, "POST", "/rule-repositories/local/sync", nil, 200)
		m.log.None(t, "syncRuleRepository of files that did not change")
	})

	t.Run("resetRuleRepository", func(t *testing.T) {
		m.call(t, "POST", "/rule-repositories/crowdsec/reset", nil, 200)
		m.entries(t, "resetRuleRepository", want{Action: "rule_repository.reset", Subject: "crowdsec"})
	})

	t.Run("updateBehaviourSettings", func(t *testing.T) {
		var limits struct {
			Items []struct {
				ID     string `json:"id"`
				Source string `json:"source"`
				Mode   string `json:"mode"`
			} `json:"items"`
		}
		_ = json.Unmarshal(m.call(t, "GET", "/behaviour/rate-limits", nil, 200), &limits)
		preset, presetMode := "", ""
		for _, l := range limits.Items {
			if l.Source == "preset" && preset == "" {
				preset, presetMode = l.ID, l.Mode
			}
		}
		st := decode[dashboard.BehaviourSettings](t, m.call(t, "GET", "/behaviour/settings", nil, 200))
		was := ""
		for _, sc := range st.Scenarios {
			if sc.ID == "path_probing" {
				was = sc.Mode
			}
		}
		now := "block"
		if was == "block" {
			now = "observe"
		}
		body := map[string]any{"scenarios": map[string]any{"path_probing": now}, "thresholds": map[string]any{"login_bruteforce": map[string]any{"count": 7}}}
		fields := map[string]field{
			"/scenarios/path_probing":            {Change: "changed", Before: was, After: now},
			"/thresholds/login_bruteforce/count": {Change: "added", After: 7},
		}
		if preset != "" {
			mode := "off"
			if presetMode == "off" {
				mode = "observe"
			}
			body["preset_limit_modes"] = map[string]any{preset: mode}
			fields["/preset_limit_modes/"+preset] = field{Change: "added", After: mode}
		} else {
			t.Errorf("no preset limit on this gateway: preset_limit_modes is not driven: %+v", limits)
		}
		m.call(t, "PATCH", "/behaviour/settings", body, 200)
		m.entries(t, "updateBehaviourSettings", want{Action: "behaviour.set", Subject: "*", Fields: fields})
		m.call(t, "PATCH", "/behaviour/settings", body, 200)
		m.log.None(t, "updateBehaviourSettings with the settings that are set")
	})

	t.Run("updateDistributedSettings", func(t *testing.T) {
		body := map[string]any{"detectors": map[string]any{"shape_wave": "respond"}, "thresholds": map[string]any{"route_wave": map[string]any{"count": 50}}}
		m.call(t, "PATCH", "/distributed/settings", body, 200)
		m.entries(t, "updateDistributedSettings", want{Action: "distributed.set", Subject: "*", Fields: map[string]field{
			"/detectors/shape_wave":        {Change: "changed", Before: "observe", After: "respond"},
			"/thresholds/route_wave/count": {Change: "added", After: 50},
		}})
		m.call(t, "PATCH", "/distributed/settings", body, 200)
		m.log.None(t, "updateDistributedSettings with the settings that are set")
	})

	var limitID string
	limit := map[string]any{"route": "/api/orders/*", "methods": []string{"POST"}, "limit": 10, "per": "1m", "burst": 12, "mode": "observe", "site": auditSite}
	t.Run("createRateLimit", func(t *testing.T) {
		limit["label"] = m.marks.Listed("ratelimit.label")
		var l dashboard.RateLimit
		_ = json.Unmarshal(m.call(t, "POST", "/behaviour/rate-limits", limit, 201), &l)
		limitID = l.ID
		m.entries(t, "createRateLimit", want{Action: "rate_limit.add", Subject: l.ID, Fields: map[string]field{
			"/route":   {Change: "added", After: "/api/orders/*"},
			"/methods": {Change: "added", Added: []string{"POST"}},
			"/limit":   {Change: "added", After: 10},
			"/per":     {Change: "added", After: "1m"},
			"/burst":   {Change: "added", After: 12},
			"/mode":    {Change: "added", After: "observe"},
			"/site":    {Change: "added", After: auditSite},
			"/label":   {Change: "added", After: limit["label"]},
		}})
	})

	t.Run("updateRateLimit", func(t *testing.T) {
		if limitID == "" {
			t.Skip("no limit")
		}
		limit["limit"], limit["mode"] = 20, "block"
		m.call(t, "PATCH", "/behaviour/rate-limits/"+limitID, limit, 200)
		m.entries(t, "updateRateLimit", want{Action: "rate_limit.update", Subject: limitID, Fields: map[string]field{
			"/limit": {Change: "changed", Before: 10, After: 20},
			"/mode":  {Change: "changed", Before: "observe", After: "block"},
		}, Absent: []string{"/route", "/label", "/per", "/site"}})
		m.call(t, "PATCH", "/behaviour/rate-limits/"+limitID, limit, 200)
		m.log.None(t, "updateRateLimit with the limit as it is")
	})

	t.Run("deleteRateLimit", func(t *testing.T) {
		if limitID == "" {
			t.Skip("no limit")
		}
		m.call(t, "DELETE", "/behaviour/rate-limits/"+limitID, nil, 204)
		m.entries(t, "deleteRateLimit", want{Action: "rate_limit.remove", Subject: limitID, Fields: map[string]field{
			"/route": {Change: "removed", Before: "/api/orders/*"},
			"/limit": {Change: "removed", Before: 20},
			"/label": {Change: "removed", Before: limit["label"]},
		}})
		m.call(t, "DELETE", "/behaviour/rate-limits/"+limitID, nil, 404)
		m.log.None(t, "deleteRateLimit of a limit that is gone")
	})

	t.Run("updateSettings", func(t *testing.T) {
		was := h.App.Config().Retention.RawIPDays
		body := map[string]any{"retention": map[string]any{"raw_ip_days": 3}}
		m.call(t, "PATCH", "/settings", body, 200)
		m.entries(t, "updateSettings", want{Action: "settings.set", Subject: "*", Fields: map[string]field{
			"/retention/raw_ip_days": {Change: "changed", Before: was, After: 3},
		}, Absent: []string{"/retention/events_days", "/retention/max_size_mb"}})
		m.call(t, "PATCH", "/settings", body, 200)
		m.log.None(t, "updateSettings with the value that is set")
	})

	t.Run("exportIncident", func(t *testing.T) {
		if r := h.Visit("GET", xssPath, "198.51.100.61", "", ""); r.StatusCode != 403 {
			t.Fatalf("the WAF did not stop the probe: %d", r.StatusCode)
		}
		h.Flush()
		rows, _, err := h.App.Store.ListEvents(ctx, store.EventFilter{IP: "198.51.100.61"}, 0, 10)
		if err != nil || len(rows) == 0 || rows[0].Incident == "" {
			t.Fatalf("no incident of the probe: %v", err)
		}
		m.call(t, "POST", "/incidents/"+rows[0].Incident+"/export", nil, 200)
		got := m.entries(t, "exportIncident", want{Action: "incident.export", Subject: rows[0].Incident, Website: "*"})
		if got[0] != nil && rows[0].Site == auditSite && audittest.Str(got[0], "website") != auditSite {
			t.Errorf("incident.export of an incident of %s names website %q", auditSite, audittest.Str(got[0], "website"))
		}
	})

	t.Run("privacyExport", func(t *testing.T) {
		m.call(t, "POST", "/privacy/export", map[string]any{"ip": "198.51.100.61"}, 200)
		got := m.entries(t, "privacyExport", want{Action: "privacy.export", Fields: map[string]field{"/events": {After: audittest.Any}}})
		if got[0] != nil && strings.Contains(audittest.JSON(got[0]), "198.51.100.61") {
			t.Errorf("privacy.export holds the address: %s", audittest.JSON(got[0]))
		}
	})

	t.Run("privacyDelete", func(t *testing.T) {
		m.call(t, "POST", "/privacy/delete", map[string]any{"ip": "198.51.100.61", "confirm": true}, 200)
		got := m.entries(t, "privacyDelete", want{Action: "privacy.erase", Fields: map[string]field{"/events": {After: audittest.Any}}})
		if got[0] != nil && strings.Contains(audittest.JSON(got[0]), "198.51.100.61") {
			t.Errorf("privacy.erase holds the address: %s", audittest.JSON(got[0]))
		}
	})

	t.Run("acceptHostFinding", func(t *testing.T) {
		r := hostcheck.Run(ctx, &hostcheck.FixtureEnv{Dir: "../hostcheck/testdata/hosts/debian12", Time: time.Now().UTC().Add(-time.Hour)}, hostcheck.Options{Role: hc.RoleGateway})
		b, err := hostcheck.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hostcheck.WriteReport(reports, r, b, 30); err != nil {
			t.Fatal(err)
		}
		if err := h.App.Hosts.ScanLocal(ctx); err != nil {
			t.Fatal(err)
		}
		d := decode[hosts.HostDetail](t, m.call(t, "GET", "/hosts/local", nil, 200))
		var rep hc.Report
		if err := json.Unmarshal(d.Report, &rep); err != nil {
			t.Fatal(err)
		}
		var f *hc.Finding
		for i := range rep.Findings {
			if x := &rep.Findings[i]; x.Status == "finding" && x.Severity == "medium" && f == nil {
				f = x
			}
		}
		if f == nil {
			t.Fatal("the fixture has no medium finding")
		}
		ref := map[string]any{"id": f.ID}
		fields := map[string]field{"/host": {Change: "added", After: "local"}, "/finding": {Change: "added", After: f.ID}}
		gone := map[string]field{"/host": {Change: "removed", Before: "local"}, "/finding": {Change: "removed", Before: f.ID}}
		if f.Subject != "" {
			ref["subject"] = f.Subject
			fields["/object"] = field{Change: "added", After: f.Subject}
			gone["/object"] = field{Change: "removed", Before: f.Subject}
		}
		note := m.marks.Listed("finding.note")
		accept := map[string]any{"note": note}
		for k, v := range ref {
			accept[k] = v
		}
		m.call(t, "POST", "/hosts/local/findings/accept", accept, 200)
		m.entries(t, "acceptHostFinding", want{Action: "host_finding.accept", Subject: f.ID, Reason: note, Fields: fields})
		t.Run("reopenHostFinding", func(t *testing.T) {
			m.call(t, "POST", "/hosts/local/findings/reopen", ref, 200)
			m.entries(t, "reopenHostFinding", want{Action: "host_finding.reopen", Subject: f.ID, Fields: gone})
			m.call(t, "POST", "/hosts/local/findings/reopen", ref, 404)
			m.log.None(t, "reopenHostFinding of a finding that is open")
		})
	})

	t.Run("createEnrolment", func(t *testing.T) {
		label := m.marks.Listed("enrolment.label")
		en := decode[hosts.Enrolment](t, m.call(t, "POST", "/agents/enrolments", map[string]any{"label": label, "ttl_minutes": 30}, 201))
		m.marks.SecretValue("the enrolment code", en.Code)
		m.entries(t, "createEnrolment", want{Action: "host_agent.enrol", Fields: map[string]field{
			"/label":       {Change: "added", After: label},
			"/ttl_minutes": {Change: "added", After: 30},
		}})

		// The agent on another machine enrols with the code; the operator
		// confirms its fingerprint and revokes it.
		srv := httptest.NewUnstartedServer(h.App.Hosts.Handler())
		lsrv, err := h.App.Hosts.Server()
		if err != nil {
			t.Fatal(err)
		}
		srv.TLS = lsrv.TLSConfig
		srv.StartTLS()
		defer srv.Close()
		st, err := hostagent.Enrol(ctx, hostagent.EnrolOptions{Dir: filepath.Join(t.TempDir(), "agent"), GatewayURL: srv.URL, GatewayName: en.GatewayName,
			Pin: en.GatewayPin, Code: en.Code, Hostname: "app-1.example"})
		if err != nil {
			t.Fatal(err)
		}
		ap := decode[hosts.AgentPage](t, m.call(t, "GET", "/agents?status=pending", nil, 200))
		if len(ap.Items) != 1 {
			t.Fatalf("pending agents: %+v", ap)
		}
		id := ap.Items[0].ID
		m.log.None(t, "the enrolment of an agent with its code (no call of the dashboard)")

		t.Run("confirmAgent", func(t *testing.T) {
			m.call(t, "POST", "/agents/"+id+"/confirm", map[string]any{"fingerprint": "sha256:" + strings.Repeat("a", 64)}, 409)
			m.log.None(t, "confirmAgent with a wrong fingerprint")
			agentLabel := m.marks.Listed("agent.label")
			m.call(t, "POST", "/agents/"+id+"/confirm", map[string]any{"fingerprint": st.Fingerprint, "label": agentLabel}, 200)
			m.entries(t, "confirmAgent", want{Action: "host_agent.confirm", Subject: id, Fields: map[string]field{
				"/fingerprint": {Change: "added", After: st.Fingerprint},
				"/label":       {Change: "added", After: agentLabel},
			}})
		})
		t.Run("revokeAgent", func(t *testing.T) {
			note := m.marks.Listed("revoke.note")
			m.call(t, "POST", "/agents/"+id+"/revoke", map[string]any{"note": note}, 200)
			m.entries(t, "revokeAgent", want{Action: "host_agent.revoke", Subject: id, Reason: note})
			m.call(t, "POST", "/agents/"+id+"/revoke", map[string]any{}, 409)
			m.log.None(t, "revokeAgent of an agent that is revoked")
		})
	})

	// Operations that write nothing, by the catalogue.
	t.Run("not audited", func(t *testing.T) {
		m.call(t, "POST", "/behaviour/rate-limits/dry-run", map[string]any{"route": "/api/*", "limit": 10, "per": "1m"}, 200)
		m.log.None(t, "dryRunRateLimit")
	})

	// A second person signs in and out with the same account: a session of
	// its own.
	t.Run("login", func(t *testing.T) {
		c := newClient(t, h)
		c.login(t, h.Password)
		m.covered["login"] = true
		got := m.log.Expect(t, want{Action: "session.start", Operation: "dashboard:login"})
		if got[0] == nil {
			t.Fatal("no session.start")
		}
		audittest.CheckDashboardActor(t, got[0], "admin", "", loopback)
		second := audittest.Str(got[0], "actor", "session")
		if second == m.session {
			t.Errorf("the second sign-in has the session id of the first: %s", second)
		}
		m.marks.SecretValue("the cookie of the second session", c.cookie(t))
		t.Run("logout", func(t *testing.T) {
			if code, b := c.api("POST", "/auth/logout", nil); code != 204 {
				t.Fatalf("logout: %d %s", code, b)
			}
			m.covered["logout"] = true
			got := m.log.Expect(t, want{Action: "session.end", Operation: "dashboard:logout"})
			if got[0] != nil {
				audittest.CheckDashboardActor(t, got[0], "admin", second, loopback)
			}
		})
	})

	t.Run("changePassword", func(t *testing.T) {
		next := m.marks.Secret("password.new_password")
		m.call(t, "POST", "/auth/password", map[string]string{"current_password": h.Password, "new_password": next}, 204)
		m.covered["changePassword"] = true
		got := m.log.Expect(t,
			want{Action: "password.change", Operation: "dashboard:changePassword", Fields: map[string]field{"/password": {Change: "changed", Hidden: "secret"}}},
			want{Action: "session.start", Operation: "dashboard:changePassword"})
		// The change is made by the session that asked for it; the session
		// that goes on is a new one.
		if got[0] != nil {
			audittest.CheckDashboardActor(t, got[0], "admin", m.session, loopback)
		}
		if got[1] != nil {
			audittest.CheckDashboardActor(t, got[1], "admin", "", loopback)
			if s := audittest.Str(got[1], "actor", "session"); s == m.session {
				t.Errorf("session.start after the password change names the old session %s", s)
			} else {
				m.session = s
			}
		}
		h.Password = next
		sess := decode[dashboard.Session](t, m.call(t, "GET", "/auth/session", nil, 200))
		h.CSRF = sess.CSRFToken
		m.marks.SecretValue("the cookie after the password change", sessionCookie(t, h))
		m.marks.SecretValue("the CSRF token after the password change", h.CSRF)
	})

	// What the catalogue names and this test did not call.
	t.Run("every operation of the catalogue", func(t *testing.T) {
		for _, op := range audittest.Operations("dashboard") {
			switch op {
			case "endWave":
				// TestAuditMatrixEndWave: it needs a gateway under a wave.
			case "setAgentAPI":
				// TestAuditMatrixAgentAPISwitch: it needs real listeners.
			default:
				if !m.covered[op] {
					t.Errorf("operation %s of the catalogue was not called", op)
				}
			}
		}
	})

	t.Run("no secret", func(t *testing.T) {
		moved(h)
		all := (&audittest.Log{T: t, Get: m.log.Get}).All("")
		for _, e := range all {
			audittest.Check(t, e)
		}
		m.marks.Check(t, all, rawAudit(t, h))
	})
}

// sessionCookie is the session token the client of the harness holds.
func sessionCookie(t testing.TB, h *apptest.Harness) string {
	t.Helper()
	req, _ := http.NewRequest("GET", h.Dash.URL+"/api/v0/overview", nil)
	for _, c := range h.Client.Jar.Cookies(req.URL) {
		if c.Name == "schild_session" && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("the client holds no session cookie")
	return ""
}

// client is a second browser at the dashboard.
type client struct {
	h    *apptest.Harness
	c    *http.Client
	csrf string
}

func newClient(t testing.TB, h *apptest.Harness) *client {
	jar, _ := cookiejar.New(nil)
	return &client{h: h, c: &http.Client{Jar: jar}}
}

func (c *client) api(method, path string, body any) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, c.h.Dash.URL+"/api/v0"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != "GET" && c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.h.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (c *client) login(t testing.TB, password string) {
	t.Helper()
	code, b := c.api("POST", "/auth/login", map[string]string{"password": password})
	if code != 200 {
		t.Fatalf("login: %d %s", code, b)
	}
	var s dashboard.Session
	_ = json.Unmarshal(b, &s)
	c.csrf = s.CSRFToken
}

func (c *client) cookie(t testing.TB) string {
	t.Helper()
	req, _ := http.NewRequest("GET", c.h.Dash.URL+"/api/v0/overview", nil)
	for _, ck := range c.c.Jar.Cookies(req.URL) {
		if ck.Name == "schild_session" && ck.Value != "" {
			return ck.Value
		}
	}
	t.Fatal("the client holds no session cookie")
	return ""
}

// TestAuditMatrixEndWave: the response to a wave that an operator ends
// early writes wave.end with the wave as its subject.
func TestAuditMatrixEndWave(t *testing.T) {
	h := apptest.New(t, apptest.Options{Mode: "review", Extra: distYAML})
	h.Login()
	log := dashLog(t, h)
	log.Fresh()
	if err := h.App.SetInstalledAt(context.Background(), time.Now().Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	h.App.Behaviour.LearnCookies("shop.example", []string{"wordpress_test_cookie"})
	for i := 0; i < 400; i++ {
		post(t, h, fmt.Sprintf("198.18.%d.%d", i/250, i%250+1), stuffUAs[i%len(stuffUAs)], "", "text/html")
	}
	h.Flush()
	page := decode[dashboard.WavePage](t, expect(t, h, "GET", "/distributed/waves", nil, 200, ""))
	log.None(t, "a wave and its response (no call of the dashboard)")
	ended := 0
	for _, w := range page.Items {
		if !w.Active {
			continue
		}
		expect(t, h, "POST", "/distributed/waves/"+w.ID+"/end", nil, 200, "")
		got := log.Expect(t, want{Action: "wave.end", Operation: "dashboard:endWave", Subject: w.ID, Website: "*", Fields: map[string]field{
			"/state": {Change: "changed", Before: "active", After: "ended"},
		}})
		if got[0] != nil {
			audittest.CheckDashboardActor(t, got[0], "admin", "", loopback)
			if strings.Contains(audittest.JSON(got[0]), "198.18.") {
				t.Errorf("wave.end names an address: %s", audittest.JSON(got[0]))
			}
		}
		expect(t, h, "POST", "/distributed/waves/"+w.ID+"/end", nil, 409, "")
		log.None(t, "endWave of a response that ended")
		ended++
	}
	if ended == 0 {
		t.Fatalf("no active wave to end: %+v", page.Items)
	}
}

// TestAuditMatrixAgentAPISwitch: the switch of the agent API in the
// dashboard writes agent_api.set, and none when it is set to what it is.
func TestAuditMatrixAgentAPISwitch(t *testing.T) {
	h := apptest.New(t, apptest.Options{Listeners: true})
	h.Login()
	log := dashLog(t, h)
	log.Fresh()
	set := func(body map[string]any, w want) {
		t.Helper()
		if code, b := h.API("PUT", "/agent-api", body); code != 200 {
			t.Fatalf("PUT /agent-api %v: %d %s", body, code, b)
		}
		w.Action, w.Operation, w.Subject = "agent_api.set", "dashboard:setAgentAPI", "*"
		for _, e := range log.Expect(t, w) {
			if e != nil {
				audittest.CheckDashboardActor(t, e, "admin", "", loopback)
			}
		}
	}
	set(map[string]any{"enabled": false}, want{Fields: map[string]field{
		"/enabled": {Change: "changed", Before: true, After: false},
		"/source":  {Change: "changed", Before: "config", After: "dashboard"},
	}})
	if code, b := h.API("PUT", "/agent-api", map[string]any{"enabled": false}); code != 200 {
		t.Fatalf("second switch off: %d %s", code, b)
	}
	log.None(t, "setAgentAPI off while it is off")
	set(map[string]any{"enabled": true}, want{Fields: map[string]field{"/enabled": {Change: "changed", Before: false, After: true}}, Absent: []string{"/source"}})
	set(map[string]any{"reset": true}, want{Fields: map[string]field{"/source": {Change: "changed", Before: "dashboard", After: "config"}}, Absent: []string{"/enabled"}})
}

// ids are the ids of entries, as a set.
func ids(es []audittest.Entry) map[string]bool {
	out := map[string]bool{}
	for _, e := range es {
		out[audittest.Str(e, "id")] = true
	}
	return out
}

// sameIDs reports the entries that are in one list and not in the other.
func sameIDs(t testing.TB, what string, got, wantEntries []audittest.Entry) {
	t.Helper()
	g, w := ids(got), ids(wantEntries)
	for _, e := range wantEntries {
		if !g[audittest.Str(e, "id")] {
			t.Errorf("%s: the answer misses %s", what, audittest.JSON(e))
		}
	}
	for _, e := range got {
		if !w[audittest.Str(e, "id")] {
			t.Errorf("%s: the answer holds an entry that does not match: %s", what, audittest.JSON(e))
		}
	}
}

// refusedEntries are the refused calls of an action in the log.
func refusedEntries(l *audittest.Log, action string) []audittest.Entry {
	var out []audittest.Entry
	for _, e := range l.All("class=refused") {
		if audittest.Str(e, "action") == action {
			out = append(out, e)
		}
	}
	return out
}

// TestAuditSignIn: a sign-in writes session.start with the id of its
// session, what the session does carries that id, a sign-out writes
// session.end. Failed sign-ins from one address are one refused entry with
// their count and without what was typed as the user name.
func TestAuditSignIn(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	var marks audittest.Markers
	// A wrong setup code before the first password: what was typed is in no
	// entry.
	if code, b := h.API("POST", "/auth/setup", map[string]string{"password": marks.Secret("setup.password"), "setup_code": marks.Secret("setup.setup_code")}); code != 403 {
		t.Fatalf("setup with a wrong code: %d %s", code, b)
	}
	marks.SecretValue("the setup code", h.App.SetupCode())
	h.Login()
	log := dashLog(t, h)
	first := log.Expect(t,
		want{Action: "password.setup", Operation: "dashboard:setupPassword"},
		want{Action: "session.start", Operation: "dashboard:setupPassword"})
	if first[1] == nil {
		t.Fatal("no session.start of the first sign-in")
	}
	s1 := audittest.Str(first[1], "actor", "session")
	if !audittest.SessionRE().MatchString(s1) {
		t.Fatalf("session id %q", s1)
	}
	expect(t, h, "POST", "/allowlist", map[string]any{"ip": "203.0.113.71", "label": "first", "level": "no_block", "ttl": "24h"}, 201, "")

	c := newClient(t, h)
	c.login(t, h.Password)
	if code, b := c.api("POST", "/allowlist", map[string]any{"ip": "203.0.113.72", "label": "second", "level": "no_block", "ttl": "24h"}); code != 201 {
		t.Fatalf("second session: %d %s", code, b)
	}
	if code, b := c.api("POST", "/auth/logout", nil); code != 204 {
		t.Fatalf("logout: %d %s", code, b)
	}
	if code, _ := c.api("GET", "/overview", nil); code != 401 {
		t.Fatalf("the session still reads after its sign-out: %d", code)
	}
	all := log.All("")
	var s2 string
	for _, e := range all {
		if audittest.Str(e, "operation") == "dashboard:login" && audittest.Str(e, "action") == "session.start" {
			s2 = audittest.Str(e, "actor", "session")
		}
	}
	if !audittest.SessionRE().MatchString(s2) || s2 == s1 {
		t.Fatalf("session of the second sign-in %q, of the first %q", s2, s1)
	}
	actions := func(session string) string {
		var out []string
		es := log.All("session=" + session)
		for i := len(es) - 1; i >= 0; i-- {
			if got := audittest.Str(es[i], "actor", "session"); got != session {
				t.Errorf("filter session=%s returns an entry of session %q: %s", session, got, audittest.JSON(es[i]))
			}
			out = append(out, audittest.Str(es[i], "action"))
		}
		return strings.Join(out, " ")
	}
	// The order within one second is the order of writing for the entries
	// of one letter; a sign-in is of another letter than a change, so the
	// actions are compared as a set.
	set := func(s string) string {
		f := strings.Fields(s)
		m := map[string]int{}
		for _, a := range f {
			m[a]++
		}
		return fmt.Sprint(m)
	}
	if got := actions(s1); set(got) != set("password.setup session.start allowlist.add") {
		t.Errorf("what the first session did: %q", got)
	}
	if got := actions(s2); set(got) != set("session.start allowlist.add session.end") {
		t.Errorf("what the second session did: %q", got)
	}

	// A password change with a wrong current password.
	if code, b := h.API("POST", "/auth/password", map[string]string{"current_password": marks.Secret("password.current_password"), "new_password": marks.Secret("password.new_password")}); code != 401 {
		t.Fatalf("password change with a wrong password: %d %s", code, b)
	}
	// Five failed sign-ins from one address.
	log.Fresh()
	bad := newClient(t, h)
	minute := time.Now().UTC().Truncate(time.Minute)
	for i := 0; i < 5; i++ {
		body := map[string]string{"password": marks.Secret("login.password")}
		if i%2 == 1 {
			body["user"] = marks.Secret("login.user")
		}
		// The wrong setup code above took one of the five attempts of this
		// address: the last sign-in is refused for the number of attempts,
		// and is counted like the others.
		if code, b := bad.api("POST", "/auth/login", body); code != 401 && !(i == 4 && code == 429) {
			t.Fatalf("failed sign-in %d: %d %s", i, code, b)
		}
	}
	oneMinute := time.Now().UTC().Truncate(time.Minute).Equal(minute)
	log.None(t, "a failed sign-in (as an entry that is done)")
	// The entry is written with its first call; the count follows every
	// 10 s and when the gateway stops. Wait for the entry, stop the gateway,
	// start it on the same data.
	h.WaitFor("the first write of the refused entries", func() bool {
		return len(refusedEntries(log, "session.start")) > 0 && len(refusedEntries(log, "password.setup")) > 0 && len(refusedEntries(log, "password.change")) > 0
	})
	dir := h.Dir
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	h2 := apptest.New(t, apptest.Options{Dir: dir})
	h2.Login()
	log2 := dashLog(t, h2)
	refused := refusedEntries(log2, "session.start")
	total := 0.0
	for _, e := range refused {
		audittest.Check(t, e)
		n, _ := e["count"].(float64)
		total += n
		if audittest.Str(e, "result") != "refused" || audittest.Str(e, "operation") != "dashboard:login" || audittest.Str(e, "address") != loopback {
			t.Errorf("a failed sign-in reads: %s", audittest.JSON(e))
		}
		if a, _ := e["actor"].(map[string]any); len(a) != 1 || a["kind"] != "dashboard" {
			t.Errorf("a failed sign-in names more than the way as its actor: %s", audittest.JSON(e["actor"]))
		}
		if id := audittest.Str(e, "subject", "id"); id != "" {
			t.Errorf("a failed sign-in names a subject %q: what was typed as the user may be a password", id)
		}
	}
	if total != 5 {
		t.Errorf("5 failed sign-ins are counted as %v in %d entries: %s", total, len(refused), audittest.JSON(refused))
	}
	if oneMinute && len(refused) != 1 {
		t.Errorf("5 failed sign-ins of one address in one minute are %d entries, want 1", len(refused))
	}
	for action, operation := range map[string]string{"password.setup": "dashboard:setupPassword", "password.change": "dashboard:changePassword"} {
		es := refusedEntries(log2, action)
		if len(es) != 1 {
			t.Errorf("one refused %s is %d entries: %s", action, len(es), audittest.JSON(es))
			continue
		}
		audittest.Check(t, es[0])
		if n, _ := es[0]["count"].(float64); n != 1 || audittest.Str(es[0], "operation") != operation || audittest.Str(es[0], "address") != loopback {
			t.Errorf("a refused %s reads: %s", action, audittest.JSON(es[0]))
		}
		if a, _ := es[0]["actor"].(map[string]any); len(a) != 1 || a["kind"] != "dashboard" {
			t.Errorf("a refused %s names more than the way as its actor: %s", action, audittest.JSON(es[0]["actor"]))
		}
	}
	moved(h2)
	everything := (&audittest.Log{T: t, Get: log2.Get}).All("")
	marks.Check(t, everything, rawAudit(t, h2))
	// The sign-ins of before the restart are still there.
	for _, e := range all {
		if !ids(everything)[audittest.Str(e, "id")] {
			t.Errorf("an entry is gone after the restart: %s", audittest.JSON(e))
		}
	}
}

// agentCall sends one call to the agent API of the harness with a token.
func agentCall(h *apptest.Harness, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = agentListen
	r.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.App.AgentAPI.Handler(agentListen).ServeHTTP(w, r)
	return w
}

// agentToken makes a token of a scope, as `schild token add`.
func agentToken(t testing.TB, h *apptest.Harness, scope, label string) string {
	t.Helper()
	tok := contractapi.NewToken()
	now := time.Now().UTC()
	if err := h.App.Store.AddAgentToken(context.Background(), store.AgentToken{ID: contractapi.TokenID(tok), Hash: contractapi.HashToken(tok), Scope: scope,
		Label: label, Created: now, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestAuditFiltersAndPaging: every filter of GET /audit returns exactly the
// entries it names, the pages of a small limit hold every entry once, and a
// filter or cursor that is not valid is 400.
func TestAuditFiltersAndPaging(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: "agent_api:\n  enabled: true\n"})
	oneSite(h)
	h.Login()
	log := &audittest.Log{T: t, Get: func(q string) (int, []byte) { return h.API("GET", "/audit?"+q, nil) }}
	site := "/websites/" + auditSite
	expect(t, h, "PUT", site+"/crawlers", map[string]any{"categories": map[string]string{"ai_training": "block"}}, 200, "")
	expect(t, h, "PUT", site+"/maintenance", map[string]any{"on": true}, 200, "")
	var block struct {
		Incident string `json:"incident"`
	}
	_ = json.Unmarshal(expect(t, h, "POST", "/blocks", map[string]any{"address": "203.0.113.57", "duration_s": 3600, "reason": "filter test"}, 200, ""), &block)
	h.Flush()
	expect(t, h, "POST", "/incidents/"+block.Incident+"/unblock", map[string]any{"allow_ip": true}, 200, "")
	tok := agentToken(t, h, contractapi.ScopeRulesWrite, "Filter agent")
	if w := agentCall(h, "PATCH", "/agent/v0/rules/crs/941100", tok, `{"disabled":true,"note":"filter test"}`); w.Code != 200 {
		t.Fatalf("agent write: %d %s", w.Code, w.Body)
	}
	if w := agentCall(h, "GET", "/agent/v0/status", contractapi.NewToken(), ""); w.Code != 401 {
		t.Fatalf("unknown token: %d", w.Code)
	}
	// Entries of two different seconds, for from and to.
	time.Sleep(1100 * time.Millisecond)
	c := newClient(t, h)
	c.login(t, h.Password)
	expect(t, h, "POST", "/privacy/export", map[string]any{"ip": "203.0.113.57"}, 200, "")
	expect(t, h, "PATCH", "/rules/crs/942100", map[string]any{"disabled": true}, 200, "")
	expect(t, h, "PUT", site+"/maintenance", map[string]any{"on": false}, 200, "")
	h.WaitFor("the refused call of the unknown token", func() bool { return len(refusedEntries(log, "agent_api.call")) == 1 })

	all := log.All("")
	if len(all) < 12 {
		t.Fatalf("only %d entries: %s", len(all), audittest.JSON(all))
	}
	for i := 1; i < len(all); i++ {
		if audittest.Str(all[i-1], "time") < audittest.Str(all[i], "time") {
			t.Errorf("the list is not newest first: %s before %s", audittest.Str(all[i-1], "time"), audittest.Str(all[i], "time"))
		}
	}
	pick := func(match func(e audittest.Entry) bool) []audittest.Entry {
		var out []audittest.Entry
		for _, e := range all {
			if match(e) {
				out = append(out, e)
			}
		}
		return out
	}
	str := audittest.Str
	session := str(pick(func(e audittest.Entry) bool { return str(e, "operation") == "dashboard:setupPassword" })[0], "actor", "session")
	tokID := contractapi.TokenID(tok)
	times := map[string]bool{}
	for _, e := range all {
		times[str(e, "time")] = true
	}
	oldest, newest := str(all[len(all)-1], "time"), str(all[0], "time")
	if oldest == newest {
		t.Fatalf("every entry has the time %s: from and to cannot be told apart", oldest)
	}
	after := func(ts string, d time.Duration) string {
		x, _ := time.Parse("2006-01-02T15:04:05Z", ts)
		return x.Add(d).Format("2006-01-02T15:04:05Z")
	}
	filters := []struct {
		query string
		match func(e audittest.Entry) bool
	}{
		{"website=" + auditSite, func(e audittest.Entry) bool { return str(e, "website") == auditSite }},
		{"website=other.example", func(e audittest.Entry) bool { return false }},
		{"class=change", func(e audittest.Entry) bool { return str(e, "class") == "change" }},
		{"class=credential", func(e audittest.Entry) bool { return str(e, "class") == "credential" }},
		{"class=privacy", func(e audittest.Entry) bool { return str(e, "class") == "privacy" }},
		{"class=access", func(e audittest.Entry) bool { return str(e, "class") == "access" }},
		{"class=refused", func(e audittest.Entry) bool { return str(e, "class") == "refused" }},
		{"action=maintenance.set", func(e audittest.Entry) bool { return str(e, "action") == "maintenance.set" }},
		{"action=rule.set", func(e audittest.Entry) bool { return str(e, "action") == "rule.set" }},
		{"way=dashboard", func(e audittest.Entry) bool { return strings.HasPrefix(str(e, "operation"), "dashboard:") }},
		{"way=agent", func(e audittest.Entry) bool { return strings.HasPrefix(str(e, "operation"), "agent:") }},
		{"way=config", func(e audittest.Entry) bool { return strings.HasPrefix(str(e, "operation"), "config:") }},
		{"way=system", func(e audittest.Entry) bool { return strings.HasPrefix(str(e, "operation"), "system:") }},
		{"way=cli", func(e audittest.Entry) bool { return false }},
		{"actor=" + tokID, func(e audittest.Entry) bool { return str(e, "actor", "id") == tokID }},
		{"subject=rule&subject_id=crs/941100", func(e audittest.Entry) bool {
			return str(e, "subject", "kind") == "rule" && str(e, "subject", "id") == "crs/941100"
		}},
		{"subject=rule", func(e audittest.Entry) bool { return str(e, "subject", "kind") == "rule" }},
		{"subject=website&subject_id=" + auditSite, func(e audittest.Entry) bool {
			return str(e, "subject", "kind") == "website" && str(e, "subject", "id") == auditSite
		}},
		{"session=" + session, func(e audittest.Entry) bool { return str(e, "actor", "session") == session }},
		{"incident=" + block.Incident, func(e audittest.Entry) bool {
			return str(e, "cause", "incident") == block.Incident || str(e, "subject", "kind") == "block" && str(e, "subject", "id") == block.Incident
		}},
		{"from=" + newest, func(e audittest.Entry) bool { return str(e, "time") >= newest }},
		{"to=" + newest, func(e audittest.Entry) bool { return str(e, "time") < newest }},
		{"from=" + oldest + "&to=" + after(oldest, time.Second), func(e audittest.Entry) bool { return str(e, "time") == oldest }},
		{"from=" + after(newest, time.Second), func(e audittest.Entry) bool { return false }},
		{"way=dashboard&class=change&website=" + auditSite, func(e audittest.Entry) bool {
			return strings.HasPrefix(str(e, "operation"), "dashboard:") && str(e, "class") == "change" && str(e, "website") == auditSite
		}},
	}
	nonEmpty := map[string]bool{"website=other.example": true, "way=cli": true, "from=" + after(newest, time.Second): true}
	for _, f := range filters {
		wantEntries := pick(f.match)
		if len(wantEntries) == 0 && !nonEmpty[f.query] {
			t.Errorf("?%s: the test made no entry for this filter", f.query)
		}
		sameIDs(t, "?"+f.query, log.All(f.query), wantEntries)
		// The same through pages of two.
		var paged []audittest.Entry
		for _, p := range log.Pages(f.query, 2) {
			paged = append(paged, p...)
		}
		sameIDs(t, "?"+f.query+" in pages of 2", paged, wantEntries)
	}
	// Every entry is on exactly one page, in the order of the whole list.
	for _, limit := range []int{1, 3, 7} {
		var paged []audittest.Entry
		for _, p := range log.Pages("", limit) {
			paged = append(paged, p...)
		}
		if len(paged) != len(all) {
			t.Errorf("limit %d: %d entries on the pages, %d in the log", limit, len(paged), len(all))
			continue
		}
		for i := range all {
			if str(paged[i], "id") != str(all[i], "id") {
				t.Errorf("limit %d: place %d holds %s, the whole list %s", limit, i, str(paged[i], "id"), str(all[i], "id"))
				break
			}
		}
	}
	for _, bad := range []string{"class=secret", "way=browser", "action=Allowlist.Add", "action=x", "actor=admin", "actor=tok_123", "subject=Rule", "session=zzzzzzzz",
		"session=abc", "event=1234", "incident=abcd-efgh", "incident=1", "from=yesterday", "to=2026-13-01T00:00:00Z", "limit=0", "limit=100000", "limit=x",
		"cursor=x", "cursor=" + strings.Repeat("a", 65), "website=" + strings.Repeat("a", 254), "website=A%20B", "subject_id=" + strings.Repeat("a", 254)} {
		if code, b := h.API("GET", "/audit?"+bad, nil); code != 400 {
			t.Errorf("GET /audit?%s: %d, want 400: %.200s", bad, code, b)
		}
	}
	// No call changes or removes an entry.
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		for _, path := range []string{"/audit", "/audit/" + str(all[0], "id")} {
			if code, _ := h.API(method, path, map[string]any{}); code < 400 {
				t.Errorf("%s %s answers %d: the log is append only", method, path, code)
			}
		}
	}
	sameIDs(t, "the log after the calls that try to change it", log.All(""), all)
}

// TestAuditSurvival: an entry is still there, as it was written, after the
// gateway stopped and started on the same data, and after the size cap of
// schild.db ran over many events.
func TestAuditSurvival(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	oneSite(h)
	h.Login()
	ctx := context.Background()
	expect(t, h, "PUT", "/websites/"+auditSite+"/maintenance", map[string]any{"on": true, "message": "Gleich wieder da."}, 200, "")
	expect(t, h, "POST", "/allowlist", map[string]any{"ip": "203.0.113.80", "label": "Büro", "level": "no_block", "ttl": "never"}, 201, "")
	expect(t, h, "PUT", "/websites/"+auditSite+"/maintenance", map[string]any{"on": false}, 200, "")
	log := &audittest.Log{T: t, Get: func(q string) (int, []byte) { return h.API("GET", "/audit?"+q, nil) }}
	before := log.All("")
	if len(before) < 5 {
		t.Fatalf("%d entries before", len(before))
	}
	moved(h)
	stored := storedBodies(t, h)

	// An entry that waits in the outbox when the cap runs: the cap counts
	// it and does not delete it.
	id, err := h.App.Store.NextAuditID(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	var waiting string
	for _, e := range before {
		if audittest.Str(e, "action") == "allowlist.add" {
			old := audittest.Str(e, "id")
			waiting = strings.Replace(stored[old], `"`+old+`"`, `"`+id+`"`, 1)
		}
	}
	if waiting == "" {
		t.Fatal("no entry to copy")
	}
	if err := h.App.Store.PutAudit(ctx, store.AuditRow{ID: id, TimeMS: time.Now().UnixMilli(), Class: "change", Body: []byte(waiting)}); err != nil {
		t.Fatal(err)
	}

	// Many events, then the size cap with the smallest cap there is.
	for i := 0; i < 300; i++ {
		h.Visit("GET", xssPath+strings.Repeat("x", 600), fmt.Sprintf("198.51.%d.%d", 100, i%250+1), "", "")
	}
	h.Flush()
	events := func() int {
		rows, _, err := h.App.Store.ListEvents(ctx, store.EventFilter{}, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	had := events()
	res, err := h.App.Store.SizeCap(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total() == 0 || events() >= had {
		t.Fatalf("the size cap deleted nothing (%d events before, %d after, %+v): the test does not show what it should", had, events(), res)
	}
	h.App.Retention(ctx)
	check := func(what string, l *audittest.Log, hh *apptest.Harness) {
		t.Helper()
		after := l.All("")
		have := ids(after)
		for _, e := range before {
			if !have[audittest.Str(e, "id")] {
				t.Errorf("%s: an entry is gone: %s", what, audittest.JSON(e))
			}
		}
		if !have[id] {
			t.Errorf("%s: the entry that waited in the outbox (%s) is gone", what, id)
		}
		byID := map[string]audittest.Entry{}
		for _, e := range after {
			byID[audittest.Str(e, "id")] = e
		}
		for _, e := range before {
			if got := byID[audittest.Str(e, "id")]; got != nil && audittest.JSON(got) != audittest.JSON(e) {
				t.Errorf("%s: an entry reads another way: %s, was %s", what, audittest.JSON(got), audittest.JSON(e))
			}
		}
		moved(hh)
		now := storedBodies(t, hh)
		for k, v := range stored {
			if now[k] != v {
				t.Errorf("%s: the stored bytes of %s changed: %q, was %q", what, k, now[k], v)
			}
		}
	}
	check("after the size cap", log, h)

	dir := h.Dir
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	h2 := apptest.New(t, apptest.Options{Dir: dir})
	h2.Login()
	check("after the restart", &audittest.Log{T: t, Get: func(q string) (int, []byte) { return h2.API("GET", "/audit?"+q, nil) }}, h2)
	// The log goes on with the next number: no id is drawn twice.
	expect(t, h2, "POST", "/allowlist", map[string]any{"ip": "203.0.113.81", "label": "danach", "level": "no_block", "ttl": "never"}, 201, "")
	(&audittest.Log{T: t, Get: func(q string) (int, []byte) { return h2.API("GET", "/audit?"+q, nil) }}).Pages("", 200)
}

// TestAuditPrivacy: an erasure by address leaves every stored entry byte
// for byte as it was and writes privacy.erase with numbers and without the
// address; an export by address lists the entries that name it and writes
// privacy.export.
func TestAuditPrivacy(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	oneSite(h)
	h.Login()
	const ip, other = "203.0.113.57", "203.0.113.58"
	log := &audittest.Log{T: t, Get: func(q string) (int, []byte) { return h.API("GET", "/audit?"+q, nil) }}

	// The address in entries: an own IP that was set and removed, a block,
	// an access lock that lets it in. Another address next to it.
	var own dashboard.AllowlistEntry
	_ = json.Unmarshal(expect(t, h, "POST", "/allowlist", map[string]any{"ip": ip, "label": "Kundin", "level": "no_block", "ttl": "24h"}, 201, ""), &own)
	expect(t, h, "DELETE", "/allowlist/"+own.ID, nil, 204, "")
	_ = json.Unmarshal(expect(t, h, "POST", "/allowlist", map[string]any{"ip": other, "label": "Büro", "level": "no_block", "ttl": "24h"}, 201, ""), &own)
	expect(t, h, "DELETE", "/allowlist/"+own.ID, nil, 204, "")
	if r := h.Visit("GET", xssPath, ip, "", ""); r.StatusCode != 403 {
		t.Fatalf("the WAF did not stop the probe: %d", r.StatusCode)
	}
	expect(t, h, "POST", "/blocks", map[string]any{"address": ip, "duration_s": 3600, "reason": "privacy test"}, 200, "")
	expect(t, h, "POST", "/blocks", map[string]any{"address": other, "duration_s": 3600, "reason": "privacy test"}, 200, "")
	h.Flush()
	expect(t, h, "PUT", "/websites/"+auditSite+"/access", map[string]any{"scope": "site", "addresses": []string{ip, "198.51.100.0/24"}, "own_networks": false}, 200, "")

	before := log.All("")
	naming := func(es []audittest.Entry, addr string) []audittest.Entry {
		var out []audittest.Entry
		for _, e := range es {
			// The address of the call is the operator's (loopback here);
			// the entries that name the address hold it as a value.
			if strings.Contains(audittest.JSON(e), `"`+addr+`"`) {
				out = append(out, e)
			}
		}
		return out
	}
	named := naming(before, ip)
	if len(named) != 4 {
		t.Fatalf("%d entries name %s, the test made 4: %s", len(named), ip, audittest.JSON(named))
	}

	// The export lists the entries that name the address, and no other.
	var export struct {
		Audit []audittest.Entry `json:"audit"`
	}
	raw := expect(t, h, "POST", "/privacy/export", map[string]any{"ip": ip}, 200, "")
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	sameIDs(t, "the audit entries of privacy/export", export.Audit, named)
	byID := map[string]audittest.Entry{}
	for _, e := range before {
		byID[audittest.Str(e, "id")] = e
	}
	for _, e := range export.Audit {
		if was := byID[audittest.Str(e, "id")]; was != nil && audittest.JSON(was) != audittest.JSON(e) {
			t.Errorf("privacy/export shows an entry another way than the log: %s, log %s", audittest.JSON(e), audittest.JSON(was))
		}
	}
	dash := dashLog(t, h)
	dash.Fresh()
	// The export is read first so its entry is the only new one below.
	expect(t, h, "POST", "/privacy/export", map[string]any{"ip": ip}, 200, "")
	exp := dash.Expect(t, want{Action: "privacy.export", Operation: "dashboard:privacyExport", Fields: map[string]field{
		"/events": {Change: "added", After: audittest.Any}, "/requests": {Change: "added", After: audittest.Any}}})
	if exp[0] != nil {
		audittest.CheckDashboardActor(t, exp[0], "admin", "", loopback)
		if strings.Contains(audittest.JSON(exp[0]), ip) {
			t.Errorf("privacy.export holds the address: %s", audittest.JSON(exp[0]))
		}
	}

	moved(h)
	stored := storedBodies(t, h)
	if _, ok := h.App.Behaviour.ActiveBlock(netip.MustParseAddr(ip)); !ok {
		t.Fatalf("no block of %s runs before the erasure: the test does not show what it should", ip)
	}
	var res dashboard.PrivacyDeleteResult
	_ = json.Unmarshal(expect(t, h, "POST", "/privacy/delete", map[string]any{"ip": ip, "confirm": true}, 200, ""), &res)
	if res.DeletedEvents == 0 {
		t.Fatalf("the erasure deleted no event: the test does not show what it should")
	}
	if _, ok := h.App.Behaviour.ActiveBlock(netip.MustParseAddr(ip)); ok {
		t.Errorf("the block of %s still runs after the erasure", ip)
	}
	// The erasure ended the one block of the address: /blocks names it
	// (contracts/audit.md section 2), there is no block.lift.
	erase := dash.Expect(t, want{Action: "privacy.erase", Operation: "dashboard:privacyDelete", Fields: map[string]field{
		"/events":         {Change: "added", After: res.DeletedEvents},
		"/incidents":      {Change: "added", After: audittest.Any},
		"/requests":       {Change: "added", After: audittest.Any},
		"/blocks":         {Change: "added", After: 1},
		"/keep_incidents": {Change: "added", After: false},
	}})
	if erase[0] != nil {
		audittest.CheckDashboardActor(t, erase[0], "admin", "", loopback)
		if strings.Contains(audittest.JSON(erase[0]), ip) || audittest.Str(erase[0], "subject", "id") != "" {
			t.Errorf("privacy.erase holds the address or a subject: %s", audittest.JSON(erase[0]))
		}
	}
	moved(h)
	now := storedBodies(t, h)
	for id, body := range stored {
		if now[id] != body {
			t.Errorf("the erasure changed the stored entry %s: %q, was %q", id, now[id], body)
		}
	}
	for id := range now {
		if _, ok := stored[id]; !ok && (erase[0] == nil || id != audittest.Str(erase[0], "id")) {
			t.Errorf("the erasure wrote another entry than privacy.erase: %s", now[id])
		}
	}
	// The entries that name the address are still listed, by the log and by
	// an export after the erasure.
	sameIDs(t, "the entries that name the address after its erasure", naming(log.All(""), ip), named)
	export.Audit = nil
	_ = json.Unmarshal(expect(t, h, "POST", "/privacy/export", map[string]any{"ip": ip}, 200, ""), &export)
	sameIDs(t, "the audit entries of privacy/export after the erasure", export.Audit, named)
}

// TestAuditPrivacyOwnIP: an erasure by address also removes the own IPs of
// that address. The address is then no longer let through, which is a
// change of the protection: the log must say that it happened.
func TestAuditPrivacyOwnIP(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	const ip = "203.0.113.90"
	var own dashboard.AllowlistEntry
	_ = json.Unmarshal(expect(t, h, "POST", "/allowlist", map[string]any{"ip": ip, "label": "Kundin", "level": "no_block", "ttl": "never"}, 201, ""), &own)
	log := dashLog(t, h)
	log.Fresh()
	var res dashboard.PrivacyDeleteResult
	_ = json.Unmarshal(expect(t, h, "POST", "/privacy/delete", map[string]any{"ip": ip, "confirm": true}, 200, ""), &res)
	if res.DeletedAllowlistEntries != 1 {
		t.Fatalf("the erasure removed %d own IPs, want 1", res.DeletedAllowlistEntries)
	}
	told := false
	for _, e := range log.Fresh() {
		if audittest.Str(e, "action") == "allowlist.remove" && audittest.Str(e, "subject", "id") == own.ID {
			told = true
		}
		if audittest.Str(e, "action") == "privacy.erase" {
			for _, f := range audittest.Fields(e) {
				if n, _ := f["after"].(float64); n == 1 && strings.Contains(audittest.Str(f, "field"), "allow") {
					told = true
				}
			}
			if !told {
				t.Logf("privacy.erase: %s", audittest.JSON(e))
			}
		}
	}
	if !told {
		t.Errorf("the erasure removed own IP %s and no entry says so: neither allowlist.remove nor a number in privacy.erase", own.ID)
	}
}

// TestAuditPrivacyExportIsWhole: the export by address lists every audit
// entry that names the address, also when there are many, or says that its
// list is cut.
func TestAuditPrivacyExportIsWhole(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	const ip = "203.0.113.91"
	const pairs = 260 // two entries each: more than one page of the log
	for i := 0; i < pairs; i++ {
		var own dashboard.AllowlistEntry
		_ = json.Unmarshal(expect(t, h, "POST", "/allowlist", map[string]any{"ip": ip, "label": fmt.Sprint("n", i), "level": "no_block", "ttl": "24h"}, 201, ""), &own)
		expect(t, h, "DELETE", "/allowlist/"+own.ID, nil, 204, "")
	}
	raw := expect(t, h, "POST", "/privacy/export", map[string]any{"ip": ip}, 200, "")
	var export map[string]json.RawMessage
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	var entries []audittest.Entry
	_ = json.Unmarshal(export["audit"], &entries)
	cut := false
	for k := range export {
		cut = cut || strings.Contains(k, "truncated") || strings.Contains(k, "more") || strings.Contains(k, "cut")
	}
	if len(entries) != 2*pairs && !cut {
		t.Errorf("%d entries name %s, the export lists %d and does not say that it is cut (fields %v)", 2*pairs, ip, len(entries), keysOf(export))
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
