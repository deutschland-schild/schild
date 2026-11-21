//go:build !release

package dashboard_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/hostagent"
	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
	"github.com/deutschland-schild/schild/gateway/internal/hosts"
)

const canaryHost = "canary-7f3a9.example"

// TestServerSection: the v0.3 dashboard operations against a running
// schild with host_check, a real enrolment over the pinned TLS listener and
// an agent delivery.
func TestServerSection(t *testing.T) {
	reports := t.TempDir()
	if keys.Release {
		t.Skip("app servers with schild-agent need the test switch " + app.HostAgentsEnv + ", which release builds ignore (D77)")
	}
	t.Setenv(app.HostAgentsEnv, "1") // agents are not part of the first version (D60b)
	h := apptest.New(t, apptest.Options{Extra: "host_check:\n  report_dir: " + reports + "\n  agents:\n    enabled: true\n    listen: \"0.0.0.0:8790\"\n"})
	if h.App.Hosts == nil {
		t.Fatal("hosts not set up")
	}
	h.Login()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// Local report written by `schild check` into the read-only directory.
	lr := hostcheck.Run(ctx, &hostcheck.FixtureEnv{Dir: "../hostcheck/testdata/hosts/debian12", Time: now}, hostcheck.Options{Role: hc.RoleGateway})
	lb, err := hostcheck.Marshal(lr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostcheck.WriteReport(reports, lr, lb, 30); err != nil {
		t.Fatal(err)
	}
	if err := h.App.Hosts.ScanLocal(ctx); err != nil {
		t.Fatal(err)
	}
	hp := decode[hosts.HostPage](t, expect(t, h, "GET", "/hosts", nil, 200, "HostPage"))
	if len(hp.Items) != 1 || hp.Items[0].ID != "local" || hp.Items[0].Status != "findings" {
		t.Fatalf("%+v", hp)
	}
	expect(t, h, "GET", "/hosts/local", nil, 200, "HostDetail")
	expect(t, h, "GET", "/hosts/nope", nil, 404, "Problem")
	expect(t, h, "GET", "/hosts?status=bogus", nil, 400, "Problem")
	expect(t, h, "POST", "/hosts/local/check", nil, 503, "Problem")

	// Enrolment code: needs the password again.
	en := decode[hosts.Enrolment](t, expect(t, h, "POST", "/agents/enrolments", map[string]any{"label": "Datenbank"}, 201, "Enrolment"))

	if en.GatewayName != "test-node" || !strings.Contains(en.Command, "--gateway-name test-node ") {
		t.Fatalf("enrolment without the gateway name: %+v", en)
	}

	// The agent on the app VM.
	srv := httptest.NewUnstartedServer(h.App.Hosts.Handler())
	lsrv, err := h.App.Hosts.Server()
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = lsrv.TLSConfig
	srv.StartTLS()
	defer srv.Close()
	agDir := filepath.Join(t.TempDir(), "agent")
	st, err := hostagent.Enrol(ctx, hostagent.EnrolOptions{Dir: agDir, GatewayURL: srv.URL, GatewayName: en.GatewayName, Pin: en.GatewayPin, Code: en.Code, Hostname: canaryHost})
	if err != nil {
		t.Fatal(err)
	}
	ap := decode[hosts.AgentPage](t, expect(t, h, "GET", "/agents?status=pending", nil, 200, "AgentPage"))
	if len(ap.Items) != 1 || ap.Items[0].Fingerprint != st.Fingerprint {
		t.Fatalf("%+v", ap)
	}
	id := ap.Items[0].ID
	p := decode[dashboard.Problem](t, expect(t, h, "POST", "/agents/"+id+"/confirm", map[string]any{"fingerprint": "sha256:" + strings.Repeat("a", 64)}, 409, "Problem"))
	if p.Code != "fingerprint_mismatch" {
		t.Fatal(p.Code)
	}
	ag := decode[hosts.Agent](t, expect(t, h, "POST", "/agents/"+id+"/confirm", map[string]any{"fingerprint": st.Fingerprint}, 200, "Agent"))
	if ag.Status != "enrolled" {
		t.Fatal(ag.Status)
	}
	a, err := hostagent.New(agDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Env = &hostcheck.FixtureEnv{Dir: "../hostcheck/testdata/hosts/rocky9", Time: now}
	rep, err := a.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ack, err := a.Deliver(ctx, rep); err != nil || ack.Status != "accepted" {
		t.Fatalf("%+v %v", ack, err)
	}
	hd := decode[hosts.HostDetail](t, expect(t, h, "GET", "/hosts/"+id, nil, 200, "HostDetail"))
	if hd.Host.Hostname != canaryHost || hd.Report == nil {
		t.Fatalf("%+v", hd.Host)
	}
	ov := decode[dashboard.Overview](t, expect(t, h, "GET", "/overview", nil, 200, "Overview"))
	if ov.Servers == nil || ov.Servers.Hosts != 2 || ov.Servers.Findings.High == 0 {
		t.Fatalf("%+v", ov.Servers)
	}

	// Revoke: password again.
	ag = decode[hosts.Agent](t, expect(t, h, "POST", "/agents/"+id+"/revoke", map[string]any{"note": "VM weg"}, 200, "Agent"))
	if ag.Status != "revoked" {
		t.Fatal(ag.Status)
	}
	expect(t, h, "POST", "/agents/"+id+"/revoke", map[string]any{}, 409, "Problem")
	expect(t, h, "GET", "/agents", nil, 200, "AgentPage")
	if ack, err := a.Deliver(ctx, rep); err == nil || ack.Error == nil || *ack.Error != "revoked" {
		t.Fatalf("after revoke: %+v %v", ack, err)
	}
}

// TestServerSectionBeforeTheFirstReport: host_check is in every starter
// config (D100), the check on the host may not be set up yet. The Server
// page lists this server without a report, so it can say how to set the
// check up; the overview shows no card that would read "keine offenen
// Befunde" for a check that never ran.
func TestServerSectionBeforeTheFirstReport(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: "host_check:\n  report_dir: " + filepath.Join(t.TempDir(), "missing") + "\n"})
	h.Login()
	hp := decode[hosts.HostPage](t, expect(t, h, "GET", "/hosts", nil, 200, "HostPage"))
	if len(hp.Items) != 1 || hp.Items[0].ID != "local" || hp.Items[0].LastReportAt != nil {
		t.Fatalf("%+v", hp)
	}
	if ov := decode[dashboard.Overview](t, expect(t, h, "GET", "/overview", nil, 200, "Overview")); ov.Servers != nil {
		t.Fatalf("server card before the first report: %+v", ov.Servers)
	}
	expect(t, h, "POST", "/hosts/local/check", nil, 503, "Problem")
}

// TestServerSectionOff: without host_check there is no Server card, the
// lists are empty (so the dashboard can explain the setup) and the other
// operations answer 404.
func TestServerSectionOff(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	h.Login()
	ov := decode[dashboard.Overview](t, expect(t, h, "GET", "/overview", nil, 200, "Overview"))
	if ov.Servers != nil || h.App.Hosts != nil {
		t.Fatal("server card without host_check")
	}
	if p := decode[hosts.HostPage](t, expect(t, h, "GET", "/hosts", nil, 200, "HostPage")); len(p.Items) != 0 || p.NextCursor != nil {
		t.Fatalf("hosts without host_check: %+v", p)
	}
	if p := decode[hosts.AgentPage](t, expect(t, h, "GET", "/agents", nil, 200, "AgentPage")); len(p.Items) != 0 {
		t.Fatalf("agents without host_check: %+v", p)
	}
	expect(t, h, "GET", "/hosts/local", nil, 404, "Problem")
	expect(t, h, "POST", "/agents/enrolments", map[string]any{}, 404, "Problem")
}

// TestAcceptedFindings (D102): an open finding is marked as accepted, no
// longer counts as open, stays listed, survives the next report, and is open
// again when it is reopened or comes back with a higher severity.
func TestAcceptedFindings(t *testing.T) {
	reports := t.TempDir()
	h := apptest.New(t, apptest.Options{Extra: "host_check:\n  report_dir: " + reports + "\n"})
	h.Login()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	write := func(at time.Time, change func(*hc.Report)) {
		t.Helper()
		r := hostcheck.Run(ctx, &hostcheck.FixtureEnv{Dir: "../hostcheck/testdata/hosts/debian12", Time: at}, hostcheck.Options{Role: hc.RoleGateway})
		if change != nil {
			change(r)
		}
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
	}
	write(now.Add(-2*time.Hour), nil)
	before := decode[hosts.HostDetail](t, expect(t, h, "GET", "/hosts/local", nil, 200, "HostDetail"))
	var rep hc.Report
	if err := json.Unmarshal(before.Report, &rep); err != nil {
		t.Fatal(err)
	}
	var f *hc.Finding
	for i := range rep.Findings {
		if x := &rep.Findings[i]; x.Status == "finding" && x.Severity == "medium" && f == nil {
			f = x
		}
	}
	if f == nil || len(before.Accepted) != 0 || before.Host.Accepted != 0 {
		t.Fatalf("fixture has no medium finding, or accepted before: %+v", before.Host)
	}
	ref := map[string]any{"id": f.ID}
	if f.Subject != "" {
		ref["subject"] = f.Subject
	}
	body := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range ref {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// Refused: unknown check, a finding that is not open, a note with a
	// line break, a note on reopen, nothing to reopen.
	expect(t, h, "POST", "/hosts/local/findings/accept", map[string]any{"id": "Not An Id"}, 400, "Problem")
	expect(t, h, "POST", "/hosts/local/findings/accept", map[string]any{"id": "ports.nonexistent"}, 404, "Problem")
	expect(t, h, "POST", "/hosts/nope/findings/accept", body(nil), 404, "Problem")
	expect(t, h, "POST", "/hosts/local/findings/accept", body(map[string]any{"note": "a\nb"}), 400, "Problem")
	expect(t, h, "POST", "/hosts/local/findings/reopen", body(map[string]any{"note": "x"}), 400, "Problem")
	expect(t, h, "POST", "/hosts/local/findings/reopen", body(nil), 404, "Problem")

	d := decode[hosts.HostDetail](t, expect(t, h, "POST", "/hosts/local/findings/accept", body(map[string]any{"note": "Firewall davor"}), 200, "HostDetail"))
	if d.Host.Accepted != 1 || d.Host.Counts.Medium != before.Host.Counts.Medium-1 || d.History[0].Counts != d.Host.Counts {
		t.Fatalf("after accept: %+v history %+v", d.Host, d.History[0])
	}
	if len(d.Accepted) != 1 || !d.Accepted[0].Active || d.Accepted[0].Severity != "medium" || d.Accepted[0].Note == nil || *d.Accepted[0].Note != "Firewall davor" {
		t.Fatalf("accepted: %+v", d.Accepted)
	}
	if !bytes.Equal(d.Report, before.Report) {
		t.Fatal("accepting must not change the stored report")
	}
	hp := decode[hosts.HostPage](t, expect(t, h, "GET", "/hosts", nil, 200, "HostPage"))
	if hp.Items[0].Accepted != 1 || hp.Items[0].Counts != d.Host.Counts {
		t.Fatalf("list: %+v", hp.Items[0])
	}
	ov := decode[dashboard.Overview](t, expect(t, h, "GET", "/overview", nil, 200, "Overview"))
	if ov.Servers == nil || ov.Servers.Findings.Medium != d.Host.Counts.Medium {
		t.Fatalf("overview: %+v", ov.Servers)
	}

	// The next report holds the same finding: still accepted.
	write(now.Add(-time.Hour), nil)
	d = decode[hosts.HostDetail](t, expect(t, h, "GET", "/hosts/local", nil, 200, "HostDetail"))
	if d.Host.Accepted != 1 || !d.Accepted[0].Active || len(d.History) != 2 {
		t.Fatalf("next report: %+v %+v", d.Host, d.Accepted)
	}
	// It comes back higher: open again, the acceptance is listed as not in force.
	write(now, func(r *hc.Report) {
		for i := range r.Findings {
			if x := &r.Findings[i]; x.ID == f.ID && x.Subject == f.Subject {
				x.Severity = "high"
			}
		}
	})
	d = decode[hosts.HostDetail](t, expect(t, h, "GET", "/hosts/local", nil, 200, "HostDetail"))
	if d.Host.Accepted != 0 || len(d.Accepted) != 1 || d.Accepted[0].Active || d.Host.Counts.High != before.Host.Counts.High+1 {
		t.Fatalf("higher severity: %+v %+v", d.Host, d.Accepted)
	}
	// Accepting again takes the new severity; reopening removes it.
	d = decode[hosts.HostDetail](t, expect(t, h, "POST", "/hosts/local/findings/accept", body(nil), 200, "HostDetail"))
	if d.Host.Accepted != 1 || d.Accepted[0].Severity != "high" || d.Accepted[0].Note != nil {
		t.Fatalf("accepted again: %+v", d.Accepted)
	}
	d = decode[hosts.HostDetail](t, expect(t, h, "POST", "/hosts/local/findings/reopen", body(nil), 200, "HostDetail"))
	if d.Host.Accepted != 0 || len(d.Accepted) != 0 || d.Host.Counts.High != before.Host.Counts.High+1 {
		t.Fatalf("reopened: %+v %+v", d.Host, d.Accepted)
	}
}
