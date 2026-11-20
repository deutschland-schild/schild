//go:build !release

package dashboard_test

import (
	"context"
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
