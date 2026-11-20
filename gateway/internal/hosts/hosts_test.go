//go:build !release

package hosts

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/dsse"
	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/vectors"
	"github.com/deutschland-schild/schild/gateway/internal/hostagent"
	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

const exampleConfig = "../../../contracts/config/examples/schild.t0.yaml"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type testGW struct {
	*Gateway
	clock *clock
	dir   string
	cfg   *config.Site
}

// newGW builds a gateway on a fresh SQLite store with host_check and agents
// enabled. extra is appended to host_check.agents (YAML, 4 spaces indent).
func newGW(t testing.TB, node string, now time.Time, keep int, agentsExtra string) *testGW {
	t.Helper()
	dir := t.TempDir()
	b, err := os.ReadFile(exampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	y := strings.Replace(string(b), "node_name: site-wordpress", "node_name: "+node, 1)
	y += "host_check:\n  report_dir: " + filepath.Join(dir, "reports") + "\n  keep_reports: " + itoa(keep) + "\n  agents:\n    enabled: true\n    listen: \"0.0.0.0:8790\"\n    interval_minutes: 60\n" + agentsExtra
	cfg, err := config.ParseSite([]byte(y))
	if err != nil {
		t.Fatalf("config: %v\n%s", err, y)
	}
	st, err := store.Open(filepath.Join(dir, "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := &clock{t: now}
	g, err := New(context.Background(), Options{DB: st.DB(), Config: func() *config.Site { return cfg }, DataDir: dir,
		Log: testLog(), Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	return &testGW{Gateway: g, clock: c, dir: dir, cfg: cfg}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// enrolKey puts a test key in as enrolled (or revoked) agent.
func (g *testGW) enrolKey(t testing.TB, name, status string) string {
	t.Helper()
	k := testkeys.Get(name)
	fp, _ := fingerprintOf(k.Public)
	id := strings.ReplaceAll(name, "-", "")
	_, err := g.db.Exec("INSERT INTO host_agents("+agentCols+") VALUES(?, ?, '', ?, ?, ?, ?, 'code', ?, ?, 0, '')",
		id, name+".example", k.KeyID, k.Public, fp, status, ms(g.now()), ms(g.now()))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestAgentReportVectors runs the contract's golden agent-report vectors
// through the gateway's ingest: valid ones are accepted, invalid ones are
// rejected with exactly the expected code.
func TestAgentReportVectors(t *testing.T) {
	files, err := vectors.Files("../../../contracts/vectors/agent-report")
	if err != nil || len(files) == 0 {
		t.Skip("no vectors")
	}
	n := 0
	for _, f := range files {
		v, err := vectors.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		if v.Context.Gateway == "" {
			continue // the gateway always checks its own name
		}
		now, _ := msg.ParseTime(v.Context.Now)
		g := newGW(t, v.Context.Gateway, now, 30, "")
		revoked := map[string]bool{}
		for _, r := range v.Context.Revoked {
			revoked[r] = true
		}
		for _, name := range v.Context.Trust {
			k := testkeys.Get(name)
			if !slices.Contains(k.Purposes, contract.PurposeAgent) {
				continue // only agent keys can be enrolled as agents
			}
			st := "enrolled"
			if revoked[name] {
				st = "revoked"
			}
			g.enrolKey(t, name, st)
		}
		for _, id := range v.Context.SeenIDs {
			if _, err := g.db.Exec("INSERT INTO agent_nonces(nonce, digest, expires_ms) VALUES(?, 'x', ?)", id, ms(now.Add(time.Hour))); err != nil {
				t.Fatal(err)
			}
		}
		status, code, detail := g.Ingest(context.Background(), []byte(v.InputRaw))
		want := "accepted"
		if !v.Expect.Valid {
			want = "rejected"
		}
		if status != want || code != v.Expect.Error {
			t.Errorf("%s: got %s/%s (%s), want %s/%s", filepath.Base(f), status, code, detail, want, v.Expect.Error)
		}
		n++
	}
	if n < 20 {
		t.Fatalf("only %d vectors ran", n)
	}
}

// TestEnrolmentVectors: the same for enrolment requests. Valid vectors get
// their code created first; invalid ones fail before the code is looked at.
func TestEnrolmentVectors(t *testing.T) {
	files, err := vectors.Files("../../../contracts/vectors/agent-enrolment")
	if err != nil || len(files) == 0 {
		t.Skip("no vectors")
	}
	n := 0
	for _, f := range files {
		v, _ := vectors.Load(f)
		if v.Context.Gateway == "" {
			continue
		}
		now, _ := msg.ParseTime(v.Context.Now)
		g := newGW(t, v.Context.Gateway, now, 30, "")
		for _, id := range v.Context.SeenIDs {
			_, _ = g.db.Exec("INSERT INTO agent_nonces(nonce, digest, expires_ms) VALUES(?, 'x', ?)", id, ms(now.Add(time.Hour)))
		}
		if code := vectorCode(v.InputRaw); code != "" {
			_, _ = g.db.Exec("INSERT INTO host_enrolments(code_hash, label, created_ms, expires_ms) VALUES(?, 'v', ?, ?)", codeHash(code), ms(now), ms(now.Add(time.Hour)))
		}
		status, code, detail := g.Enrol(context.Background(), []byte(v.InputRaw))
		want := "pending"
		if !v.Expect.Valid {
			want = "rejected"
		}
		if status != want || code != v.Expect.Error {
			t.Errorf("%s: got %s/%s (%s), want %s/%s", filepath.Base(f), status, code, detail, want, v.Expect.Error)
		}
		n++
	}
	if n < 15 {
		t.Fatalf("only %d vectors ran", n)
	}
}

func vectorCode(raw string) string {
	var env dsse.Envelope
	if json.Unmarshal([]byte(raw), &env) != nil {
		return ""
	}
	p, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return ""
	}
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(p, &e)
	return e.Code
}

// ---------------------------------------------------------------- end to end

type e2e struct {
	g      *testGW
	srv    *httptest.Server
	agent  *hostagent.Agent
	state  *hostagent.State
	agDir  string
	served atomic.Int64
}

func fixtureEnv(now time.Time) *hostcheck.FixtureEnv {
	return &hostcheck.FixtureEnv{Dir: "../hostcheck/testdata/hosts/rocky9", Time: now}
}

// setup: gateway with a TLS listener, a dashboard code, `schild-agent
// enrol` against it, confirmation with the fingerprint.
func setup(t *testing.T, confirm bool) *e2e {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	e := &e2e{g: g}
	h := g.Handler()
	e.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.served.Add(1)
		h.ServeHTTP(w, r)
	}))
	e.srv.TLS = tlsConfig(g.cert)
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)
	en, err := g.CreateEnrolment(context.Background(), "Nextcloud", 0, "gw-1.example:8788")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(en.Command, "sudo schild-agent enrol ") || !strings.Contains(en.Command, "--code "+en.Code) || !strings.Contains(en.Command, "--pin "+g.Pin()) || !strings.Contains(en.Command, "--gateway-name gw-1") || en.GatewayURL != "https://gw-1.example:8790" {
		t.Fatalf("%+v", en)
	}
	e.agDir = filepath.Join(t.TempDir(), "schild-agent")
	var out bytes.Buffer
	st, err := hostagent.Enrol(context.Background(), hostagent.EnrolOptions{Dir: e.agDir, GatewayURL: e.srv.URL, GatewayName: "gw-1", Pin: g.Pin(),
		Code: strings.ToLower(en.Code), Hostname: "db-1.example", Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	e.state = st
	if fi, _ := os.Stat(st.KeyFile); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", fi.Mode())
	}
	if !strings.Contains(out.String(), st.Fingerprint) {
		t.Fatal("enrol must print the fingerprint")
	}
	as, _ := g.Agents(context.Background(), "pending")
	if len(as) != 1 || as[0].Fingerprint != st.Fingerprint || as[0].Label == nil || *as[0].Label != "Nextcloud" {
		t.Fatalf("%+v", as)
	}
	if confirm {
		if _, err := g.Confirm(context.Background(), as[0].ID, "sha256:"+strings.Repeat("0", 64), ""); err != ErrFingerprintMismatch {
			t.Fatalf("wrong fingerprint: %v", err)
		}
		if _, err := g.Confirm(context.Background(), as[0].ID, strings.ToUpper(st.Fingerprint[:7])+st.Fingerprint[7:], ""); err != nil {
			t.Fatal(err)
		}
	}
	a, err := hostagent.New(e.agDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Env = fixtureEnv(now)
	a.Version = "0.1.0-alpha"
	a.BaseDelay, a.MaxDelay = 5*time.Millisecond, 20*time.Millisecond
	e.agent = a
	return e
}

func TestEnrolDeliverReplayRevoke(t *testing.T) {
	e := setup(t, true)
	ctx := context.Background()
	r, err := e.agent.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := e.agent.Deliver(ctx, r)
	if err != nil || ack.Status != "accepted" {
		t.Fatalf("%+v %v", ack, err)
	}
	hs, _ := e.g.Hosts(ctx)
	if len(hs) != 2 || hs[0].ID != LocalID || hs[1].Hostname != "db-1.example" || hs[1].Status != "findings" || hs[1].Counts.High == 0 {
		t.Fatalf("%+v", hs)
	}
	d, err := e.g.Host(ctx, hs[1].ID)
	if err != nil || len(d.History) != 1 {
		t.Fatal(err)
	}
	var stored hc.Report
	if err := json.Unmarshal(d.Report, &stored); err != nil || stored.ReportID != r.ReportID || stored.Host.AgentKeyID == nil || *stored.Host.AgentKeyID != e.state.KeyID {
		t.Fatalf("stored report: %v", err)
	}
	// Replays: the same bytes again are a duplicate; the same nonce with
	// other bytes is a replay.
	signer, _ := keys.LoadSigner(e.state.KeyID, e.state.KeyFile)
	p := hc.AgentReport{Schema: hc.SchemaAgentReport, Gateway: "gw-1", IssuedAt: msg.FormatTime(time.Now()), Nonce: strings.Repeat("ab", 16), Report: *r}
	raw := sign(t, p, signer)
	if code := post(t, e, raw); code != "accepted" {
		t.Fatalf("first: %s", code)
	}
	if code := post(t, e, raw); code != "duplicate" {
		t.Fatalf("same bytes: %s", code)
	}
	p.Report.Run.DurationMS++
	if code := post(t, e, sign(t, p, signer)); code != "rejected:replay" {
		t.Fatalf("same nonce: %s", code)
	}
	// Unknown key.
	other := testkeys.Signer("agent-b")
	p2 := p
	p2.Nonce = strings.Repeat("cd", 16)
	kid := other.KeyID()
	p2.Report.Host.AgentKeyID = &kid
	if code := post(t, e, sign(t, p2, other)); code != "rejected:signature" {
		t.Fatalf("unknown key: %s", code)
	}
	// Revoke: valid signature, answered with revoked; shown at the host.
	if _, err := e.g.Revoke(ctx, hs[1].ID, "VM decommissioned"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.g.Revoke(ctx, hs[1].ID, ""); err != ErrConflict {
		t.Fatalf("revoke twice: %v", err)
	}
	ack, err = e.agent.Deliver(ctx, r)
	if err == nil || ack == nil || ack.Error == nil || *ack.Error != "revoked" {
		t.Fatalf("after revoke: %+v %v", ack, err)
	}
	d, _ = e.g.Host(ctx, hs[1].ID)
	if d.Host.Status != "revoked" || d.LastRejected == nil || d.LastRejected.Code != "revoked" || d.Report == nil {
		t.Fatalf("%+v", d)
	}
}

func sign(t *testing.T, p hc.AgentReport, s dsse.Signer) []byte {
	t.Helper()
	b, _ := json.Marshal(p)
	env, err := dsse.Sign(contract.KindAgentReport.PayloadType(), b, s)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := env.Marshal()
	return raw
}

func post(t *testing.T, e *e2e, raw []byte) string {
	t.Helper()
	resp, err := e.agent.Client.HTTP.Post(e.srv.URL+"/v0/agent/report", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var ack hc.Ack
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &ack); err != nil {
		t.Fatalf("%s", b)
	}
	// Only ack fields: nothing that could carry an instruction.
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for k := range m {
		switch k {
		case "schema", "status", "nonce", "received_at", "error", "retry_after_s":
		default:
			t.Fatalf("ack carries %s", k)
		}
	}
	if ack.Error != nil {
		return ack.Status + ":" + *ack.Error
	}
	return ack.Status
}

func TestPendingAgentIsNotTrusted(t *testing.T) {
	e := setup(t, false)
	r, _ := e.agent.Check(context.Background())
	ack, err := e.agent.Deliver(context.Background(), r)
	if err == nil || ack.Error == nil || *ack.Error != "signature" {
		t.Fatalf("pending agent: %+v %v", ack, err)
	}
}

func TestEnrolmentCodeOnce(t *testing.T) {
	g := newGW(t, "gw-1", time.Now().UTC(), 30, "")
	srv := httptest.NewUnstartedServer(g.Handler())
	srv.TLS = tlsConfig(g.cert)
	srv.StartTLS()
	defer srv.Close()
	en, _ := g.CreateEnrolment(context.Background(), "", 5, "127.0.0.1:8788")
	if en.GatewayURL != "https://gw-1:8790" {
		t.Fatalf("loopback dashboard host falls back to node_name: %s", en.GatewayURL)
	}
	o := hostagent.EnrolOptions{GatewayURL: srv.URL, GatewayName: "gw-1", Pin: g.Pin(), Code: en.Code, Hostname: "a.example"}
	o.Dir = t.TempDir()
	if _, err := hostagent.Enrol(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	o.Dir, o.Hostname = t.TempDir(), "b.example"
	if _, err := hostagent.Enrol(context.Background(), o); err == nil || !strings.Contains(err.Error(), "enrolment_code") {
		t.Fatalf("second use: %v", err)
	}
	if _, err := os.Stat(filepath.Join(o.Dir, "agent.key")); !os.IsNotExist(err) {
		t.Fatal("a rejected enrolment removes its key")
	}
	// Wrong pin: the agent refuses the gateway before sending anything.
	o.Dir, o.Pin = t.TempDir(), "sha256:"+strings.Repeat("1", 64)
	en2, _ := g.CreateEnrolment(context.Background(), "", 5, "")
	o.Code = en2.Code
	if _, err := hostagent.Enrol(context.Background(), o); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("wrong pin: %v", err)
	}
	// Expired code.
	g.clock.Add(10 * time.Minute)
	o.Dir, o.Pin = t.TempDir(), g.Pin()
	if _, err := hostagent.Enrol(context.Background(), o); err == nil {
		t.Fatal("expired code accepted")
	}
}

func TestGatewayDownAgentRetries(t *testing.T) {
	e := setup(t, true)
	e.srv.Close() // gateway down
	start := time.Now()
	err := e.agent.RunOnce(context.Background(), time.Now().Add(150*time.Millisecond))
	if err == nil {
		t.Fatal("no error with the gateway down")
	}
	if time.Since(start) < 20*time.Millisecond {
		t.Fatal("no backoff")
	}
}

func TestRetentionAndSilent(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	g := newGW(t, "gw-1", now, 3, "")
	id := g.enrolKey(t, "agent-a", "enrolled")
	signer := testkeys.Signer("agent-a")
	for i := 0; i < 5; i++ {
		r := hostcheck.Run(context.Background(), &hostcheck.FixtureEnv{Dir: "../hostcheck/testdata/hosts/debian11", Time: g.now()},
			hostcheck.Options{Role: hc.RoleAgent, AgentKeyID: signer.KeyID()})
		p := hc.AgentReport{Schema: hc.SchemaAgentReport, Gateway: "gw-1", IssuedAt: msg.FormatTime(g.now()), Nonce: strings.Repeat(string("0123456789"[i]), 32), Report: *r}
		b, _ := json.Marshal(p)
		env, _ := dsse.Sign(contract.KindAgentReport.PayloadType(), b, signer)
		raw, _ := env.Marshal()
		if st, code, d := g.Ingest(context.Background(), raw); st != "accepted" {
			t.Fatalf("%d: %s %s %s", i, st, code, d)
		}
		g.clock.Add(10 * time.Minute)
	}
	d, err := g.Host(context.Background(), id)
	if err != nil || len(d.History) != 3 {
		t.Fatalf("keep 3: %v %d", err, len(d.History))
	}
	if d.Host.Silent || d.Host.Status != "findings" {
		t.Fatalf("%+v", d.Host)
	}
	g.clock.Add(2*time.Hour + time.Minute) // interval 60 min
	d, _ = g.Host(context.Background(), id)
	if !d.Host.Silent || d.Host.Status != "silent" {
		t.Fatalf("silent: %+v", d.Host)
	}
	s, _ := g.Summary(context.Background())
	if s.Hosts != 2 || s.Silent != 1 || s.Findings.High == 0 {
		t.Fatalf("%+v", s)
	}
}

func TestConfigAgents(t *testing.T) {
	a, c := testkeys.Get("agent-a"), testkeys.Get("agent-c")
	extra := "    keys:\n      - { keyid: " + a.KeyID + ", public_key: \"" + a.Public + "\", hostname: app-1.example }\n" +
		"      - { keyid: " + c.KeyID + ", public_key: \"" + c.Public + "\", revoked: true }\n"
	g := newGW(t, "gw-1", time.Now().UTC(), 30, extra)
	as, _ := g.Agents(context.Background(), "")
	if len(as) != 2 {
		t.Fatalf("%+v", as)
	}
	for _, x := range as {
		if x.Source != "config" {
			t.Fatal(x)
		}
		if x.KeyID == c.KeyID && x.Status != "revoked" {
			t.Fatal("revoked in config")
		}
		if _, err := g.Revoke(context.Background(), x.ID, ""); err != ErrConfigAgent {
			t.Fatalf("config agent revoked in dashboard: %v", err)
		}
	}
	// Re-sync is idempotent.
	if err := g.SyncConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if as2, _ := g.Agents(context.Background(), ""); len(as2) != 2 || as2[0].ID != as[0].ID {
		t.Fatalf("%+v", as2)
	}
}

func TestLocalReportsAndCheck(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	g := newGW(t, "gw-1", now, 30, "")
	ctx := context.Background()
	// No way to run the check from the dashboard: 503 path.
	if _, err := g.RunLocalCheck(ctx); err != ErrCheckUnavailable {
		t.Fatal(err)
	}
	hs, _ := g.Hosts(ctx)
	if hs[0].ID != LocalID || hs[0].Status != "waiting" {
		t.Fatalf("%+v", hs[0])
	}
	// schild check writes into the directory; the gateway imports it.
	dir := g.reportDir()
	r := hostcheck.Run(ctx, &hostcheck.FixtureEnv{Dir: "../hostcheck/testdata/hosts/debian12", Time: now}, hostcheck.Options{Role: hc.RoleGateway})
	b, _ := hostcheck.Marshal(r)
	if _, err := hostcheck.WriteReport(dir, r, b, 30); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "2026-10-27T11:00:00Z-00000000-0000-4000-8000-000000000000.json"), []byte(`{"env":"PATH=/x"}`), 0o640)
	if err := g.ScanLocal(ctx); err != nil {
		t.Fatal(err)
	}
	d, err := g.Host(ctx, LocalID)
	if err != nil || d.Host.Status != "findings" || d.Host.Hostname != "gw-1.example" || d.Host.Counts.Critical != 1 || len(d.History) != 1 {
		t.Fatalf("%+v %v", d, err)
	}
	if !bytes.Equal(d.Report, b) {
		t.Fatal("local report must be served unchanged")
	}
	// Trigger file.
	g.TriggerFile = filepath.Join(t.TempDir(), "check-request")
	run, err := g.RunLocalCheck(ctx)
	if err != nil || run.State != "queued" {
		t.Fatal(err)
	}
	if _, err := g.RunLocalCheck(ctx); err != ErrCheckRunning {
		t.Fatalf("second request: %v", err)
	}
	// In-process (schild on the host): runs the fixture and imports it.
	g.TriggerFile, g.InProcess = "", true
	g.localState = ""
	g.CheckEnv = &hostcheck.FixtureEnv{Dir: "../hostcheck/testdata/hosts/ubuntu2404", Time: now.Add(time.Minute)}
	if run, err = g.RunLocalCheck(ctx); err != nil || run.State != "running" {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if d, _ = g.Host(ctx, LocalID); len(d.History) == 2 && d.Host.Hostname == "gw-2.example" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(d.History) != 2 || d.Host.Hostname != "gw-2.example" {
		t.Fatalf("in-process check not imported: %+v %+v", d.Host, d.History)
	}
}

// TestConcurrentIngest: the same envelope from many goroutines is stored
// once; reads run in parallel (race detector).
func TestConcurrentIngest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, "")
	id := g.enrolKey(t, "agent-b", "enrolled")
	signer := testkeys.Signer("agent-b")
	r := hostcheck.Run(context.Background(), &hostcheck.FixtureEnv{Dir: "../hostcheck/testdata/hosts/alma9", Time: now},
		hostcheck.Options{Role: hc.RoleAgent, AgentKeyID: signer.KeyID()})
	var raws [][]byte
	for i := 0; i < 4; i++ {
		rr := *r
		rr.ReportID = msg.NewID()
		p := hc.AgentReport{Schema: hc.SchemaAgentReport, Gateway: "gw-1", IssuedAt: msg.FormatTime(now), Nonce: strings.Repeat(string("abcd"[i]), 32), Report: rr}
		b, _ := json.Marshal(p)
		env, _ := dsse.Sign(contract.KindAgentReport.PayloadType(), b, signer)
		raw, _ := env.Marshal()
		raws = append(raws, raw)
	}
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if st, _, _ := g.Ingest(context.Background(), raws[i%4]); st == "accepted" {
				accepted.Add(1)
			}
			_, _ = g.Hosts(context.Background())
			_, _ = g.Summary(context.Background())
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 4 {
		t.Fatalf("accepted %d, want 4 (one per nonce)", accepted.Load())
	}
	d, _ := g.Host(context.Background(), id)
	if len(d.History) != 4 {
		t.Fatalf("history %d", len(d.History))
	}
}

func TestAgentsDisabled(t *testing.T) {
	g := newGW(t, "gw-1", time.Now().UTC(), 30, "")
	cfg := *g.cfg
	h := *cfg.HostCheck
	f := false
	h.Agents.Enabled = &f
	cfg.HostCheck = &h
	g.Gateway.cfg = func() *config.Site { return &cfg }
	raw := sign(t, hc.AgentReport{Schema: hc.SchemaAgentReport, Gateway: "gw-1", IssuedAt: msg.FormatTime(time.Now()), Nonce: strings.Repeat("a", 32)}, testkeys.Signer("agent-a"))
	if st, _, _ := g.Ingest(context.Background(), raw); st != "rejected" {
		t.Fatal(st)
	}
	if _, err := g.CreateEnrolment(context.Background(), "", 0, ""); err != ErrAgentsDisabled {
		t.Fatal(err)
	}
}

func testLog() *slog.Logger {
	if os.Getenv("SCHILD_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestConfigAgentInit: `schild-agent init` with an existing key (enrolled
// by public key in schild.yaml) delivers without a code; the printed entry
// is exactly what schild.yaml needs.
func TestConfigAgentInit(t *testing.T) {
	a := testkeys.Get("agent-a")
	extra := "    keys:\n      - { keyid: " + a.KeyID + ", public_key: \"" + a.Public + "\", hostname: app-1.example }\n"
	now := time.Now().UTC().Truncate(time.Second)
	g := newGW(t, "gw-1", now, 30, extra)
	srv := httptest.NewUnstartedServer(g.Handler())
	srv.TLS = tlsConfig(g.cert)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	keyFile := filepath.Join(t.TempDir(), "agent.key")
	if err := os.WriteFile(keyFile, keys.FormatSeedFile(testkeys.Private("agent-a")), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "schild-agent")
	var out bytes.Buffer
	if _, err := hostagent.Init(hostagent.InitOptions{Dir: dir, GatewayURL: srv.URL, GatewayName: "gw-1", Pin: g.Pin(), KeyFile: keyFile,
		Hostname: "app-1.example", Out: &out}); err == nil {
		t.Fatal("--key without --keyid accepted")
	}
	if _, err := hostagent.Init(hostagent.InitOptions{Dir: dir, GatewayURL: srv.URL, GatewayName: "gw-1", Pin: g.Pin(), KeyFile: keyFile, KeyID: a.KeyID,
		Hostname: "app-1.example", Out: &out}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "public_key: "+a.Public) || !strings.Contains(out.String(), "keyid: "+a.KeyID) {
		t.Fatalf("init output: %s", out.String())
	}
	if _, err := hostagent.Init(hostagent.InitOptions{Dir: dir, GatewayURL: srv.URL, GatewayName: "gw-1", Pin: g.Pin(), KeyFile: keyFile, KeyID: a.KeyID}); err == nil {
		t.Fatal("init twice")
	}
	ag, err := hostagent.New(dir, testLog())
	if err != nil {
		t.Fatal(err)
	}
	ag.Env = fixtureEnv(now)
	ag.Version = "0.1.0-alpha"
	r, err := ag.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ack, err := ag.Deliver(context.Background(), r)
	if err != nil || ack.Status != "accepted" {
		t.Fatalf("%+v %v", ack, err)
	}
}

// TestEnrolmentURLFromHostHeader: the gateway URL of the enrolment command
// (run with sudo on the app VM) takes an address or a DNS name from the
// dashboard's Host header, never text a shell would run.
func TestEnrolmentURLFromHostHeader(t *testing.T) {
	t.Setenv("SCHILD_AGENT_URL", "")
	g := newGW(t, "gw-1", time.Now().UTC(), 30, "")
	for host, want := range map[string]string{
		"gw.example.net:8788": "https://gw.example.net:8790",
		"10.0.0.5:8788":       "https://10.0.0.5:8790",
		"[2001:db8::5]:8788":  "https://[2001:db8::5]:8790",
		"127.0.0.1:8788":      "https://gw-1:8790",
		"x$(reboot):8788":     "https://gw-1:8790",
		"a;id":                "https://gw-1:8790",
		"a&&id:8788":          "https://gw-1:8790",
	} {
		if got := g.agentURL(host); got != want {
			t.Errorf("%q: %s, want %s", host, got, want)
		}
	}
	en, err := g.CreateEnrolment(context.Background(), "", 5, "x$(reboot):8788")
	if err != nil || strings.Contains(en.Command, "$(") {
		t.Fatalf("command: %v %+v", err, en)
	}
}
