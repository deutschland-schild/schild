package hostagent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
)

// TestCheckKeepsPreviousReport: the agent hands its previous report to the
// next check, so logs.large_file reports growth per day (D38).
func TestCheckKeepsPreviousReport(t *testing.T) {
	env := func(size int64, at time.Time) *hostcheck.FixtureEnv {
		d := t.TempDir()
		if err := os.MkdirAll(filepath.Join(d, "fs/var/log/app"), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(d, "fs/var/log/app/big.log"), nil, 0o644)
		_ = os.WriteFile(filepath.Join(d, "stat"), []byte(fmt.Sprintf("/var/log/app/big.log size=%d\n", size)), 0o644)
		_ = os.WriteFile(filepath.Join(d, "statfs"), []byte("/ 429496729600 214748364800\n"), 0o644)
		return &hostcheck.FixtureEnv{Dir: d, Time: at}
	}
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	a := &Agent{State: &State{KeyID: "app-1/agent/2026-10", Hostname: "app-1"}, Version: "test", Env: env(2<<30, t0)}
	growth := func() *int64 {
		r, err := a.Check(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range r.Findings {
			if f.ID == "logs.large_file" && f.Subject == "/var/log/app/big.log" {
				return f.Evidence.GrowthBytesPerDay
			}
		}
		t.Fatal("no logs.large_file result")
		return nil
	}
	if g := growth(); g != nil {
		t.Fatalf("growth on the first run: %d", *g)
	}
	a.Env = env(3<<30, t0.Add(24*time.Hour))
	if g := growth(); g == nil || *g != 1<<30 {
		t.Fatalf("growth %v, want 1 GiB per day", g)
	}
}

func TestNewClientValidates(t *testing.T) {
	pin := "sha256:" + strings.Repeat("a", 64)
	for _, u := range []string{"http://gw:8790", "https://user@gw:8790", "https://gw:8790/x", "https://gw:8790?a=1", "gw:8790"} {
		if _, err := NewClient(u, pin); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if _, err := NewClient("https://gw.example:8790", "sha256:xyz"); err == nil {
		t.Error("bad pin accepted")
	}
	c, err := NewClient("https://gw.example:8790/", pin)
	if err != nil || c.URL != "https://gw.example:8790" {
		t.Fatal(err)
	}
	if c.HTTP.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("the agent never uses a proxy")
	}
}

// TestPinRefusesOtherCertificate: a gateway with another certificate gets
// nothing, not even the request.
func TestPinRefusesOtherCertificate(t *testing.T) {
	hit := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "sha256:"+strings.Repeat("0", 64))
	if _, err := c.post(context.Background(), "/v0/agent/report", []byte("{}"), strings.Repeat("a", 32), ""); err == nil || hit {
		t.Fatalf("pin not enforced: %v %v", err, hit)
	}
	good, _ := NewClient(srv.URL, CertPin(srv.Certificate()))
	if _, err := good.post(context.Background(), "/x", []byte("{}"), strings.Repeat("a", 32), ""); err == nil || !hit {
		t.Fatalf("a non-ack answer must be an error: %v", err)
	}
}

// TestNoRedirects: the agent never follows a redirect elsewhere.
func TestNoRedirects(t *testing.T) {
	other := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other = true }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, CertPin(srv.Certificate()))
	_, _ = c.post(context.Background(), "/v0/agent/report", []byte("{}"), strings.Repeat("a", 32), "")
	if other {
		t.Fatal("redirect followed")
	}
}

func TestJitter(t *testing.T) {
	for i := 0; i < 200; i++ {
		d := jitter(30*time.Second, 0.2)
		if d < 24*time.Second || d > 36*time.Second {
			t.Fatal(d)
		}
	}
	if jitter(0, 0.2) != 0 {
		t.Fatal("zero")
	}
}

func TestFingerprint(t *testing.T) {
	if fp := Fingerprint(make([]byte, 32)); fp != "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925" {
		t.Fatal(fp)
	}
}

// TestNewWarnsAboutAnOpenKey: a key other users can read lets them sign
// reports as this agent; New says so (enrol and init write 0600).
func TestNewWarnsAboutAnOpenKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(InitOptions{Dir: dir, GatewayURL: "https://192.0.2.10:8790", GatewayName: "gw-1", Pin: "sha256:" + strings.Repeat("a", 64),
		Hostname: "app-1.example", Now: func() time.Time { return time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC) }}); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "agent.key")
	for _, c := range []struct {
		mode os.FileMode
		warn bool
	}{{0o600, false}, {0o640, true}, {0o644, true}} {
		if err := os.Chmod(key, c.mode); err != nil {
			t.Fatal(err)
		}
		var buf strings.Builder
		if _, err := New(dir, slog.New(slog.NewTextHandler(&buf, nil))); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(buf.String(), "chmod 600"); got != c.warn {
			t.Errorf("mode %04o: warning %v, want %v (%s)", c.mode, got, c.warn, buf.String())
		}
	}
}
