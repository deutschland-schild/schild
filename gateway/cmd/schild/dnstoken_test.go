package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A DNS provider without a token passes Caddy's provisioning; `schild ingress
// validate` refuses it and says what it means. -adapt-only does not look at
// the server's files.
func TestIngressValidateDNSToken(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root gets another result line")
	}
	old := readUnitSandbox
	defer func() { readUnitSandbox = old }()
	readUnitSandbox = func() unitSandbox { return unitSandbox{Known: true, Strict: true} }
	token := filepath.Join(t.TempDir(), "hetzner.token")
	cfg := writeStandalone(t, "*.example.test {\n\ttls {\n\t\tdns hetzner {file."+token+"}\n\t}\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n")
	run := func(args ...string) (string, error) {
		var err error
		out := captureStdout(t, func() { err = cmdIngress(append([]string{"validate", "-config", cfg}, args...)) })
		return out, err
	}
	out, err := run()
	if err == nil || !errors.As(err, new(reportedError)) || !strings.Contains(out, "REFUSE    dns hetzner: the API token from {file."+token+"} is empty") ||
		!strings.HasSuffix(out, "result: REFUSE (DNS provider); schild would start, serve the certificates it holds and obtain or renew none that needs this token\n") {
		t.Fatalf("token file missing: %v\n%s", err, out)
	}
	if out, err := run("-adapt-only"); err != nil || !strings.Contains(out, "result: PASS (Caddyfile)") {
		t.Fatalf("-adapt-only: %v\n%s", err, out)
	}
	if err := os.WriteFile(token, []byte("TEST-ONLY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run(); err != nil || !strings.HasSuffix(out, "result: PASS\n") {
		t.Fatalf("token there: %v\n%s", err, out)
	}
}
