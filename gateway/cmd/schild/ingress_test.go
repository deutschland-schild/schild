package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/ingress"
	"github.com/deutschland-schild/schild/gateway/internal/app"
)

func TestSSHClientIP(t *testing.T) {
	env := map[string]string{"SSH_CONNECTION": "203.0.113.7 51234 192.0.2.1 22"}
	if ip, err := sshClientIP(func(k string) string { return env[k] }); err != nil || ip != "203.0.113.7" {
		t.Fatalf("%q %v", ip, err)
	}
	env = map[string]string{"SSH_CLIENT": "2001:db8::7 51234 22"}
	if ip, err := sshClientIP(func(k string) string { return env[k] }); err != nil || ip != "2001:db8::7" {
		t.Fatalf("%q %v", ip, err)
	}
	if _, err := sshClientIP(func(string) string { return "" }); err == nil {
		t.Fatal("no session accepted")
	}
}

func writeStandalone(t *testing.T, caddyfile string) string {
	t.Helper()
	dir := t.TempDir()
	cf := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cf, []byte(caddyfile), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "config_version: 0\nprofile: production\nmode: autoblock\nnode_name: web-1\ningress:\n  caddyfile: " + cf +
		"\n  storage: " + filepath.Join(dir, "caddy") + "\nstorage:\n  path: " + filepath.Join(dir, "data") + "\ngeo:\n  db_path: " + filepath.Join(dir, "geo.mmdb") + "\n"
	p := filepath.Join(dir, "schild.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIngressValidate(t *testing.T) {
	good := writeStandalone(t, "(schild) {\n\tschild\n}\nhttp://shop.example.de:18080 {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n}\n")
	if err := cmdIngress([]string{"validate", "-config", good}); err != nil {
		t.Fatal(err)
	}
	if err := cmdIngress([]string{"validate", "-config", good, "-adapt-only"}); err != nil {
		t.Fatal(err)
	}
	bad := writeStandalone(t, "http://shop.example.de:18080 {\n\treverse_proxy 127.0.0.1:9\n}\n")
	if err := cmdIngress([]string{"validate", "-config", bad}); err == nil || !strings.Contains(err.Error(), "without schild") {
		t.Fatalf("unprotected site: %v", err)
	}
	// D31 amendment: a rewrite before schild is refused with the contract
	// message, one REFUSE line per finding.
	hidden := writeStandalone(t, "http://shop.example.de:18080 {\n\troute {\n\t\trewrite * /hidden?\n\t\tschild\n\t\treverse_proxy 127.0.0.1:9\n\t}\n}\n")
	var err error
	out := captureStdout(t, func() { err = cmdIngress([]string{"validate", "-config", hidden, "-adapt-only"}) })
	if err == nil || !strings.Contains(err.Error(), ingress.CodeRewriteBeforeSchild) {
		t.Fatalf("rewrite before schild: %v\n%s", err, out)
	}
	want := ingress.Message(ingress.Finding{Server: "srv0", Route: "/routes/0", Hosts: []string{"shop.example.de"}, Directive: ingress.DirectiveRewrite,
		Rewrite: "/routes/0/handle/0/routes/0/handle/0/routes/0/handle/0", Schild: "/routes/0/handle/0/routes/0/handle/0/routes/1/handle/0"})
	if !strings.Contains(out, "  REFUSE    "+want+"\n") || !strings.Contains(out, "result: REFUSE (Caddyfile)") {
		t.Fatalf("missing %q in:\n%s", want, out)
	}
	if hc, _, _ := app.LoadConfig(hidden); checkIngress(hc, t.TempDir(), false) == nil {
		t.Fatal("preflight accepted a rewrite before schild")
	}
	broken := writeStandalone(t, "http://shop.example.de:18080 {\n\tschild\n\treverse_proxy\n")
	if err := cmdIngress([]string{"validate", "-config", broken}); err == nil {
		t.Fatal("broken Caddyfile accepted")
	}
	// Preflight: production without keys passes, the Caddyfile is checked.
	cfg, _, err := app.LoadConfig(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkIngress(cfg, t.TempDir(), true); err != nil {
		t.Fatal(err)
	}
	cfg, _, _ = app.LoadConfig(bad)
	if err := checkIngress(cfg, t.TempDir(), false); err == nil {
		t.Fatal("preflight accepted an unprotected site")
	}
}

// TestDeployExample keeps deploy/schild.standalone.yaml and
// deploy/Caddyfile.ingress valid together (adapt and directive check).
func TestDeployExample(t *testing.T) {
	cf, err := filepath.Abs("../../deploy/Caddyfile.ingress")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../deploy/schild.standalone.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "schild.yaml")
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "/etc/caddy/Caddyfile", cf, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := app.LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	ing, err := app.IngressFor(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The only warning: the access log uses roll_disabled, so the host's
	// logrotate rule needs copytruncate (D38 section 6).
	if len(ing.Check.Warnings) != 1 || !strings.HasPrefix(ing.Check.Warnings[0], "log_roll_disabled: output file /var/log/caddy/access.log ") || len(ing.Check.Sites) != 3 {
		t.Fatalf("deploy example: %+v", ing.Check)
	}
}

// captureStdout runs f and returns what it printed.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	defer func() { os.Stdout = old }()
	f()
	_ = w.Close()
	os.Stdout = old
	return string(<-done)
}

// TestIngressValidateLogRollDisabled (D38 section 6): roll_disabled is a
// warning with the contract message and a copytruncate logrotate rule,
// never an error (the result and the exit code stay PASS).
func TestIngressValidateLogRollDisabled(t *testing.T) {
	cfg := writeStandalone(t, "http://shop.example.de:18080 {\n\tschild\n\tlog {\n\t\toutput file /var/log/caddy/access.log {\n\t\t\troll_disabled\n\t\t}\n\t}\n\treverse_proxy 127.0.0.1:9\n}\n")
	var err error
	out := captureStdout(t, func() { err = cmdIngress([]string{"validate", "-config", cfg, "-adapt-only"}) })
	if err != nil {
		t.Fatalf("roll_disabled is an error: %v\n%s", err, out)
	}
	for _, want := range []string{
		"  warning   log_roll_disabled: output file /var/log/caddy/access.log uses roll_disabled; the embedded Caddy does not reopen it, so the logrotate rule needs copytruncate (schild check: logs.logrotate_config)\n",
		"  suggest   logrotate rule for /var/log/caddy/access.log (file /etc/logrotate.d/schild-caddy-access):\n",
		"            /var/log/caddy/access.log {\n",
		"              copytruncate\n",
		"result: PASS (Caddyfile)\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

// TestIngressValidateNoSideEffects: `schild ingress validate` with Caddy
// provisioning creates no log file, no log directory, no storage root and
// no data directory.
func TestIngressValidateNoSideEffects(t *testing.T) {
	logs := t.TempDir()
	cfg := writeStandalone(t, "http://shop.example.de:18080 {\n\tschild\n\tlog {\n\t\toutput file "+filepath.Join(logs, "sub", "access.log")+"\n\t}\n\treverse_proxy 127.0.0.1:9\n}\n")
	var err error
	out := captureStdout(t, func() { err = cmdIngress([]string{"validate", "-config", cfg}) })
	if err != nil || !strings.Contains(out, "caddy provisioning: valid") {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	if e, _ := os.ReadDir(logs); len(e) > 0 {
		t.Fatalf("validation created %s", e[0].Name())
	}
	for _, n := range []string{"caddy", "data"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(cfg), n)); err == nil {
			t.Fatalf("validation created %s", n)
		}
	}
}
