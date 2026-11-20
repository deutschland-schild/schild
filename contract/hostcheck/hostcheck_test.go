package hostcheck

import (
	"testing"

	"github.com/deutschland-schild/schild/contract"
)

func TestForbiddenContent(t *testing.T) {
	bad := map[string]string{
		"-----BEGIN OPENSSH PRIVATE KEY-----":        "pem",
		"x -----END RSA PRIVATE KEY----- y":          "pem",
		"ENCRYPTED PRIVATE KEY-----":                 "pem",
		"PuTTY-User-Key-File-3: ssh-ed25519":         "pem",
		"DB_PASSWORD=hunter2":                        "secret assignment",
		"mysql --password=geheim":                    "secret assignment",
		"GITHUB_TOKEN=ghp_x":                         "secret assignment",
		"aws_secret_access_key=abc":                  "secret assignment",
		"API_KEY=1":                                  "secret assignment",
		"PATH=/usr/bin HOME=/root USER=root":         "environment dump",
		"PATH=/bin\x00HOME=/root\x00LANG=C":          "environment dump",
		"APP_ENV=prod;APP_DEBUG=0;DB_HOST=localhost": "environment dump",
	}
	for s, want := range bad {
		if got := ForbiddenContent(s); got != want {
			t.Errorf("%q: got %q, want %q", s, got, want)
		}
	}
	// Ordinary German copy and fix commands must pass.
	good := []string{
		"SSH erlaubt Anmeldung mit Passwort",
		"Passwörter lassen sich durchprobieren. Mit Schlüsseln geht das nicht.",
		"Setze PermitRootLogin auf prohibit-password: root meldet sich dann nur mit Schlüssel an.",
		"sudo sed -i 's/^#\\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload ssh",
		"sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -y upgrade",
		"Der private Schlüssel bleibt auf dem Server.",
		"sudo -u www-data wp core update --path=/var/www/shop",
		"Das Token-Verfahren von ACME erneuert Zertifikate automatisch.",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
	}
	for _, s := range good {
		if got := ForbiddenContent(s); got != "" {
			t.Errorf("%q flagged as %q", s, got)
		}
	}
}

func TestCheckForbiddenOrder(t *testing.T) {
	// A forbidden key wins over forbidden content elsewhere, whatever the
	// map iteration order (two passes).
	v := map[string]any{"a": "-----BEGIN PRIVATE KEY-----", "z": map[string]any{"Environment": "x"}}
	for range 20 {
		if c := contract.CodeOf(CheckForbidden(v)); c != contract.CodeForbiddenField {
			t.Fatalf("got %q", c)
		}
	}
	if c := contract.CodeOf(CheckForbidden(map[string]any{"title": []any{"ok", "PATH=/x HOME=/y USER=z"}})); c != contract.CodeForbiddenContent {
		t.Fatalf("got %q", c)
	}
	for _, f := range []string{"schema", "report_id", "hostname", "agent_key_id", "fix_command", "evidence", "setting", "value", "packages", "unreadable", "needs", "inventory", "parent", "gateway", "nonce", "code", "keyid", "public_key"} {
		if IsForbiddenField(f) {
			t.Errorf("contract field %s is in the forbidden list", f)
		}
	}
}

func TestCheckReportDuplicates(t *testing.T) {
	f := func(id, subj string) any {
		m := map[string]any{"id": id}
		if subj != "" {
			m["subject"] = subj
		}
		return m
	}
	if err := CheckReport(map[string]any{"findings": []any{f("ports.public_service", "tcp/22"), f("ports.public_service", "tcp/80"), f("ssh.x", "")}}); err != nil {
		t.Fatal(err)
	}
	if contract.CodeOf(CheckReport(map[string]any{"findings": []any{f("ssh.x", ""), f("ssh.x", "")}})) != contract.CodeSchema {
		t.Fatal("duplicate not caught")
	}
}
