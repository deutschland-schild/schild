package caddymod

import (
	"slices"
	"strings"
	"testing"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/storage"
)

const wantRollWarning = "log_roll_disabled: output file /var/log/caddy/access.log uses roll_disabled; the embedded Caddy does not reopen it, so the logrotate rule needs copytruncate (schild check: logs.logrotate_config)"

// TestLogRollDisabled (D38 section 6): every `output file <path>` with
// roll_disabled is one log_roll_disabled warning (once per path), files
// that Caddy rolls itself and other outputs are not, and the warning never
// turns into an error.
func TestLogRollDisabled(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "Caddyfile", `{
	log {
		output file /var/log/caddy/global.log {
			roll_disabled
		}
	}
}
(access_log) {
	log {
		output file /var/log/caddy/access.log {
			roll_disabled
		}
		format json
	}
}
http://a.example.test {
	schild
	import access_log
	reverse_proxy 127.0.0.1:9
}
http://b.example.test {
	schild
	import access_log
	reverse_proxy 127.0.0.1:9
}
http://c.example.test {
	schild
	log {
		output file /var/log/caddy/rolled.log
	}
	reverse_proxy 127.0.0.1:9
}
http://d.example.test {
	schild
	log {
		output stderr
	}
	reverse_proxy 127.0.0.1:9
}
`)
	ing, err := PrepareIngress(IngressOptions{Caddyfile: p, DefaultStorage: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/var/log/caddy/access.log", "/var/log/caddy/global.log"}; !slices.Equal(ing.Check.RollDisabled, want) {
		t.Fatalf("roll disabled: %v", ing.Check.RollDisabled)
	}
	var got []string
	for _, w := range ing.Check.Warnings {
		if strings.HasPrefix(w, storage.WarnLogRollDisabled+":") {
			got = append(got, w)
		}
	}
	if len(got) != 2 || got[0] != wantRollWarning || !strings.Contains(got[1], "output file /var/log/caddy/global.log uses roll_disabled") {
		t.Fatalf("warnings: %q", ing.Check.Warnings)
	}
	if len(ing.Check.Errors) != 0 {
		t.Fatalf("errors: %v", ing.Check.Errors)
	}
}

// TestLogrotateSuggestion: the suggested rule uses copytruncate and is a
// valid rendering of the host check template, so `schild check` accepts
// it as fix_config of logs.logrotate_config.
func TestLogrotateSuggestion(t *testing.T) {
	fix := LogrotateSuggestion("/var/log/caddy/access.log")
	if fix.Path != "/etc/logrotate.d/schild-caddy-access" {
		t.Fatalf("path %q", fix.Path)
	}
	want := "/var/log/caddy/access.log {\n  daily\n  rotate 14\n  maxsize 200M\n  missingok\n  notifempty\n  compress\n  delaycompress\n  copytruncate\n}\n"
	if fix.Content != want {
		t.Fatalf("content %q", fix.Content)
	}
	for _, p := range []string{"/var/log/caddy/access.log", "/srv/shop/logs/Caddy_Access.log", "/var/log/" + strings.Repeat("x", 60) + ".log"} {
		fix := LogrotateSuggestion(p)
		if !hc.FixConfigKnown("logs.logrotate_config", fix.Path, fix.Content) {
			t.Fatalf("not a template rendering: %+v", fix)
		}
	}
	if fix := LogrotateSuggestion("/srv/shop/logs/Caddy_Access.log"); fix.Path != "/etc/logrotate.d/schild-caddy-caddy-access" {
		t.Fatalf("slug: %q", fix.Path)
	}
}
