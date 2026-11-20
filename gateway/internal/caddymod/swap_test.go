package caddymod

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func adaptText(t *testing.T, caddyfile string) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(p, []byte(caddyfile), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _, err := ReadCaddyfile(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestSwapHelpers: what `schild init -caddyfile` reads from an adapted
// Caddyfile: its storage root, its log files and whether HTTP/3 is on.
func TestSwapHelpers(t *testing.T) {
	plain := adaptText(t, "a.example.de {\n\trespond \"a\"\n}\n")
	if FileStorageRoot(plain) != "" || LogFiles(plain) != nil || !HTTP3Open(plain) {
		t.Errorf("plain: storage %q logs %v h3 %v", FileStorageRoot(plain), LogFiles(plain), HTTP3Open(plain))
	}
	full := adaptText(t, "{\n\tstorage file_system /srv/store\n\tservers {\n\t\tprotocols h1 h2\n\t}\n}\n"+
		"a.example.de {\n\tlog {\n\t\toutput file /var/log/caddy/a.log\n\t}\n\trespond \"a\"\n}\n"+
		"b.example.de {\n\tlog {\n\t\toutput stdout\n\t}\n\trespond \"b\"\n}\n")
	if got := FileStorageRoot(full); got != "/srv/store" {
		t.Errorf("storage root %q", got)
	}
	if got := LogFiles(full); !reflect.DeepEqual(got, []string{"/var/log/caddy/a.log"}) {
		t.Errorf("log files %v", got)
	}
	if HTTP3Open(full) {
		t.Error("protocols h1 h2 counted as HTTP/3")
	}
	socks := adaptText(t, "a.example.de {\n\tphp_fastcgi unix//run/php/php-fpm.sock\n\thandle /api/* {\n\t\treverse_proxy unix//run/app.sock 127.0.0.1:3000\n\t}\n}\n")
	if got := UnixSockets(socks); !reflect.DeepEqual(got, []string{"/run/app.sock", "/run/php/php-fpm.sock"}) {
		t.Errorf("unix sockets %v", got)
	}
	if httpOnly := adaptText(t, "http://a.example.de {\n\trespond \"a\"\n}\n"); HTTP3Open(httpOnly) {
		t.Error("a plain HTTP site counted as HTTP/3")
	}
}
