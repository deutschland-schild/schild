package geo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/config"
)

func TestPreflightNotes(t *testing.T) {
	if PreflightNotes(config.Geo{Provider: "dbip"}, os.Getenv) != nil {
		t.Fatal("dbip has no geo download notes")
	}
	f := filepath.Join(t.TempDir(), "maxmind.token")
	if err := os.WriteFile(f, []byte(testMMAccount+":"+testMMKey+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := config.Geo{DBPath: "/var/lib/schild/geo/geo.mmdb", Provider: "maxmind", TokenFile: f, Database: []string{"GeoLite2-Country"}, RefreshHours: 24}
	out := strings.Join(PreflightNotes(g, func(string) string { return "" }), "\n")
	if !strings.Contains(out, "readable by other users") || !strings.Contains(out, "ok        geo token from token_file") {
		t.Fatalf("notes:\n%s", out)
	}
	g.TokenFile = ""
	out += strings.Join(PreflightNotes(g, func(k string) string { return "garbage-no-colon" }), "\n")
	if !strings.Contains(out, "WARN      geo token ($SCHILD_GEO_TOKEN)") {
		t.Fatalf("notes:\n%s", out)
	}
	for _, s := range []string{testMMKey, "garbage-no-colon"} {
		if strings.Contains(out, s) {
			t.Fatalf("token in preflight output:\n%s", out)
		}
	}
}
