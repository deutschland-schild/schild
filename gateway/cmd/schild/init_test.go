package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/preflight"
	"github.com/deutschland-schild/schild/gateway/internal/app"
)

func host(name string) func() (string, error) {
	return func() (string, error) { return name, nil }
}

// TestInitWritesAValidConfig: the file `schild init` writes loads with the
// loader of `schild run`, passes the preflight and has the four keys of the
// starter config with the defaults of everything else.
func TestInitWritesAValidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "schild", "schild.yaml")
	var out bytes.Buffer
	if err := runInit(&out, path, "http://127.0.0.1:3000", "", false, host("Web-1.example.net")); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := app.LoadConfig(path)
	if err != nil {
		t.Fatalf("schild run would not load the file: %v", err)
	}
	if err := preflight.Site(cfg).Err(); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if cfg.ModeWarning() != "" || cfg.NodeName != "web-1" || cfg.Upstream.URL != "http://127.0.0.1:3000" || cfg.CaddyIngress() {
		t.Fatalf("config: mode %q node %q upstream %q", cfg.LegacyMode, cfg.NodeName, cfg.Upstream.URL)
	}
	if cfg.Listen.Dashboard != "127.0.0.1:8788" || !app.Loopback(cfg.Listen.Dashboard) {
		t.Fatalf("dashboard not on loopback: %q", cfg.Listen.Dashboard)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, want 0644 (%v)", fi.Mode().Perm(), err)
	}
	if di, err := os.Stat(filepath.Dir(path)); err != nil || di.Mode().Perm()&0o022 != 0 {
		t.Fatalf("directory writable by others: %v (%v)", di.Mode().Perm(), err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "wrote "+path) {
		t.Fatalf("output:\n%s", out.String())
	}
	for i, want := range []string{"schild run -config " + path, "http://127.0.0.1:8788", "schild dashboard setup-code"} {
		if !strings.Contains(lines[i+1], want) {
			t.Errorf("next step %d %q lacks %q", i+1, lines[i+1], want)
		}
	}
}

// TestInitKeepsAnExistingFile: without -force nothing is overwritten, with
// it the file is replaced.
func TestInitKeepsAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schild.yaml")
	if err := os.WriteFile(path, []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runInit(&out, path, initUpstream, "gw", false, host("x"))
	if err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("existing file: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "mine\n" || out.Len() != 0 {
		t.Fatalf("file touched or output written: %q %q", b, out.String())
	}
	if err := runInit(&out, path, initUpstream, "gw", true, host("x")); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadSite(path)
	if err != nil || cfg.NodeName != "gw" {
		t.Fatalf("after -force: %v %+v", err, cfg)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode after -force: %v", fi.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".schild.yaml.*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

// TestInitDoesNotFollowADanglingLink: a symlink at the path counts as an
// existing file, so init never writes through it.
func TestInitDoesNotFollowADanglingLink(t *testing.T) {
	dir := t.TempDir()
	path, target := filepath.Join(dir, "schild.yaml"), filepath.Join(dir, "elsewhere")
	if err := os.Symlink(target, path); err != nil {
		t.Skip(err)
	}
	if err := runInit(&bytes.Buffer{}, path, initUpstream, "gw", false, host("x")); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("link target created: %v", err)
	}
}

// TestInitRefusesBadInput: nothing is written when the values would not
// give a valid schild.yaml.
func TestInitRefusesBadInput(t *testing.T) {
	for name, c := range map[string]struct{ upstream, node string }{
		"no scheme":       {"127.0.0.1:3000", "gw"},
		"other scheme":    {"ftp://app", "gw"},
		"yaml in the url": {"http://app\"\nmode: autoblock", "gw"},
		"upper case node": {initUpstream, "Web"},
		"yaml in node":    {initUpstream, "gw\nmode: autoblock"},
		"long node":       {initUpstream, strings.Repeat("a", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "schild.yaml")
			if err := runInit(&bytes.Buffer{}, path, c.upstream, c.node, false, host("x")); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("file written: %v", err)
			}
		})
	}
}

func TestInitDefaults(t *testing.T) {
	for in, want := range map[string]string{"web-1": "web-1", "Web-1.example.net": "web-1", "my_host": initNodeName, "": initNodeName, "-x": initNodeName} {
		if got := defaultNodeName(host(in)); got != want {
			t.Errorf("node name of host %q: %q, want %q", in, got, want)
		}
	}
	if got := defaultNodeName(func() (string, error) { return "", errors.New("no name") }); got != initNodeName {
		t.Errorf("without a host name: %q", got)
	}
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == config.SitePathEnv {
				return v
			}
			return ""
		}
	}
	// The same order as `schild run` (app.LoadConfig).
	if got := configPath("", env("")); got != config.SitePathDefault {
		t.Errorf("default path %q", got)
	}
	if got := configPath("", env("/srv/schild.yaml")); got != "/srv/schild.yaml" {
		t.Errorf("path from the environment %q", got)
	}
	if got := configPath("/x/schild.yaml", env("/srv/schild.yaml")); got != "/x/schild.yaml" {
		t.Errorf("path from the flag %q", got)
	}
}
