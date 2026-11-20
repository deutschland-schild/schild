package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/preflight"
	"github.com/deutschland-schild/schild/gateway/internal/app"
)

const (
	swapCaddyfileBare = "a.example.de {\n\treverse_proxy 127.0.0.1:3000\n}\n\nb.example.de {\n\treverse_proxy 127.0.0.1:3001\n}\n\nstatic.example.de {\n\troot * /srv/static\n\tfile_server\n}\n"
	swapCaddyfileDone = "(schild) {\n\tschild\n}\n\na.example.de {\n\timport schild\n\treverse_proxy 127.0.0.1:3000\n}\n"
)

// swapInput writes a Caddyfile and returns the inputs of
// `schild init -caddyfile` for it, with no storage candidates.
func swapInput(t *testing.T, caddyfile string) caddyInit {
	t.Helper()
	dir := t.TempDir()
	cf := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cf, []byte(caddyfile), 0o644); err != nil {
		t.Fatal(err)
	}
	return caddyInit{Path: filepath.Join(dir, "etc", "schild.yaml"), Caddyfile: cf, Hostname: host("Web-1.example.net"), Candidates: []string{}}
}

// TestInitFlagConflict: the Caddy swap and the proxy behind a web server
// are two setups; their flags do not mix.
func TestInitFlagConflict(t *testing.T) {
	for name, c := range map[string]struct {
		set  []string
		want string
	}{
		"swap":              {[]string{"caddyfile", "caddy-storage", "config", "force", "node-name"}, ""},
		"proxy":             {[]string{"upstream", "config"}, ""},
		"neither":           {nil, ""},
		"both":              {[]string{"caddyfile", "upstream"}, "exclude each other"},
		"storage, no caddy": {[]string{"caddy-storage"}, "needs -caddyfile"},
	} {
		set := map[string]bool{}
		for _, f := range c.set {
			set[f] = true
		}
		err := initFlagConflict(set)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// TestInitCaddyWritesAValidConfig: the file loads with the loader of
// `schild run` as an ingress config in observe mode with the production
// profile and the dashboard on loopback; the Caddyfile is not touched.
func TestInitCaddyWritesAValidConfig(t *testing.T) {
	o := swapInput(t, swapCaddyfileBare)
	var out bytes.Buffer
	if err := runInitCaddy(&out, o); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := app.LoadConfig(o.Path)
	if err != nil {
		t.Fatalf("schild run would not load the file: %v", err)
	}
	if err := preflight.Site(cfg).Err(); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if !cfg.CaddyIngress() || cfg.Ingress.Caddyfile != o.Caddyfile || cfg.Ingress.CaddyStorage != caddySwapStorage {
		t.Fatalf("ingress: %+v", cfg.Ingress)
	}
	if cfg.ModeWarning() != "" || cfg.Profile != "production" || cfg.NodeName != "web-1" || cfg.Upstream.URL != "" {
		t.Fatalf("config: mode %q profile %q node %q upstream %q", cfg.LegacyMode, cfg.Profile, cfg.NodeName, cfg.Upstream.URL)
	}
	if !app.Loopback(cfg.Listen.Dashboard) {
		t.Fatalf("dashboard not on loopback: %q", cfg.Listen.Dashboard)
	}
	if fi, err := os.Stat(o.Path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode: %v (%v)", fi.Mode().Perm(), err)
	}
	if b, _ := os.ReadFile(o.Caddyfile); string(b) != swapCaddyfileBare {
		t.Fatal("init changed the Caddyfile")
	}
}

// TestInitCaddyOutput: every site with its state, the exact lines to add
// for the sites that reach a backend, the swap and the way back.
func TestInitCaddyOutput(t *testing.T) {
	o := swapInput(t, swapCaddyfileBare)
	var out bytes.Buffer
	if err := runInitCaddy(&out, o); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"wrote " + o.Path + " (Caddyfile " + o.Caddyfile + ", node_name web-1)",
		"site      a.example.de: WITHOUT schild: reverse_proxy 127.0.0.1:3000",
		"site      b.example.de: WITHOUT schild: reverse_proxy 127.0.0.1:3001",
		"site      static.example.de: files without schild",
		"add to " + o.Caddyfile + " (schild never edits your Caddyfile)",
		"        (schild) {\n        \tschild\n        }\n",
		"        import schild\n      - a.example.de\n      - b.example.de\n      - static.example.de (serves files only: optional)\n",
		"result: REFUSE (Caddyfile)",
		"No Caddy storage found",
		"1. Caddyfile:    add the lines above to " + o.Caddyfile,
		"2. check:        sudo -u schild schild ingress validate -config " + o.Path,
		"3. swap:         sudo systemctl disable --now caddy && sudo systemctl enable --now schild",
		"5. setup code:   sudo schild dashboard setup-code -config " + o.Path,
		"way back: put a \"#\" in front of the line \"schild\" in the (schild) snippet",
		"sudo systemctl disable --now schild && sudo systemctl enable --now caddy",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(got, "cp -a") {
		t.Errorf("copy commands without a storage:\n%s", got)
	}

	// A Caddyfile that is ready: PASS, nothing to add, and the snippet is
	// not offered again when only one site lacks the import.
	o = swapInput(t, swapCaddyfileDone)
	out.Reset()
	if err := runInitCaddy(&out, o); err != nil {
		t.Fatal(err)
	}
	got = out.String()
	if !strings.Contains(got, "site      a.example.de: schild") || !strings.Contains(got, "result: PASS (Caddyfile)") ||
		strings.Contains(got, "add to ") || strings.Contains(got, "Caddyfile:    add") || !strings.Contains(got, "1. check:") {
		t.Errorf("ready Caddyfile:\n%s", got)
	}
	o = swapInput(t, swapCaddyfileDone+"\nb.example.de {\n\treverse_proxy 127.0.0.1:3001\n}\n")
	out.Reset()
	if err := runInitCaddy(&out, o); err != nil {
		t.Fatal(err)
	}
	got = out.String()
	if strings.Contains(got, "(schild) {") || !strings.Contains(got, "      - b.example.de\n") || strings.Contains(got, "      - a.example.de") {
		t.Errorf("one site left:\n%s", got)
	}
}

// TestInitCaddyStorage: the flag wins, then the storage option of the
// Caddyfile, then the first usual place that exists; the copy commands
// name the source that was taken.
func TestInitCaddyStorage(t *testing.T) {
	base := t.TempDir()
	first, second, flagDir := filepath.Join(base, "pkg"), filepath.Join(base, "image"), filepath.Join(base, "my storage")
	for _, d := range []string{second, flagDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	run := func(caddyfile string, change func(*caddyInit)) string {
		t.Helper()
		o := swapInput(t, caddyfile)
		o.Candidates = []string{first, second}
		change(&o)
		var out bytes.Buffer
		if err := runInitCaddy(&out, o); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	// first does not exist: the second candidate is taken and named.
	got := run(swapCaddyfileDone, func(*caddyInit) {})
	for _, want := range []string{
		"Caddy's storage: " + second + " (found)",
		"    sudo mkdir -p /var/lib/schild/caddy\n    sudo cp -a " + second + "/. /var/lib/schild/caddy/\n    sudo chown -R schild:schild /var/lib/schild/caddy\n",
		"1. certificates: run the copy commands above",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("detected storage: output lacks %q\n%s", want, got)
		}
	}
	// Both exist: the first wins.
	if err := os.Mkdir(first, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := run(swapCaddyfileDone, func(*caddyInit) {}); !strings.Contains(got, "Caddy's storage: "+first+" (found)") {
		t.Errorf("order of the candidates:\n%s", got)
	}
	// The storage option of the Caddyfile wins over the usual places.
	own := "{\n\tstorage file_system /srv/caddy-storage\n}\n" + swapCaddyfileDone
	if got := run(own, func(*caddyInit) {}); !strings.Contains(got, "Caddy's storage: /srv/caddy-storage (the storage option of the Caddyfile)") {
		t.Errorf("storage of the Caddyfile:\n%s", got)
	}
	// The flag wins over both; a name with a space is quoted for the shell.
	got = run(own, func(o *caddyInit) { o.Storage = flagDir })
	if !strings.Contains(got, "Caddy's storage: "+flagDir+" (-caddy-storage)") || !strings.Contains(got, "sudo cp -a '"+flagDir+"/.' /var/lib/schild/caddy/") {
		t.Errorf("-caddy-storage:\n%s", got)
	}
}

// TestInitCaddyRefuses: without a usable Caddyfile, storage or name nothing
// is written; an existing schild.yaml is kept.
func TestInitCaddyRefuses(t *testing.T) {
	for name, c := range map[string]struct {
		caddyfile string
		change    func(*caddyInit)
		want      string
	}{
		"missing Caddyfile":   {swapCaddyfileDone, func(o *caddyInit) { o.Caddyfile += ".nope" }, "no such file"},
		"broken Caddyfile":    {"a.example.de {\n\tno_such_directive\n}\n", func(*caddyInit) {}, "no_such_directive"},
		"storage not a dir":   {swapCaddyfileDone, func(o *caddyInit) { o.Storage = o.Caddyfile }, "not a directory"},
		"storage missing":     {swapCaddyfileDone, func(o *caddyInit) { o.Storage = o.Caddyfile + ".d" }, "not a directory"},
		"upper case node":     {swapCaddyfileDone, func(o *caddyInit) { o.NodeName = "Web" }, "-node-name"},
		"yaml in node":        {swapCaddyfileDone, func(o *caddyInit) { o.NodeName = "gw\nmode: autoblock" }, "-node-name"},
		"yaml in the file":    {swapCaddyfileDone, func(o *caddyInit) { o.Caddyfile += "\"\nmode: autoblock\n#" }, ""},
		"newline in the file": {swapCaddyfileDone, func(o *caddyInit) { o.Caddyfile += "\nx" }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			o := swapInput(t, c.caddyfile)
			c.change(&o)
			var out bytes.Buffer
			err := runInitCaddy(&out, o)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want %q", err, c.want)
			}
			if _, statErr := os.Stat(o.Path); statErr == nil || out.Len() != 0 {
				t.Fatalf("file written or output printed: %q", out.String())
			}
		})
	}

	o := swapInput(t, swapCaddyfileDone)
	if err := os.MkdirAll(filepath.Dir(o.Path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.Path, []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runInitCaddy(&out, o); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("existing file: %v", err)
	}
	if b, _ := os.ReadFile(o.Path); string(b) != "mine\n" || out.Len() != 0 {
		t.Fatalf("file touched or output written: %q %q", b, out.String())
	}
	o.Force = true
	if err := runInitCaddy(&out, o); err != nil {
		t.Fatal(err)
	}
	if cfg, _, err := app.LoadConfig(o.Path); err != nil || !cfg.CaddyIngress() {
		t.Fatalf("after -force: %v", err)
	}
}

// TestIngressValidateAdvice: `schild ingress validate` prints the lines to
// add when a site lacks the directive, and counts the stored certificates.
func TestIngressValidateAdvice(t *testing.T) {
	bad := writeStandalone(t, "http://shop.example.de:18080 {\n\treverse_proxy 127.0.0.1:9\n}\n")
	out := captureStdout(t, func() { _ = cmdIngress([]string{"validate", "-config", bad, "-adapt-only"}) })
	if !strings.Contains(out, "        import schild\n      - shop.example.de\n") || !strings.Contains(out, "(schild) {") {
		t.Errorf("no advice:\n%s", out)
	}
	good := writeStandalone(t, swapCaddyfileDoneHTTP)
	out = captureStdout(t, func() { _ = cmdIngress([]string{"validate", "-config", good, "-adapt-only"}) })
	if strings.Contains(out, "add to ") || strings.Contains(out, "certificates:") {
		t.Errorf("ready Caddyfile, empty storage, -adapt-only:\n%s", out)
	}
	cert := filepath.Join(filepath.Dir(good), "caddy", "certificates", "local", "shop.example.de")
	if err := os.MkdirAll(cert, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cert, "shop.example.de.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// -adapt-only never looks at the storage, with or without certificates.
	out = captureStdout(t, func() { _ = cmdIngress([]string{"validate", "-config", good, "-adapt-only"}) })
	if strings.Contains(out, "certificates:") || !strings.Contains(out, "not checked: data directory, certificate storage") || !strings.HasSuffix(out, "result: PASS (Caddyfile)\n") || strings.Count(out, "result:") != 1 {
		t.Errorf("-adapt-only looked at the storage:\n%s", out)
	}
	out = captureStdout(t, func() { _ = cmdIngress([]string{"validate", "-config", good}) })
	if !strings.Contains(out, "certificates: 1 in ") || !strings.HasSuffix(out, "result: PASS\n") || strings.Count(out, "result:") != 1 {
		t.Errorf("stored certificate not counted:\n%s", out)
	}
}

// TestIngressValidateStorageAccess: a certificate storage that exists but
// that the user cannot read and write (a copy of Caddy's storage that still
// belongs to caddy) keeps schild from starting. `schild ingress validate`
// refuses it with the chown command, in one stream, and never says "ok".
func TestIngressValidateStorageAccess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may read everything")
	}
	cfg := writeStandalone(t, swapCaddyfileDoneHTTP)
	root := filepath.Join(filepath.Dir(cfg), "caddy")
	old := readUnitSandbox
	defer func() { readUnitSandbox = old }()
	readUnitSandbox = func() unitSandbox { return unitSandbox{Known: true, Strict: true} }
	pki := filepath.Join(root, "pki", "authorities", "local")
	cert := filepath.Join(root, "certificates", "local", "shop.example.de")
	for _, d := range []string{pki, cert} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(pki, "root.key")
	for _, f := range []string{key, filepath.Join(pki, "root.crt"), filepath.Join(cert, "shop.example.de.crt")} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func() (string, error) {
		var err error
		out := captureStdout(t, func() { err = cmdIngress([]string{"validate", "-config", cfg}) })
		return out, err
	}
	if out, err := run(); err != nil || !strings.Contains(out, "readable and writable for this user") || !strings.HasSuffix(out, "result: PASS\n") {
		t.Fatalf("own storage: %v\n%s", err, out)
	}
	cases := []struct {
		name string
		path string
		mode os.FileMode
		back os.FileMode
		read bool // what the user cannot do: read (else: write)
	}{
		{"storage directory closed", root, 0o000, 0o700, true},
		{"storage directory read-only", root, 0o500, 0o700, false},
		{"directory inside closed", pki, 0o000, 0o700, true},
		{"key unreadable", key, 0o000, 0o600, true},
		{"key read-only", key, 0o400, 0o600, false},
	}
	const cannotRead = "schild cannot load what is in there, so it would not start or the sites would fail"
	const cannotWrite = "schild starts, but could not renew or store certificates"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.Chmod(c.path, c.mode); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(c.path, c.back)
			out, err := run()
			if err == nil || !errors.As(err, new(reportedError)) {
				t.Fatalf("accepted (%v):\n%s", err, out)
			}
			verb, consequence := "cannot write ", cannotWrite
			if c.read {
				verb, consequence = "cannot read ", cannotRead
			}
			for _, want := range []string{"  REFUSE    certificate storage " + root + ": this user " + verb + c.path + " (", "sudo chown -R ", " " + root + "\n", "result: REFUSE (certificate storage); " + consequence + "\n"} {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			// The reason is the true one: "would not start" only where
			// schild cannot read.
			if !c.read && strings.Contains(out, "would not start") {
				t.Errorf("read-only storage, but the output says schild would not start:\n%s", out)
			}
			if strings.Count(out, "result:") != 1 {
				t.Errorf("more than one result line:\n%s", out)
			}
			for _, not := range []string{"file access: ok", "result: PASS\n", "caddy provisioning: valid"} {
				if strings.Contains(out, not) {
					t.Errorf("output has %q:\n%s", not, out)
				}
			}
			// The Caddyfile alone is still fine.
			if err := cmdIngress([]string{"validate", "-config", cfg, "-adapt-only"}); err != nil {
				t.Errorf("-adapt-only: %v", err)
			}
		})
	}
	// In a container the user has no name and there is no sudo.
	readUnitSandbox = func() unitSandbox { return unitSandbox{None: true} }
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatal(err)
	}
	out, err := run()
	_ = os.Chmod(root, 0o700)
	if want := fmt.Sprintf(": chown -R %d:%d %s (as root", os.Getuid(), os.Getgid(), root); err == nil || !strings.Contains(out, want) {
		t.Errorf("container: %v, output lacks %q:\n%s", err, want, out)
	}
	// A storage that does not exist yet is created by schild.
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if out, err := run(); err != nil || !strings.Contains(out, "certificates: none in ") {
		t.Fatalf("no storage yet: %v\n%s", err, out)
	}
}

// TestIngressValidateUnitSandbox: file permissions are half of it under
// systemd. A log file outside the ReadWritePaths of schild.service is
// refused with the drop-in when systemctl shows the unit, and is a visible
// warning ("PASS with warnings") when the unit cannot be read.
func TestIngressValidateUnitSandbox(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the check as root ends with its own warning")
	}
	logs := filepath.Join(t.TempDir(), "my-sites")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(logs, "access.log")
	cfg := writeStandalone(t, "(schild) {\n\tschild\n}\nhttp://shop.example.de:18080 {\n\timport schild\n\tlog {\n\t\toutput file "+logFile+"\n\t}\n\treverse_proxy 127.0.0.1:9\n}\n")
	old := readUnitSandbox
	defer func() { readUnitSandbox = old }()
	run := func(u unitSandbox) (string, error) {
		readUnitSandbox = func() unitSandbox { return u }
		var err error
		out := captureStdout(t, func() { err = cmdIngress([]string{"validate", "-config", cfg}) })
		return out, err
	}
	shipped := []string{"/var/lib/schild", "/var/log/caddy"}

	out, err := run(unitSandbox{Known: true, Strict: true, Paths: shipped})
	if err == nil || !errors.As(err, new(reportedError)) {
		t.Fatalf("log file outside ReadWritePaths accepted:\n%s", out)
	}
	for _, want := range []string{"  REFUSE    log file " + logFile + ": schild.service may not write to " + logs, "sudo systemctl edit schild", "ReadWritePaths=" + logs, "result: REFUSE (file access); schild would not start\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "file access: ok") {
		t.Errorf("refusal says ok:\n%s", out)
	}

	out, err = run(unitSandbox{Known: true, Strict: true, Paths: append([]string{filepath.Dir(logs)}, shipped...)})
	if err != nil || !strings.Contains(out, "is inside what schild.service may write") || !strings.HasSuffix(out, "result: PASS\n") {
		t.Fatalf("drop-in in place: %v\n%s", err, out)
	}

	out, err = run(unitSandbox{Known: true})
	if err != nil || !strings.HasSuffix(out, "result: PASS\n") {
		t.Fatalf("unit without ProtectSystem=strict: %v\n%s", err, out)
	}

	// No systemd (a container): no unit, nothing to warn about.
	out, err = run(unitSandbox{None: true})
	if err != nil || strings.Contains(out, "warning") || !strings.HasSuffix(out, "result: PASS\n") {
		t.Fatalf("no systemd: %v\n%s", err, out)
	}

	out, err = run(unitSandbox{})
	if err != nil {
		t.Fatalf("unit unknown: %v\n%s", err, out)
	}
	for _, want := range []string{"  warning   log file " + logFile, "ReadWritePaths=" + logs, "result: PASS with warnings (1, see the lines above)\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "result: PASS\n") {
		t.Errorf("a warning, but a plain PASS:\n%s", out)
	}
	if !strings.Contains(out, "could not be read as this user") {
		t.Errorf("unreadable unit, other wording:\n%s", out)
	}

	// systemd runs, but there is no schild.service: say so, do not send
	// the admin to root for a unit that is not there.
	out, err = run(unitSandbox{Absent: true})
	if err != nil || !strings.Contains(out, "schild.service is not installed on this system, so its sandbox was not checked") ||
		strings.Contains(out, "could not be read") || strings.Contains(out, "Root can read") || !strings.HasSuffix(out, "result: PASS with warnings (1, see the lines above)\n") {
		t.Fatalf("unit not installed: %v\n%s", err, out)
	}
}

// TestIngressValidateDataDir: schild keeps gateway.lock and its databases
// in the data directory. A directory this user cannot write is refused
// before the swap, with the chown for the whole directory; in a container
// that one chown also covers a certificate storage inside it.
func TestIngressValidateDataDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may write everywhere")
	}
	cfg := writeStandalone(t, swapCaddyfileDoneHTTP)
	dir := filepath.Dir(cfg)
	data := filepath.Join(dir, "data")
	// The storage inside the data directory, as in the image.
	storage := filepath.Join(data, "caddy")
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte(strings.Replace(string(b), "storage: "+filepath.Join(dir, "caddy"), "storage: "+storage, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(storage, 0o700); err != nil {
		t.Fatal(err)
	}
	old := readUnitSandbox
	defer func() { readUnitSandbox = old }()
	run := func(u unitSandbox) (string, error) {
		readUnitSandbox = func() unitSandbox { return u }
		var err error
		out := captureStdout(t, func() { err = cmdIngress([]string{"validate", "-config", cfg}) })
		return out, err
	}
	container := unitSandbox{None: true}
	if out, err := run(container); err != nil || !strings.HasSuffix(out, "result: PASS\n") {
		t.Fatalf("own data directory: %v\n%s", err, out)
	}
	if left, _ := os.ReadDir(data); len(left) != 1 {
		t.Fatalf("validate left files in the data directory: %v", left)
	}
	numeric := fmt.Sprintf("chown -R %d:%d %s (as root, in a container that mounts the volume)\n", os.Getuid(), os.Getgid(), data)

	// The storage belongs to the user, the volume root does not: what is
	// left after a chown of the storage alone.
	if err := os.Chmod(data, 0o555); err != nil {
		t.Fatal(err)
	}
	out, err := run(container)
	if err == nil || !errors.As(err, new(reportedError)) {
		t.Fatalf("read-only data directory accepted:\n%s", out)
	}
	for _, want := range []string{"  REFUSE    data directory " + data + ": this user cannot read and write it", numeric, "result: REFUSE (data directory); schild would not start\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "caddy provisioning") || strings.Count(out, "result:") != 1 {
		t.Errorf("refusal went on:\n%s", out)
	}
	// On a host the command has sudo and a name.
	if out, _ := run(unitSandbox{Known: true}); !strings.Contains(out, "sudo chown -R ") || !strings.Contains(out, " "+data+"\n") {
		t.Errorf("host wording:\n%s", out)
	}
	// The StateDirectory of the unit is handed over by systemd at start.
	if out, err := run(unitSandbox{Known: true, State: []string{data}}); err != nil {
		t.Errorf("StateDirectory refused: %v\n%s", err, out)
	}
	_ = os.Chmod(data, 0o755)

	// A lock file the user cannot open.
	lock := filepath.Join(data, "gateway.lock")
	if err := os.WriteFile(lock, nil, 0o400); err != nil {
		t.Fatal(err)
	}
	if out, err := run(container); err == nil || !strings.Contains(out, "cannot read and write "+lock) || !strings.Contains(out, "result: REFUSE (data directory)") {
		t.Errorf("read-only lock file: %v\n%s", err, out)
	}
	_ = os.Remove(lock)

	// A storage that is not the user's, inside the data directory: in a
	// container the chown names the data directory, as the documented copy
	// command does, so following it leaves nothing behind.
	if err := os.Chmod(storage, 0o500); err != nil {
		t.Fatal(err)
	}
	out, err = run(container)
	_ = os.Chmod(storage, 0o700)
	if err == nil || !strings.Contains(out, "REFUSE    certificate storage "+storage) || !strings.Contains(out, numeric) || strings.Contains(out, " "+storage+" (as root") {
		t.Errorf("container, storage in the data directory: %v\n%s", err, out)
	}

	// No data directory yet: fine where the user can create it.
	if err := os.RemoveAll(data); err != nil {
		t.Fatal(err)
	}
	if out, err := run(container); err != nil {
		t.Errorf("no data directory yet: %v\n%s", err, out)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)
	if out, err := run(container); err == nil || !strings.Contains(out, "it does not exist and this user cannot create it in ") || !strings.Contains(out, "mkdir -p "+data+" && chown -R ") {
		t.Errorf("data directory cannot be created: %v\n%s", err, out)
	}
}

// TestIngressValidateStorageLink: a certificate storage that is a symbolic
// link is checked where it points.
func TestIngressValidateStorageLink(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may read everything")
	}
	cfg := writeStandalone(t, swapCaddyfileDoneHTTP)
	root := filepath.Join(filepath.Dir(cfg), "caddy")
	target := filepath.Join(t.TempDir(), "real")
	cert := filepath.Join(target, "certificates", "local", "shop.example.de")
	if err := os.MkdirAll(cert, 0o700); err != nil {
		t.Fatal(err)
	}
	crt := filepath.Join(cert, "shop.example.de.crt")
	if err := os.WriteFile(crt, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A link inside the storage is not followed.
	if err := os.Symlink("/nonexistent", filepath.Join(target, "stray")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	old := readUnitSandbox
	defer func() { readUnitSandbox = old }()
	readUnitSandbox = func() unitSandbox { return unitSandbox{Known: true} }
	run := func() (string, error) {
		var err error
		out := captureStdout(t, func() { err = cmdIngress([]string{"validate", "-config", cfg}) })
		return out, err
	}
	if out, err := run(); err != nil || !strings.Contains(out, "certificates: 1 in "+root+", readable and writable") || !strings.HasSuffix(out, "result: PASS\n") {
		t.Fatalf("link to an own storage: %v\n%s", err, out)
	}
	if err := os.Chmod(crt, 0o000); err != nil {
		t.Fatal(err)
	}
	out, err := run()
	_ = os.Chmod(crt, 0o600)
	if err == nil || !strings.Contains(out, "this user cannot read "+filepath.Join(root, "certificates", "local", "shop.example.de", "shop.example.de.crt")) || strings.Contains(out, "certificates:") {
		t.Fatalf("link to a storage with an unreadable file: %v\n%s", err, out)
	}
	if err := os.Chmod(target, 0o000); err != nil {
		t.Fatal(err)
	}
	out, err = run()
	_ = os.Chmod(target, 0o700)
	if err == nil || !strings.Contains(out, "result: REFUSE (certificate storage)") || strings.Contains(out, "none in") {
		t.Fatalf("link to a closed storage: %v\n%s", err, out)
	}
	// A link to nowhere.
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	if out, err := run(); err == nil || !strings.Contains(out, "it is a link this user cannot follow") || !strings.Contains(out, "schild would not start") || strings.Contains(out, "chown") {
		t.Fatalf("dangling link: %v\n%s", err, out)
	}
}

// TestBelowResolvesLinks: a log path through a symbolic link is judged by
// where it really is.
func TestBelowResolvesLinks(t *testing.T) {
	dir := t.TempDir()
	real, other := filepath.Join(dir, "real"), filepath.Join(dir, "other")
	for _, d := range []string{real, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(real, "out")
	if err := os.Symlink(other, out); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path, dir string
		want      bool
	}{
		{filepath.Join(link, "new", "a.log"), real, true}, // through a link into the directory
		{filepath.Join(real, "a.log"), link, true},        // the directory named by its link
		{filepath.Join(out, "a.log"), real, false},        // looks inside, is elsewhere
		{filepath.Join(out, "a.log"), other, true},
		{filepath.Join(dir, "missing", "a.log"), real, false},
	} {
		if got := below(c.path, c.dir); got != c.want {
			t.Errorf("below(%s, %s) = %v, want %v", c.path, c.dir, got, c.want)
		}
	}
}

func TestParseUnitSandbox(t *testing.T) {
	// The shipped unit, as systemd 252 prints it.
	u := parseUnitSandbox("ReadWritePaths=-/var/log/caddy +/srv/logs/\nProtectSystem=strict\nStateDirectory=schild\nLogsDirectory=\nLoadState=loaded\n")
	if !u.Known || u.Absent || !u.Strict || strings.Join(u.Paths, " ") != "/var/log/caddy /srv/logs /var/lib/schild" || strings.Join(u.State, " ") != "/var/lib/schild" {
		t.Errorf("shipped unit: %+v", u)
	}
	if u := parseUnitSandbox("LoadState=not-found\nProtectSystem=no\nReadWritePaths=\n"); u.Known || !u.Absent {
		t.Errorf("no unit: %+v", u)
	}
	if u := parseUnitSandbox("LoadState=loaded\nProtectSystem=full\nReadWritePaths=\n"); !u.Known || u.Strict {
		t.Errorf("unit without strict: %+v", u)
	}
	if u := parseUnitSandbox(""); u.Known || u.Absent {
		t.Errorf("no answer: %+v", u)
	}
	for path, want := range map[string]bool{"/var/log/caddy/a.log": true, "/var/log/caddy": true, "/var/log/caddy2/a.log": false, "/var/log/a.log": false} {
		if below(path, "/var/log/caddy") != want {
			t.Errorf("below(%s) != %v", path, want)
		}
	}
}

const swapCaddyfileDoneHTTP = "(schild) {\n\tschild\n}\nhttp://shop.example.de:18080 {\n\timport schild\n\treverse_proxy 127.0.0.1:9\n}\n"

// TestIngressValidateFileAccess: a log file the user cannot write keeps
// schild from starting, so `schild ingress validate` refuses it before the
// swap; a writable one passes. init names the directory to hand over.
func TestIngressValidateFileAccess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may write everywhere")
	}
	logs := filepath.Join(t.TempDir(), "log", "caddy")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	caddyfile := "(schild) {\n\tschild\n}\nhttp://shop.example.de:18080 {\n\timport schild\n\tlog {\n\t\toutput file " + filepath.Join(logs, "new", "a.log") + "\n\t}\n\treverse_proxy 127.0.0.1:9\n}\n"
	cfg := writeStandalone(t, caddyfile)
	old := readUnitSandbox
	defer func() { readUnitSandbox = old }()
	readUnitSandbox = func() unitSandbox { return unitSandbox{Known: true} }
	var err error
	out := captureStdout(t, func() { err = cmdIngress([]string{"validate", "-config", cfg}) })
	if err != nil || !strings.Contains(out, "a.log is writable") || !strings.Contains(out, "file access: ok for this user") || !strings.HasSuffix(out, "result: PASS\n") {
		t.Fatalf("writable log directory: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(logs, "new")); statErr == nil {
		t.Fatal("validate created the log directory")
	}
	if err := os.Chmod(logs, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(logs, 0o755)
	out = captureStdout(t, func() { err = cmdIngress([]string{"validate", "-config", cfg}) })
	// The directory of the log file does not exist: the advice creates it.
	missing := filepath.Join(logs, "new")
	if err == nil || !strings.Contains(err.Error(), "schild would not start") || !strings.Contains(out, "REFUSE    log file") ||
		!strings.Contains(out, "sudo mkdir -p "+missing+" && sudo chown -R ") || !strings.Contains(out, " "+missing+" (the way back: sudo chown -R caddy "+missing+")\n") {
		t.Fatalf("read-only log directory: %v\n%s", err, out)
	}
	// In a container there is no sudo, no user schild and no caddy to go back to.
	readUnitSandbox = func() unitSandbox { return unitSandbox{None: true} }
	out = captureStdout(t, func() { err = cmdIngress([]string{"validate", "-config", cfg}) })
	if want := fmt.Sprintf(": mkdir -p %s && chown -R %d:%d %s (as root, in a container that mounts the volume)\n", missing, os.Getuid(), os.Getgid(), missing); err == nil || !strings.Contains(out, want) || strings.Contains(out, "sudo") || strings.Contains(out, "caddy "+missing) {
		t.Fatalf("container, read-only log directory: %v, want %q\n%s", err, want, out)
	}
	readUnitSandbox = func() unitSandbox { return unitSandbox{Known: true} }
	// -adapt-only is for machines without the server's files: no file check.
	if err := cmdIngress([]string{"validate", "-config", cfg, "-adapt-only"}); err != nil {
		t.Fatalf("-adapt-only: %v", err)
	}

	o := swapInput(t, caddyfile)
	var b bytes.Buffer
	if err := runInitCaddy(&b, o); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(logs, "new")
	for _, want := range []string{"sudo chown -R schild " + dir, "ReadWritePaths=" + dir, "and give the log files back: sudo chown -R caddy " + dir} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("init output lacks %q\n%s", want, b.String())
		}
	}
}

// TestCaddyQuickstart keeps deploy/quickstart/caddy/schild.yaml loadable as
// an ingress configuration that matches what `schild init -caddyfile`
// writes (same Caddyfile path and storage), and its compose file on the
// same storage path.
func TestCaddyQuickstart(t *testing.T) {
	b, err := os.ReadFile("../../deploy/quickstart/caddy/schild.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cf := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cf, []byte(swapCaddyfileDone), 0o644); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "caddyfile: /etc/caddy/Caddyfile\n") || !strings.Contains(string(b), "storage: "+caddySwapStorage+"\n") {
		t.Fatal("quickstart config: Caddyfile path or storage differ from schild init -caddyfile")
	}
	p := filepath.Join(dir, "schild.yaml")
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "/etc/caddy/Caddyfile", cf, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := app.LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	// D89: no mode; the CRS blocks, CrowdSec detects.
	if cfg.ModeWarning() != "" || cfg.Rules.CRS.State != "block" || cfg.Rules.Crowdsec.State != "detect" {
		t.Fatalf("quickstart: mode %q, rules %+v", cfg.LegacyMode, cfg.Rules)
	}
	ing, err := app.IngressFor(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(ing.Check.Sites) != 1 {
		t.Fatalf("quickstart check: %+v", ing.Check)
	}
	c, err := os.ReadFile("../../deploy/quickstart/caddy/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\"127.0.0.1:8788:8788\"", "read_only: true", "cap_drop: [ALL]", "no-new-privileges:true", "schild-data:/var/lib/schild", "/to/caddy"} {
		if !strings.Contains(string(c), want) {
			t.Errorf("quickstart compose file lacks %q", want)
		}
	}
}
