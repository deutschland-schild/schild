package hostsetup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newInstaller(t *testing.T, self string) (*Installer, *[]string, *bytes.Buffer) {
	t.Helper()
	var ran []string
	out := &bytes.Buffer{}
	in := &Installer{Root: t.TempDir(), Self: self, Version: "test", Out: out,
		Run: func(name string, args ...string) error {
			ran = append(ran, name+" "+strings.Join(args, " "))
			return nil
		}}
	return in, &ran, out
}

func put(t *testing.T, in *Installer, path, body string) {
	t.Helper()
	full := in.path(path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, in *Installer, path string) string {
	t.Helper()
	b, err := os.ReadFile(in.path(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The embedded units are the ones documented in docs/ops/systemd.
func TestEmbeddedUnitsMatchDocs(t *testing.T) {
	docs := filepath.Join("..", "..", "..", "docs", "ops", "systemd")
	if _, err := os.Stat(docs); err != nil {
		t.Skip("docs/ops/systemd not in this tree")
	}
	for _, n := range append(append([]string{}, unitNames...), "schild-host-check.tmpfiles.conf") {
		want, err := os.ReadFile(filepath.Join(docs, n))
		if err != nil {
			t.Fatal(err)
		}
		got, err := units.ReadFile("units/" + n)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("units/%s differs from docs/ops/systemd/%s: change both", n, n)
		}
	}
}

func TestInstallContainer(t *testing.T) {
	self := filepath.Join(t.TempDir(), "schild")
	if err := os.WriteFile(self, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	in, ran, out := newInstaller(t, self)
	put(t, in, "/var/lib/docker/volumes/schild-data/_data/caddy/certificates/x", "")
	if err := in.Install(Options{Apps: []string{"/var/www/shop"}, Caddyfile: "/srv/caddy/Caddyfile"}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, in, DefaultBin); got != "binary" {
		t.Errorf("binary not copied: %q", got)
	}
	if st, _ := os.Stat(in.path(DefaultBin)); st.Mode().Perm() != 0o755 {
		t.Errorf("binary mode %v", st.Mode())
	}
	svc := read(t, in, UnitDir+"/schild-check.service")
	if !strings.Contains(svc, "\nExecStart=/usr/local/bin/schild check -dir /var/lib/schild/host-check -app /var/www/shop -caddyfile /srv/caddy/Caddyfile\n") {
		t.Errorf("ExecStart:\n%s", svc)
	}
	if strings.Count(svc, "ExecStart=") != 1 {
		t.Error("more than one ExecStart")
	}
	tmp := read(t, in, TmpfilesPath)
	if strings.Count(tmp, " root 65532 -\n") != 2 {
		t.Errorf("tmpfiles:\n%s", tmp)
	}
	for _, n := range []string{"schild-check.timer", "schild-check.path"} {
		read(t, in, UnitDir+"/"+n)
	}
	if in.exists(DropInPath) {
		t.Error("drop-in written in container mode")
	}
	want := []string{
		"systemd-tmpfiles --create /etc/tmpfiles.d/schild-host-check.conf",
		"systemctl daemon-reload",
		"systemctl enable --now schild-check.timer schild-check.path",
		"systemctl start schild-check.service",
	}
	if strings.Join(*ran, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands:\n%s", strings.Join(*ran, "\n"))
	}
	for _, s := range []string{"host_check: {}", "-v /var/lib/schild/host-check:/var/lib/schild/host-check:ro", "-v /run/schild-check:/run/schild-check",
		"-e SCHILD_HOST_CHECK_TRIGGER=/run/schild-check/request",
		"-cert '/var/lib/docker/volumes/schild-data/_data/caddy/certificates/*/*/*.crt'"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

func TestInstallService(t *testing.T) {
	in, ran, out := newInstaller(t, "/usr/bin/schild")
	put(t, in, "/usr/lib/systemd/system/schild.service", "[Service]\n")
	put(t, in, "/etc/group", "root:x:0:\nschild:x:997:\n")
	if err := in.Install(Options{NoStart: true, Certs: []string{"/etc/ssl/site/*.crt"}}); err != nil {
		t.Fatal(err)
	}
	if in.exists(DefaultBin) {
		t.Error("a binary in /usr/bin must not be copied")
	}
	svc := read(t, in, UnitDir+"/schild-check.service")
	if !strings.Contains(svc, "\nExecStart=/usr/bin/schild check -dir /var/lib/schild/host-check -cert /etc/ssl/site/*.crt\n") {
		t.Errorf("ExecStart:\n%s", svc)
	}
	if tmp := read(t, in, TmpfilesPath); strings.Count(tmp, " root 997 -\n") != 2 || strings.Contains(tmp, " root 65532 ") {
		t.Errorf("tmpfiles:\n%s", tmp)
	}
	d := read(t, in, DropInPath)
	if !strings.Contains(d, "Environment=SCHILD_HOST_CHECK_TRIGGER=/run/schild-check/request\n") || !strings.Contains(d, "ReadWritePaths=-/run/schild-check\n") {
		t.Errorf("drop-in:\n%s", d)
	}
	for _, c := range *ran {
		if strings.Contains(c, "start schild-check.service") {
			t.Error("-no-start ran the check")
		}
		if strings.Contains(c, "restart") {
			t.Error("install must never restart schild")
		}
	}
	if !strings.Contains(out.String(), "sudo systemctl restart schild") || !strings.Contains(out.String(), "Add this line to /etc/schild/schild.yaml") {
		t.Errorf("output:\n%s", out)
	}
	// With host_check in schild.yaml only the restart is left.
	put(t, in, "/etc/schild/schild.yaml", "config_version: 0\nhost_check: {}\n")
	out.Reset()
	if err := in.Install(Options{NoStart: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Add this line") || !strings.Contains(out.String(), "sudo systemctl restart schild") {
		t.Errorf("output:\n%s", out)
	}
}

func TestPlanRefuses(t *testing.T) {
	in, _, _ := newInstaller(t, "/usr/bin/schild")
	for _, o := range []Options{
		{Apps: []string{"relative/path"}},
		{Apps: []string{"/var/www/my shop"}},
		{Certs: []string{"/etc/ssl/%n.crt"}},
		{Certs: []string{"/etc/ssl/$X.crt"}},
		{Apps: []string{"/x\nExecStartPre=/bin/sh"}},
		{Caddyfile: "Caddyfile"},
		{Mode: "host"},
		{Mode: ModeService}, // no group schild
		{GID: -1},
	} {
		if _, err := in.Plan(o); err == nil {
			t.Errorf("accepted %+v", o)
		}
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	in, ran, out := newInstaller(t, "/tmp/schild")
	if err := in.Install(Options{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	es, _ := os.ReadDir(in.Root)
	if len(es) != 0 || len(*ran) != 0 {
		t.Errorf("dry run wrote %d entries, ran %v", len(es), *ran)
	}
	if !strings.Contains(out.String(), "run: systemctl enable --now") || !strings.Contains(out.String(), "copy /tmp/schild -> /usr/local/bin/schild") {
		t.Errorf("output:\n%s", out)
	}
}

func TestUninstall(t *testing.T) {
	in, ran, _ := newInstaller(t, "/usr/bin/schild")
	put(t, in, "/usr/lib/systemd/system/schild.service", "[Service]\n")
	put(t, in, "/etc/group", "schild:x:997:\n")
	put(t, in, ReportDir+"/report.json", "{}")
	put(t, in, UnitDir+"/other.service", "")
	if err := in.Install(Options{}); err != nil {
		t.Fatal(err)
	}
	*ran = nil
	if err := in.Uninstall(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{UnitDir + "/schild-check.service", UnitDir + "/schild-check.timer", UnitDir + "/schild-check.path", TmpfilesPath, DropInPath, filepath.Dir(DropInPath)} {
		if in.exists(p) {
			t.Errorf("%s still there", p)
		}
	}
	for _, p := range []string{ReportDir + "/report.json", UnitDir + "/other.service", "/usr/lib/systemd/system/schild.service"} {
		if !in.exists(p) {
			t.Errorf("%s removed", p)
		}
	}
	if len(*ran) != 2 || !strings.HasPrefix((*ran)[0], "systemctl disable --now") || (*ran)[1] != "systemctl daemon-reload" {
		t.Errorf("commands: %v", *ran)
	}
	// A second run finds nothing and still succeeds.
	if err := in.Uninstall(); err != nil {
		t.Fatal(err)
	}
}
