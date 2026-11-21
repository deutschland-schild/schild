// Package hostsetup is `schild check install` and `schild check uninstall`
// (D100): it sets up the server check of MVP-11 as systemd units on the host,
// from the unit files embedded in the binary.
//
// It is the only part of the server check that writes outside the report
// directory, and it only runs when an admin calls it by name. The check
// itself (internal/hostcheck) stays read only and never imports this package.
//
// Two modes, by who reads the reports:
//
//   - container: schild runs as a container (uid/gid 65532). The binary was
//     copied out of the image; install puts it at /usr/local/bin/schild.
//   - service: schild runs as schild.service with the user schild. The
//     reports get that group, and a drop-in lets the service write the
//     request file of "Jetzt prüfen".
package hostsetup

import (
	"bufio"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

//go:embed units/schild-check.service units/schild-check.timer units/schild-check.path units/schild-host-check.tmpfiles.conf
var units embed.FS

// Paths on the host. ReportDir and RequestDir are the ones the units, the
// tmpfiles entry and the container mounts agree on.
const (
	ReportDir     = "/var/lib/schild/host-check"
	RequestDir    = "/run/schild-check"
	RequestFile   = RequestDir + "/request"
	UnitDir       = "/etc/systemd/system"
	TmpfilesPath  = "/etc/tmpfiles.d/schild-host-check.conf"
	DropInPath    = UnitDir + "/schild.service.d/50-host-check.conf"
	DefaultBin    = "/usr/local/bin/schild"
	ContainerGID  = 65532
	ModeAuto      = "auto"
	ModeContainer = "container"
	ModeService   = "service"
)

// unitNames are the files written to UnitDir, in the order they are named.
var unitNames = []string{"schild-check.service", "schild-check.timer", "schild-check.path"}

// serviceUnitPaths: where a schild.service may be installed (package,
// tarball, by hand).
var serviceUnitPaths = []string{"/etc/systemd/system/schild.service", "/usr/lib/systemd/system/schild.service", "/lib/systemd/system/schild.service"}

// argRe is what -app and -cert may contain: an absolute path or glob without
// spaces, quotes or the characters systemd expands (% and $).
var argRe = regexp.MustCompile(`^/[A-Za-z0-9._/*?\[\]@:+,-]{0,254}$`)

// Options of Install.
type Options struct {
	Mode  string   // auto, container, service
	GID   int      // group that reads the reports; 0: by mode
	Apps  []string // -app of the check
	Certs []string // -cert of the check
	// Caddyfile is -caddyfile of the check: schild's Caddyfile as the host
	// sees it, for a gateway in a container whose schild.yaml is not at
	// /etc/schild on the host.
	Caddyfile string
	NoStart   bool // do not run the first check
	DryRun    bool // print the files and commands, change nothing
}

// Installer does the work; the fields are the host as tests replace it.
type Installer struct {
	Root    string                                  // prefix of every path ("" on a real host)
	Self    string                                  // the running binary
	Version string                                  // for the header of the written files
	Run     func(name string, args ...string) error // systemctl, systemd-tmpfiles
	Out     io.Writer
}

// File is one rendered file.
type File struct {
	Path string
	Body []byte
}

// Plan is what Install will do.
type Plan struct {
	Mode    string
	GID     int
	Bin     string // path in ExecStart
	CopyBin bool   // Self is copied to Bin
	Files   []File
}

func (in *Installer) path(p string) string { return filepath.Join(in.Root, p) }

func (in *Installer) exists(p string) bool {
	_, err := os.Stat(in.path(p))
	return err == nil
}

// groupGID reads the gid of a group from /etc/group.
func (in *Installer) groupGID(name string) (int, bool) {
	f, err := os.Open(in.path("/etc/group"))
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) >= 3 && p[0] == name {
			if n, err := strconv.Atoi(p[2]); err == nil && n > 0 {
				return n, true
			}
		}
	}
	return 0, false
}

// Plan resolves mode, group and binary path and renders the files.
func (in *Installer) Plan(o Options) (*Plan, error) {
	args := append(append([]string{}, o.Apps...), o.Certs...)
	if o.Caddyfile != "" {
		args = append(args, o.Caddyfile)
	}
	for _, a := range args {
		if !argRe.MatchString(a) {
			return nil, fmt.Errorf("%q: -app, -cert and -caddyfile take an absolute path without spaces, quotes, %% or $", a)
		}
	}
	p := &Plan{Mode: o.Mode, GID: o.GID}
	if p.Mode == "" || p.Mode == ModeAuto {
		p.Mode = ModeContainer
		for _, u := range serviceUnitPaths {
			if in.exists(u) {
				p.Mode = ModeService
			}
		}
	}
	switch p.Mode {
	case ModeContainer:
		if p.GID == 0 {
			p.GID = ContainerGID
		}
	case ModeService:
		if p.GID == 0 {
			gid, ok := in.groupGID("schild")
			if !ok {
				return nil, errors.New("mode service: no group schild in /etc/group; name the group that reads the reports with -gid")
			}
			p.GID = gid
		}
	default:
		return nil, fmt.Errorf("-mode %s: auto, container or service", o.Mode)
	}
	if p.GID < 1 || p.GID > 1<<31-1 {
		return nil, errors.New("-gid: a group id above 0")
	}

	// A binary that already sits in a system directory stays there (a
	// package owns /usr/bin/schild); anything else, such as a copy out of
	// the image in /tmp, is installed to /usr/local/bin.
	p.Bin = in.Self
	if d := filepath.Dir(in.Self); d != "/usr/bin" && d != "/usr/local/bin" && d != "/usr/sbin" && d != "/usr/local/sbin" {
		p.Bin, p.CopyBin = DefaultBin, true
	}

	header := "# Written by `schild check install` (" + in.Version + "); `schild check uninstall` removes it.\n"
	for _, n := range unitNames {
		b, err := units.ReadFile("units/" + n)
		if err != nil {
			return nil, err
		}
		if n == "schild-check.service" {
			if b, err = renderService(b, p.Bin, o.Apps, o.Certs, o.Caddyfile); err != nil {
				return nil, err
			}
		}
		p.Files = append(p.Files, File{Path: UnitDir + "/" + n, Body: append([]byte(header), b...)})
	}
	b, err := units.ReadFile("units/schild-host-check.tmpfiles.conf")
	if err != nil {
		return nil, err
	}
	if b, err = renderTmpfiles(b, p.GID); err != nil {
		return nil, err
	}
	p.Files = append(p.Files, File{Path: TmpfilesPath, Body: append([]byte(header), b...)})
	if p.Mode == ModeService {
		p.Files = append(p.Files, File{Path: DropInPath, Body: []byte(header + dropIn)})
	}
	return p, nil
}

// dropIn lets schild.service (ProtectSystem=strict) write the request file.
const dropIn = `# "Jetzt prüfen": schild writes the request file, schild-check.path starts the check.
[Service]
Environment=SCHILD_HOST_CHECK_TRIGGER=` + RequestFile + `
ReadWritePaths=-` + RequestDir + `
`

// renderService sets the binary and the check's flags in ExecStart.
func renderService(b []byte, bin string, apps, certs []string, caddyfile string) ([]byte, error) {
	const old = "ExecStart=/usr/local/bin/schild check -dir " + ReportDir + "\n"
	if strings.Count(string(b), old) != 1 {
		return nil, errors.New("hostsetup: schild-check.service has no known ExecStart line")
	}
	line := "ExecStart=" + bin + " check -dir " + ReportDir
	for _, a := range apps {
		line += " -app " + a
	}
	for _, c := range certs {
		line += " -cert " + c
	}
	if caddyfile != "" {
		line += " -caddyfile " + caddyfile
	}
	return []byte(strings.Replace(string(b), old, line+"\n", 1)), nil
}

// renderTmpfiles sets the group of the report and request directories.
func renderTmpfiles(b []byte, gid int) ([]byte, error) {
	const old = " root 65532 -\n"
	if strings.Count(string(b), old) != 2 {
		return nil, errors.New("hostsetup: tmpfiles entry has no known group fields")
	}
	return []byte(strings.ReplaceAll(string(b), old, " root "+strconv.Itoa(gid)+" -\n")), nil
}

// writeFile writes atomically (temp file, rename).
func (in *Installer) writeFile(path string, body []byte, mode os.FileMode) error {
	full := in.path(path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(full), ".schild-install-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}

// Install writes the files, enables timer and path unit and runs the first
// check.
func (in *Installer) Install(o Options) error {
	p, err := in.Plan(o)
	if err != nil {
		return err
	}
	cmds := [][]string{
		{"systemd-tmpfiles", "--create", TmpfilesPath},
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "schild-check.timer", "schild-check.path"},
	}
	if !o.NoStart {
		cmds = append(cmds, []string{"systemctl", "start", "schild-check.service"})
	}
	if o.DryRun {
		if p.CopyBin {
			fmt.Fprintf(in.Out, "copy %s -> %s (0755)\n\n", in.Self, p.Bin)
		}
		for _, f := range p.Files {
			fmt.Fprintf(in.Out, "--- %s\n%s\n", f.Path, f.Body)
		}
		for _, c := range cmds {
			fmt.Fprintln(in.Out, "run:", strings.Join(c, " "))
		}
		return nil
	}
	if p.CopyBin {
		b, err := os.ReadFile(in.Self)
		if err != nil {
			return err
		}
		if err := in.writeFile(p.Bin, b, 0o755); err != nil {
			return err
		}
		fmt.Fprintf(in.Out, "binary:   %s\n", p.Bin)
	}
	for _, f := range p.Files {
		if err := in.writeFile(f.Path, f.Body, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(in.Out, "written:  %s\n", f.Path)
	}
	for _, c := range cmds {
		if err := in.Run(c[0], c[1:]...); err != nil {
			if c[len(c)-1] == "schild-check.service" {
				return fmt.Errorf("timer and units are installed, but the first check failed: %w (journalctl -u schild-check.service)", err)
			}
			return fmt.Errorf("%s: %w", strings.Join(c, " "), err)
		}
	}
	fmt.Fprintf(in.Out, "enabled:  schild-check.timer (daily), schild-check.path (\"Jetzt prüfen\")\n")
	if !o.NoStart {
		fmt.Fprintf(in.Out, "checked:  first report is in %s\n", ReportDir)
	}
	fmt.Fprint(in.Out, nextSteps(p, in.certHints(o), in.hasHostCheck()))
	return nil
}

// hasHostCheck: the schild.yaml of a service install already has the
// host_check section (schild init writes it).
func (in *Installer) hasHostCheck() bool {
	b, err := os.ReadFile(in.path("/etc/schild/schild.yaml"))
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "host_check:") {
			return true
		}
	}
	return false
}

// certHints: certificate stores of Caddy inside Docker volumes, which the
// check's default globs do not cover. Only named, never added by itself: a
// left-over volume of an earlier Caddy would report certificates nobody uses.
func (in *Installer) certHints(o Options) []string {
	if len(o.Certs) > 0 {
		return nil
	}
	ms, _ := filepath.Glob(in.path("/var/lib/docker/volumes/*/_data/caddy/certificates"))
	var out []string
	for _, m := range ms {
		out = append(out, strings.TrimPrefix(m, filepath.Clean(in.Root))+"/*/*/*.crt")
	}
	return out
}

func nextSteps(p *Plan, certs []string, hasHostCheck bool) string {
	var b strings.Builder
	b.WriteString("\nNext:\n")
	if p.Mode == ModeContainer {
		b.WriteString(`  1. Add this line to schild.yaml:
       host_check: {}
  2. Give the schild container two mounts and one variable (docker run; in a
     compose file under volumes and environment):
       -v ` + ReportDir + `:` + ReportDir + `:ro
       -v ` + RequestDir + `:` + RequestDir + `
       -e SCHILD_HOST_CHECK_TRIGGER=` + RequestFile + `
  3. Start the container again with them. The report is under "Server" in the dashboard.

After an update of the image, copy the binary out again and run "check install" again,
so the check on the host has the version of the gateway.
`)
	} else if hasHostCheck {
		b.WriteString(`  sudo systemctl restart schild
  The report is then under "Server" in the dashboard (host_check is in /etc/schild/schild.yaml already).
`)
	} else {
		b.WriteString(`  1. Add this line to /etc/schild/schild.yaml:
       host_check: {}
  2. sudo systemctl restart schild
     The report is under "Server" in the dashboard.
`)
	}
	if len(certs) > 0 {
		b.WriteString("\nCertificates in a Docker volume are not found by themselves. When this is the volume of\nschild, run the install again with:\n")
		for _, c := range certs {
			b.WriteString("       -cert '" + c + "'\n")
		}
	}
	return b.String()
}

// Uninstall disables the units and removes every file Install wrote. The
// reports and the binary stay.
func (in *Installer) Uninstall() error {
	// Errors of disable are not fatal: units that were never enabled.
	_ = in.Run("systemctl", "disable", "--now", "schild-check.timer", "schild-check.path")
	var paths []string
	for _, n := range unitNames {
		paths = append(paths, UnitDir+"/"+n)
	}
	paths = append(paths, TmpfilesPath, DropInPath)
	for _, p := range paths {
		err := os.Remove(in.path(p))
		switch {
		case err == nil:
			fmt.Fprintf(in.Out, "removed:  %s\n", p)
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
	}
	_ = os.Remove(in.path(filepath.Dir(DropInPath))) // only when empty
	if err := in.Run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	fmt.Fprintf(in.Out, "\nKept: the reports in %s and the binary. Remove host_check from schild.yaml\nand the mounts from the container when you no longer want the Server section.\n", ReportDir)
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

// Main is `schild check install|uninstall`; it returns the exit code.
func Main(sub string, args []string, version string) int {
	fs := flag.NewFlagSet("check "+sub, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var o Options
	var apps, certs multiFlag
	if sub == "install" {
		fs.StringVar(&o.Mode, "mode", ModeAuto, "who reads the reports: container (schild in Docker, gid 65532), service (schild.service, group schild) or auto (service when a schild.service is installed)")
		fs.IntVar(&o.GID, "gid", 0, "group id that may read the reports (default: by mode)")
		fs.Var(&apps, "app", "application path the check inventories (repeatable)")
		fs.Var(&certs, "cert", "certificate file glob of the sites (repeatable)")
		fs.StringVar(&o.Caddyfile, "caddyfile", "", "schild's Caddyfile on this host, for the logrotate cross-check (default: ingress.caddyfile of /etc/schild/schild.yaml)")
		fs.BoolVar(&o.NoStart, "no-start", false, "do not run the first check now")
		fs.BoolVar(&o.DryRun, "dry-run", false, "print the files and commands, change nothing")
	}
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		if err == nil {
			fmt.Fprintln(os.Stderr, "schild check "+sub+": unexpected argument", fs.Arg(0))
		}
		return 2
	}
	o.Apps, o.Certs = apps, certs
	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "schild check "+sub+":", err)
		return 1
	}
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		return fail(err)
	}
	in := &Installer{Self: self, Version: version, Run: runCommand, Out: os.Stdout}
	if !o.DryRun {
		switch {
		case runtime.GOOS != "linux":
			return fail(errors.New("the server check runs on Linux"))
		case os.Geteuid() != 0:
			return fail(errors.New("needs root (sudo): it writes systemd units"))
		case !in.exists("/run/systemd/system"):
			return fail(errors.New("this host does not run systemd; run `schild check` from your own scheduler instead"))
		}
	}
	if sub == "uninstall" {
		if err := in.Uninstall(); err != nil {
			return fail(err)
		}
		return 0
	}
	if err := in.Install(o); err != nil {
		return fail(err)
	}
	return 0
}
