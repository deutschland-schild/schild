package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/preflight"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/caddymod"
)

// `schild init -caddyfile` (D79): schild runs as the admin's Caddy (it
// is a Caddy distribution with the WAF module). It loads the admin's Caddyfile and works on a copy of Caddy's
// certificate storage. init writes schild.yaml and prints what the admin
// still has to do; it never edits the Caddyfile and copies nothing itself.

// caddySwapStorage is ingress.storage of the starter config: below
// storage.path, the only directory schild.service may write to.
const caddySwapStorage = "/var/lib/schild/caddy"

// caddySwapConfig is the file `schild init -caddyfile` writes.
const caddySwapConfig = `# schild.yaml of the Schild Gateway, written by "schild init -caddyfile".
# schild is Caddy with the WAF module built in: it loads your Caddyfile, listens where the
# Caddyfile says (usually ports 80 and 443) and passes requests on as the
# Caddyfile says. Check both files with: schild ingress validate
#
# Changes to this file or the Caddyfile take effect after a restart of schild.
# All keys: https://deutschland-schild.de/doku
config_version: 0

# Every rule repository has its own switch: off, detect (record only) or
# block. By default the OWASP CRS and your own rules block, CrowdSec rules
# only detect. For a careful start with a sensitive application, let the
# CRS only detect for a few days and switch it to block in the dashboard:
#
# rules:
#   crs:
#     state: detect

# The name of this gateway in the dashboard and in the logs
# (lowercase letters, digits and "-").
node_name: %s

ingress:
  # Your Caddyfile. Every site that reaches a backend needs the line
  # "import schild"; schild refuses to start otherwise.
  caddyfile: %q
  # Certificates and the ACME account. schild works on a copy of Caddy's
  # storage: nothing is issued again, and Caddy's own storage stays as it is
  # for the way back.
  storage: %q

# The server check: schild shows the reports of "schild check" under "Server"
# in the dashboard. The check runs on the host and reads only; set it up
# once with: sudo schild check install   (docs: "Server-Check einrichten")
host_check: {}

# Defaults you may want to change (remove the "#" of a whole block):
#
# ingress:
#   unprotected_sites: []        # sites that may reach a backend without schild
#   trusted_proxies: []          # only with a CDN or load balancer in front
#
# listen:
#   dashboard: "127.0.0.1:8788"  # this server only; reach it with ssh -L
#
# dashboard:
#   allowed_hosts: []            # further host names of the dashboard
#
# storage:
#   path: /var/lib/schild        # events, settings, metrics
`

// caddyStorageCandidates are the places Caddy keeps its storage by default,
// in the order init looks for them.
var caddyStorageCandidates = []struct{ dir, what string }{
	{"/var/lib/caddy/.local/share/caddy", "the Caddy package (apt, dnf)"},
	{"/data/caddy", "the official caddy image"},
	{"/root/.local/share/caddy", "a Caddy started by root"},
}

// caddyInit are the inputs of `schild init -caddyfile`.
type caddyInit struct {
	Path      string // schild.yaml to write
	Caddyfile string // the admin's Caddyfile
	Storage   string // -caddy-storage ("" = detect)
	NodeName  string
	Force     bool
	Hostname  func() (string, error)
	// Candidates replaces caddyStorageCandidates in tests.
	Candidates []string
}

// caddySwapYAML renders the starter config for a Caddyfile and validates it
// with the checks of `schild preflight`.
func caddySwapYAML(caddyfile, nodeName string) ([]byte, *config.Site, error) {
	if !nodeNameRe.MatchString(nodeName) {
		return nil, nil, fmt.Errorf("-node-name %q: lowercase letters, digits and \"-\", at most 63 characters, not starting with \"-\"", nodeName)
	}
	b := fmt.Appendf(nil, caddySwapConfig, nodeName, caddyfile, caddySwapStorage)
	cfg, err := config.ParseSite(b)
	if err != nil {
		return nil, nil, fmt.Errorf("the starter config would not be valid: %w", err)
	}
	// The path must arrive as it was given: a name that YAML reads
	// differently (control characters) is refused instead of written.
	if cfg.Ingress.Caddyfile != caddyfile || !cfg.CaddyIngress() {
		return nil, nil, fmt.Errorf("-caddyfile %q: not a usable file name", caddyfile)
	}
	if err := app.CheckHostAgents(cfg, func(string) string { return "" }); err != nil {
		return nil, nil, err
	}
	if err := preflight.Site(cfg).Err(); err != nil {
		return nil, nil, err
	}
	return b, cfg, nil
}

// caddyStorage finds Caddy's storage: the flag, else the storage option of
// the Caddyfile, else the first usual place that exists. what says where the
// answer comes from; dir is "" when nothing was found.
func caddyStorage(o caddyInit, adapted []byte) (dir, what string, err error) {
	isDir := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && fi.IsDir()
	}
	if o.Storage != "" {
		abs, err := filepath.Abs(o.Storage)
		if err != nil || !isDir(abs) {
			return "", "", fmt.Errorf("-caddy-storage %s: not a directory", o.Storage)
		}
		return abs, "-caddy-storage", nil
	}
	if root := caddymod.FileStorageRoot(adapted); root != "" {
		return root, "the storage option of the Caddyfile", nil
	}
	if o.Candidates != nil {
		for _, c := range o.Candidates {
			if isDir(c) {
				return c, "found", nil
			}
		}
		return "", "", nil
	}
	for _, c := range caddyStorageCandidates {
		if isDir(c.dir) {
			return c.dir, "found, the default of " + c.what, nil
		}
	}
	return "", "", nil
}

func runInitCaddy(w io.Writer, o caddyInit) error {
	caddyfile, err := filepath.Abs(o.Caddyfile)
	if err != nil {
		return fmt.Errorf("init: -caddyfile %s: %w", o.Caddyfile, err)
	}
	if o.NodeName == "" {
		o.NodeName = defaultNodeName(o.Hostname)
	}
	b, cfg, err := caddySwapYAML(caddyfile, o.NodeName)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	// A Caddyfile that is missing or does not adapt gives no usable config:
	// nothing is written. Sites without `import schild` are the normal case
	// here and are reported after the file is written.
	adapted, _, err := caddymod.ReadCaddyfile(caddyfile)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	ing, checkErr := app.IngressFor(cfg, app.DataDir(cfg, ""))
	if ing == nil {
		return fmt.Errorf("init: %w", checkErr)
	}
	storage, what, err := caddyStorage(o, adapted)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if err := writeConfig(o.Path, b, o.Force); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	withConfig := ""
	if o.Path != config.SitePathDefault {
		withConfig = " -config " + o.Path
	}

	fmt.Fprintf(w, "wrote %s (Caddyfile %s, node_name %s)\n\n", o.Path, caddyfile, o.NodeName)
	fprintIngress(w, cfg, ing, checkErr)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "certificates")
	if storage == "" {
		fmt.Fprintf(w, "  No Caddy storage found. Name it with -caddy-storage DIR, or schild starts with an\n  empty storage in %s and obtains new certificates.\n", caddySwapStorage)
	} else {
		fmt.Fprintf(w, "  Caddy's storage: %s (%s)\n", storage, what)
		fmt.Fprintf(w, "  schild works on a copy in %s: nothing is issued again, and Caddy's own\n  storage stays as it is for the way back. Copy it (\"schild\" is the user of schild.service):\n", caddySwapStorage)
		for _, c := range copyStorageCommands(storage) {
			fmt.Fprintf(w, "    %s\n", c)
		}
	}
	logDirs := logDirs(adapted)
	for _, d := range logDirs {
		fmt.Fprintf(w, "  note      the Caddyfile writes log files to %s. schild runs as the user schild, so hand the directory over: sudo chown -R schild %s\n", d, d)
		if d != "/var/log/caddy" {
			fmt.Fprintf(w, "            schild.service lets schild write to /var/lib/schild and /var/log/caddy only: add a drop-in (sudo systemctl edit schild) with the two lines [Service] and ReadWritePaths=%s; the check below refuses until it is there\n", d)
		}
	}
	if socks := caddymod.UnixSockets(adapted); len(socks) > 0 {
		fmt.Fprintf(w, "  note      the Caddyfile reaches backends through unix sockets (%s): the user schild needs the group your caddy user has for them, e.g. sudo usermod -aG www-data schild\n", strings.Join(socks, ", "))
	}
	if caddymod.HTTP3Open(adapted) {
		fmt.Fprintln(w, "  note      HTTP/3 is on in this Caddyfile. It ignores the read_body timeout; keep port 443/udp closed or add `servers { protocols h1 h2 }` to the global options")
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "next steps")
	n := 0
	step := func(format string, a ...any) {
		n++
		fmt.Fprintf(w, "%d. "+format+"\n", append([]any{n}, a...)...)
	}
	if checkErr != nil {
		step("Caddyfile:    add the lines above to %s", caddyfile)
	}
	if storage != "" {
		step("certificates: run the copy commands above")
	}
	step("check:        sudo -u schild schild ingress validate%s", withConfig)
	step("swap:         sudo systemctl disable --now caddy && sudo systemctl enable --now schild")
	step("dashboard:    http://127.0.0.1:8788 on this server; from your machine: ssh -N -L 8788:127.0.0.1:8788 you@this-server")
	step("setup code:   sudo schild dashboard setup-code%s", withConfig)
	step("server check (optional): sudo schild check install")
	fmt.Fprintln(w, "way back: put a \"#\" in front of the line \"schild\" in the (schild) snippet (stock Caddy does not know")
	fmt.Fprintln(w, "the directive, everything else stays), then: sudo systemctl disable --now schild && sudo systemctl enable --now caddy")
	for _, d := range logDirs {
		fmt.Fprintf(w, "and give the log files back: sudo chown -R caddy %s\n", d)
	}
	return nil
}

// logDirs are the directories of the log files the Caddyfile writes.
func logDirs(adapted []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range caddymod.LogFiles(adapted) {
		if d := filepath.Dir(f); !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// copyStorageCommands are the commands that copy Caddy's storage to
// caddySwapStorage. "/." copies the content, so a second run refreshes the
// copy instead of nesting it.
func copyStorageCommands(from string) []string {
	return []string{
		"sudo mkdir -p " + caddySwapStorage,
		"sudo cp -a " + shellQuote(strings.TrimRight(from, "/")+"/.") + " " + caddySwapStorage + "/",
		"sudo chown -R schild:schild " + caddySwapStorage,
	}
}

var shellSafeRe = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)

// shellQuote quotes s for a POSIX shell when it needs quoting.
func shellQuote(s string) string {
	if shellSafeRe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var schildSnippetRe = regexp.MustCompile(`(?m)^[ \t]*\(schild\)[ \t]*\{`)

// fprintImportAdvice prints the lines a Caddyfile needs so that every site
// that reaches a backend runs schild: the snippet `(schild)` once and
// `import schild` per site. Nothing is printed when no site lacks it.
func fprintImportAdvice(w io.Writer, caddyfile string, sites []caddymod.SiteCheck) {
	var need, optional []string
	for _, s := range sites {
		switch {
		case s.Schild || s.Listed:
		case s.Errors:
			need = append(need, s.Name()+" (its handle_errors block)")
		case len(s.Backends) > 0:
			need = append(need, s.Name())
		case s.Files:
			optional = append(optional, s.Name()+" (serves files only: optional)")
		}
	}
	if len(need) == 0 {
		return
	}
	need = append(need, optional...)
	fmt.Fprintf(w, "  add to %s (schild never edits your Caddyfile):\n", caddyfile)
	body, err := os.ReadFile(caddyfile)
	if err != nil || !schildSnippetRe.Match(body) {
		fmt.Fprintln(w, "    once, above the first site (below the global options block, if there is one):")
		fmt.Fprintln(w, "        (schild) {")
		fmt.Fprintln(w, "        \tschild")
		fmt.Fprintln(w, "        }")
	}
	fmt.Fprintln(w, "    one line in the site block of each of these sites:")
	fmt.Fprintln(w, "        import schild")
	for _, n := range need {
		fmt.Fprintf(w, "      - %s\n", n)
	}
}

// storedCertificates counts the certificates in a Caddy storage root;
// exists says whether the root is there at all.
func storedCertificates(root string) (n int, exists bool) {
	if _, err := os.Stat(root); err != nil {
		return 0, false
	}
	certs, _ := filepath.Glob(filepath.Join(root, "certificates", "*", "*", "*.crt"))
	return len(certs), true
}

// Modes of access(2).
const (
	accessExec  = 1
	accessWrite = 2
	accessRead  = 4
)

// storageFinding is one reason to refuse a certificate storage and what it
// would mean for schild.
// Fix is set when a chown would not help.
type storageFinding struct{ Text, Consequence, Fix string }

// storageState is what storageAccess found.
type storageState struct {
	Exists bool
	root   string
	broken string // the root itself cannot be used
	// The first path this user cannot read, the first it cannot write, and
	// how many more of each.
	unreadable, unwritable         string
	moreUnreadable, moreUnwritable int
}

func (s storageState) findings() []storageFinding {
	var out []storageFinding
	more := func(n int) string {
		if n == 0 {
			return ""
		}
		return fmt.Sprintf(" and %d more", n)
	}
	if s.broken != "" {
		out = append(out, storageFinding{fmt.Sprintf("certificate storage %s: %s", s.root, s.broken), "schild would not start",
			"Make it a directory or a link to one, or remove it and schild creates it"})
	}
	if s.unreadable != "" {
		out = append(out, storageFinding{fmt.Sprintf("certificate storage %s: this user cannot read %s%s", s.root, s.unreadable, more(s.moreUnreadable)),
			"schild cannot load what is in there, so it would not start or the sites would fail", ""})
	}
	if s.unwritable != "" {
		out = append(out, storageFinding{fmt.Sprintf("certificate storage %s: this user cannot write %s%s", s.root, s.unwritable, more(s.moreUnwritable)),
			"schild starts, but could not renew or store certificates", ""})
	}
	return out
}

// storageAccess checks that the user who runs the command can use a
// certificate storage that exists: every directory and every file in it
// (certificates, keys, the local CA, the ACME account). What it cannot read
// keeps schild from starting or a site from answering; what it cannot write
// breaks the next renewal. A root that is a symbolic link is followed and
// its target walked; links inside the storage are skipped. A storage that
// does not exist yet is fine: schild creates it.
func storageAccess(root string) storageState {
	st := storageState{root: root}
	if _, err := os.Lstat(root); err != nil {
		// Not there yet is fine. Not reachable is a matter of the
		// directories above it, which the walk below cannot name.
		if !errors.Is(err, os.ErrNotExist) {
			st.unreadable = fmt.Sprintf("%s (%v)", root, err)
		}
		return st
	}
	st.Exists = true
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		st.broken = fmt.Sprintf("it is a link this user cannot follow (%v)", err)
		return st
	}
	if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
		st.broken = fmt.Sprintf("%s is not a directory", real)
		return st
	}
	note := func(p string, read bool, err error) {
		// Named as the admin wrote the storage, not as the link resolves.
		entry := fmt.Sprintf("%s (%v)", root+strings.TrimPrefix(p, real), err)
		switch {
		case read && st.unreadable == "":
			st.unreadable = entry
		case read:
			st.moreUnreadable++
		case st.unwritable == "":
			st.unwritable = entry
		default:
			st.moreUnwritable++
		}
	}
	_ = filepath.WalkDir(real, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			note(p, true, err)
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		read := uint32(accessRead)
		switch {
		case d.IsDir():
			read |= accessExec
		case !d.Type().IsRegular():
			return nil
		}
		if err := syscall.Access(p, read); err != nil {
			note(p, true, err)
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if err := syscall.Access(p, accessWrite); err != nil {
			note(p, false, err)
		}
		return nil
	})
	return st
}

// dataDirAccess checks the data directory, where schild keeps gateway.lock
// and its databases: it must be readable and writable for this user, and so
// must the files directly in it. A directory that does not exist yet must
// be creatable (under systemd the unit creates it: StateDirectory). It
// returns "" when all is well.
func dataDirAccess(dir string) string {
	if dir == "" {
		return ""
	}
	real := resolveExisting(dir)
	// The StateDirectory of schild.service: systemd creates it and hands it
	// to the service user at every start, whoever owns it now.
	managed := false
	if u := readUnitSandbox(); u.Known {
		for _, p := range u.State {
			managed = managed || filepath.Clean(dir) == p
		}
	}
	fi, err := os.Stat(real)
	if errors.Is(err, os.ErrNotExist) {
		if managed {
			return ""
		}
		parent := real
		for {
			parent = filepath.Dir(parent)
			if _, err := os.Stat(parent); err == nil || parent == filepath.Dir(parent) {
				break
			}
		}
		if err := syscall.Access(parent, accessWrite|accessExec); err != nil {
			return fmt.Sprintf("data directory %s: it does not exist and this user cannot create it in %s (%v)", dir, parent, err)
		}
		return ""
	}
	if err != nil {
		return fmt.Sprintf("data directory %s: this user cannot reach it (%v)", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Sprintf("data directory %s: not a directory", dir)
	}
	if err := syscall.Access(real, accessRead|accessWrite|accessExec); err != nil {
		if managed {
			return ""
		}
		return fmt.Sprintf("data directory %s: this user cannot read and write it (%v)", dir, err)
	}
	entries, _ := os.ReadDir(real)
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(real, e.Name())
		if err := syscall.Access(p, accessRead|accessWrite); err != nil {
			return fmt.Sprintf("data directory %s: this user cannot read and write %s (%v)", dir, filepath.Join(dir, e.Name()), err)
		}
	}
	return ""
}

// ownerCommand is the command that hands dir to the user who runs the
// check, with a mkdir when dir does not exist yet. As root that user is not
// known: the command names the user of schild.service. Without systemd (a
// container) the user often has no name, there is no sudo and the directory
// is a volume: the command is numeric, to be run as root wherever the
// volume is mounted.
func ownerCommand(dir string) string {
	uid := os.Getuid()
	_, statErr := os.Stat(dir)
	missing := errors.Is(statErr, os.ErrNotExist)
	q := shellQuote(dir)
	if uid != 0 && readUnitSandbox().None {
		cmd := fmt.Sprintf("chown -R %d:%d %s", uid, os.Getgid(), q)
		if missing {
			cmd = "mkdir -p " + q + " && " + cmd
		}
		return cmd + " (as root, in a container that mounts the volume)"
	}
	owner := "schild:schild"
	if uid != 0 {
		owner = fmt.Sprintf("%d:%d", uid, os.Getgid())
		if u, err := user.Current(); err == nil && u.Username != "" {
			owner = u.Username
			if g, err := user.LookupGroupId(u.Gid); err == nil && g.Name != "" {
				owner += ":" + g.Name
			}
		}
	}
	cmd := "sudo chown -R " + owner + " " + q
	if missing {
		cmd = "sudo mkdir -p " + q + " && " + cmd
	}
	return cmd
}

// resolveExisting resolves the symbolic links in the part of path that
// exists and keeps the rest as written.
func resolveExisting(path string) string {
	path = filepath.Clean(path)
	rest := ""
	for p := path; ; {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(real, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return path
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}

// unitSandbox is what systemd lets schild.service write to.
type unitSandbox struct {
	None   bool     // this system does not run systemd (a container): no unit, no sandbox
	Absent bool     // systemd runs, but schild.service is not installed
	Known  bool     // systemctl answered and the unit is loaded
	Strict bool     // ProtectSystem=strict: only ReadWritePaths are writable
	Paths  []string // writable: ReadWritePaths without the "-" and "+" prefixes, StateDirectory, LogsDirectory
	State  []string // StateDirectory: systemd creates these and hands them to the service user at start
}

// readUnitSandbox asks systemd for the sandbox of schild.service (with its
// drop-ins). Replaced in tests.
var readUnitSandbox = func() unitSandbox {
	// The test of sd_booted(3): systemd is the init system of this machine.
	if _, err := os.Lstat("/run/systemd/system"); err != nil {
		return unitSandbox{None: true}
	}
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return unitSandbox{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "show", "schild.service", "-p", "LoadState", "-p", "ProtectSystem", "-p", "ReadWritePaths", "-p", "StateDirectory", "-p", "LogsDirectory").Output()
	if err != nil {
		return unitSandbox{}
	}
	return parseUnitSandbox(string(out))
}

// parseUnitSandbox reads the output of `systemctl show -p LoadState -p
// ProtectSystem -p ReadWritePaths -p StateDirectory -p LogsDirectory`.
// StateDirectory=schild makes /var/lib/schild writable, LogsDirectory=NAME
// would make /var/log/NAME writable.
func parseUnitSandbox(out string) unitSandbox {
	var u unitSandbox
	loaded, seen := false, false
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "LoadState":
			loaded = v == "loaded"
			u.Absent = v == "not-found"
		case "ProtectSystem":
			seen = true
			u.Strict = v == "strict"
		case "ReadWritePaths":
			for _, p := range strings.Fields(v) {
				if p = strings.TrimLeft(p, "-+"); p != "" {
					u.Paths = append(u.Paths, filepath.Clean(p))
				}
			}
		case "StateDirectory", "LogsDirectory":
			base := "/var/lib"
			if k == "LogsDirectory" {
				base = "/var/log"
			}
			for _, p := range strings.Fields(v) {
				// "name:link" names a symlink too; the directory is the first part.
				name, _, _ := strings.Cut(p, ":")
				u.Paths = append(u.Paths, filepath.Join(base, name))
				if k == "StateDirectory" {
					u.State = append(u.State, filepath.Join(base, name))
				}
			}
		}
	}
	u.Known = loaded && seen
	return u
}

// below reports whether path is dir or inside it. Symbolic links in the
// parts of both that exist are resolved first, so a log path through a link
// is judged by where it really is.
func below(path, dir string) bool {
	rel, err := filepath.Rel(resolveExisting(dir), resolveExisting(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// unitLogPaths are the directories the shipped schild.service lets schild
// write log files to, next to the data directory.
var unitLogPaths = []string{"/var/log/caddy"}

// fileAccess checks what the Caddyfile needs from the file system as the
// user who runs the command, without creating or changing anything: every
// log file must be writable (Caddy opens them at start, so schild would not
// start), every unix socket of a backend that exists should be reachable.
//
// File permissions are half of it under systemd: schild.service may write
// only to the data directory and /var/log/caddy (ProtectSystem=strict). A
// log directory elsewhere needs a drop-in. When systemctl shows the loaded
// unit, a log file outside its ReadWritePaths is a refusal; when systemd
// runs but the unit cannot be read, it is a warning with the drop-in, never
// silence. Without systemd (a container) there is no such sandbox.
//
// It prints one line per finding and returns the problems that keep schild
// from starting and the number of warnings.
func fileAccess(w io.Writer, adapted []byte, dataDir string) (problems []string, warnings int) {
	asRoot := os.Geteuid() == 0
	var unit unitSandbox
	unitRead := false
	unitNow := func() unitSandbox {
		if !unitRead {
			unit, unitRead = readUnitSandbox(), true
		}
		return unit
	}
	for _, f := range caddymod.LogFiles(adapted) {
		target, mode := f, uint32(accessWrite)
		if _, err := os.Lstat(f); errors.Is(err, os.ErrNotExist) {
			// Caddy creates the file and missing directories: the nearest
			// directory that exists must allow it.
			mode = accessWrite | accessExec
			for target = filepath.Dir(f); ; target = filepath.Dir(target) {
				if _, err := os.Lstat(target); err == nil || target == filepath.Dir(target) {
					break
				}
			}
		}
		dir := filepath.Dir(f)
		if err := syscall.Access(target, mode); err != nil {
			p := fmt.Sprintf("log file %s: this user cannot write %s (%v)", f, target, err)
			problems = append(problems, p)
			back := ""
			if !unitNow().None {
				back = fmt.Sprintf(" (the way back: sudo chown -R caddy %s)", shellQuote(dir))
			}
			fmt.Fprintf(w, "  REFUSE    %s; give the directory to the user schild runs as: %s%s\n", p, ownerCommand(dir), back)
			continue
		} else if !asRoot {
			fmt.Fprintf(w, "  ok        log file %s is writable for this user\n", f)
		}
		shipped := dataDir != "" && below(f, dataDir)
		for _, d := range unitLogPaths {
			shipped = shipped || below(f, d)
		}
		unitNow()
		dropIn := fmt.Sprintf("sudo systemctl edit schild, then the two lines: [Service] and ReadWritePaths=%s; afterwards sudo systemctl daemon-reload", dir)
		switch {
		case unit.None, unit.Known && !unit.Strict:
		case unit.Known:
			covered := false
			for _, d := range unit.Paths {
				covered = covered || below(f, d)
			}
			if covered {
				fmt.Fprintf(w, "  ok        log file %s is inside what schild.service may write (ReadWritePaths, StateDirectory)\n", f)
				continue
			}
			p := fmt.Sprintf("log file %s: schild.service may not write to %s (ProtectSystem=strict, writable: %s)", f, dir, strings.Join(unit.Paths, " "))
			problems = append(problems, p)
			fmt.Fprintf(w, "  REFUSE    %s; add a drop-in: %s\n", p, dropIn)
		case !shipped && unit.Absent:
			warnings++
			fmt.Fprintf(w, "  warning   log file %s: schild.service is not installed on this system, so its sandbox was not checked. The shipped unit lets schild write only to the data directory and /var/log/caddy; with it schild does not start until %s is allowed. Add a drop-in once the unit is installed: %s\n", f, dir, dropIn)
		case !shipped:
			warnings++
			fmt.Fprintf(w, "  warning   log file %s: the sandbox of schild.service could not be read as this user (systemctl show needs the system bus). The shipped unit lets schild write only to the data directory and /var/log/caddy; schild does not start until %s is allowed. Add a drop-in: %s. Root can read the unit: sudo schild ingress validate checks the drop-in\n", f, dir, dropIn)
		}
	}
	for _, s := range caddymod.UnixSockets(adapted) {
		if _, err := os.Stat(s); err != nil {
			continue
		}
		if err := syscall.Access(s, accessRead|accessWrite); err != nil {
			warnings++
			fmt.Fprintf(w, "  warning   backend socket %s: this user cannot connect (%v); add the service user to the group of the socket, as your caddy user is\n", s, err)
		} else if !asRoot {
			fmt.Fprintf(w, "  ok        backend socket %s is reachable\n", s)
		}
	}
	return problems, warnings
}
