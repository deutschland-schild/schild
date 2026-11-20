// Package hostcheck implements the read-only server check of MVP-11
// (contracts/host-check.md): `schild check` on the gateway and the same checks
// in `schild-agent` on every app VM. Every check is a pure function over an
// Env (files and a fixed set of read-only commands), so the unit tests run
// on fixture trees of real distributions.
//
// Rules the code keeps (kill criterion of MVP-11):
//   - read only: no command that changes the system, never `apt update`,
//     `dnf makecache` or an install; the only commands are the fixed argv
//     lists in commands below (Env implementations refuse anything else);
//   - no network: nothing in this package opens a socket;
//   - evidence is typed facts only: no file bodies, no command output, no
//     environment variables; a check that cannot read reports "unreadable";
//   - the only writes are the report files (store.go), and the CLI removes
//     the "Jetzt prüfen" request file (hostcli); TestReviewOnlyTheReportStoreWrites
//     keeps it that way.
package hostcheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Command is one read-only command with a fixed argv. Checks refer to the
// package-level values below; Env implementations run nothing else.
//
// Unprivileged commands never run as root: when the check runs as root,
// OSEnv starts them as uid/gid 65534 (nobody) without supplementary groups,
// so the kernel refuses any write they might attempt (rpm's sqlite
// shared-memory file, dnf logs and caches, JVM perf data). When the drop is
// not possible (no CAP_SETUID/CAP_SETGID), the command is not run at all and
// the check reports "nicht lesbar".
type Command struct {
	ID           string
	Argv         []string
	Unprivileged bool
}

// UnprivilegedUID is the uid/gid unprivileged commands run as under root.
const UnprivilegedUID = 65534

// The complete list of commands the check may run. Every one only reads.
var (
	CmdUnameR = Command{ID: "uname-r", Argv: []string{"uname", "-r"}}
	CmdUnameM = Command{ID: "uname-m", Argv: []string{"uname", "-m"}}
	// apt: list from the existing package lists; no index refresh. The empty
	// Dir::Cache::pkgcache/srcpkgcache keep apt's binary cache in memory: run
	// as root, apt would otherwise rewrite /var/cache/apt/*.bin when they are
	// missing or stale (the testlab read-only proof catches that write).
	CmdAptUpgradable = Command{ID: "apt-list-upgradable", Argv: []string{"apt", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "list", "--upgradable"}}
	// apt-get -s only simulates (no root needed, no lock taken).
	CmdAptSimUpgrade = Command{ID: "apt-get-sim-upgrade", Argv: []string{"apt-get", "-s", "-o", "Debug::NoLocking=1", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "dist-upgrade"}}
	// RHEL-like: dnf, yum and needs-restarting are never run. Even with -C
	// they append to /var/log/dnf*.log and hawkey.log, rewrite
	// /var/cache/dnf/*.solv and expired_repos.json as root, and create
	// /var/tmp/dnf-<user>-*/ as a normal user. Instead a fixed script reads
	// dnf's existing metadata cache and the rpm database through libdnf's
	// hawkey bindings (the library dnf itself uses), with the solv cache,
	// the hawkey log and module state writes switched off, as nobody. The
	// platform python of RHEL 8 comes first (hawkey lives there), then python3.
	CmdDnfUpdatesPlatform = Command{ID: "dnf-updates-platform-python", Argv: []string{"/usr/libexec/platform-python", "-I", "-B", "-W", "ignore", "-c", dnfUpdatesScript}, Unprivileged: true}
	CmdDnfUpdates         = Command{ID: "dnf-updates", Argv: []string{"python3", "-I", "-B", "-W", "ignore", "-c", dnfUpdatesScript}, Unprivileged: true}
	// Install time of every package (reboot needed: a kernel, glibc, systemd
	// ... installed after the last boot, the rule of needs-restarting -r).
	CmdRpmInstallTime = Command{ID: "rpm-installtime", Argv: []string{"rpm", "-qa", "--qf", "%{NAME}\\t%{INSTALLTIME}\\n"}, Unprivileged: true}
	CmdSS             = Command{ID: "ss", Argv: []string{"ss", "-tlnp"}}
	CmdNft            = Command{ID: "nft", Argv: []string{"nft", "list", "ruleset"}}
	CmdIptablesSave   = Command{ID: "iptables-save", Argv: []string{"iptables-save"}}
	CmdIp6tablesSave  = Command{ID: "ip6tables-save", Argv: []string{"ip6tables-save"}}
	CmdSshdT          = Command{ID: "sshd-t", Argv: []string{"sshd", "-T"}}
	CmdJournalSSHD    = Command{ID: "journal-sshd", Argv: []string{"journalctl", "-q", "--no-pager", "-o", "short-iso", "--since=-24h", "_COMM=sshd", "_COMM=sshd-session"}}
	CmdDpkgQuery      = Command{ID: "dpkg-query", Argv: []string{"dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${db:Status-Abbrev}\\n"}, Unprivileged: true}
	// rpm as root maps the sqlite rpmdb's shared-memory file writable and
	// updates it (mtime); as nobody it reads only.
	CmdRpmQA         = Command{ID: "rpm-qa", Argv: []string{"rpm", "-qa", "--qf", "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n"}, Unprivileged: true}
	CmdNodeVersion   = Command{ID: "node-version", Argv: []string{"node", "--version"}, Unprivileged: true}
	CmdPHPVersion    = Command{ID: "php-version", Argv: []string{"php", "-n", "--version"}, Unprivileged: true}
	CmdPythonVersion = Command{ID: "python3-version", Argv: []string{"python3", "-I", "-S", "--version"}, Unprivileged: true}
	// Only when no <java home>/release file names the version: the JVM
	// writes /tmp/hsperfdata_<user>/ unless perf data is off. Under
	// MemoryDenyWriteExecute the JVM cannot start at all (the release file
	// still works there).
	CmdJavaVersion = Command{ID: "java-version", Argv: []string{"java", "-XX:-UsePerfData", "-Xshare:off", "-version"}, Unprivileged: true}
)

// Commands lists every command the check may run (README, tests).
var Commands = []Command{CmdUnameR, CmdUnameM, CmdAptUpgradable, CmdAptSimUpgrade, CmdDnfUpdatesPlatform, CmdDnfUpdates, CmdRpmInstallTime,
	CmdSS, CmdNft, CmdIptablesSave, CmdIp6tablesSave, CmdSshdT, CmdJournalSSHD, CmdDpkgQuery, CmdRpmQA,
	CmdNodeVersion, CmdPHPVersion, CmdPythonVersion, CmdJavaVersion}

// Result of a command. Stdout and Stderr are parsed by the checks and never
// copied into a report.
type Result struct {
	Stdout []byte
	Stderr []byte
	Exit   int
}

// Errors of Env.Run besides fs.ErrPermission.
var (
	ErrNotInstalled = errors.New("hostcheck: command not installed")
	ErrTimeout      = errors.New("hostcheck: command timed out")
	ErrRefused      = errors.New("hostcheck: command not on the read-only list")
	// ErrNoPrivDrop: an unprivileged command could not drop root (no
	// CAP_SETUID/CAP_SETGID); it was not run.
	ErrNoPrivDrop = fmt.Errorf("hostcheck: cannot drop root for an unprivileged command: %w", fs.ErrPermission)
)

// Env is everything a check may touch.
type Env interface {
	// ReadFile reads at most max bytes of a file.
	ReadFile(path string, max int64) ([]byte, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	Stat(path string) (fs.FileInfo, error)
	Glob(pattern string) ([]string, error)
	// EvalSymlinks resolves symbolic links (absolute result).
	EvalSymlinks(path string) (string, error)
	// Run runs one of Commands. A non-zero exit status is no error.
	Run(ctx context.Context, c Command) (Result, error)
	IsRoot() bool
	Now() time.Time
}

// ---------------------------------------------------------------- OS

// OSEnv is the real host. It runs only the commands of the read-only list,
// with a minimal environment (no inherited variables) and a timeout.
//
// ReadFile opens nothing but regular files and ReadDir nothing but
// directories (openRegular, openDir): the check runs as root and also reads
// below paths other users can write to (--app document roots), where a FIFO
// would block the run forever and a link to a device node could make the
// open itself change something.
type OSEnv struct {
	Timeout time.Duration // per command, default 60 s
	MaxOut  int64         // per stream, default 16 MiB
}

// errNotRegular: ReadFile refuses FIFOs, sockets and device nodes.
var errNotRegular = errors.New("not a regular file")

func (OSEnv) ReadFile(path string, max int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// ReadFileTail reads the last max bytes of a regular file (tailReader).
func (OSEnv) ReadFileTail(path string, max int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := int64(0)
	if st.Size() > max {
		off = st.Size() - max
	}
	b, err := io.ReadAll(io.NewSectionReader(f, off, max))
	if err != nil {
		return nil, err
	}
	return dropPartialLine(b, off), nil
}

func (OSEnv) ReadDir(path string) ([]fs.DirEntry, error) {
	f, err := openDir(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	es, err := f.ReadDir(-1)
	slices.SortFunc(es, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return es, err
}

func (OSEnv) Stat(path string) (fs.FileInfo, error)    { return os.Stat(path) }
func (OSEnv) Glob(pattern string) ([]string, error)    { return filepath.Glob(pattern) }
func (OSEnv) EvalSymlinks(path string) (string, error) { return filepath.EvalSymlinks(path) }
func (OSEnv) IsRoot() bool                             { return os.Geteuid() == 0 }
func (OSEnv) Now() time.Time                           { return time.Now().UTC() }

// safePath is the only PATH commands see.
const safePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

type limitedBuffer struct {
	buf bytes.Buffer
	max int64
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - int64(l.buf.Len()); room > 0 {
		if int64(len(p)) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

func (e OSEnv) Run(ctx context.Context, c Command) (Result, error) {
	if !allowed(c) {
		return Result{}, ErrRefused
	}
	bin, err := lookPath(c.Argv[0])
	if err != nil {
		return Result{}, ErrNotInstalled
	}
	timeout := e.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	max := e.MaxOut
	if max == 0 {
		max = 16 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, c.Argv[1:]...)
	cmd.Env = []string{"PATH=" + safePath, "LC_ALL=C", "LANG=C"}
	cmd.Dir = "/"
	cmd.Stdin = nil
	if c.Unprivileged && os.Geteuid() == 0 {
		cmd.SysProcAttr = unprivileged()
		cmd.Env = append(cmd.Env, "HOME=/nonexistent")
	}
	out, errb := &limitedBuffer{max: max}, &limitedBuffer{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, errb
	err = cmd.Run()
	res := Result{Stdout: out.buf.Bytes(), Stderr: errb.buf.Bytes()}
	if ctx.Err() != nil {
		return res, ErrTimeout
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.Exit = ee.ExitCode()
		return res, nil
	}
	if err != nil {
		if cmd.SysProcAttr != nil && cmd.Process == nil && errors.Is(err, fs.ErrPermission) {
			return res, ErrNoPrivDrop
		}
		if errors.Is(err, fs.ErrPermission) {
			return res, fs.ErrPermission
		}
		return res, err
	}
	return res, nil
}

func lookPath(name string) (string, error) {
	if filepath.IsAbs(name) {
		if st, err := os.Stat(name); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return name, nil
		}
		return "", ErrNotInstalled
	}
	for _, d := range strings.Split(safePath, ":") {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", ErrNotInstalled
}

func allowed(c Command) bool {
	for _, k := range Commands {
		if k.ID == c.ID && slices.Equal(k.Argv, c.Argv) && k.Unprivileged == c.Unprivileged {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- fixture

// FixtureEnv replays a recorded host (tests, docs). Layout of Dir:
//
//	fs/...            the file tree ("/etc/os-release" is fs/etc/os-release)
//	cmd/<id>.out      stdout of a command (missing file and no .err: not installed)
//	cmd/<id>.stderr   stderr (optional)
//	cmd/<id>.exit     exit status (optional, default 0)
//	cmd/<id>.err      "permission", "timeout" or "not_installed"
//	denied            paths (one per line) that answer permission denied
//	meta              "root" when the check ran as root
//
// Now is fixed by the caller.
type FixtureEnv struct {
	Dir  string
	Time time.Time
	// Root overrides meta when set (tests of privilege handling).
	Root *bool
	// Ran records the commands that were run (tests: never anything else).
	Ran []string

	statOnce sync.Once
	statOver map[string]statOverride
}

func (f *FixtureEnv) denied(path string) bool {
	b, err := os.ReadFile(filepath.Join(f.Dir, "denied"))
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && (path == l || strings.HasPrefix(path, strings.TrimSuffix(l, "/")+"/")) {
			return true
		}
	}
	return false
}

func (f *FixtureEnv) real(path string) string {
	return filepath.Join(f.Dir, "fs", filepath.FromSlash(path))
}

func (f *FixtureEnv) ReadFile(path string, max int64) ([]byte, error) {
	if f.denied(path) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	b, err := os.ReadFile(f.real(path))
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	if int64(len(b)) > max {
		b = b[:max]
	}
	return b, nil
}

// ReadFileTail reads the last max bytes of a fixture file (tailReader).
func (f *FixtureEnv) ReadFileTail(path string, max int64) ([]byte, error) {
	b, err := f.ReadFile(path, 1<<62)
	if err != nil || int64(len(b)) <= max {
		return b, err
	}
	off := int64(len(b)) - max
	return dropPartialLine(b[off:], off), nil
}

func (f *FixtureEnv) ReadDir(path string) ([]fs.DirEntry, error) {
	if f.denied(path) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	es, err := os.ReadDir(f.real(path))
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	return es, nil
}

func (f *FixtureEnv) Stat(path string) (fs.FileInfo, error) {
	st, err := os.Lstat(f.real(path))
	if err != nil {
		if f.denied(path) {
			return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrPermission}
		}
		return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
	return fixtureInfo{FileInfo: st, o: f.overrides()[filepath.ToSlash(filepath.Clean(path))]}, nil
}

func (f *FixtureEnv) Glob(pattern string) ([]string, error) {
	// A glob below a denied directory sees nothing, like on a real host.
	if f.denied(strings.SplitN(pattern, "*", 2)[0]) {
		return nil, nil
	}
	ms, err := filepath.Glob(f.real(pattern))
	if err != nil {
		return nil, err
	}
	base := filepath.Join(f.Dir, "fs")
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		rel, _ := filepath.Rel(base, m)
		out = append(out, "/"+filepath.ToSlash(rel))
	}
	return out, nil
}

// EvalSymlinks follows links inside the fixture tree (absolute targets are
// fixture paths too).
func (f *FixtureEnv) EvalSymlinks(path string) (string, error) {
	p := filepath.ToSlash(filepath.Clean(path))
	for i := 0; i < 16; i++ {
		st, err := os.Lstat(f.real(p))
		if err != nil {
			return "", &fs.PathError{Op: "lstat", Path: path, Err: fs.ErrNotExist}
		}
		if st.Mode()&fs.ModeSymlink == 0 {
			return p, nil
		}
		t, err := os.Readlink(f.real(p))
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(t, "/") {
			t = filepath.ToSlash(filepath.Join(filepath.Dir(p), t))
		}
		p = filepath.ToSlash(filepath.Clean(t))
	}
	return "", &fs.PathError{Op: "lstat", Path: path, Err: errors.New("too many links")}
}

func (f *FixtureEnv) Run(_ context.Context, c Command) (Result, error) {
	if !allowed(c) {
		return Result{}, ErrRefused
	}
	f.Ran = append(f.Ran, c.ID)
	p := filepath.Join(f.Dir, "cmd", c.ID)
	if b, err := os.ReadFile(p + ".err"); err == nil {
		switch strings.TrimSpace(string(b)) {
		case "permission":
			return Result{}, fs.ErrPermission
		case "timeout":
			return Result{}, ErrTimeout
		default:
			return Result{}, ErrNotInstalled
		}
	}
	out, err := os.ReadFile(p + ".out")
	if err != nil {
		return Result{}, ErrNotInstalled
	}
	res := Result{Stdout: out}
	res.Stderr, _ = os.ReadFile(p + ".stderr")
	if b, err := os.ReadFile(p + ".exit"); err == nil {
		_, _ = fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &res.Exit)
	}
	return res, nil
}

func (f *FixtureEnv) IsRoot() bool {
	if f.Root != nil {
		return *f.Root
	}
	b, _ := os.ReadFile(filepath.Join(f.Dir, "meta"))
	return strings.Contains(string(b), "root")
}

func (f *FixtureEnv) Now() time.Time { return f.Time }

// ---------------------------------------------------------------- helpers

// tailReader is implemented by envs that read the end of a file. Logs are
// read from the end: the newest lines are the ones a check counts, and
// from the start a long log would fill the read limit with old lines.
type tailReader interface {
	ReadFileTail(path string, max int64) ([]byte, error)
}

// readTail reads the last max bytes of a file (the first max bytes when env
// cannot read from the end).
func readTail(env Env, path string, max int64) ([]byte, error) {
	if t, ok := env.(tailReader); ok {
		return t.ReadFileTail(path, max)
	}
	return env.ReadFile(path, max)
}

// dropPartialLine drops the cut first line of a tail read from offset off.
func dropPartialLine(b []byte, off int64) []byte {
	if off == 0 {
		return b
	}
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[i+1:]
	}
	return nil
}

// readErr classifies a read error.
func readErr(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, fs.ErrPermission):
		return ReasonPermission
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, ErrNotInstalled):
		return ReasonNotInstalled
	case errors.Is(err, ErrTimeout):
		return ReasonTimeout
	}
	return ReasonNotSupported
}

func exists(env Env, path string) bool {
	_, err := env.Stat(path)
	return err == nil
}
