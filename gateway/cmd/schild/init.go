package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/preflight"
	"github.com/deutschland-schild/schild/gateway/internal/app"
)

const initUsage = `schild init -caddyfile FILE [-caddy-storage DIR] [-config FILE] [-node-name NAME] [-force]
schild init [-upstream URL] [-config FILE] [-node-name NAME] [-force]

Writes a commented starter schild.yaml. Every rule repository has its own
switch: the OWASP CRS and your own rules block, CrowdSec rules only detect.
The file is checked like "schild
preflight" checks it before it is written. An existing file is kept unless
-force is given.

With -caddyfile schild runs as your Caddy (it is a Caddy distribution
with the WAF module built in): it loads your
Caddyfile and serves your sites itself. init then lists every site of the
Caddyfile, the lines that are still missing ("import schild" per site that
reaches a backend) and the commands that copy Caddy's certificate storage, so
nothing is issued again. init never changes the Caddyfile and copies nothing
itself. The storage is looked for in the Caddyfile, then in
/var/lib/caddy/.local/share/caddy (Caddy package), /data/caddy (official
image) and /root/.local/share/caddy; -caddy-storage names another place.

Without -caddyfile schild is a proxy behind your web server (nginx, Apache,
a load balancer): it listens on 127.0.0.1:8080, so only the web server on
this machine reaches it, and passes every request on to -upstream. The two
flags exclude each other.

The file holds no secrets and is written with mode 0644 (a directory that
has to be created: 0755), so the service user can read it.

Exit codes: 0 written, 1 error or file exists, 2 usage.
`

// Defaults of `schild init`.
const (
	initUpstream = "http://127.0.0.1:3000"
	initNodeName = "schild-1"
)

// starterConfig is the file `schild init` writes. Four keys are enough;
// everything else has a default.
const starterConfig = `# schild.yaml of the Schild Gateway, written by "schild init".
# schild listens on 127.0.0.1:8080 and passes every request on to your
# application (upstream.url). Check the file with: schild preflight
#
# Changes to this file take effect after a restart of schild.
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

upstream:
  # Your application, as schild reaches it.
  url: %q

listen:
  # Your web server sends the requests of your visitors here. Only this
  # machine reaches it; write "0.0.0.0:8080" only when the web server in
  # front runs on another machine, and close the port to everyone else.
  proxy: "127.0.0.1:8080"
  # dashboard: "127.0.0.1:8788"  # this server only; reach it with ssh -L

# The server check: schild shows the reports of "schild check" under "Server"
# in the dashboard. The check runs on the host and reads only; set it up
# once with: sudo schild check install   (docs: "Server-Check einrichten")
host_check: {}

# Defaults you may want to change (remove the "#" of a whole block):
#
# dashboard:
#   allowed_hosts: []            # further host names of the dashboard
#
# storage:
#   path: /var/lib/schild        # events, settings, metrics
`

var nodeNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// defaultNodeName derives node_name from the host name: its first label in
// lower case when that is a valid name, else initNodeName.
func defaultNodeName(hostname func() (string, error)) string {
	h, err := hostname()
	if err != nil {
		return initNodeName
	}
	h, _, _ = strings.Cut(strings.ToLower(h), ".")
	if !nodeNameRe.MatchString(h) {
		return initNodeName
	}
	return h
}

// initConfig renders the starter config and validates it with the checks
// of `schild preflight`: the contract validation of schild.yaml, the rule
// for host agents and the key check.
func initConfig(upstream, nodeName string) ([]byte, error) {
	if !nodeNameRe.MatchString(nodeName) {
		return nil, fmt.Errorf("-node-name %q: lowercase letters, digits and \"-\", at most 63 characters, not starting with \"-\"", nodeName)
	}
	u, err := url.Parse(upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("-upstream %q: an http:// or https:// URL of your application, e.g. %s", upstream, initUpstream)
	}
	b := fmt.Appendf(nil, starterConfig, nodeName, upstream)
	cfg, err := config.ParseSite(b)
	if err != nil {
		return nil, fmt.Errorf("the starter config would not be valid: %w", err)
	}
	if err := app.CheckHostAgents(cfg, func(string) string { return "" }); err != nil {
		return nil, err
	}
	if err := preflight.Site(cfg).Err(); err != nil {
		return nil, err
	}
	return b, nil
}

// mkdirAllReadable creates dir and its missing parents with mode 0755, also
// under a tight umask (077), so the service user can reach the file.
// Directories that exist already keep their mode.
func mkdirAllReadable(dir string) error {
	var created []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil || d == filepath.Dir(d) {
			break
		}
		created = append(created, d)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, d := range created {
		if err := os.Chmod(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// writeConfig writes b to path with mode 0644. Without force an existing
// file (also a dangling symlink) is never touched; with force it is replaced
// in one step, so a reader never sees half a file.
func writeConfig(path string, b []byte, force bool) error {
	dir := filepath.Dir(path)
	if err := mkdirAllReadable(dir); err != nil {
		return err
	}
	if !force {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists and is kept. Use another -config FILE, or -force to replace it", path)
		}
		if err != nil {
			return err
		}
		if _, err := f.Write(b); err != nil {
			f.Close()
			_ = os.Remove(path)
			return err
		}
		if err := f.Chmod(0o644); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	tmp, err := os.CreateTemp(dir, ".schild.yaml.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// configPath is the schild.yaml every command uses: the flag, else
// $SCHILD_CONFIG, else /etc/schild/schild.yaml (as app.LoadConfig).
func configPath(flagValue string, getenv func(string) string) string {
	if flagValue != "" {
		return flagValue
	}
	if p := getenv(config.SitePathEnv); p != "" {
		return p
	}
	return config.SitePathDefault
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, initUsage)
		fs.PrintDefaults()
	}
	cfgPath := fs.String("config", "", "file to write (default $SCHILD_CONFIG or /etc/schild/schild.yaml)")
	upstream := fs.String("upstream", initUpstream, "URL of your application, as schild reaches it")
	caddyfile := fs.String("caddyfile", "", "your Caddyfile: schild runs as your Caddy (not with -upstream)")
	caddyStorage := fs.String("caddy-storage", "", "Caddy's certificate storage (with -caddyfile; default: the Caddyfile's, else the usual places)")
	nodeName := fs.String("node-name", "", "name of this gateway in the dashboard and logs (default: the host name, else "+initNodeName+")")
	force := fs.Bool("force", false, "replace an existing file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		os.Exit(2)
	}
	if fs.NArg() > 0 {
		fs.Usage()
		os.Exit(2)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if err := initFlagConflict(set); err != nil {
		fmt.Fprintln(os.Stderr, "schild init:", err)
		os.Exit(2)
	}
	if set["caddyfile"] {
		return runInitCaddy(os.Stdout, caddyInit{Path: configPath(*cfgPath, os.Getenv), Caddyfile: *caddyfile, Storage: *caddyStorage,
			NodeName: *nodeName, Force: *force, Hostname: os.Hostname})
	}
	return runInit(os.Stdout, configPath(*cfgPath, os.Getenv), *upstream, *nodeName, *force, os.Hostname)
}

// initFlagConflict: -caddyfile (schild as your Caddy) and -upstream (schild
// behind a web server) are two different setups, and -caddy-storage belongs
// to the first. set holds the flags given on the command line.
func initFlagConflict(set map[string]bool) error {
	switch {
	case set["caddyfile"] && set["upstream"]:
		return errors.New("-caddyfile and -upstream exclude each other: with -caddyfile schild runs as your Caddy and the Caddyfile names the backends; with -upstream schild is a proxy behind your web server")
	case set["caddy-storage"] && !set["caddyfile"]:
		return errors.New("-caddy-storage needs -caddyfile")
	}
	return nil
}

func runInit(w io.Writer, path, upstream, nodeName string, force bool, hostname func() (string, error)) error {
	if nodeName == "" {
		nodeName = defaultNodeName(hostname)
	}
	b, err := initConfig(upstream, nodeName)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if err := writeConfig(path, b, force); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	run := "schild run"
	if path != config.SitePathDefault {
		run += " -config " + path
	}
	fmt.Fprintf(w, "wrote %s (upstream %s, node_name %s)\n", path, upstream, nodeName)
	fmt.Fprintf(w, "1. start:      %s   (or: systemctl enable --now schild)\n", run)
	fmt.Fprintln(w, "2. dashboard:  http://127.0.0.1:8788 on this server; from your machine: ssh -N -L 8788:127.0.0.1:8788 you@this-server")
	fmt.Fprintln(w, "3. setup code: in the start log (setup_code), or: schild dashboard setup-code")
	fmt.Fprintln(w, "4. server check (optional): sudo schild check install")
	return nil
}
