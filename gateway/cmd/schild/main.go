// Command schild is the Schild Gateway: a reverse proxy with WAF (Caddy,
// Coraza, OWASP CRS, CrowdSec Hub rules) and local events, with its
// dashboard and the server check of its own host (`schild check`).
// schild-agent (cmd/schild-agent) for app servers behind it is not part of
// the first version.
//
//	schild init     [-config FILE] [-caddyfile FILE | -upstream URL] [-node-name NAME] [-force]   (starter schild.yaml)
//	schild run      [-config /etc/schild/schild.yaml] [-check]
//	schild preflight [-config ...]   (D24 test key check, prints and exits)
//	schild ingress validate [-config ...] [-adapt-only]   (MVP-19 Caddyfile check)
//	schild allow    <ip|cidr|host> [-ttl 7d] [-label "..."] [-level no_block|bypass_waf]
//	schild allow    --mine [-ttl 7d]   (address of the current SSH session)
//	schild allow    list | rm <id>
//	schild token    add|list|revoke|log   (agent API tokens, MVP-21)
//	schild status   [-config ...]
//	schild dashboard setup-code | reset-password [-config ...] [-data DIR]   (host only, MVP-09 addendum)
//	schild rules    sync local|crowdsec | reset crowdsec [-config ...] [-data DIR]   (host only)
//	schild lock     on|off|status WEBSITE ...   (host only, D56)
//	schild version
//	schild front    -listen :80 -schild http://127.0.0.1:8080 -app http://127.0.0.1:8081
//	schild geo-fixture -out geo.mmdb   (TEST ONLY database of documentation ranges)
//	schild health | logcheck ...   (container health check, D23 log check)
//	schild check    [-dir DIR] ...   (read-only server check of this host, MVP-11)
//	schild check install | uninstall   (D100: the check's systemd units, from this binary)
//
// `schild help` prints the full usage with flags and exit codes. Multipath
// TCP stays off for every listener (multipath_test.go).
//
//go:debug multipathtcp=0
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/preflight"
	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
	"github.com/deutschland-schild/schild/gateway/internal/caddymod"
	"github.com/deutschland-schild/schild/gateway/internal/control"
	"github.com/deutschland-schild/schild/gateway/internal/diskbudget"
	"github.com/deutschland-schild/schild/gateway/internal/failopen"
	"github.com/deutschland-schild/schild/gateway/internal/geo"
	"github.com/deutschland-schild/schild/gateway/internal/hostcli"
	"github.com/deutschland-schild/schild/gateway/internal/hostsetup"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

func logger() *slog.Logger { return hostcli.Logger("schild") }

func usage() {
	fmt.Fprint(os.Stderr, `schild - Schild Gateway (proxy with WAF, events, dashboard)

Usage:
  schild init     -caddyfile FILE [-caddy-storage DIR] [-config FILE] [-node-name NAME] [-force]
                                                 take the place of a Caddy: write a starter schild.yaml that loads
                                                 your Caddyfile, list the sites that still need
                                                 "import schild" and the commands that copy Caddy's certificates;
                                                 the Caddyfile itself is never changed (schild init -h)
  schild init     [-upstream URL] [-config FILE] [-node-name NAME] [-force]
                                                 behind another web server: write a starter schild.yaml for a proxy
                                                 in front of one application; both forms check the
                                                 file like schild preflight and keep an existing one unless -force
  schild run      [-config FILE] [-data DIR] [-check]
                                                 run the proxy, dashboard and metrics (-check: preflight only);
                                                 upgrades schild.db of an older release at start and keeps a
                                                 backup copy next to it (schild.db.backup-vN)
  schild preflight [-config FILE]                refuse test agent keys, "test" key ids and the test lab CA;
                                                 checks the Caddyfile in ingress mode; prints the result,
                                                 exit 1 when schild would refuse to start
  schild ingress validate [-config FILE] [-adapt-only]
                                                 check schild.yaml and the Caddyfile of ingress.caddyfile without
                                                 starting: stock Caddyfile adapter, schild directive on every site
                                                 that reaches a backend; then, as the current user: data directory,
                                                 certificate storage, Caddy provisioning, log files and sockets of
                                                 the Caddyfile (-adapt-only: the Caddyfile only); exit 1 on REFUSE
  schild allow    IP|CIDR|HOST [-ttl 24h|7d|30d|never] [-label TEXT] [-level no_block|bypass_waf]
  schild allow    --mine [-ttl ...] [-label TEXT] allow the address of the current SSH session (SSH_CONNECTION)
  schild allow    list | rm ID                   show or remove local allowlist entries
  schild token    add --scope SCOPE --expires 90d [--label TEXT] | list | revoke ID | log [ID]
                                                 agent API tokens (agent_api in schild.yaml); shown once, stored hashed;
                                                 SCOPE: `+contractapi.ScopeList()+`; write scopes need --label
  schild status   [-config FILE]                 show profile, backend, allowlist and health; says when settings
                                                 saved in the dashboard no longer fit schild.yaml
  schild dashboard setup-code [-config FILE] [-data DIR]
                                                 host only: print the one-time setup code of the first start again
                                                 (needs a running schild without a dashboard password)
  schild dashboard reset-password [-config FILE] [-data DIR]
                                                 host only: remove all dashboard users and sessions, print a new
                                                 one-time setup code once; through the running gateway's control
                                                 path, or directly while schild is stopped; events, settings and
                                                 blocks stay; exit 0 done, 1 error or refused, 2 usage
  schild rules    sync local|crowdsec [-config FILE] [-data DIR]
                                                 host only: local loads rules.d again without a restart (SIGHUP does
                                                 the same), crowdsec checks the hub now; a set that does not build
                                                 leaves the running rules in place
  schild rules    reset crowdsec [-config FILE] [-data DIR]
                                                 host only: back to the crowdsec rules of the image, through the
                                                 running gateway's control path or directly while schild is stopped
  schild lock     on WEBSITE [-path PATH]... [-except PATH]... [-address IP|CIDR]... [-own-networks]
                  [-password-stdin] [-message TEXT]
                                                 host only: access lock of a website, whole website or paths
  schild lock     off WEBSITE | status           off at once, or list the locks in force (schild lock -h)
  schild version                                show the version and the embedded Caddy version
  schild front    -listen ADDR -schild URL -app URL [-timeout 30s] [-access-dir /var/lib/schild] [-no-access-lock]
                                                 front proxy: fail-open only on connection refused, 503 on timeout;
                                                 never fail-open while an access lock is in force or the front cannot
                                                 read schild's lock file below -access-dir (mount the storage read-only)
  schild geo-fixture -out FILE                   TEST ONLY geo database of documentation ranges
  schild health   [-url http://127.0.0.1:9101/readyz]   exit 0 when ready (container health check)
  schild logcheck [-format auto|combined|combined-rl|nginx-json|apache-check|caddy] [-json] [SITE=]FILE ...
                                                 access logs vs. the hard limits, per site; no IPs unless -show-ips
  schild check    [-config FILE] [-dir DIR] [-keep N] [-json] [-app PATH]... [-cert GLOB]... [-caddyfile FILE]
                  [-hostname NAME] [-trigger-file FILE] [-fail-on SEVERITY] [-privileges]
                                                 read-only server check of this host, writes a host report (0640);
                                                 exit 0 written, 1 error, 2 usage, 3 -fail-on hit, 4 report invalid
                                                 (schild check -h)
  schild check install [-mode auto|container|service] [-gid N] [-app PATH]... [-cert GLOB]... [-caddyfile FILE]
                       [-no-start] [-dry-run]
                                                 as root on the host: set up the daily check and "Jetzt prüfen" as
                                                 systemd units from this binary and run the first check; a binary
                                                 copied out of the image is put at /usr/local/bin/schild
  schild check uninstall                         remove those units again; reports and binary stay
  schild firewall run | status | off            CAP_NET_ADMIN on the host's network: keep schild's address blocks
                                                 in the nftables table "inet schild" (ports 80 and 443, kernel
                                                 timeouts), from the agent API (schild firewall -h)

Changes to schild.yaml take effect after a restart of schild (systemctl restart schild, docker compose
restart). SIGHUP and "schild rules sync local" only load rules.d again. Settings changed in the dashboard
apply at once, are stored in the data directory and win over schild.yaml.

Environment: SCHILD_CONFIG, SCHILD_DATA_DIR, SCHILD_LOG_LEVEL, SCHILD_LOG_FORMAT (json|text),
SCHILD_CADDY_LOG_LEVEL, SCHILD_GEO_TOKEN (token of geo.provider instead of geo.token_file),
SCHILD_HOST_CHECK_TRIGGER (request file of the server check for a schild in a container),
SCHILD_HOST_CHECK_INPROCESS=1 (the dashboard runs the server check itself; schild runs on the host).
Test lab only, ignored by release builds: SCHILD_ALLOW_TEST_KEYS=1 (start despite test keys or the test CA),
SCHILD_WAF_MAX_EVALS and SCHILD_WAF_QUEUE_WAIT_MS (override waf.max_concurrent_evals and waf.queue_wait_ms),
SCHILD_HOST_AGENTS=1, SCHILD_EVENTS_NDJSON_DIR, SCHILD_CROWDSEC_HUB_URL.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "preflight":
		err = cmdRun(append([]string{"-check"}, os.Args[2:]...))
	case "allow":
		err = cmdAllow(os.Args[2:])
	case "token":
		err = cmdToken(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "dashboard":
		err = cmdDashboard(os.Args[2:])
	case "rules":
		err = cmdRules(os.Args[2:])
	case "lock":
		err = cmdLock(os.Args[2:])
	case "ingress":
		err = cmdIngress(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(buildinfo.String())
		fmt.Printf("  caddy %s (embedded)\n", caddymod.CaddyVersion())
		for k, v := range buildinfo.Deps() {
			fmt.Printf("  %s %s\n", k, v)
		}
	case "front":
		err = cmdFront(os.Args[2:])
	case "geo-fixture":
		err = cmdGeoFixture(os.Args[2:])
	case "health":
		err = cmdHealth(os.Args[2:])
	case "logcheck":
		err = cmdLogcheck(os.Args[2:])
	case "check":
		// D100: install and uninstall set up the check's systemd units; the
		// check itself stays read only.
		if len(os.Args) > 2 && (os.Args[2] == "install" || os.Args[2] == "uninstall") {
			os.Exit(hostsetup.Main(os.Args[2], os.Args[3:], buildinfo.Version))
		}
		os.Exit(hostcli.Check("schild check", os.Args[2:]))
	case "firewall":
		err = cmdFirewall(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		// A command that already printed its findings and result (schild
		// ingress validate) is not repeated on stderr: two streams would
		// mix the report.
		if !errors.As(err, new(reportedError)) {
			fmt.Fprintln(os.Stderr, "schild:", err)
		}
		os.Exit(1)
	}
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "", "schild.yaml (default $SCHILD_CONFIG or /etc/schild/schild.yaml)")
	data := fs.String("data", "", "data directory (default $SCHILD_DATA_DIR or storage.path)")
	check := fs.Bool("check", false, "run the preflight only: print the result and exit")
	_ = fs.Parse(args)
	log := logger()
	cfg, base, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	// D60b: before anything else, so `schild preflight` says it too.
	if err := app.CheckHostAgents(cfg, os.Getenv); err != nil {
		return err
	}
	pf := preflight.Site(cfg)
	if *check {
		printStoredSettings(app.DataDir(cfg, *data), base)
	}
	ingressErr := checkIngress(cfg, app.DataDir(cfg, *data), *check)
	budgetErr := checkBudget(cfg, app.DataDir(cfg, *data), *check)
	if *check {
		pf.Print(os.Stdout)
		if err := pf.Err(); err != nil {
			return err
		}
		if ingressErr != nil {
			return ingressErr
		}
		return budgetErr
	}
	if err := pf.Enforce(log); err != nil {
		return err
	}
	if ingressErr != nil {
		return ingressErr
	}
	if budgetErr != nil {
		return budgetErr
	}
	// One gateway per data directory; the lock also tells
	// `schild dashboard reset-password` that it must use the control path.
	dir := app.DataDir(cfg, *data)
	release, err := control.Lock(dir)
	if errors.Is(err, control.ErrLocked) {
		return fmt.Errorf("data directory %s is in use by another schild process (a running gateway or schild dashboard reset-password); not started", dir)
	}
	if err != nil {
		return fmt.Errorf("gateway lock %s: %w", control.LockPath(dir), err)
	}
	defer release()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The first signal starts the graceful shutdown; from then on the default
	// handling is back, so a second Ctrl-C or SIGTERM ends a hung shutdown.
	go func() {
		<-ctx.Done()
		stop()
	}()
	// Without this a SIGHUP ends the process. It stays buffered during the start.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	a, err := app.New(ctx, app.Options{ConfigPath: *cfgPath, DataDir: *data, Log: log, BodyTemp: true})
	if err != nil {
		return err
	}
	go a.ReloadOnSignal(ctx, hup)
	if srv, err := a.ServeControl(ctx, dir); err != nil {
		log.Warn("control path not available: schild dashboard reset-password needs schild stopped", "path", control.SocketPath(dir), "err", err)
	} else {
		defer srv.Close()
	}
	return a.Run(ctx)
}

// printStoredSettings is the preflight line about settings the dashboard
// stored that no longer fit schild.yaml (D78). It only reads, and only a
// store that exists and has this build's schema.
func printStoredSettings(dataDir string, base map[string]any) {
	db := filepath.Join(dataDir, "schild.db")
	if _, err := os.Stat(db); err != nil {
		return
	}
	st, err := store.Open(db)
	if err != nil {
		if errors.Is(err, store.ErrNeedsUpgrade) {
			fmt.Printf("  note      %s is from an older release: schild run upgrades it at start and keeps a backup copy next to it\n", db)
		} else {
			fmt.Printf("  WARN      %v\n", err)
		}
		return
	}
	defer st.Close()
	for _, n := range app.DroppedSettings(context.Background(), st, base) {
		fmt.Printf("  WARN      %s\n", n)
	}
}

func openStore(cfgPath, data string) (*store.Store, string, error) {
	cfg, _, err := app.LoadConfig(cfgPath)
	if err != nil {
		return nil, "", err
	}
	dir := app.DataDir(cfg, data)
	st, err := store.Open(filepath.Join(dir, "schild.db"))
	return st, dir, err
}

// parseInterleaved parses flags that stand before, between or after the
// positional arguments and returns the positional ones in order ("--"
// ends the flags).
func parseInterleaved(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return pos
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos
		}
		if len(args) > len(rest) && args[len(args)-len(rest)-1] == "--" {
			return append(pos, rest...)
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func cmdAllow(args []string) error {
	fs := flag.NewFlagSet("allow", flag.ExitOnError)
	cfgPath := fs.String("config", "", "schild.yaml")
	data := fs.String("data", "", "data directory")
	ttl := fs.String("ttl", "7d", "24h, 7d, 30d or never")
	label := fs.String("label", "", "label shown in the dashboard")
	level := fs.String("level", allowlist.NoBlock, "no_block or bypass_waf")
	mine := fs.Bool("mine", false, "allow the address of the current SSH session (SSH_CONNECTION or SSH_CLIENT)")
	if len(args) == 0 {
		return errors.New("allow: IP, CIDR, host, --mine, list or rm ID")
	}
	// Flags anywhere: schild allow --mine -ttl 30d, schild allow 203.0.113.7
	// -ttl 24h, schild allow rm ID -config FILE (D36 fix round 2: -config
	// after the ID was ignored and /etc/schild/schild.yaml opened).
	pos := parseInterleaved(fs, args)
	target := ""
	if len(pos) > 0 {
		target, pos = pos[0], pos[1:]
	}
	if *mine {
		ip, err := sshClientIP(os.Getenv)
		if err != nil {
			return err
		}
		target = ip
		if *label == "" {
			*label = "My IP (SSH)"
		}
	}
	if target == "" {
		return errors.New("allow: IP, CIDR, host, --mine, list or rm ID")
	}
	st, _, err := openStore(*cfgPath, *data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch target {
	case "list":
		es, err := st.ListAllow(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tADDRESS\tLEVEL\tEXPIRES\tSOURCE\tLABEL")
		for _, e := range es {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.IP+e.CIDR+e.Host, e.Level, e.Expires, e.Source, e.Label)
		}
		return tw.Flush()
	case "rm":
		if len(pos) < 1 {
			return errors.New("allow rm ID")
		}
		return st.DeleteAllow(ctx, pos[0])
	}
	in := allowlist.Input{Label: *label, Level: *level, TTL: *ttl}
	switch {
	case strings.Contains(target, "/"):
		in.CIDR = target
	case strings.ContainsAny(target, ":") || strings.Trim(target, "0123456789.") == "":
		in.IP = target
	default:
		in.Host = target
	}
	if in.Label == "" {
		in.Label = "CLI " + target
		if len(in.Label) > 64 {
			in.Label = in.Label[:64]
		}
	}
	e, errs := allowlist.Validate(in, time.Now().UTC())
	if len(errs) > 0 {
		for k, v := range errs {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", k, v)
		}
		return errors.New("allow: invalid input")
	}
	e.Source = "cli"
	if err := st.AddAllow(ctx, e); err != nil {
		return err
	}
	fmt.Printf("allowed %s (%s) until %s, id %s - a running schild picks it up within a few seconds\n", target, e.Level, e.Expires, e.ID)
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", "", "schild.yaml")
	data := fs.String("data", "", "data directory")
	_ = fs.Parse(args)
	cfg, base, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	st, dir, err := openStore(*cfgPath, *data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	dropped := app.DroppedSettings(ctx, st, base)
	fmt.Println(buildinfo.String())
	if cfg.Profile == "test" {
		fmt.Printf("profile:         test (nothing is blocked)\n")
	} else {
		fmt.Printf("profile:         %s\n", cfg.Profile)
	}
	for _, w := range cfg.Warnings() {
		fmt.Printf("warning:         %s\n", w)
	}
	if cfg.CaddyIngress() {
		fmt.Printf("ingress:         Caddyfile %s\n", cfg.Ingress.Caddyfile)
	} else {
		fmt.Printf("upstream:        %s\n", cfg.Upstream.URL)
	}
	fmt.Printf("data dir:        %s (%.1f MB)\n", dir, float64(st.SizeBytes())/(1<<20))
	es, _ := st.ListAllow(ctx)
	fmt.Printf("allowlist:       %d stored + %d in schild.yaml\n", len(es), len(cfg.Allowlist))
	for _, p := range []struct{ name, addr string }{{"dashboard", cfg.Listen.Dashboard}, {"metrics", cfg.Listen.Metrics}} {
		c := &http.Client{Timeout: 2 * time.Second}
		resp, err := c.Get(readyURL(p.addr))
		state := "not reachable (is schild running?)"
		if err == nil {
			state = resp.Status
			resp.Body.Close()
		}
		fmt.Printf("%-16s %s %s\n", p.name+":", p.addr, state)
	}
	for _, n := range dropped {
		fmt.Printf("WARNING:         %s\n", n)
	}
	return nil
}

// readyURL is the /readyz URL of a listen address as seen from this host: a
// wildcard or empty host (":9101", "0.0.0.0:9101", "[::]:9101") is asked on
// loopback.
func readyURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + "/readyz"
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/readyz"
}

func cmdFront(args []string) error {
	fs := flag.NewFlagSet("front", flag.ExitOnError)
	listen := fs.String("listen", ":80", "listen address")
	schild := fs.String("schild", "http://127.0.0.1:8080", "schild proxy URL")
	appURL := fs.String("app", "", "application URL (used only when schild refuses connections)")
	timeout := fs.Duration("timeout", 30*time.Second, "wait for schild's response headers; on timeout answer 503")
	accessDir := fs.String("access-dir", failopen.DefaultAccessDir, "schild's storage path (mount it read-only): never fail open while an access lock is in force or its state is unknown")
	noLock := fs.Bool("no-access-lock", false, "fail open without reading the access lock state (only for gateways that never use access locks)")
	_ = fs.Parse(args)
	if *appURL == "" {
		return errors.New("front: -app URL")
	}
	log := logger().With("component", "schild-front")
	f, err := failopen.New(*schild, *appURL, *timeout, log)
	if err != nil {
		return err
	}
	f.AccessDir, f.NoAccessLock = *accessDir, *noLock
	srv := f.Server(*listen)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	go ratelog.Default.Run(ctx) // tail of rate-limited warnings (D38 section 5)
	log.Info("front proxy running", "listen", *listen, "schild", *schild, "app", *appURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func cmdGeoFixture(args []string) error {
	fs := flag.NewFlagSet("geo-fixture", flag.ExitOnError)
	out := fs.String("out", "", "file to write")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("geo-fixture: -out FILE")
	}
	return geo.WriteFixture(*out)
}

func cmdHealth(args []string) error {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:9101/readyz", "readiness URL")
	_ = fs.Parse(args)
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(*url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: %s", resp.Status)
	}
	return nil
}

// sshClientIP returns the client address of the current SSH session.
func sshClientIP(getenv func(string) string) (string, error) {
	for _, k := range []string{"SSH_CONNECTION", "SSH_CLIENT"} {
		if f := strings.Fields(getenv(k)); len(f) > 0 {
			if ip, err := netip.ParseAddr(f[0]); err == nil {
				return ip.Unmap().String(), nil
			}
		}
	}
	return "", errors.New("allow --mine: no SSH session found (SSH_CONNECTION and SSH_CLIENT are empty); " +
		"sudo and containers do not pass it on: sudo schild allow \"${SSH_CONNECTION%% *}\", " +
		"docker exec -e SSH_CONNECTION=\"$SSH_CONNECTION\" ..., or give the address: schild allow 203.0.113.7")
}

// checkIngress is the preflight part of ingress mode (MVP-19): the Caddyfile
// exists, adapts with the stock adapter and every site that reaches a
// backend uses the schild directive. print writes the result (schild
// preflight); otherwise only the error is returned.
func checkIngress(cfg *config.Site, dataDir string, print bool) error {
	if print {
		for _, n := range localChecks(cfg, dataDir) {
			fmt.Printf("  %s\n", n)
		}
	}
	if !cfg.CaddyIngress() {
		return nil
	}
	ing, err := app.IngressFor(cfg, dataDir)
	if print {
		printIngress(cfg, ing, err)
	}
	if err != nil {
		return fmt.Errorf("ingress: %w", err)
	}
	return nil
}

func printIngress(cfg *config.Site, ing *caddymod.Ingress, err error) {
	fprintIngress(os.Stdout, cfg, ing, err)
}

// fprintIngress prints the Caddyfile check with its result line.
func fprintIngress(w io.Writer, cfg *config.Site, ing *caddymod.Ingress, err error) {
	fprintIngressReport(w, cfg, ing, err)
	if err == nil {
		fmt.Fprintln(w, "result: PASS (Caddyfile)")
	}
}

// fprintIngressReport prints the Caddyfile check: one line per site, the
// warnings and, when sites lack the schild directive, the lines to add
// (fprintImportAdvice) and the refusal. A pass gets no result line here:
// the full check of `schild ingress validate` ends with one result line.
func fprintIngressReport(w io.Writer, cfg *config.Site, ing *caddymod.Ingress, err error) {
	fmt.Fprintf(w, "schild ingress\n  caddyfile %s\n", cfg.Ingress.Caddyfile)
	if ing != nil {
		fmt.Fprintf(w, "  storage   %s\n", ing.StorageRoot)
		for _, s := range ing.Check.Sites {
			state := "schild"
			switch {
			case s.Schild:
			case s.Listed:
				state = "unprotected (ingress.unprotected_sites)"
			case len(s.Backends) > 0:
				state = "WITHOUT schild: " + strings.Join(s.Backends, ", ")
			case s.Files:
				state = "files without schild"
			default:
				state = "no backend"
			}
			fmt.Fprintf(w, "  site      %s: %s\n", s.Name(), state)
		}
		for _, warn := range ing.Check.Warnings {
			fmt.Fprintf(w, "  warning   %s\n", warn)
		}
		fprintLogrotate(w, ing.Check.RollDisabled)
	}
	if err != nil {
		// One line per check error (e.g. ingress.Message of each
		// rewrite_before_schild finding), else the error itself.
		if ing != nil && len(ing.Check.Errors) > 0 {
			for _, e := range ing.Check.Errors {
				fmt.Fprintf(w, "  REFUSE    %s\n", e)
			}
			fprintImportAdvice(w, cfg.Ingress.Caddyfile, ing.Check.Sites)
		} else {
			fmt.Fprintf(w, "  REFUSE    %v\n", err)
		}
		fmt.Fprintln(w, "result: REFUSE (Caddyfile); schild does not start")
	}
}

// fprintLogrotate prints the suggested logrotate rule (copytruncate) for
// every log file the Caddyfile writes with roll_disabled (D38). A
// suggestion next to the log_roll_disabled warning; it never changes the
// result.
func fprintLogrotate(w io.Writer, paths []string) {
	for _, p := range paths {
		fix := caddymod.LogrotateSuggestion(p)
		fmt.Fprintf(w, "  suggest   logrotate rule for %s (file %s):\n", p, fix.Path)
		for _, l := range strings.Split(strings.TrimRight(fix.Content, "\n"), "\n") {
			fmt.Fprintf(w, "            %s\n", l)
		}
	}
}

func cmdIngress(args []string) error {
	if len(args) == 0 || args[0] != "validate" {
		return errors.New("ingress: schild ingress validate [-config FILE] [-adapt-only]")
	}
	fs := flag.NewFlagSet("ingress validate", flag.ExitOnError)
	cfgPath := fs.String("config", "", "schild.yaml (default $SCHILD_CONFIG or /etc/schild/schild.yaml)")
	data := fs.String("data", "", "data directory (default $SCHILD_DATA_DIR or storage.path; only for the default storage root)")
	adaptOnly := fs.Bool("adapt-only", false, "check the Caddyfile only: no Caddy provisioning, no look at the certificate storage, log files and sockets (for machines without the server's files)")
	_ = fs.Parse(args[1:])
	cfg, _, err := app.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Printf("schild.yaml: valid (profile %s)\n", cfg.Profile)
	for _, w := range cfg.Warnings() {
		fmt.Printf("  WARN      %s\n", w)
	}
	if !cfg.CaddyIngress() {
		return errors.New("ingress validate: schild.yaml has no ingress.caddyfile")
	}
	dataDir := app.DataDir(cfg, *data)
	ing, err := app.IngressFor(cfg, dataDir)
	fprintIngressReport(os.Stdout, cfg, ing, err)
	if err != nil {
		return reportedError{err}
	}
	if *adaptOnly {
		// For machines without the server's files: the Caddyfile only. No
		// look at the data directory or the certificate storage, no
		// provisioning, no file access.
		fmt.Println("caddy provisioning: skipped (-adapt-only)")
		fmt.Println("not checked: data directory, certificate storage, log files and sockets (run without -adapt-only where schild runs, as the user it runs as)")
		fmt.Println("result: PASS (Caddyfile)")
		return nil
	}
	// consequence says what the refusal means; not every finding keeps
	// schild from starting.
	refuse := func(what, consequence string, problems []string) error {
		fmt.Printf("result: REFUSE (%s); %s\n", what, consequence)
		return reportedError{fmt.Errorf("ingress validate: %s; %s", strings.Join(problems, "; "), consequence)}
	}
	asRoot := os.Geteuid() == 0
	// Where gateway.lock and the databases go, and where the certificate
	// storage is: after a Caddy swap a copy of Caddy's. Both are checked
	// before the first line of the verdict, so one run names every chown.
	var problems []string
	what, consequence := "certificate storage", ""
	if p := dataDirAccess(dataDir); p != "" {
		problems = append(problems, p)
		what, consequence = "data directory", "schild would not start"
		fmt.Printf("  REFUSE    %s; schild keeps its lock and databases there and would not start. Give it to the user schild runs as: %s\n", p, ownerCommand(dataDir))
	}
	if ing.StorageRoot != "" {
		st := storageAccess(ing.StorageRoot)
		// In a container the storage is part of the data volume: one chown
		// for the volume, as the documented copy command does.
		target := ing.StorageRoot
		if os.Geteuid() != 0 && readUnitSandbox().None && below(target, dataDir) {
			target = dataDir
		}
		for _, f := range st.findings() {
			problems = append(problems, f.Text)
			if consequence == "" {
				consequence = f.Consequence
			}
			fix := f.Fix
			if fix == "" {
				fix = "Give it to the user schild runs as: " + ownerCommand(target)
			}
			fmt.Printf("  REFUSE    %s: %s. %s\n", f.Text, f.Consequence, fix)
		}
		if len(problems) == 0 {
			n, _ := storedCertificates(ing.StorageRoot)
			switch {
			case n == 0:
				fmt.Printf("certificates: none in %s yet; schild obtains what the Caddyfile asks for at start\n", ing.StorageRoot)
			case asRoot:
				fmt.Printf("certificates: %d in %s, reused at start\n", n, ing.StorageRoot)
			default:
				fmt.Printf("certificates: %d in %s, readable and writable for this user, reused at start\n", n, ing.StorageRoot)
			}
		}
	}
	if len(problems) > 0 {
		return refuse(what, consequence, problems)
	}
	// The temporary directory of the provisioning: the system's, else the
	// data directory, which was just checked (read-only container).
	if err := caddymod.ValidateIngress(ing, dataDir); err != nil {
		fmt.Printf("  REFUSE    caddy: %v\n", err)
		return refuse("Caddy provisioning", "schild would not start", []string{"caddy: " + err.Error()})
	}
	fmt.Printf("caddy provisioning: valid (caddy %s)\n", caddymod.CaddyVersion())
	// Provisioning opens no log file and dials no backend; what the
	// Caddyfile needs from the file system is checked for this user.
	problems, warnings := fileAccess(os.Stdout, ing.JSON, dataDir)
	if len(problems) > 0 {
		return refuse("file access", "schild would not start", problems)
	}
	warnings += len(ing.Check.Warnings)
	if asRoot {
		fmt.Println("file access: checked as root, which may do everything; check as the service user: sudo -u schild schild ingress validate")
		warnings++
	} else {
		fmt.Println("file access: ok for this user")
	}
	if warnings > 0 {
		fmt.Printf("result: PASS with warnings (%d, see the lines above)\n", warnings)
	} else {
		fmt.Println("result: PASS")
	}
	return nil
}

// reportedError is an error whose text the command already printed with its
// report; main exits 1 without printing it again.
type reportedError struct{ error }

func (e reportedError) Unwrap() error { return e.error }

// budgetCheck is replaced in tests.
var budgetCheck = diskbudget.Check

// checkBudget is the disk budget of D38 (contracts/storage-bounds.md
// section 2): the bounds schild keeps on storage.path must fit the file
// system, else `schild preflight` and `schild run` refuse (contract code
// config, /retention/max_size_mb). print writes the figures.
func checkBudget(cfg *config.Site, dataDir string, print bool) error {
	f, err := budgetCheck(cfg, dataDir, app.WebsiteCount(cfg, dataDir))
	if err != nil {
		if print {
			fmt.Printf("  note      storage budget not checked: %v\n", err)
		}
		return nil
	}
	if print {
		state := "ok      "
		switch f.Verdict {
		case storage.BudgetHint:
			state = "WARN    "
		case storage.BudgetError:
			state = "REFUSE  "
		}
		fmt.Printf("  %s  storage budget %s (used %s) on %s: total %s, available %s, reserve %s\n", state,
			diskbudget.MiB(f.BudgetBytes), diskbudget.MiB(f.UsedBytes), f.Path, diskbudget.MiB(f.TotalBytes), diskbudget.MiB(f.AvailBytes), diskbudget.MiB(f.ReserveBytes))
		if f.Verdict == storage.BudgetHint {
			fmt.Println("            filling the bounds would leave less than the reserve available (hint storage_budget)")
		}
	}
	if err := f.Err(); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	return nil
}

// localChecks are the notes of `schild preflight` beyond the key check:
// data dir, geo database and listen addresses (MVP-19).
func localChecks(cfg *config.Site, dataDir string) []string {
	var out []string
	if fi, err := os.Stat(dataDir); err != nil || !fi.IsDir() {
		out = append(out, fmt.Sprintf("note      data dir %s does not exist yet (created at start)", dataDir))
	} else {
		out = append(out, fmt.Sprintf("ok        data dir %s", dataDir))
	}
	// The same file and the same words as the start log (geo.MissingNote).
	if geoPath, ok := geo.Found(cfg.Geo.DBPath); ok {
		out = append(out, fmt.Sprintf("ok        geo database %s", geoPath))
	} else {
		out = append(out, "note      "+geo.MissingNote(cfg.Geo))
	}
	out = append(out, geo.PreflightNotes(cfg.Geo, os.Getenv)...)
	for _, l := range []struct{ name, addr string }{{"dashboard", cfg.Listen.Dashboard}, {"metrics", cfg.Listen.Metrics}} {
		_, _, err := net.SplitHostPort(l.addr)
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf("WARN      %s listen address %q is not host:port", l.name, l.addr))
		case app.Loopback(l.addr):
			out = append(out, fmt.Sprintf("ok        %s on %s (loopback; reach it with ssh -L)", l.name, l.addr))
		case l.name == "dashboard" && *cfg.Dashboard.Enabled:
			out = append(out, fmt.Sprintf("WARN      dashboard on %s: %s", l.addr, app.DashboardExposedMsg))
		default:
			out = append(out, fmt.Sprintf("WARN      %s on %s is not loopback: make sure only you can reach it", l.name, l.addr))
		}
	}
	return out
}
