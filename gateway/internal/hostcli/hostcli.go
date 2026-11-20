// Package hostcli is the command line of the server check (MVP-11) shared by
// both binaries: `schild check` on the gateway host and the whole
// `schild-agent` binary on app VMs (check, enrol, init, run, once, status).
//
// It must not import the proxy (Caddy, Coraza, the WAF, the dashboard):
// schild-agent links only this package, internal/hostcheck,
// internal/hostagent and the contract module. cmd/schild-agent's test
// fails when a proxy package shows up in its dependencies.
package hostcli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
	"github.com/deutschland-schild/schild/gateway/internal/hostagent"
	"github.com/deutschland-schild/schild/gateway/internal/hostcheck"
)

// Exit codes of `schild check` and `schild-agent check` (documented in
// gateway/README.md).
const (
	ExitCheckOK      = 0 // report written (or printed); findings do not change this
	ExitCheckError   = 1 // could not write the report, bad config
	ExitCheckUsage   = 2 // bad flags
	ExitCheckFailOn  = 3 // --fail-on: an open finding at or above the given severity
	ExitCheckInvalid = 4 // the report failed the contract (a bug in a check); nothing written
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// Check is `schild check` and `schild-agent check` (prog is the command name
// in messages): run every check once, read-only, and write the host report
// (or print it with --json). It returns the process exit code.
func Check(prog string, args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "schild.yaml for host_check.report_dir and keep_reports (optional; default $SCHILD_CONFIG or /etc/schild/schild.yaml when it exists)")
	dir := fs.String("dir", "", "report directory (default host_check.report_dir or "+hostcheck.DefaultReportDir+")")
	keep := fs.Int("keep", 0, "reports to keep in the directory (default host_check.keep_reports or 30)")
	asJSON := fs.Bool("json", false, "print the report to stdout instead of writing a file")
	failOn := fs.String("fail-on", "", "exit 3 when an open finding has this severity or higher (low, medium, high, critical)")
	hostname := fs.String("hostname", "", "host name in the report (default: the system host name)")
	trigger := fs.String("trigger-file", os.Getenv("SCHILD_HOST_CHECK_TRIGGER"), "request file of \"Jetzt prüfen\" to remove when the run starts")
	privileges := fs.Bool("privileges", false, "print what each check reads and the rights it needs, then exit")
	caddyfile := fs.String("caddyfile", "", "schild's Caddyfile for the logrotate cross-check of its log files (default ingress.caddyfile of the config)")
	var apps, certs multiFlag
	fs.Var(&apps, "app", "application path to inventory (WordPress, TYPO3, Laravel, Nextcloud); repeatable; nothing else is searched")
	fs.Var(&certs, "cert", "certificate file glob of the sites (repeatable; default: Let's Encrypt and Caddy stores)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return ExitCheckUsage
	}
	if *privileges {
		hostcheck.PrintPrivileges(os.Stdout)
		return ExitCheckOK
	}
	if *failOn != "" && hostcheck.SeverityRank(*failOn) < 1 {
		fmt.Fprintln(os.Stderr, prog+": --fail-on low|medium|high|critical")
		return ExitCheckUsage
	}
	reportDir, keepN, caddy := hostcheck.DefaultReportDir, 30, ""
	path := *cfgPath
	if path == "" {
		path = os.Getenv("SCHILD_CONFIG")
	}
	if path == "" {
		if _, err := os.Stat(config.SitePathDefault); err == nil {
			path = config.SitePathDefault
		}
	}
	if path != "" {
		cfg, err := config.LoadSite(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, prog+":", err)
			return ExitCheckError
		}
		caddy = cfg.Ingress.Caddyfile
		if h := cfg.HostCheck; h != nil {
			if h.ReportDir != "" {
				reportDir = h.ReportDir
			}
			if h.KeepReports > 0 {
				keepN = h.KeepReports
			}
		}
	}
	if *dir != "" {
		reportDir = *dir
	}
	if *keep > 0 {
		keepN = *keep
	}
	if *caddyfile != "" {
		caddy = *caddyfile
	}
	if *trigger != "" {
		_ = os.Remove(*trigger)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	// The newest kept report gives logs.large_file its growth per day.
	r := hostcheck.Run(ctx, hostcheck.OSEnv{}, hostcheck.Options{Role: hc.RoleGateway, Hostname: *hostname, SchildVersion: buildinfo.Version, Apps: apps, CertGlobs: certs,
		Previous: hostcheck.Latest(reportDir), Caddyfile: caddy})
	b, err := hostcheck.Marshal(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, prog+":", err)
		return ExitCheckInvalid
	}
	if *asJSON {
		_, _ = os.Stdout.Write(append(b, '\n'))
	} else {
		p, err := hostcheck.WriteReport(reportDir, r, b, keepN)
		if err != nil {
			fmt.Fprintln(os.Stderr, prog+":", err)
			return ExitCheckError
		}
		c := hostcheck.Count(r)
		fmt.Fprintf(os.Stderr, prog+": %s (critical %d, high %d, medium %d, low %d, not readable %d)\n", p, c.Critical, c.High, c.Medium, c.Low, c.Unreadable)
	}
	if *failOn != "" {
		if m := hostcheck.MaxSeverity(r); m != "" && hostcheck.SeverityRank(m) >= hostcheck.SeverityRank(*failOn) {
			return ExitCheckFailOn
		}
	}
	return ExitCheckOK
}

// Agent runs one agent subcommand of `schild-agent`: enrol, init, run,
// once or status. log is used by run and once.
func Agent(sub string, args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("schild-agent "+sub, flag.ExitOnError)
	dir := fs.String("dir", hostagent.DefaultDir, "agent directory: key (0600) and agent.json, outside any source checkout")
	switch sub {
	case "enrol", "enroll":
		gw := fs.String("gateway", "", "agent URL of the gateway, https://<gateway>:8790 (from the dashboard)")
		name := fs.String("gateway-name", "", "the gateway's node_name (from the dashboard)")
		pin := fs.String("pin", "", "sha256:<hex> of the gateway's agent certificate (from the dashboard)")
		code := fs.String("code", "", "one-time code XXXX-XXXX-XXXX-XXXX (from the dashboard)")
		keyid := fs.String("keyid", "", "key id (default <hostname>/agent/<yyyy-mm>)")
		hostname := fs.String("hostname", "", "host name (default: the system host name)")
		_ = fs.Parse(args)
		if *gw == "" || *pin == "" || *code == "" || *name == "" {
			return errors.New("enrol: --gateway, --gateway-name, --pin and --code are required (copy the line from the dashboard)")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, err := hostagent.Enrol(ctx, hostagent.EnrolOptions{Dir: *dir, GatewayURL: *gw, GatewayName: *name, Pin: *pin, Code: *code, KeyID: *keyid,
			Hostname: *hostname, Out: os.Stdout})
		return err
	case "init":
		gw := fs.String("gateway", "", "agent URL of the gateway, https://<gateway>:8790")
		name := fs.String("gateway-name", "", "the gateway's node_name")
		pin := fs.String("pin", "", "sha256:<hex> of the gateway's agent certificate")
		keyFile := fs.String("key", "", "existing key file to use (default: create <dir>/agent.key)")
		keyid := fs.String("keyid", "", "key id (default <hostname>/agent/<yyyy-mm>; required with --key)")
		hostname := fs.String("hostname", "", "host name (default: the system host name)")
		_ = fs.Parse(args)
		if *gw == "" || *pin == "" || *name == "" {
			return errors.New("init: --gateway, --gateway-name and --pin are required")
		}
		_, err := hostagent.Init(hostagent.InitOptions{Dir: *dir, GatewayURL: *gw, GatewayName: *name, Pin: *pin, KeyFile: *keyFile, KeyID: *keyid,
			Hostname: *hostname, Out: os.Stdout})
		return err
	case "run", "once":
		var apps multiFlag
		fs.Var(&apps, "app", "application path to inventory (repeatable; overrides agent.json apps)")
		interval := fs.Duration("interval", 0, "check interval (default agent.json interval_minutes or 24h; keep it equal to host_check.agents.interval_minutes on the gateway)")
		_ = fs.Parse(args)
		a, err := hostagent.New(*dir, log)
		if err != nil {
			return err
		}
		a.Version = buildinfo.Version
		if len(apps) > 0 {
			a.Apps = apps
		}
		if *interval > 0 {
			if *interval < 5*time.Minute {
				return errors.New("--interval at least 5m")
			}
			a.Interval = *interval
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if sub == "once" {
			return a.RunOnce(ctx, time.Now().Add(10*time.Minute))
		}
		log.Info("schild-agent running: checks read only, reports go only to the gateway, no commands accepted",
			"gateway", a.State.GatewayURL, "keyid", a.State.KeyID, "interval", a.Interval.String())
		return a.Run(ctx)
	case "status":
		_ = fs.Parse(args)
		st, err := hostagent.LoadState(*dir)
		if err != nil {
			return err
		}
		fmt.Printf("gateway:     %s (%s)\npin:         %s\nkey id:      %s\nkey file:    %s\nfingerprint: %s\nenrolled:    %s\n",
			st.GatewayURL, st.GatewayName, st.Pin, st.KeyID, st.KeyFile, st.Fingerprint, st.EnrolledAt)
		return nil
	}
	return fmt.Errorf("unknown command %q (schild-agent help)", sub)
}

// AgentUsage is the help text of schild-agent.
const AgentUsage = `schild-agent - Schild Agent: read-only server check on an app VM, signed reports to the Schild Gateway

Install schild-agent on internal VMs and schild on the reverse proxy. schild-agent contains
no proxy, no WAF, no dashboard and opens no listener.

Usage:
  schild-agent enrol --gateway https://GW:8790 --gateway-name NAME --pin sha256:HEX --code XXXX-XXXX-XXXX-XXXX [--dir /etc/schild-agent]
        create the agent key (0600) and enrol it with the one-time code from the dashboard;
        prints the key fingerprint to compare in the dashboard
  schild-agent init --gateway https://GW:8790 --gateway-name NAME --pin sha256:HEX [--key FILE --keyid ID] [--dir DIR]
        without a code: create (or use) the agent key and print the entry for
        host_check.agents.keys in the gateway's schild.yaml; contacts nobody
  schild-agent run  [--dir DIR] [--app PATH]... [--interval 24h]   check and deliver on an interval (systemd service)
  schild-agent once [--dir DIR] [--app PATH]...                    check and deliver once
  schild-agent status [--dir DIR]                                  show the enrolment
  schild-agent check [-dir DIR] [-keep N] [-json] [-app PATH]... [-cert GLOB]... [-fail-on SEVERITY] [-privileges]
        the same local check as schild check (same flags, same report, nothing delivered);
        exit 0 written, 1 error, 2 usage, 3 -fail-on hit, 4 report invalid
  schild-agent version                                             show the version

No listener, no commands: the gateway only answers with an ack.
Environment: SCHILD_LOG_LEVEL, SCHILD_LOG_FORMAT (json|text), SCHILD_CONFIG (check only).
`

// Logger is the process logger of both binaries: JSON (or text with
// SCHILD_LOG_FORMAT=text) to stdout, level from SCHILD_LOG_LEVEL.
func Logger(component string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("SCHILD_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.ToLower(os.Getenv("SCHILD_LOG_FORMAT")) == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(h).With("component", component)
}
