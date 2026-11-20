package hostcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/verify"
)

// Unreadable reasons and needs (host-report.schema.json).
const (
	ReasonPermission    = "permission_denied"
	ReasonNotInstalled  = "not_installed"
	ReasonNotSupported  = "not_supported"
	ReasonNotConfigured = "not_configured"
	ReasonTimeout       = "timeout"
	ReasonParse         = "parse_error"

	NeedsRoot         = "root"
	NeedsNetAdmin     = "CAP_NET_ADMIN"
	NeedsGroupAdm     = "group:adm"
	NeedsGroupJournal = "group:systemd-journal"
)

// Options of one check run.
type Options struct {
	Role          string // hc.RoleGateway or hc.RoleAgent
	AgentKeyID    string // agents only
	Hostname      string // default: /proc/sys/kernel/hostname, /etc/hostname
	SchildVersion string
	// Apps are configured application paths (WordPress, TYPO3, Laravel,
	// Nextcloud). Nothing outside them is searched.
	Apps []string
	// CertGlobs are certificate files of the sites (gateway only). Default
	// DefaultCertGlobs.
	CertGlobs []string
	// Previous is the newest kept report of this host (logs.large_file
	// growth per day); nil on the first run.
	Previous *hc.Report
	// Caddyfile is schild's own Caddyfile (ingress mode, gateway only):
	// its output files are cross-checked with the logrotate rules.
	Caddyfile string
}

// DefaultCertGlobs are the usual certificate stores of the front proxy.
var DefaultCertGlobs = []string{
	"/etc/letsencrypt/live/*/cert.pem",
	"/var/lib/caddy/.local/share/caddy/certificates/*/*/*.crt",
	"/var/lib/schild/caddy/certificates/*/*/*.crt",
}

// checker collects findings.
type checker struct {
	ctx      context.Context
	env      Env
	opts     Options
	findings []hc.Finding
	inv      []hc.InventoryItem
	facts    facts
}

// facts are shared between checks (distribution family, package manager).
type facts struct {
	osID, versionID, idLike string
	family                  string // debian, rhel, other
	kernel                  string
	osEOL, osExtended       string
	osSupported             bool              // regular or extended support still running
	packages                map[string]string // relevant installed packages -> version
	pkgSource               string            // dpkg, rpm
	dockerPresent           bool
	sshPort                 int // sshd's port (checkSSH), so the ports check never suggests closing it
}

func (c *checker) add(f hc.Finding) {
	c.findings = append(c.findings, f)
}

func ok(id, area, title, expl string, ev hc.Evidence) hc.Finding {
	return hc.Finding{ID: id, Area: area, Severity: "info", Status: hc.StatusOK, Title: title, Explanation: expl, Evidence: ev}
}

func finding(id, area, sev, title, expl, fix string, ev hc.Evidence) hc.Finding {
	f := hc.Finding{ID: id, Area: area, Severity: sev, Status: hc.StatusFinding, Title: title, Explanation: expl, Evidence: ev}
	if fix != "" {
		f.FixCommand = &fix
	}
	return f
}

// unreadable builds a "nicht lesbar" result.
func unreadable(id, area, what, reason, needs string, ev hc.Evidence) hc.Finding {
	expl := what + " " + reasonText(reason, needs)
	return hc.Finding{ID: id, Area: area, Severity: "info", Status: hc.StatusUnreadable, Title: strings.TrimSuffix(what, "."), // the status carries "nicht lesbar"; the dashboard shows it as a tag
		Explanation: expl, Evidence: ev, Unreadable: &hc.Unreadable{Reason: reason, Needs: needs}}
}

func reasonText(reason, needs string) string {
	s := ""
	switch reason {
	case ReasonPermission:
		s = "Dem Prüfprogramm fehlen die Rechte, das zu lesen."
	case ReasonNotInstalled:
		s = "Das nötige Programm oder die Datei gibt es auf diesem Server nicht."
	case ReasonNotSupported:
		s = "Auf diesem System kann die Prüfung das nicht lesen."
	case ReasonNotConfigured:
		s = "Dafür ist nichts eingerichtet."
	case ReasonTimeout:
		s = "Das Lesen hat zu lange gedauert und wurde abgebrochen."
	case ReasonParse:
		s = "Die Ausgabe hatte ein unerwartetes Format."
	}
	switch {
	case needs == NeedsRoot:
		s += " Mit Root-Rechten (zum Beispiel über den systemd-Timer) klappt es."
	case strings.HasPrefix(needs, "CAP_"):
		s += " Es braucht die Capability " + needs + "."
	case strings.HasPrefix(needs, "group:"):
		s += " Es braucht die Gruppe " + strings.TrimPrefix(needs, "group:") + "."
	}
	return s
}

func sp(s string) *string { return &s }

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9._:/@+,-]{0,128}$`)

// tokp returns s as an evidence token (value, expected) or nil when it does
// not fit the contract's token pattern.
func tokp(s string) *string {
	if !tokenRe.MatchString(s) {
		return nil
	}
	return &s
}
func bp(b bool) *bool     { return &b }
func ip(n int) *int       { return &n }
func i64p(n int64) *int64 { return &n }

var hostnameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)

func (c *checker) hostname() string {
	if h := strings.ToLower(strings.TrimSpace(c.opts.Hostname)); hostnameRe.MatchString(h) {
		return h
	}
	for _, p := range []string{"/proc/sys/kernel/hostname", "/etc/hostname"} {
		if b, err := c.env.ReadFile(p, 256); err == nil {
			if h := strings.ToLower(strings.TrimSpace(string(b))); hostnameRe.MatchString(h) {
				return h
			}
		}
	}
	return "localhost"
}

// Run runs every check and returns the report. It never fails because of
// one check: what cannot be read becomes "unreadable".
func Run(ctx context.Context, env Env, opts Options) *hc.Report {
	start := env.Now().UTC()
	t0 := time.Now()
	if opts.Role == "" {
		opts.Role = hc.RoleGateway
	}
	c := &checker{ctx: ctx, env: env, opts: opts}
	host := hc.Host{Hostname: c.hostname(), Role: opts.Role}
	if opts.Role == hc.RoleAgent {
		k := opts.AgentKeyID
		host.AgentKeyID = &k
	}
	host.OS = c.checkDistribution()
	c.loadPackages()
	c.checkKernel()
	c.checkUpdates()
	c.checkSSH() // before the ports: a custom SSH port counts as expected there
	c.checkPorts()
	c.checkFirewall()
	if opts.Role == hc.RoleGateway {
		c.checkTLS()
	}
	c.checkSoftware()
	c.checkLogs()
	version := opts.SchildVersion
	if !regexp.MustCompile(`^[A-Za-z0-9.+_-]{1,64}$`).MatchString(version) {
		version = "unknown"
	}
	r := &hc.Report{
		Schema: hc.SchemaReport, ReportID: msg.NewID(), Host: host,
		Run: hc.Run{StartedAt: msg.FormatTime(start), DurationMS: time.Since(t0).Milliseconds(), SchildVersion: version,
			EOLTable: Table().Date, AsRoot: env.IsRoot()},
		Findings: c.findings, Inventory: c.inv,
	}
	Normalize(r)
	return r
}

// Normalize sorts and caps a report to the contract limits.
func Normalize(r *hc.Report) {
	area := func(a string) int { return slices.Index(hc.Areas, a) }
	sort.SliceStable(r.Findings, func(i, j int) bool { return area(r.Findings[i].Area) < area(r.Findings[j].Area) })
	if len(r.Findings) > hc.MaxFindings {
		r.Findings = r.Findings[:hc.MaxFindings]
	}
	if len(r.Inventory) > hc.MaxInventory {
		r.Inventory = r.Inventory[:hc.MaxInventory]
	}
	if r.Findings == nil {
		r.Findings = []hc.Finding{}
	}
	if r.Inventory == nil {
		r.Inventory = []hc.InventoryItem{}
	}
}

// Marshal encodes a report and checks it against the contract (forbidden
// content, schema, unique findings). A report that fails is a bug in a check
// and is never written or sent. Oversize reports drop inventory first.
func Marshal(r *hc.Report) ([]byte, error) {
	for {
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		if len(b) > 512<<10 && len(r.Inventory) > 0 {
			r.Inventory = r.Inventory[:len(r.Inventory)/2]
			continue
		}
		if _, err := verify.Document(verify.DocHostReport, b, &verify.Context{}); err != nil {
			return nil, fmt.Errorf("host report fails the contract (bug in a check): %w", err)
		}
		return b, nil
	}
}

// Counts are open findings by severity plus unreadable checks.
type Counts struct {
	Critical, High, Medium, Low, Info int64
	Unreadable                        int64
}

// Count summarises a report.
func Count(r *hc.Report) Counts {
	var c Counts
	for _, f := range r.Findings {
		switch f.Status {
		case hc.StatusUnreadable:
			c.Unreadable++
		case hc.StatusFinding:
			switch f.Severity {
			case "critical":
				c.Critical++
			case "high":
				c.High++
			case "medium":
				c.Medium++
			case "low":
				c.Low++
			default:
				c.Info++
			}
		}
	}
	return c
}

// SeverityRank orders severities (info 0 .. critical 4); unknown is -1.
func SeverityRank(s string) int { return slices.Index(hc.Severities, s) }

// MaxSeverity returns the highest severity among open findings ("" if none).
func MaxSeverity(r *hc.Report) string {
	best := -1
	for _, f := range r.Findings {
		if f.Status == hc.StatusFinding && SeverityRank(f.Severity) > best {
			best = SeverityRank(f.Severity)
		}
	}
	if best < 0 {
		return ""
	}
	return hc.Severities[best]
}
