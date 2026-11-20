package hostcheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/msg"
)

// Tests of area logs (MVP-11 addendum "Log-Hygiene", D38). Every test runs
// on a fixture root built in a temp directory; nothing touches the real
// host. Sizes, owners, modes and mtimes come from the fixture's "stat"
// overrides (a fixture cannot hold a 5 GiB file or root-owned files).

// fx builds a fixture root.
type fx struct {
	t      *testing.T
	dir    string
	stat   []string
	statfs []string
	denied []string
	root   bool
}

func newFx(t *testing.T) *fx {
	t.Helper()
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "fs"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &fx{t: t, dir: d, root: true, statfs: []string{"/ 42949672960 32212254720"}} // 40 GiB, 30 GiB free
}

func (f *fx) real(p string) string { return filepath.Join(f.dir, "fs", filepath.FromSlash(p)) }

func (f *fx) file(p, content string) *fx {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(f.real(p)), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.real(p), []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return f
}

func (f *fx) mkdir(p string) *fx {
	f.t.Helper()
	if err := os.MkdirAll(f.real(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	return f
}

func (f *fx) rm(p string) *fx {
	f.t.Helper()
	if err := os.RemoveAll(f.real(p)); err != nil {
		f.t.Fatal(err)
	}
	return f
}

// st adds a stat override ("size=…", "mode=…", "uid=…", "gid=…", "mtime=…").
func (f *fx) st(p string, kv ...string) *fx {
	f.stat = append(f.stat, p+" "+strings.Join(kv, " "))
	return f
}

func (f *fx) env() *FixtureEnv {
	f.t.Helper()
	w := func(name string, lines []string) {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	w("stat", f.stat)
	w("statfs", f.statfs)
	w("denied", f.denied)
	root := f.root
	return &FixtureEnv{Dir: f.dir, Time: fixtureNow, Root: &root}
}

func ago(d time.Duration) string { return "mtime=" + fixtureNow.Add(-d).Format(time.RFC3339) }

func size(n int64) string { return fmt.Sprintf("size=%d", n) }

// ---------------------------------------------------------------- default installs

const debianLogrotateConf = `# see "man logrotate" for details

# global options do not affect preceding include directives

# rotate log files weekly
weekly

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
#dateext

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may also be configured here.
`

const ubuntuLogrotateConf = `# see "man logrotate" for details

# global options do not affect preceding include directives

# rotate log files weekly
weekly

# use the adm group by default, since this is the owning group
# of /var/log/.
su root adm

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

#dateext
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d
`

const almaLogrotateConf = `# see "man logrotate" for details

# global options do not affect preceding include directives

# rotate log files weekly
weekly

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
dateext

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may be also be configured here.
`

const rsyslogRule = `/var/log/syslog
/var/log/mail.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/cron.log
{
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
	sharedscripts
	postrotate
		/usr/lib/rsyslog/rsyslog-rotate
	endscript
}
`

const aptRule = `/var/log/apt/term.log {
  rotate 12
  monthly
  compress
  missingok
  notifempty
}

/var/log/apt/history.log {
  rotate 12
  monthly
  compress
  missingok
  notifempty
}
`

const dpkgRule = `/var/log/dpkg.log {
	monthly
	rotate 12
	compress
	delaycompress
	missingok
	notifempty
	create 644 root root
}
`

const wtmpRule = `# no packages own wtmp -- we'll rotate it here
/var/log/wtmp {
    missingok
    monthly
    create 0664 root utmp
    minsize 1M
    rotate 1
}
`

const btmpRule = `# no packages own btmp -- we'll rotate it here
/var/log/btmp {
    missingok
    monthly
    create 0660 root utmp
    rotate 1
}
`

const journaldConf = `#  This file is part of systemd.
[Journal]
#Storage=auto
#Compress=yes
#SystemMaxUse=
#SystemKeepFree=
#SystemMaxFileSize=
`

// defaultDebian is a Debian 12 default install with rsyslog, apt, a
// persistent journal of 900 MB and logrotate run by its timer.
func defaultDebian(t *testing.T) *fx {
	f := newFx(t)
	f.file("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	f.file("/usr/sbin/logrotate", "")
	f.file("/lib/systemd/systemd-journald", "")
	f.file("/etc/systemd/system/timers.target.wants/logrotate.timer", "")
	f.file("/etc/cron.daily/logrotate", "")
	f.file("/var/lib/logrotate/status", "").st("/var/lib/logrotate/status", ago(9*time.Hour))
	f.file("/proc/stat", fmt.Sprintf("btime %d\n", fixtureNow.Add(-30*24*time.Hour).Unix()))
	f.file("/etc/logrotate.conf", debianLogrotateConf)
	f.file("/etc/logrotate.d/rsyslog", rsyslogRule)
	f.file("/etc/logrotate.d/apt", aptRule)
	f.file("/etc/logrotate.d/dpkg", dpkgRule)
	f.file("/etc/logrotate.d/wtmp", wtmpRule)
	f.file("/etc/logrotate.d/btmp", btmpRule)
	f.file("/etc/logrotate.d/alternatives", "/var/log/alternatives.log {\n\tmonthly\n\trotate 12\n\tcompress\n\tdelaycompress\n\tmissingok\n\tnotifempty\n\tcreate 644 root root\n}\n")
	f.file("/etc/systemd/journald.conf", journaldConf)
	f.file("/var/log/journal/0123456789abcdef0123456789abcdef/system.journal", "").st("/var/log/journal/0123456789abcdef0123456789abcdef/system.journal", size(900*mib))
	f.file("/var/log/syslog", "").st("/var/log/syslog", size(120*mib))
	f.file("/var/log/auth.log", "")
	f.file("/var/log/dpkg.log", "")
	f.file("/var/log/apt/history.log", "")
	f.file("/var/log/apt/term.log", "")
	f.file("/var/log/wtmp", "").st("/var/log/wtmp", size(2*gib))
	f.file("/var/log/lastlog", "").st("/var/log/lastlog", size(300*mib))
	f.file("/var/log/syslog.1", "").st("/var/log/syslog.1", size(150*mib))
	f.mkdir("/var/log/private")
	return f
}

func defaultUbuntu(t *testing.T) *fx {
	f := defaultDebian(t)
	f.file("/etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE=debian\n")
	f.file("/etc/logrotate.conf", ubuntuLogrotateConf)
	// /var/log is 0775 root:syslog on Ubuntu; logrotate.conf sets su.
	f.st("/var/log", "mode=0775", "gid=104")
	return f
}

func defaultAlma(t *testing.T) *fx {
	f := newFx(t)
	f.file("/etc/os-release", "ID=\"almalinux\"\nVERSION_ID=\"9.4\"\nID_LIKE=\"rhel centos fedora\"\n")
	f.file("/usr/sbin/logrotate", "")
	f.file("/usr/lib/systemd/systemd-journald", "")
	f.file("/etc/systemd/system/timers.target.wants/logrotate.timer", "")
	f.file("/var/lib/logrotate/logrotate.status", "").st("/var/lib/logrotate/logrotate.status", ago(20*time.Hour))
	f.file("/etc/logrotate.conf", almaLogrotateConf)
	f.file("/etc/logrotate.d/btmp", btmpRule)
	f.file("/etc/logrotate.d/wtmp", wtmpRule)
	f.file("/etc/logrotate.d/dnf", "/var/log/hawkey.log {\n    missingok\n    notifempty\n    rotate 4\n    weekly\n    create\n}\n")
	f.file("/etc/logrotate.d/rsyslog", "/var/log/cron\n/var/log/maillog\n/var/log/messages\n/var/log/secure\n/var/log/spooler\n{\n    missingok\n    sharedscripts\n    postrotate\n        /usr/bin/systemctl -s HUP kill rsyslog.service >/dev/null 2>&1 || true\n    endscript\n}\n")
	f.file("/etc/logrotate.d/sssd", "/var/log/sssd/*.log {\n    weekly\n    missingok\n    notifempty\n    sharedscripts\n    rotate 2\n    compress\n    delaycompress\n    postrotate\n        /bin/kill -HUP `cat /var/run/sssd.pid  2>/dev/null`  2> /dev/null || true\n    endscript\n}\n")
	f.file("/etc/systemd/journald.conf", journaldConf)
	f.file("/var/log/journal/fedcba9876543210fedcba9876543210/system.journal", "").st("/var/log/journal/fedcba9876543210fedcba9876543210/system.journal", size(300*mib))
	f.file("/var/log/messages", "").st("/var/log/messages", size(130*mib))
	f.file("/var/log/secure", "")
	f.file("/var/log/hawkey.log", "")
	f.file("/var/log/sssd/sssd.log", "")
	f.file("/var/log/btmp", "").st("/var/log/btmp", size(400*mib))
	f.mkdir("/var/log/audit").st("/var/log/audit", "mode=0700")
	return f
}

// runLogs runs only the logs checks.
func runLogs(t *testing.T, env Env, opts Options) []hc.Finding {
	t.Helper()
	c := &checker{ctx: context.Background(), env: env, opts: opts}
	if b, err := env.ReadFile("/etc/os-release", 4096); err == nil && strings.Contains(string(b), "rhel") {
		c.facts.family = "rhel"
	}
	c.checkLogs()
	mustValid(t, c.findings)
	return c.findings
}

// mustValid wraps findings in a report and runs the contract validator
// (schema, forbidden content, fix_config templates).
func mustValid(t *testing.T, fs []hc.Finding) {
	t.Helper()
	r := &hc.Report{Schema: hc.SchemaReport, ReportID: msg.NewID(),
		Host:     hc.Host{Hostname: "logs-test", Role: hc.RoleGateway, OS: hc.OS{ID: "debian", VersionID: "12", Name: "Debian GNU/Linux 12", Kernel: "6.1.0-26-amd64", Arch: "x86_64"}},
		Run:      hc.Run{StartedAt: msg.FormatTime(fixtureNow), DurationMS: 1, SchildVersion: "test", EOLTable: Table().Date, AsRoot: true},
		Findings: append([]hc.Finding(nil), fs...)}
	Normalize(r)
	if _, err := Marshal(r); err != nil {
		t.Fatalf("logs findings fail the contract: %v", err)
	}
}

func get(fs []hc.Finding, id, subject string) *hc.Finding {
	for i := range fs {
		if fs[i].ID == id && fs[i].Subject == subject {
			return &fs[i]
		}
	}
	return nil
}

func mustGet(t *testing.T, fs []hc.Finding, id, subject string) *hc.Finding {
	t.Helper()
	f := get(fs, id, subject)
	if f == nil {
		var have []string
		for _, x := range fs {
			have = append(have, x.ID+"|"+x.Subject+"="+x.Status+"/"+x.Severity)
		}
		t.Fatalf("no result %s|%s; have %v", id, subject, have)
	}
	return f
}

func want(t *testing.T, f *hc.Finding, status, sev string) {
	t.Helper()
	if f.Status != status || f.Severity != sev {
		t.Errorf("%s|%s: got %s/%s, want %s/%s (%s)", f.ID, f.Subject, f.Status, f.Severity, status, sev, f.Explanation)
	}
}

var logIDs = []string{"logs.docker_unbounded", "logs.journald_size", "logs.logrotate_missing", "logs.logrotate_stale", "logs.logrotate_config", "logs.large_file"}

// TestLogsDefaultInstalls: Debian 12, Ubuntu 24.04 and Alma 9 default
// installs have 0 findings above info, and every logs check reports a
// result.
func TestLogsDefaultInstalls(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) *fx{"debian12": defaultDebian, "ubuntu2404": defaultUbuntu, "alma9": defaultAlma} {
		t.Run(name, func(t *testing.T) {
			fs := runLogs(t, mk(t).env(), Options{})
			for _, f := range fs {
				if f.Status == hc.StatusFinding && f.Severity != "info" {
					t.Errorf("false positive on a default install: %s|%s %s/%s: %s", f.ID, f.Subject, f.Status, f.Severity, f.Explanation)
				}
			}
			for _, id := range logIDs {
				found := false
				for _, f := range fs {
					found = found || f.ID == id
				}
				if !found {
					t.Errorf("%s: no result", id)
				}
			}
			want(t, mustGet(t, fs, "logs.logrotate_missing", ""), hc.StatusOK, "info")
			want(t, mustGet(t, fs, "logs.logrotate_stale", ""), hc.StatusOK, "info")
			want(t, mustGet(t, fs, "logs.logrotate_config", ""), hc.StatusOK, "info")
			want(t, mustGet(t, fs, "logs.journald_size", ""), hc.StatusOK, "info")
		})
	}
}

// TestLogsDefaultInstallWithoutRoot: root-only log directories are "nicht
// lesbar" (needs root), never a finding.
func TestLogsDefaultInstallWithoutRoot(t *testing.T) {
	f := defaultDebian(t)
	f.root = false
	f.denied = []string{"/var/log/private"}
	fs := runLogs(t, f.env(), Options{})
	u := mustGet(t, fs, "logs.large_file", "/var/log/private")
	want(t, u, hc.StatusUnreadable, "info")
	if u.Unreadable.Reason != ReasonPermission || u.Unreadable.Needs != NeedsRoot {
		t.Errorf("unreadable %+v", u.Unreadable)
	}
	for _, x := range fs {
		if x.Status == hc.StatusFinding && x.Severity != "info" {
			t.Errorf("false positive: %s|%s %s", x.ID, x.Subject, x.Severity)
		}
	}
}

const (
	cidA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cidB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cidC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func container(f *fx, id, logConfig string, logSize int64, running bool) {
	d := "/var/lib/docker/containers/" + id
	f.file(d+"/hostconfig.json", `{"Binds":null,"LogConfig":`+logConfig+`,"NetworkMode":"bridge"}`)
	f.file(d+"/"+id+"-json.log", "").st(d+"/"+id+"-json.log", size(logSize))
	if running {
		f.mkdir("/run/containerd/io.containerd.runtime.v2.task/moby/" + id)
	}
}

func TestLogsDockerUnbounded(t *testing.T) {
	const id = "logs.docker_unbounded"
	base := func(t *testing.T) *fx {
		f := defaultDebian(t)
		f.mkdir("/var/lib/docker")
		// Kamal app with logging (max-size per container), an accessory
		// without, and an old stopped container without.
		container(f, cidA, `{"Type":"json-file","Config":{"max-size":"10m","max-file":"5"}}`, 30*mib, true)
		container(f, cidB, `{"Type":"json-file","Config":{}}`, 2560*mib, true)
		container(f, cidC, `{"Type":"json-file","Config":{}}`, 10*mib, false)
		return f
	}
	t.Run("no limits, no daemon.json", func(t *testing.T) {
		fs := runLogs(t, base(t).env(), Options{})
		d := mustGet(t, fs, id, "")
		want(t, d, hc.StatusFinding, "medium")
		if *d.Evidence.Count != 2 || *d.Evidence.SizeBytes != 2560*mib || d.Evidence.Source != "docker_container" {
			t.Errorf("evidence %+v", d.Evidence)
		}
		if !strings.Contains(d.Explanation, "Die Logs von 2 Containern haben keine Obergrenze. Das größte ist 2,5 GB groß (Container bbbbbbbbbbbb).") ||
			!strings.Contains(d.Explanation, "deploy.yml") || !strings.Contains(d.Explanation, "deploye danach also neu") {
			t.Errorf("explanation %q", d.Explanation)
		}
		if d.FixConfig == nil || d.FixConfig.Path != "/etc/docker/daemon.json" ||
			d.FixConfig.Content != `{"log-driver": "local", "log-opts": {"max-size": "10m", "max-file": "5"}}`+"\n" {
			t.Errorf("fix_config %+v", d.FixConfig)
		}
	})
	t.Run("stopped and small: low", func(t *testing.T) {
		f := base(t)
		f.rm("/var/lib/docker/containers/" + cidB)
		want(t, mustGet(t, runLogs(t, f.env(), Options{}), id, ""), hc.StatusFinding, "low")
	})
	t.Run("daemon.json with other keys: no fix_config", func(t *testing.T) {
		f := base(t)
		f.file("/etc/docker/daemon.json", `{"data-root": "/srv/docker", "log-driver": "json-file"}`)
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "")
		if d.FixConfig != nil || !strings.Contains(d.Explanation, "log-driver") || !strings.Contains(d.Explanation, "log-opts") {
			t.Errorf("fix %+v, explanation %q", d.FixConfig, d.Explanation)
		}
	})
	t.Run("daemon.json bounded, old containers", func(t *testing.T) {
		f := base(t)
		f.file("/etc/docker/daemon.json", `{"log-driver": "local"}`)
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "")
		want(t, d, hc.StatusFinding, "medium")
		if d.FixConfig != nil {
			t.Error("no fix_config when the daemon is already bounded")
		}
	})
	t.Run("all bounded", func(t *testing.T) {
		f := defaultDebian(t)
		f.file("/etc/docker/daemon.json", `{"log-driver": "local", "log-opts": {"max-size": "10m"}}`)
		container(f, cidA, `{"Type":"json-file","Config":{"max-size":"10m"}}`, 30*mib, true)
		container(f, cidB, `{"Type":"journald","Config":{}}`, 0, true)
		container(f, cidC, `{"Type":"","Config":{}}`, 0, true) // daemon default
		want(t, mustGet(t, runLogs(t, f.env(), Options{}), id, ""), hc.StatusOK, "info")
	})
	t.Run("containers need root", func(t *testing.T) {
		f := base(t)
		f.root = false
		f.denied = []string{"/var/lib/docker/containers"}
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "")
		want(t, d, hc.StatusUnreadable, "info")
		if d.Unreadable.Needs != NeedsRoot {
			t.Errorf("needs %q", d.Unreadable.Needs)
		}
	})
	t.Run("podman only", func(t *testing.T) {
		f := defaultDebian(t)
		f.file("/usr/bin/podman", "")
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "")
		want(t, d, hc.StatusUnreadable, "info")
		if d.Unreadable.Reason != ReasonNotSupported {
			t.Errorf("reason %q", d.Unreadable.Reason)
		}
	})
}

func TestLogsJournald(t *testing.T) {
	const id = "logs.journald_size"
	jf := "/var/log/journal/0123456789abcdef0123456789abcdef/system.journal"
	t.Run("oversized", func(t *testing.T) {
		f := defaultDebian(t)
		f.st(jf, size(5*gib))
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "")
		want(t, d, hc.StatusFinding, "low")
		if d.Explanation != "Das Journal belegt 5,0 GB (12 % von /). Eine feste Obergrenze hält es kleiner. Danach journald neu starten." {
			t.Errorf("explanation %q", d.Explanation)
		}
		if d.FixCommand == nil || *d.FixCommand != fixJournaldRestart || !KnownFix(id, *d.FixCommand) {
			t.Errorf("fix_command %v", d.FixCommand)
		}
		if d.FixConfig == nil || d.FixConfig.Path != "/etc/systemd/journald.conf.d/50-schild-size.conf" ||
			d.FixConfig.Content != "[Journal]\nSystemMaxUse=1024M\nSystemKeepFree=2048M\nMaxRetentionSec=1month\n" {
			t.Errorf("fix_config %+v", d.FixConfig)
		}
		if *d.Evidence.FSPercent != 12 || d.Evidence.Mount != "/" || *d.Evidence.SizeBytes != 5*gib {
			t.Errorf("evidence %+v", d.Evidence)
		}
	})
	t.Run("over 10 % of a small disk", func(t *testing.T) {
		f := defaultDebian(t)
		f.statfs = []string{"/ 8589934592 2147483648"} // 8 GiB
		f.st(jf, size(1200*mib))
		want(t, mustGet(t, runLogs(t, f.env(), Options{}), id, ""), hc.StatusFinding, "low")
	})
	t.Run("SystemMaxUse infinity in a drop-in", func(t *testing.T) {
		f := defaultDebian(t)
		f.file("/etc/systemd/journald.conf.d/90-keep.conf", "[Journal]\nSystemMaxUse=infinity\n")
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "")
		want(t, d, hc.StatusFinding, "low")
		if d.Evidence.Setting != "SystemMaxUse" || d.Evidence.Value == nil || *d.Evidence.Value != "infinity" {
			t.Errorf("evidence %+v", d.Evidence)
		}
	})
	t.Run("schild drop-in after a raised value", func(t *testing.T) {
		f := defaultDebian(t)
		f.file("/etc/systemd/journald.conf.d/10-big.conf", "[Journal]\nSystemMaxUse=20G\n")
		f.file("/etc/systemd/journald.conf.d/50-schild-size.conf", "[Journal]\nSystemMaxUse=1024M\nSystemKeepFree=2048M\nMaxRetentionSec=1month\n")
		want(t, mustGet(t, runLogs(t, f.env(), Options{}), id, ""), hc.StatusOK, "info")
	})
	t.Run("volatile", func(t *testing.T) {
		f := defaultDebian(t)
		f.rm("/var/log/journal")
		want(t, mustGet(t, runLogs(t, f.env(), Options{}), id, ""), hc.StatusOK, "info")
	})
}

func TestLogsLogrotateMissing(t *testing.T) {
	const id = "logs.logrotate_missing"
	t.Run("journald only: info", func(t *testing.T) {
		f := defaultDebian(t)
		f.rm("/usr/sbin/logrotate").rm("/etc/systemd/system/timers.target.wants").rm("/etc/cron.daily")
		f.st("/var/log/syslog", size(50*mib))
		fs := runLogs(t, f.env(), Options{})
		d := mustGet(t, fs, id, "")
		want(t, d, hc.StatusFinding, "info")
		if *d.FixCommand != fixLogrotateApt || !KnownFix(id, *d.FixCommand) {
			t.Errorf("fix %q", *d.FixCommand)
		}
		want(t, mustGet(t, fs, "logs.logrotate_stale", ""), hc.StatusUnreadable, "info")
	})
	t.Run("large files: medium", func(t *testing.T) {
		f := defaultDebian(t)
		f.rm("/usr/sbin/logrotate").rm("/etc/systemd/system/timers.target.wants").rm("/etc/cron.daily")
		want(t, mustGet(t, runLogs(t, f.env(), Options{}), id, ""), hc.StatusFinding, "medium") // syslog is 120 MiB
	})
	t.Run("installed, timer off", func(t *testing.T) {
		f := defaultDebian(t)
		f.rm("/etc/systemd/system/timers.target.wants").rm("/etc/cron.daily")
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "")
		if *d.FixCommand != fixLogrotateTimer {
			t.Errorf("fix %q", *d.FixCommand)
		}
	})
	t.Run("rhel: dnf", func(t *testing.T) {
		f := defaultAlma(t)
		f.rm("/usr/sbin/logrotate").rm("/etc/systemd/system/timers.target.wants")
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "")
		if *d.FixCommand != fixLogrotateDnf || !KnownFix(id, *d.FixCommand) {
			t.Errorf("fix %q", *d.FixCommand)
		}
	})
}

func TestLogsLogrotateStale(t *testing.T) {
	const id = "logs.logrotate_stale"
	t.Run("stale", func(t *testing.T) {
		f := defaultDebian(t)
		f.st("/var/lib/logrotate/status", ago(5*24*time.Hour))
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "")
		want(t, d, hc.StatusFinding, "low")
		if d.Evidence.Date != "2026-10-22" || !strings.HasPrefix(d.Explanation, "logrotate ist zuletzt am 22.10.2026 gelaufen. Normal ist einmal am Tag.") {
			t.Errorf("%+v %q", d.Evidence, d.Explanation)
		}
		if !KnownFix(id, *d.FixCommand) || *d.FixCommand != "sudo logrotate -d /etc/logrotate.conf" {
			t.Errorf("fix %q", *d.FixCommand)
		}
	})
	t.Run("stale with a large file: medium", func(t *testing.T) {
		f := defaultDebian(t)
		f.st("/var/lib/logrotate/status", ago(5*24*time.Hour))
		f.file("/var/log/app/app.log", "").st("/var/log/app/app.log", size(3*gib))
		fs := runLogs(t, f.env(), Options{})
		want(t, mustGet(t, fs, id, ""), hc.StatusFinding, "medium")
		want(t, mustGet(t, fs, "logs.large_file", "/var/log/app/app.log"), hc.StatusFinding, "medium") // 7 % of the disk
	})
	t.Run("host was off", func(t *testing.T) {
		f := defaultDebian(t)
		f.st("/var/lib/logrotate/status", ago(5*24*time.Hour))
		f.file("/proc/stat", fmt.Sprintf("btime %d\n", fixtureNow.Add(-20*time.Minute).Unix()))
		want(t, mustGet(t, runLogs(t, f.env(), Options{}), id, ""), hc.StatusOK, "info")
	})
	t.Run("fresh install", func(t *testing.T) {
		f := defaultDebian(t)
		f.rm("/var/lib/logrotate/status")
		want(t, mustGet(t, runLogs(t, f.env(), Options{}), id, ""), hc.StatusOK, "info")
	})
}

func TestLogsLogrotateConfig(t *testing.T) {
	const id = "logs.logrotate_config"
	t.Run("bad mode", func(t *testing.T) {
		f := defaultDebian(t)
		f.file("/etc/logrotate.d/app", "/var/log/app/*.log {\n  daily\n}\n").st("/etc/logrotate.d/app", "mode=0664")
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "/etc/logrotate.d/app")
		want(t, d, hc.StatusFinding, "low")
		if d.Explanation != "logrotate überspringt /etc/logrotate.d/app, weil andere sie beschreiben dürfen. Die Regeln darin wirken nicht." {
			t.Errorf("explanation %q", d.Explanation)
		}
		if *d.FixCommand != "sudo chmod 0644 /etc/logrotate.d/app" || !KnownFix(id, *d.FixCommand) {
			t.Errorf("fix %q", *d.FixCommand)
		}
	})
	t.Run("not owned by root", func(t *testing.T) {
		f := defaultDebian(t)
		f.file("/etc/logrotate.d/app", "/var/log/app/*.log {\n  daily\n}\n").st("/etc/logrotate.d/app", "uid=1000")
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "/etc/logrotate.d/app")
		if *d.FixCommand != "sudo chown root:root /etc/logrotate.d/app" || !KnownFix(id, *d.FixCommand) {
			t.Errorf("fix %q", *d.FixCommand)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		f := defaultDebian(t)
		f.file("/etc/logrotate.d/myapp", "/var/log/syslog {\n  daily\n}\n")
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "/var/log/syslog")
		want(t, d, hc.StatusFinding, "low")
		if !strings.Contains(d.Explanation, "/etc/logrotate.d/myapp") || !strings.Contains(d.Explanation, "/etc/logrotate.d/rsyslog") {
			t.Errorf("explanation %q", d.Explanation)
		}
	})
	t.Run("glob duplicate", func(t *testing.T) {
		f := defaultDebian(t)
		f.file("/etc/logrotate.d/zz-apt", "/var/log/apt/*.log {\n  daily\n}\n")
		fs := runLogs(t, f.env(), Options{})
		want(t, mustGet(t, fs, id, "/var/log/apt/history.log"), hc.StatusFinding, "low")
	})
	t.Run("taboo extension", func(t *testing.T) {
		f := defaultDebian(t)
		f.file("/etc/logrotate.d/nginx.dpkg-old", "/var/log/nginx/*.log {\n  daily\n}\n")
		f.file("/etc/logrotate.d/rsyslog~", rsyslogRule) // backup next to the live file: fine
		fs := runLogs(t, f.env(), Options{})
		want(t, mustGet(t, fs, id, "/etc/logrotate.d/nginx.dpkg-old"), hc.StatusFinding, "low")
		if get(fs, id, "/etc/logrotate.d/rsyslog~") != nil {
			t.Error("a backup next to the live file is no finding")
		}
	})
	t.Run("writable log dir without su", func(t *testing.T) {
		f := defaultDebian(t)
		f.file("/etc/logrotate.d/app", "/var/log/app/app.log {\n  daily\n  copytruncate\n}\n")
		f.file("/var/log/app/app.log", "").st("/var/log/app", "mode=0777")
		d := mustGet(t, runLogs(t, f.env(), Options{}), id, "/var/log/app/app.log")
		want(t, d, hc.StatusFinding, "low")
		if d.FixCommand != nil {
			t.Error("no fix command (the fix is a config edit)")
		}
		// With su in the rule: fine.
		f.file("/etc/logrotate.d/app", "/var/log/app/app.log {\n  su app app\n  daily\n}\n")
		if get(runLogs(t, f.env(), Options{}), id, "/var/log/app/app.log") != nil {
			t.Error("su makes the directory fine")
		}
	})
	t.Run("scripts with braces are skipped", func(t *testing.T) {
		rules, _, _ := parseLogrotate("/var/log/a.log /var/log/b.log {\n postrotate\n  if [ -f x ]; then { kill -HUP 1; }; fi\n endscript\n copytruncate\n}\n\"/var/log/c d.log\" { su root adm }\n", "/etc/logrotate.d/x", false, false)
		if len(rules) != 2 || len(rules[0].patterns) != 2 || !rules[0].copytruncate || rules[1].patterns[0] != "/var/log/c d.log" || !rules[1].su {
			t.Errorf("rules %+v", rules)
		}
	})
}

const caddyfile = `{
	order schild first
}

(access_log) {
	log {
		output file /var/log/caddy/access.log {
			roll_disabled
		}
		format json
	}
}

(app_log) {
	log app {
		output file /var/log/caddy/app.log
	}
}

shop.example.de {
	import access_log
	import app_log
	reverse_proxy app:3000
}
`

func TestLogsCaddyCrossCheck(t *testing.T) {
	const id = "logs.logrotate_config"
	setup := func(t *testing.T, rule string) []hc.Finding {
		f := defaultDebian(t)
		f.file("/etc/schild/Caddyfile", caddyfile)
		f.file("/var/log/caddy/access.log", "").st("/var/log/caddy/access.log", size(300*mib))
		if rule != "" {
			f.file("/etc/logrotate.d/caddy", rule)
		}
		return runLogs(t, f.env(), Options{Caddyfile: "/etc/schild/Caddyfile"})
	}
	t.Run("roll_disabled without a rule", func(t *testing.T) {
		fs := setup(t, "")
		d := mustGet(t, fs, id, "/var/log/caddy/access.log")
		want(t, d, hc.StatusFinding, "medium")
		if !strings.HasPrefix(d.Explanation, "Caddy schreibt /var/log/caddy/access.log selbst und öffnet die Datei nach dem Umbenennen nicht neu. Ohne copytruncate landet das Log weiter in der alten Datei.") {
			t.Errorf("explanation %q", d.Explanation)
		}
		// The rendering equals the contract vector (valid 007).
		if d.FixConfig == nil || d.FixConfig.Path != "/etc/logrotate.d/schild-caddy-access" ||
			d.FixConfig.Content != "/var/log/caddy/access.log {\n  daily\n  rotate 14\n  maxsize 200M\n  missingok\n  notifempty\n  compress\n  delaycompress\n  copytruncate\n}\n" {
			t.Errorf("fix_config %+v", d.FixConfig)
		}
		want(t, mustGet(t, fs, id, "/var/log/caddy/app.log"), hc.StatusOK, "info")
		if get(fs, "logs.large_file", "/var/log/caddy/access.log") != nil {
			t.Error("Caddy outputs are checked here, not as large files (one fix per file)")
		}
	})
	t.Run("roll_disabled with copytruncate", func(t *testing.T) {
		fs := setup(t, "/var/log/caddy/access.log {\n  daily\n  rotate 14\n  copytruncate\n}\n")
		want(t, mustGet(t, fs, id, "/var/log/caddy/access.log"), hc.StatusOK, "info")
	})
	t.Run("roll_disabled without copytruncate", func(t *testing.T) {
		fs := setup(t, "/var/log/caddy/*.log {\n  daily\n  rotate 14\n  postrotate\n    systemctl reload caddy\n  endscript\n}\n")
		d := mustGet(t, fs, id, "/var/log/caddy/access.log")
		want(t, d, hc.StatusFinding, "medium")
		if d.FixConfig != nil || !strings.Contains(d.Explanation, "/etc/logrotate.d/caddy") {
			t.Errorf("fix %+v explanation %q", d.FixConfig, d.Explanation)
		}
		// app.log is rolled by Caddy itself and by the rule: double rotation.
		want(t, mustGet(t, fs, id, "/var/log/caddy/app.log"), hc.StatusFinding, "medium")
	})
	t.Run("parser", func(t *testing.T) {
		got := parseCaddyOutputs(caddyfile + "\n# output file /var/log/x.log {\nb {\n log {\n  output file /var/log/caddy/access.log\n }\n}\n")
		if len(got) != 2 || got[0] != (caddyOutput{"/var/log/caddy/access.log", true}) || got[1] != (caddyOutput{"/var/log/caddy/app.log", false}) {
			t.Errorf("%+v", got)
		}
	})
}

func TestLogsLargeFile(t *testing.T) {
	const id = "logs.large_file"
	const p = "/srv/app/storage/logs/laravel.log"
	setup := func(t *testing.T) *fx {
		f := defaultDebian(t)
		f.file(p, "").st(p, size(6*gib))
		f.file("/var/log/app/big.log", "").st("/var/log/app/big.log", size(1536*mib))
		return f
	}
	prev := func(sizes map[string]int64, at time.Time) *hc.Report {
		r := &hc.Report{Run: hc.Run{StartedAt: msg.FormatTime(at)}}
		for s, n := range sizes {
			r.Findings = append(r.Findings, hc.Finding{ID: id, Subject: s, Status: hc.StatusOK, Evidence: hc.Evidence{SizeBytes: i64p(n)}})
		}
		return r
	}
	t.Run("first run", func(t *testing.T) {
		fs := runLogs(t, setup(t).env(), Options{Apps: []string{"/srv/app"}})
		d := mustGet(t, fs, id, p)
		want(t, d, hc.StatusFinding, "medium") // 15 % of the file system
		if d.Explanation != p+" ist 6,0 GB groß. Keine logrotate-Regel erfasst die Datei." {
			t.Errorf("explanation %q", d.Explanation)
		}
		if d.FixConfig == nil || d.FixConfig.Path != "/etc/logrotate.d/schild-laravel" ||
			d.FixConfig.Content != p+" {\n  daily\n  rotate 7\n  maxsize 500M\n  missingok\n  notifempty\n  compress\n  delaycompress\n  copytruncate\n}\n" {
			t.Errorf("fix_config %+v", d.FixConfig)
		}
		if *d.Evidence.FSPercent != 15 || d.Evidence.Mount != "/" || d.Evidence.GrowthBytesPerDay != nil || *d.Evidence.Enabled {
			t.Errorf("evidence %+v", d.Evidence)
		}
		b := mustGet(t, fs, id, "/var/log/app/big.log")
		want(t, b, hc.StatusFinding, "low")
		if b.FixConfig == nil || b.FixConfig.Path != "/etc/logrotate.d/schild-app-big" {
			t.Errorf("fix_config %+v", b.FixConfig)
		}
		// wtmp (2 GiB), lastlog and rotated files are never reported.
		for _, s := range []string{"/var/log/wtmp", "/var/log/lastlog", "/var/log/syslog.1"} {
			if get(fs, id, s) != nil {
				t.Errorf("%s reported", s)
			}
		}
		// syslog (120 MiB) is covered by a rule: ok with its size.
		want(t, mustGet(t, fs, id, "/var/log/syslog"), hc.StatusOK, "info")
	})
	t.Run("growth", func(t *testing.T) {
		pr := prev(map[string]int64{p: 5 * gib, "/var/log/app/big.log": 1536 * mib}, fixtureNow.Add(-24*time.Hour))
		fs := runLogs(t, setup(t).env(), Options{Apps: []string{"/srv/app"}, Previous: pr})
		d := mustGet(t, fs, id, p)
		if d.Evidence.GrowthBytesPerDay == nil || *d.Evidence.GrowthBytesPerDay != gib ||
			d.Explanation != p+" ist 6,0 GB groß und wächst um etwa 1,0 GB pro Tag. Keine logrotate-Regel erfasst die Datei." {
			t.Errorf("growth %v %q", d.Evidence.GrowthBytesPerDay, d.Explanation)
		}
		// No growth: a one-off dump, not a finding.
		want(t, mustGet(t, fs, id, "/var/log/app/big.log"), hc.StatusOK, "info")
	})
	t.Run("fills the disk in under 14 days", func(t *testing.T) {
		f := setup(t)
		f.statfs = []string{"/ 429496729600 21474836480"} // 400 GiB, 20 GiB free
		f.st("/var/log/app/big.log", size(1024*mib+1))
		pr := prev(map[string]int64{"/var/log/app/big.log": 1024*mib + 1 - 2*gib}, fixtureNow.Add(-24*time.Hour))
		fs := runLogs(t, f.env(), Options{Previous: pr})
		want(t, mustGet(t, fs, id, "/var/log/app/big.log"), hc.StatusFinding, "medium")
	})
	t.Run("covered by a rule", func(t *testing.T) {
		f := setup(t)
		f.file("/etc/logrotate.d/app", "/var/log/app/*.log {\n  daily\n  copytruncate\n}\n")
		fs := runLogs(t, f.env(), Options{})
		want(t, mustGet(t, fs, id, "/var/log/app/big.log"), hc.StatusOK, "info")
	})
	t.Run("not under an allowed root: no fix_config", func(t *testing.T) {
		if logrotateFix(id, "/home/u/app.log", 7, 500) != nil || logrotateFix(id, "/srv/app/data.db", 7, 500) != nil ||
			logrotateFix(id, "/var/log/../etc/passwd", 7, 500) != nil {
			t.Error("fix_config outside the template roots")
		}
	})
}

// TestLogsBoundedWalk: a /var/log with many files stops at the bound and
// says so ("nicht lesbar", timeout); 10 000 files cost well under 1 s.
func TestLogsBoundedWalk(t *testing.T) {
	f := defaultDebian(t)
	for i := 0; i < 10000; i++ {
		d := fmt.Sprintf("/var/log/many/d%02d", i%50)
		if i < 50 {
			f.mkdir(d)
		}
		if err := os.WriteFile(f.real(fmt.Sprintf("%s/f%05d.log", d, i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env := f.env()
	start := time.Now()
	fs := runLogs(t, env, Options{})
	if el := time.Since(start); el > time.Second {
		t.Errorf("logs checks took %s with 10 000 files", el)
	}
	u := mustGet(t, fs, "logs.large_file", "/var/log")
	want(t, u, hc.StatusUnreadable, "info")
	if u.Unreadable.Reason != ReasonTimeout || *u.Evidence.Count > int64(logWalkEntries)+1 {
		t.Errorf("%+v %+v", u.Unreadable, u.Evidence)
	}
	// The time bound holds on its own as well.
	old := logWalkBudget
	logWalkBudget = time.Nanosecond
	defer func() { logWalkBudget = old }()
	w := (&checker{env: env}).walkLogs()
	if !w.truncated || w.entries > 256 {
		t.Errorf("time bound: truncated %v after %d entries", w.truncated, w.entries)
	}
}

// recordingEnv records every file the checks open and every command.
type recordingEnv struct {
	*FixtureEnv
	read []string
}

func (r *recordingEnv) ReadFile(p string, max int64) ([]byte, error) {
	r.read = append(r.read, p)
	return r.FixtureEnv.ReadFile(p, max)
}

func treeHash(t *testing.T, dir string) string {
	t.Helper()
	h := sha256.New()
	var paths []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil {
			paths = append(paths, p)
		}
		return nil
	})
	sort.Strings(paths)
	for _, p := range paths {
		st, err := os.Lstat(p)
		if err != nil {
			continue
		}
		fmt.Fprintf(h, "%s %v %d %d\n", p, st.Mode(), st.Size(), st.ModTime().UnixNano())
		if st.Mode().IsRegular() {
			fh, _ := os.Open(p)
			_, _ = io.Copy(h, fh)
			fh.Close()
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestLogsReadOnly: the logs checks run no command, open only the listed
// config files (never a log file) and change nothing in the tree.
func TestLogsReadOnly(t *testing.T) {
	f := defaultDebian(t)
	f.file("/etc/schild/Caddyfile", caddyfile)
	f.file("/etc/docker/daemon.json", `{"log-driver": "json-file"}`)
	container(f, cidB, `{"Type":"json-file","Config":{}}`, 2*gib, true)
	f.file("/var/log/app/big.log", "SECRET-LOG-LINE").st("/var/log/app/big.log", size(3*gib))
	f.file("/srv/app/storage/logs/laravel.log", "SECRET-LOG-LINE").st("/srv/app/storage/logs/laravel.log", size(3*gib))
	env := &recordingEnv{FixtureEnv: f.env()}
	before := treeHash(t, f.dir)
	fs := runLogs(t, env, Options{Caddyfile: "/etc/schild/Caddyfile", Apps: []string{"/srv/app"}})
	if after := treeHash(t, f.dir); after != before {
		t.Error("the fixture tree changed")
	}
	if len(env.Ran) != 0 {
		t.Errorf("commands run: %v", env.Ran)
	}
	allowed := func(p string) bool {
		switch {
		case p == "/etc/docker/daemon.json", p == "/etc/logrotate.conf", p == "/etc/schild/Caddyfile", p == "/proc/stat", p == "/etc/os-release":
			return true
		case strings.HasPrefix(p, "/etc/logrotate.d/"), strings.HasPrefix(p, "/etc/systemd/journald.conf"):
			return true
		case strings.HasPrefix(p, "/var/lib/docker/containers/") && strings.HasSuffix(p, "/hostconfig.json"):
			return true
		}
		return false
	}
	for _, p := range env.read {
		if !allowed(p) {
			t.Errorf("opened %s", p)
		}
	}
	for _, x := range fs {
		b := fmt.Sprintf("%+v", x)
		if strings.Contains(b, "SECRET-LOG-LINE") {
			t.Errorf("log content in %s", x.ID)
		}
	}
	// The read-only proof of the whole run: logs adds no command.
	for _, c := range Commands {
		for _, a := range c.Argv {
			if a == "logrotate" || a == "docker" {
				t.Errorf("%s runs %s", c.ID, a)
			}
		}
	}
}

// TestLogsInFullRun: the logs area is part of Run (schild check and
// schild-agent) and the whole report passes the contract.
func TestLogsInFullRun(t *testing.T) {
	f := defaultDebian(t)
	f.file("/etc/schild/Caddyfile", caddyfile)
	for _, role := range []string{hc.RoleGateway, hc.RoleAgent} {
		r := Run(context.Background(), f.env(), Options{Role: role, AgentKeyID: "logs/agent/2026-10", SchildVersion: "test", Caddyfile: "/etc/schild/Caddyfile"})
		if _, err := Marshal(r); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, x := range r.Findings {
			if x.Area == areaLogs {
				n++
			}
		}
		if n < len(logIDs) {
			t.Errorf("%s: %d logs results", role, n)
		}
	}
}

func TestLogsHelpers(t *testing.T) {
	for in, want := range map[string]string{"/var/log/caddy/access.log": "caddy-access", "/srv/app/storage/logs/laravel.log": "laravel", "/var/log/syslog": "syslog", "/var/log/My App/X_Y.log": "my-app-x-y"} {
		if got := logSlug(in); got != want {
			t.Errorf("slug %s: %s, want %s", in, got, want)
		}
	}
	for in, want := range map[int64]string{5 * gib: "5,0 GB", 2576980378: "2,4 GB", 380 * mib: "380 MB", 12 * kib: "12 KB", 3: "3 Bytes"} {
		if got := humanSize(in); got != want {
			t.Errorf("size %d: %s, want %s", in, got, want)
		}
	}
	for in, want := range map[string]int64{"1G": gib, "512M": 512 * mib, "1.5G": gib + gib/2, "100": 100} {
		if n, _, ok := parseSystemdSize(in); !ok || n != want {
			t.Errorf("parse %s: %d", in, n)
		}
	}
	if _, inf, ok := parseSystemdSize("infinity"); !ok || !inf {
		t.Error("infinity")
	}
	if _, _, ok := parseSystemdSize("10%"); ok {
		t.Error("percent is not parsed")
	}
	for m, bad := range map[fs.FileMode]bool{0o644: false, 0o444: false, 0o600: false, 0o664: true, 0o666: true, 0o755: true, 0o640: false} {
		if lrBadMode(m) != bad {
			t.Errorf("mode %o: bad %v", m, !bad)
		}
	}
}
