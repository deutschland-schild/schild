package hostcheck

import (
	"bufio"
	"bytes"
	"sort"
	"strconv"
	"strings"
	"time"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
)

// SSHSettings are the global settings the check looks at (lower-case keys).
type SSHSettings map[string]string

var sshKeys = []string{"passwordauthentication", "permitrootlogin", "port", "kbdinteractiveauthentication",
	"challengeresponseauthentication", "usepam", "authenticationmethods"}

// sshAliases are deprecated names sshd_config still accepts for a setting
// (OpenSSH 8.7 and later: one setting, the first value of either name wins).
var sshAliases = map[string]string{"challengeresponseauthentication": "kbdinteractiveauthentication"}

// passwordViaPAM reports whether sshd still asks for the account password
// with PasswordAuthentication off: keyboard-interactive authentication on
// and UsePAM yes (PAM's password prompt; the sshd_config manual says to
// turn off both for key-only logins). Older sshd -T prints
// challengeresponseauthentication separately, which switched
// keyboard-interactive on as well. AuthenticationMethods other than "any"
// is a deliberate setup (e.g. key plus one-time code) and is not judged.
func passwordViaPAM(set SSHSettings) bool {
	kbd := set["kbdinteractiveauthentication"] == "yes" || set["challengeresponseauthentication"] == "yes"
	am := set["authenticationmethods"]
	return kbd && set["usepam"] == "yes" && (am == "" || am == "any")
}

// ParseSshdT parses `sshd -T` (lower-case "key value" lines).
func ParseSshdT(b []byte) SSHSettings {
	out := SSHSettings{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		k = strings.ToLower(k)
		for _, want := range sshKeys {
			if k == want {
				if _, seen := out[k]; !seen {
					out[k] = strings.ToLower(strings.TrimSpace(v))
				}
			}
		}
	}
	return out
}

// sshdConfig parses sshd_config like sshd does for the global section: the
// first value wins, Include is expanded in place, parsing stops at the first
// Match block. Only the settings in sshKeys are kept; nothing else of the
// file is looked at or stored.
type sshdConfig struct {
	env      Env
	settings SSHSettings
	files    int
	include  bool // the main file includes sshd_config.d
	stopped  bool
}

func (p *sshdConfig) parse(file string, depth int) error {
	if depth > 8 || p.files > 64 || p.stopped {
		return nil
	}
	b, err := p.env.ReadFile(file, 1<<20)
	if err != nil {
		return err
	}
	p.files++
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v := splitSSHLine(line)
		switch k {
		case "match":
			p.stopped = true
			return nil
		case "include":
			for _, pat := range strings.Fields(v) {
				if !strings.HasPrefix(pat, "/") {
					pat = "/etc/ssh/" + pat
				}
				if strings.HasPrefix(pat, "/etc/ssh/sshd_config.d/") {
					p.include = true
				}
				ms, _ := p.env.Glob(pat)
				sort.Strings(ms)
				for _, m := range ms {
					_ = p.parse(m, depth+1)
					if p.stopped {
						return nil
					}
				}
			}
		default:
			if a, ok := sshAliases[k]; ok {
				k = a
			}
			for _, want := range sshKeys {
				if k == want {
					if _, seen := p.settings[k]; !seen {
						p.settings[k] = strings.ToLower(strings.Trim(strings.Fields(v + " x")[0], `"`))
					}
				}
			}
		}
	}
	return nil
}

func splitSSHLine(line string) (string, string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	k := strings.ToLower(line[:i])
	v := strings.TrimLeft(line[i:], " \t=")
	return k, v
}

func (c *checker) checkSSH() {
	const area = "ssh"
	installed := exists(c.env, "/usr/sbin/sshd") || exists(c.env, "/etc/ssh/sshd_config")
	if !installed {
		for _, id := range []string{"ssh.password_authentication", "ssh.permit_root_login", "ssh.port", "ssh.failed_logins"} {
			c.add(ok(id, area, "Kein SSH-Server installiert", "Auf diesem Server läuft kein OpenSSH-Server.", hc.Evidence{Source: "sshd_config", Path: "/etc/ssh/sshd_config"}))
		}
		return
	}
	src, cfgPath := "sshd_t", ""
	var set SSHSettings
	include := false
	if res, err := c.env.Run(c.ctx, CmdSshdT); err == nil && res.Exit == 0 && len(res.Stdout) > 0 {
		set = ParseSshdT(res.Stdout)
	}
	p := &sshdConfig{env: c.env, settings: SSHSettings{}}
	perr := p.parse("/etc/ssh/sshd_config", 0)
	include = p.include
	if set == nil {
		if perr != nil {
			reason, needs := readErr(perr), ""
			if reason == ReasonPermission {
				needs = NeedsRoot
			}
			for _, id := range []string{"ssh.password_authentication", "ssh.permit_root_login", "ssh.port"} {
				c.add(unreadable(id, area, "Die SSH-Einstellungen ließen sich nicht lesen.", reason, needs, hc.Evidence{Source: "sshd_config", Path: "/etc/ssh/sshd_config"}))
			}
			c.checkFailedLogins(false)
			return
		}
		set, src, cfgPath = p.settings, "sshd_config", "/etc/ssh/sshd_config"
		// OpenSSH defaults for what the files do not set.
		def := map[string]string{"passwordauthentication": "yes", "permitrootlogin": "prohibit-password", "port": "22", "kbdinteractiveauthentication": "yes",
			"usepam": "no", "authenticationmethods": "any"}
		for k, v := range def {
			if _, ok := set[k]; !ok {
				set[k] = v
			}
		}
	}
	service := "ssh"
	if c.facts.family == "rhel" {
		service = "sshd"
	}
	setFix := func(key, value string) string {
		if include {
			// sshd takes the first value; a drop-in that sorts first wins
			// over cloud-init's 50-cloud-init.conf.
			return "echo '" + key + " " + value + "' | sudo tee -a /etc/ssh/sshd_config.d/00-schild.conf && sudo sshd -t && sudo systemctl reload " + service
		}
		return "sudo sed -i 's/^#\\?" + key + " .*/" + key + " " + value + "/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload " + service
	}
	// PasswordAuthentication, and the same password over keyboard-interactive and PAM
	pw := set["passwordauthentication"]
	ev := hc.Evidence{Source: src, Path: cfgPath, Setting: "PasswordAuthentication", Value: tokp(pw), Expected: sp("no")}
	pwOn := pw != "no"
	const pwExpl = "Passwörter lassen sich aus dem Internet durchprobieren, Schlüssel nicht. Prüf vorher, dass dein SSH-Schlüssel hinterlegt ist und die Anmeldung damit klappt, sonst sperrst du dich aus."
	switch {
	case pwOn:
		c.add(finding("ssh.password_authentication", area, "medium", "SSH erlaubt Anmeldung mit Passwort", pwExpl,
			setFix("PasswordAuthentication", "no"), ev))
	case passwordViaPAM(set):
		pwOn = true
		ev.Setting, ev.Value = "KbdInteractiveAuthentication", sp("yes")
		c.add(finding("ssh.password_authentication", area, "medium", "SSH erlaubt Anmeldung mit Passwort",
			"PasswordAuthentication ist aus, aber KbdInteractiveAuthentication und UsePAM sind an: Dann fragt SSH über PAM trotzdem nach dem Passwort. "+pwExpl,
			setFix("KbdInteractiveAuthentication", "no"), ev))
	default:
		c.add(ok("ssh.password_authentication", area, "SSH nur mit Schlüssel", "Anmeldung mit Passwort ist abgeschaltet.", ev))
	}
	// PermitRootLogin
	rl := set["permitrootlogin"]
	ev = hc.Evidence{Source: src, Path: cfgPath, Setting: "PermitRootLogin", Value: tokp(rl), Expected: sp("prohibit-password")}
	switch rl {
	case "yes":
		sev := "medium"
		if pwOn {
			sev = "high"
		}
		c.add(finding("ssh.permit_root_login", area, sev, "root darf sich mit Passwort anmelden",
			"Der Benutzer root existiert auf jedem Server, Angreifer müssen nur das Passwort raten. Mit prohibit-password meldet sich root nur noch mit Schlüssel an (oder gar nicht, mit no).",
			setFix("PermitRootLogin", "prohibit-password"), ev))
	default:
		c.add(ok("ssh.permit_root_login", area, "root nur mit Schlüssel oder gar nicht", "Die Anmeldung als root mit Passwort ist abgeschaltet.", ev))
	}
	// Port
	port := set["port"]
	ev = hc.Evidence{Source: src, Path: cfgPath, Setting: "Port", Value: tokp(port)}
	if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 65536 {
		ev.Port, ev.Protocol = n, "tcp"
		c.facts.sshPort = n
	}
	c.add(ok("ssh.port", area, "SSH lauscht auf Port "+port, "Ein anderer Port verringert nur das Rauschen im Log; entscheidend sind Schlüssel statt Passwörter.", ev))
	c.checkFailedLogins(pwOn)
}

// CountFailedSSH counts failed SSH logins in journal or auth.log lines since
// `since`. Each attempt counts once: "Invalid user" lines, and "Failed ..."
// lines for existing users.
func CountFailedSSH(b []byte, since, now time.Time) int64 {
	var n int64
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "sshd") {
			continue
		}
		invalid := strings.Contains(line, "Invalid user ")
		failed := (strings.Contains(line, "Failed password for ") || strings.Contains(line, "Failed keyboard-interactive/pam for ")) && !strings.Contains(line, "for invalid user ")
		if !invalid && !failed {
			continue
		}
		if t, ok := logTime(line, now); ok && t.Before(since) {
			continue
		}
		n++
	}
	return n
}

// logTime parses the timestamp of an ISO (journal short-iso, rsyslog) or a
// classic syslog line.
func logTime(line string, now time.Time) (time.Time, bool) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return time.Time{}, false
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999-07:00", "2006-01-02T15:04:05-0700", "2006-01-02T15:04:05-07:00", time.RFC3339Nano} {
		if t, err := time.Parse(layout, f[0]); err == nil {
			return t, true
		}
	}
	if len(f) >= 3 {
		if t, err := time.Parse("Jan 2 15:04:05 2006", f[0]+" "+f[1]+" "+f[2]+" "+strconv.Itoa(now.Year())); err == nil {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, true
		}
	}
	return time.Time{}, false
}

// authLogMax is how much of the end of auth.log or secure is read.
var authLogMax int64 = 64 << 20

func (c *checker) checkFailedLogins(pwOn bool) {
	const id, area = "ssh.failed_logins", "ssh"
	now := c.env.Now()
	since := now.Add(-24 * time.Hour)
	var count int64 = -1
	src, p := "journal", ""
	needs := NeedsGroupJournal
	res, err := c.env.Run(c.ctx, CmdJournalSSHD)
	if err == nil && res.Exit == 0 && !bytes.Contains(res.Stderr, []byte("not seeing messages")) && !bytes.Contains(res.Stderr, []byte("insufficient permissions")) {
		count = CountFailedSSH(res.Stdout, since, now)
	} else {
		for _, f := range []string{"/var/log/auth.log", "/var/log/secure"} {
			b, ferr := readTail(c.env, f, authLogMax)
			if ferr != nil {
				if readErr(ferr) == ReasonPermission {
					needs = NeedsGroupAdm
					if f == "/var/log/secure" {
						needs = NeedsRoot
					}
				}
				continue
			}
			count, src, p = CountFailedSSH(b, since, now), "auth_log", f
			break
		}
	}
	if count < 0 {
		c.add(unreadable(id, area, "Fehlgeschlagene SSH-Anmeldungen ließen sich nicht zählen.", ReasonPermission, needs, hc.Evidence{Source: "journal", WindowHours: 24}))
		return
	}
	ev := hc.Evidence{Source: src, Path: p, Count: i64p(count), WindowHours: 24}
	if pwOn && count >= 20 {
		c.add(finding(id, area, "medium", strconv.FormatInt(count, 10)+" fehlgeschlagene SSH-Anmeldungen in 24 Stunden",
			"Jemand probiert Passwörter durch. Solange Anmeldung mit Passwort erlaubt ist, reicht ein schwaches Passwort für einen Einbruch. Schalte Passwörter ab (siehe oben).", "", ev))
		return
	}
	c.add(ok(id, area, strconv.FormatInt(count, 10)+" fehlgeschlagene SSH-Anmeldungen in 24 Stunden",
		"Fehlversuche aus dem Internet sind normal. Mit Anmeldung nur per Schlüssel laufen sie ins Leere.", ev))
}
