package hostcheck

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
)

// Update is one pending package update.
type Update struct {
	Package   string
	Installed string
	Candidate string
	Security  bool
}

var (
	aptListRe = regexp.MustCompile(`^([^/\s]+)/(\S+)\s+(\S+)\s+\S+(?:\s+\[upgradable from:\s+([^\]]+)\])?`)
	aptSimRe  = regexp.MustCompile(`^Inst\s+(\S+)\s+(?:\[([^\]]+)\]\s+)?\((\S+)\s+([^\[]*)`)
)

// ParseAptUpgradable parses `apt list --upgradable`.
func ParseAptUpgradable(b []byte) []Update {
	var out []Update
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		m := aptListRe.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		out = append(out, Update{Package: m[1], Candidate: m[3], Installed: m[4], Security: strings.Contains(m[2], "-security")})
	}
	return out
}

// ParseAptSimulate parses `apt-get -s dist-upgrade` ("Inst" lines).
func ParseAptSimulate(b []byte) []Update {
	var out []Update
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		m := aptSimRe.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		out = append(out, Update{Package: m[1], Installed: m[2], Candidate: m[3], Security: strings.Contains(strings.ToLower(m[4]), "security")})
	}
	return out
}

var packageNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.+_:@/-]{0,127}$`)

// names returns up to 50 package names that fit the contract pattern.
func names(us []Update, security bool) []string {
	var out []string
	for _, u := range us {
		if (!security || u.Security) && packageNameRe.MatchString(u.Package) {
			out = append(out, u.Package)
		}
	}
	sort.Strings(out)
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func (c *checker) checkUpdates() {
	switch c.facts.family {
	case "debian":
		c.aptUpdates()
		c.aptAutomatic()
		c.rebootRequiredDebian()
	case "rhel":
		c.dnfUpdates()
		c.dnfAutomatic()
		c.rebootRequiredRHEL()
	default:
		for _, id := range []string{"updates.pending", "updates.automatic", "updates.reboot_required"} {
			c.add(unreadable(id, "updates", "Updates lassen sich nur für Debian, Ubuntu und RHEL-Verwandte prüfen.", ReasonNotSupported, "", hc.Evidence{Source: "os_release"}))
		}
	}
}

const (
	aptFix = "sudo apt update && sudo apt full-upgrade"
)

func (c *checker) aptUpdates() {
	const area = "updates"
	src := "apt"
	res, err := c.env.Run(c.ctx, CmdAptUpgradable)
	var ups []Update
	if err == nil && res.Exit == 0 {
		ups = ParseAptUpgradable(res.Stdout)
	} else {
		res, err = c.env.Run(c.ctx, CmdAptSimUpgrade)
		if err == nil && res.Exit != 0 {
			err = fs.ErrPermission
		}
		ups = ParseAptSimulate(res.Stdout)
	}
	if err != nil {
		reason := readErr(err)
		c.add(unreadable("updates.pending", area, "Ausstehende Updates ließen sich nicht lesen.", reason, "", hc.Evidence{Source: src}))
		c.add(unreadable("updates.security_pending", area, "Ausstehende Sicherheitsupdates ließen sich nicht lesen.", reason, "", hc.Evidence{Source: src}))
		return
	}
	c.reportUpdates(ups, true, src, aptFix, aptFix)
}

// reportUpdates writes updates.security_pending and updates.pending.
func (c *checker) reportUpdates(ups []Update, securityKnown bool, src, secFix, fix string) {
	const area = "updates"
	sec := 0
	for _, u := range ups {
		if u.Security {
			sec++
		}
	}
	listNote := " Die Paketliste stammt aus dem vorhandenen Paket-Cache; die Prüfung lädt keine neuen Paketlisten. Ist der Cache alt, können es mehr sein."
	if securityKnown {
		ev := hc.Evidence{Source: src, Count: i64p(int64(sec)), Packages: names(ups, true)}
		if sec > 0 {
			c.add(finding("updates.security_pending", area, "high", strconv.Itoa(sec)+" Sicherheitsupdates ausstehend",
				"Für installierte Pakete gibt es Sicherheitskorrekturen, die noch nicht eingespielt sind. Bekannte Lücken bleiben offen, bis du sie installierst."+listNote, secFix, ev))
		} else {
			c.add(ok("updates.security_pending", area, "Keine Sicherheitsupdates ausstehend", "Laut Paket-Cache sind alle bekannten Sicherheitskorrekturen eingespielt."+listNote, ev))
		}
	}
	other := len(ups) - sec
	ev := hc.Evidence{Source: src, Count: i64p(int64(other)), Packages: names(nonSecurity(ups), false)}
	switch {
	case other > 0:
		sev := "low"
		if !securityKnown {
			sev = "medium"
		}
		c.add(finding("updates.pending", area, sev, strconv.Itoa(other)+" weitere Updates ausstehend",
			"Es gibt Updates, die (soweit bekannt) keine Sicherheitslücken schließen, etwa Fehlerkorrekturen. Spiel sie bei Gelegenheit ein."+listNote, fix, ev))
	default:
		c.add(ok("updates.pending", area, "Keine weiteren Updates ausstehend", "Laut Paket-Cache ist alles auf dem neuesten Stand."+listNote, ev))
	}
}

func nonSecurity(us []Update) []Update {
	var out []Update
	for _, u := range us {
		if !u.Security {
			out = append(out, u)
		}
	}
	return out
}

// aptPeriodic finds the effective APT::Periodic::Unattended-Upgrade value
// (the last file in apt.conf.d order wins). Only that one setting is parsed.
var aptPeriodicRe = regexp.MustCompile(`(?m)^\s*APT::Periodic::Unattended-Upgrade\s+"([0-9]+)"\s*;`)

func (c *checker) aptAutomatic() {
	const id, area = "updates.automatic", "updates"
	installed := exists(c.env, "/usr/bin/unattended-upgrade")
	if _, ok := c.facts.packages["unattended-upgrades"]; ok {
		installed = true
	}
	val, from := "", "/etc/apt/apt.conf.d"
	files, _ := c.env.Glob("/etc/apt/apt.conf.d/*")
	sort.Strings(files)
	for _, f := range files {
		b, err := c.env.ReadFile(f, 256<<10)
		if err != nil {
			continue
		}
		if ms := aptPeriodicRe.FindAllSubmatch(b, -1); len(ms) > 0 {
			val, from = string(ms[len(ms)-1][1]), f
		}
	}
	on := installed && val != "" && val != "0"
	ev := hc.Evidence{Source: "unattended_upgrades", Path: from, Setting: "Unattended-Upgrade", Value: tokp(val), Enabled: bp(on)}
	if !absPathRe.MatchString(ev.Path) {
		ev.Path = ""
	}
	if on {
		c.add(ok(id, area, "Automatische Sicherheitsupdates sind an", "unattended-upgrades spielt Sicherheitsupdates selbst ein.", ev))
		return
	}
	c.add(finding(id, area, "medium", "Automatische Sicherheitsupdates sind aus",
		"Sicherheitsupdates kommen nur, wenn jemand sie von Hand einspielt. Mit unattended-upgrades passiert das täglich von selbst; größere Upgrades bleiben deine Entscheidung.",
		fixAptAutomatic, ev))
}

func (c *checker) rebootRequiredDebian() {
	const id, area = "updates.reboot_required", "updates"
	p := "/var/run/reboot-required"
	if _, err := c.env.Stat(p); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			c.add(unreadable(id, area, "Ob ein Neustart nötig ist, ließ sich nicht lesen.", ReasonPermission, "", hc.Evidence{Source: "reboot_required", Path: p}))
			return
		}
		c.add(ok(id, area, "Kein Neustart nötig", "Kein Update wartet auf einen Neustart.", hc.Evidence{Source: "reboot_required", Path: p, Enabled: bp(false)}))
		return
	}
	var pkgs []string
	if b, err := c.env.ReadFile(p+".pkgs", 64<<10); err == nil {
		seen := map[string]bool{}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if packageNameRe.MatchString(l) && !seen[l] && len(pkgs) < 50 {
				seen[l] = true
				pkgs = append(pkgs, l)
			}
		}
	}
	sort.Strings(pkgs)
	c.add(finding(id, area, "medium", "Neustart nötig",
		"Ein Update wirkt erst nach einem Neustart, oft ist es ein neuer Kernel oder eine Systembibliothek. Bis dahin läuft noch die alte Version.",
		fixReboot, hc.Evidence{Source: "reboot_required", Path: p, Enabled: bp(true), Packages: pkgs}))
}

// ParseDnfUpdates parses the output of dnfUpdatesScript. ok is false when
// the header is missing (not our script's output).
func ParseDnfUpdates(b []byte) (ups []Update, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	seen := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		if line == "schild-dnf-updates 1" {
			ok = true
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 5 || f[0] != "u" {
			continue
		}
		if seen[f[1]] {
			// Several arches of one name (x86_64 and i686): one update,
			// security if any of them is.
			for i := range ups {
				if ups[i].Package == f[1] && f[4] == "1" {
					ups[i].Security = true
				}
			}
			continue
		}
		seen[f[1]] = true
		ups = append(ups, Update{Package: f[1], Candidate: f[3], Security: f[4] == "1"})
	}
	return ups, ok
}

func (c *checker) dnfUpdates() {
	const area = "updates"
	src := "dnf"
	fix, secFix := dnfFix, dnfSecFix
	if c.facts.versionID != "" && strings.HasPrefix(c.facts.versionID, "7") && (c.facts.osID == "centos" || c.facts.osID == "rhel" || c.facts.osID == "ol") {
		// yum (RHEL 7 family) writes its cache and history even with -C and
		// has no read-only interface the check could use.
		what := "Ausstehende Updates lassen sich mit yum nicht lesen, ohne dass yum dabei schreibt; die Prüfung lässt es deshalb."
		c.add(unreadable("updates.pending", area, what, ReasonNotSupported, "", hc.Evidence{Source: "yum"}))
		c.add(unreadable("updates.security_pending", area, what, ReasonNotSupported, "", hc.Evidence{Source: "yum"}))
		return
	}
	res, err := c.env.Run(c.ctx, CmdDnfUpdatesPlatform)
	if errors.Is(err, ErrNotInstalled) {
		res, err = c.env.Run(c.ctx, CmdDnfUpdates)
	}
	var ups []Update
	reason, needs, what := "", "", "Ausstehende Updates ließen sich nicht aus dem Paket-Cache lesen."
	switch {
	case err != nil:
		reason = readErr(err)
		if errors.Is(err, ErrNoPrivDrop) {
			needs = "CAP_SETUID"
		}
	case res.Exit == 2:
		reason, what = ReasonNotSupported, "Ausstehende Updates lassen sich hier nicht nur lesend bestimmen (die dnf-Bibliothek libdnf/hawkey fehlt, etwa bei dnf5)."
	case res.Exit == 3:
		reason, what = ReasonNotConfigured, "Für keine aktive Paketquelle liegt ein dnf-Cache vor; die Prüfung lädt selbst keine Paketlisten. Ein regelmäßiges „dnf makecache“ (Timer von dnf) füllt ihn."
	case res.Exit == 4:
		reason, what = ReasonNotSupported, "Die Modul-Streams von dnf ließen sich nicht nur lesend auswerten; ohne sie wäre die Liste falsch."
	case res.Exit != 0:
		reason = ReasonParse
	default:
		var ok bool
		if ups, ok = ParseDnfUpdates(res.Stdout); !ok {
			reason = ReasonParse
		}
	}
	if reason != "" {
		c.add(unreadable("updates.pending", area, what, reason, needs, hc.Evidence{Source: src}))
		c.add(unreadable("updates.security_pending", area, what, reason, needs, hc.Evidence{Source: src}))
		return
	}
	c.reportUpdates(ups, true, src, secFix, fix)
}

var dnfApplyRe = regexp.MustCompile(`(?m)^\s*apply_updates\s*=\s*(\S+)`)

func (c *checker) dnfAutomatic() {
	const id, area = "updates.automatic", "updates"
	var timer, conf, src, fix string
	switch {
	case c.facts.versionID != "" && strings.HasPrefix(c.facts.versionID, "7"):
		src, conf = "systemd", "/etc/yum/yum-cron.conf"
		timer = "/etc/systemd/system/multi-user.target.wants/yum-cron.service"
		fix = fixYumCron
	default:
		src, conf = "dnf_automatic", "/etc/dnf/automatic.conf"
		fix = fixDnfAutomatic
		for _, t := range []string{"dnf-automatic-install.timer", "dnf-automatic.timer"} {
			if p := "/etc/systemd/system/timers.target.wants/" + t; exists(c.env, p) {
				timer = p
				break
			}
		}
		if timer == "" {
			timer = "/etc/systemd/system/timers.target.wants/dnf-automatic-install.timer"
		}
	}
	on := exists(c.env, timer)
	apply := ""
	if b, err := c.env.ReadFile(conf, 256<<10); err == nil {
		if m := dnfApplyRe.FindSubmatch(b); m != nil {
			apply = string(m[1])
		}
	}
	// dnf-automatic-install.timer applies updates whatever automatic.conf says.
	if on && !strings.HasSuffix(timer, "dnf-automatic-install.timer") && apply != "yes" && apply != "True" && apply != "true" && apply != "1" {
		on = false
	}
	ev := hc.Evidence{Source: src, Path: timer, Setting: "apply_updates", Value: tokp(apply), Enabled: bp(on)}
	if on {
		c.add(ok(id, area, "Automatische Updates sind an", "Ein systemd-Timer spielt Updates regelmäßig von selbst ein.", ev))
		return
	}
	c.add(finding(id, area, "medium", "Automatische Updates sind aus",
		"Updates kommen nur, wenn jemand sie von Hand einspielt. Ein Timer kann das täglich übernehmen.", fix, ev))
}

// needsReboot are the packages after whose update needs-restarting -r
// (dnf-plugins-core) asks for a reboot.
var needsReboot = map[string]bool{"kernel": true, "kernel-core": true, "kernel-rt": true, "kernel-rt-core": true, "glibc": true,
	"linux-firmware": true, "systemd": true, "dbus": true, "dbus-broker": true, "dbus-daemon": true, "microcode_ctl": true,
	"zlib": true, "openssl-libs": true, "gnutls": true}

// ParseRpmInstallTime parses `rpm -qa --qf '%{NAME}\t%{INSTALLTIME}\n'`
// into the newest install time per name (Unix seconds).
func ParseRpmInstallTime(b []byte) map[string]int64 {
	out := map[string]int64{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		name, ts, ok := strings.Cut(strings.TrimSpace(sc.Text()), "\t")
		if !ok {
			continue
		}
		t, err := strconv.ParseInt(strings.TrimSpace(ts), 10, 64)
		if err != nil {
			continue
		}
		if t > out[name] {
			out[name] = t
		}
	}
	return out
}

// bootTime reads btime from /proc/stat (Unix seconds).
func bootTime(env Env) (int64, error) {
	b, err := env.ReadFile("/proc/stat", 1<<20)
	if err != nil {
		return 0, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "btime "); ok {
			return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	return 0, errors.New("no btime")
}

// rebootRequiredRHEL applies the rule of `needs-restarting -r` without
// running it (it is a dnf plugin and writes dnf's logs and caches): a reboot
// is needed when one of the core packages was installed after the last boot.
// Additional names from /etc/dnf/plugins/needs-restarting.d/*.conf count too.
func (c *checker) rebootRequiredRHEL() {
	const id, area = "updates.reboot_required", "updates"
	ev := hc.Evidence{Source: "needs_restarting"}
	boot, err := bootTime(c.env)
	if err != nil {
		reason := readErr(err)
		if reason == ReasonNotInstalled {
			reason = ReasonParse
		}
		c.add(unreadable(id, area, "Ob ein Neustart nötig ist, ließ sich nicht prüfen (Startzeit unbekannt).", reason, "", ev))
		return
	}
	res, err := c.env.Run(c.ctx, CmdRpmInstallTime)
	if err != nil || res.Exit != 0 {
		reason, needs := ReasonParse, ""
		if err != nil {
			reason = readErr(err)
			if errors.Is(err, ErrNoPrivDrop) {
				needs = "CAP_SETUID"
			}
		}
		c.add(unreadable(id, area, "Ob ein Neustart nötig ist, ließ sich nicht prüfen (Paketdatenbank nicht lesbar).", reason, needs, ev))
		return
	}
	times := ParseRpmInstallTime(res.Stdout)
	if len(times) == 0 {
		c.add(unreadable(id, area, "Ob ein Neustart nötig ist, ließ sich nicht prüfen (Paketdatenbank leer).", ReasonParse, "", ev))
		return
	}
	names := map[string]bool{}
	for n := range needsReboot {
		names[n] = true
	}
	files, _ := c.env.Glob("/etc/dnf/plugins/needs-restarting.d/*.conf")
	for _, f := range files {
		if b, err := c.env.ReadFile(f, 64<<10); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") && packageNameRe.MatchString(l) {
					names[l] = true
				}
			}
		}
	}
	var pkgs []string
	for n := range names {
		if t, ok := times[n]; ok && t > boot {
			pkgs = append(pkgs, n)
		}
	}
	sort.Strings(pkgs)
	if len(pkgs) == 0 {
		ev.Enabled = bp(false)
		c.add(ok(id, area, "Kein Neustart nötig", "Kein Update wartet auf einen Neustart.", ev))
		return
	}
	ev.Enabled, ev.Packages = bp(true), pkgs
	c.add(finding(id, area, "medium", "Neustart nötig",
		"Ein Update wirkt erst nach einem Neustart, oft ist es ein neuer Kernel oder eine Systembibliothek. Bis dahin läuft noch die alte Version.",
		fixReboot, ev))
}

var absPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]{0,255}$`)
