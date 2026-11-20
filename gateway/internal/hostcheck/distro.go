package hostcheck

import (
	"bufio"
	"bytes"
	"path"
	"regexp"
	"strconv"
	"strings"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
)

// ParseOSRelease parses /etc/os-release (KEY=value, optionally quoted).
func ParseOSRelease(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `"'`)
		}
		out[k] = v
	}
	return out
}

var (
	osIDRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	versionIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{0,32}$`)
	kernelRe    = regexp.MustCompile(`^[A-Za-z0-9._+~-]{1,64}$`)
	archRe      = regexp.MustCompile(`^[a-z0-9_]{1,16}$`)
)

// oneLine strips control characters and caps the length (text fields).
func oneLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
		for len(s) > 0 && !validUTF8Tail(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

func validUTF8Tail(s string) bool { return strings.ToValidUTF8(s, "") == s }

func (c *checker) runOut(cmd Command) (string, error) {
	res, err := c.env.Run(c.ctx, cmd)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// checkDistribution reads os-release and uname and looks up the EOL table.
func (c *checker) checkDistribution() hc.OS {
	const area = "distribution"
	o := hc.OS{ID: "unknown", Name: "Unbekanntes Linux", Kernel: "unknown", Arch: "unknown"}
	if k, err := c.runOut(CmdUnameR); err == nil && kernelRe.MatchString(k) {
		o.Kernel = k
	}
	if a, err := c.runOut(CmdUnameM); err == nil && archRe.MatchString(a) {
		o.Arch = a
	}
	c.facts.kernel = o.Kernel
	src := "/etc/os-release"
	b, err := c.env.ReadFile(src, 64<<10)
	if err != nil {
		src = "/usr/lib/os-release"
		b, err = c.env.ReadFile(src, 64<<10)
	}
	if err != nil {
		c.add(unreadable("distribution.eol", area, "Die Distribution ließ sich nicht bestimmen.", readErr(err), "", hc.Evidence{Source: "os_release", Path: "/etc/os-release"}))
		return o
	}
	rel := ParseOSRelease(b)
	if id := strings.ToLower(rel["ID"]); osIDRe.MatchString(id) {
		o.ID = id
	}
	if v := rel["VERSION_ID"]; versionIDRe.MatchString(v) {
		o.VersionID = v
	}
	if n := oneLine(rel["PRETTY_NAME"], 128); n != "" {
		o.Name = n
	}
	c.facts.osID, c.facts.versionID = o.ID, o.VersionID
	c.facts.idLike = strings.ToLower(rel["ID_LIKE"])
	switch {
	case o.ID == "debian" || o.ID == "ubuntu" || strings.Contains(c.facts.idLike, "debian") || strings.Contains(c.facts.idLike, "ubuntu"):
		c.facts.family = "debian"
	case rhelLike[o.ID] || o.ID == "fedora" || strings.Contains(c.facts.idLike, "rhel") || strings.Contains(c.facts.idLike, "fedora"):
		c.facts.family = "rhel"
	default:
		c.facts.family = "other"
	}
	now := c.env.Now()
	e := Table().LookupOS(o.ID, o.VersionID, rel["PRETTY_NAME"])
	ev := hc.Evidence{Source: "eol_table", Path: src}
	if e == nil {
		c.facts.osSupported = true
		c.add(ok("distribution.eol", area, "Kein Supportende für diese Version hinterlegt",
			"Diese Distribution oder Version steht nicht in der mitgelieferten Liste der Supportenden. Prüf beim Hersteller, wie lange es noch Sicherheitsupdates gibt.", ev))
		return o
	}
	o.EOL = sp(e.EOL)
	if e.Extended != "" {
		o.ExtendedSupportUntil = sp(e.Extended)
	}
	c.facts.osEOL, c.facts.osExtended = e.EOL, e.Extended
	ev.Date = e.EOL
	upgrade := "Plane den Umzug auf eine unterstützte Version (neu aufsetzen oder Release-Upgrade nach Anleitung des Herstellers)."
	switch {
	case !past(e.EOL, now):
		c.facts.osSupported = true
		days := int(parseDate(e.EOL).Sub(now).Hours() / 24)
		if days <= 180 {
			c.add(finding("distribution.eol", area, "low", "Supportende in "+strconv.Itoa(days)+" Tagen",
				o.Name+" bekommt ab "+e.EOL+" keine regulären Sicherheitsupdates mehr. Ein halbes Jahr reicht gut, um den Umzug in Ruhe zu planen. "+upgrade, "", ev))
		} else {
			c.add(ok("distribution.eol", area, "Distribution bekommt Sicherheitsupdates",
				o.Name+" wird bis "+e.EOL+" mit Sicherheitsupdates versorgt.", ev))
		}
	case e.Extended != "" && !past(e.Extended, now):
		c.facts.osSupported = true
		ev.Date = e.Extended
		expl := o.Name + " hat das reguläre Supportende (" + e.EOL + ") hinter sich. Bis " + e.Extended + " gibt es noch " + e.ExtendedName + "."
		if e.Paid {
			expl += " Das gibt es nur mit einem passenden Abo; ohne das kommen keine Sicherheitsupdates mehr."
		}
		sev := "low"
		if e.Paid {
			sev = "medium"
		}
		c.add(finding("distribution.eol", area, sev, "Nur noch verlängerter Support", expl+" "+upgrade, "", ev))
	default:
		c.add(finding("distribution.eol", area, "high", "Distribution ohne Sicherheitsupdates",
			o.Name+" bekommt seit "+lastDate(e)+" keine Sicherheitsupdates mehr. Neue Lücken bleiben offen. "+upgrade, "", ev))
	}
	return o
}

func lastDate(e *OSEOL) string {
	if e.Extended != "" {
		return e.Extended
	}
	return e.EOL
}

var vmlinuzRe = regexp.MustCompile(`^vmlinu[xz]-(.+)$`)

// checkKernel compares the running kernel with the newest installed one.
func (c *checker) checkKernel() {
	const id, area = "distribution.kernel_outdated", "distribution"
	files, _ := c.env.Glob("/boot/vmlinu[xz]-*")
	newest := ""
	for _, f := range files {
		m := vmlinuzRe.FindStringSubmatch(path.Base(f))
		if m == nil || strings.Contains(m[1], "rescue") || !kernelRe.MatchString(m[1]) {
			continue
		}
		if newest == "" || CompareVersions(m[1], newest) > 0 {
			newest = m[1]
		}
	}
	run := c.facts.kernel
	if newest == "" || run == "unknown" {
		reason, needs := ReasonNotSupported, ""
		if _, err := c.env.ReadDir("/boot"); err != nil && readErr(err) == ReasonPermission {
			reason, needs = ReasonPermission, NeedsRoot
		}
		c.add(unreadable(id, area, "Die installierten Kernel ließen sich nicht vergleichen.", reason, needs, hc.Evidence{Source: "uname", Path: "/boot"}))
		return
	}
	ev := hc.Evidence{Source: "uname", Path: "/boot", InstalledVersion: cleanVersion(newest), Value: tokp(run)}
	if CompareVersions(newest, run) > 0 {
		c.add(finding(id, area, "medium", "Neuer Kernel installiert, aber nicht aktiv",
			"Es ist ein neuerer Kernel installiert, als gerade läuft. Seine Sicherheitskorrekturen wirken erst nach einem Neustart.",
			fixReboot, ev))
		return
	}
	c.add(ok(id, area, "Der neueste installierte Kernel läuft", "Der laufende Kernel ist der neueste, der installiert ist.", ev))
}
