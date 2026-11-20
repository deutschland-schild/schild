package hostcheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
)

// relevantPackage selects the installed packages that matter for advisories:
// runtimes, servers, databases and the base system pieces that are attacked
// most often. The full package list is not reported.
var relevantPackage = regexp.MustCompile(`^(` + strings.Join([]string{
	`php[0-9.]*(-cli|-fpm|-common)?`, `php[0-9]{2}-php-(cli|fpm|common)`, `nodejs`, `python3(\.[0-9]+)?`, `python3[0-9]{1,2}`, `python2(\.7)?`,
	`openjdk-[0-9]+-jre(-headless)?`, `java-[0-9.]+-openjdk(-headless)?`, `tomcat[0-9]*`,
	`nginx(-core|-full|-light)?`, `apache2(-bin)?`, `httpd`, `caddy`, `haproxy`, `varnish`,
	`mariadb-server(-core)?(-[0-9.]+)?`, `mysql-server(-core)?(-[0-9.]+)?`, `mysql-community-server`, `postgresql-[0-9]+`, `postgresql[0-9]*-server`,
	`redis(-server)?`, `memcached`, `mongodb-org-server`, `elasticsearch`, `rabbitmq-server`,
	`openssh-server`, `openssl`, `libssl[0-9.]+[a-z]?`, `libc6`, `glibc`, `sudo`, `bash`, `curl`, `libcurl[0-9a-z-]*`, `xz-utils`, `xz-libs`,
	`docker-ce`, `docker\.io`, `containerd(\.io)?`, `podman`, `exim4(-daemon-[a-z]+)?`, `postfix`, `dovecot-core`, `dovecot`, `bind9`, `bind`,
	`samba`, `vsftpd`, `proftpd(-basic|-core)?`, `pure-ftpd`, `git`, `imagemagick(-6\.q16)?`, `ImageMagick`, `ghostscript`, `systemd`,
	`linux-image-[0-9a-z.+-]+`, `kernel(-core)?`, `wordpress`, `phpmyadmin`, `roundcube(-core)?`, `nextcloud`,
}, "|") + `)$`)

// classify maps a package to a runtime, server or database (kind, name,
// cycle digits).
type pkgClass struct {
	re     *regexp.Regexp
	kind   string
	name   string
	digits int // components of the version cycle for the EOL table
}

var pkgClasses = []pkgClass{
	{regexp.MustCompile(`^php([0-9.]*)(-cli|-fpm|-common)?$|^php[0-9]{2}-php-(cli|fpm|common)$`), "runtime", "php", 2},
	{regexp.MustCompile(`^nodejs$`), "runtime", "node", 1},
	{regexp.MustCompile(`^python3(\.[0-9]+)?$|^python3[0-9]{1,2}$`), "runtime", "python", 2},
	{regexp.MustCompile(`^python2(\.7)?$`), "runtime", "python", 2},
	{regexp.MustCompile(`^openjdk-[0-9]+-jre(-headless)?$|^java-[0-9.]+-openjdk(-headless)?$`), "runtime", "java", 1},
	{regexp.MustCompile(`^tomcat[0-9]*$`), "server", "tomcat", 1},
	{regexp.MustCompile(`^nginx(-core|-full|-light)?$`), "server", "nginx", 2},
	{regexp.MustCompile(`^apache2(-bin)?$|^httpd$`), "server", "apache", 2},
	{regexp.MustCompile(`^caddy$`), "server", "caddy", 2},
	{regexp.MustCompile(`^mariadb-server(-core)?(-[0-9.]+)?$`), "database", "mariadb", 2},
	{regexp.MustCompile(`^mysql-server(-core)?(-[0-9.]+)?$|^mysql-community-server$`), "database", "mysql", 2},
	{regexp.MustCompile(`^postgresql-[0-9]+$|^postgresql[0-9]*-server$`), "database", "postgresql", 1},
	{regexp.MustCompile(`^redis(-server)?$`), "database", "redis", 2},
	{regexp.MustCompile(`^memcached$`), "database", "memcached", 2},
	{regexp.MustCompile(`^mongodb-org-server$`), "database", "mongodb", 2},
}

// ParseDpkgQuery parses dpkg-query output ("name\tversion\tstatus"); only
// installed packages ("ii") count.
func ParseDpkgQuery(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 2 {
			continue
		}
		if len(f) >= 3 && !strings.HasPrefix(strings.TrimSpace(f[2]), "ii") {
			continue
		}
		name, _, _ := strings.Cut(f[0], ":") // libssl3:amd64
		out[name] = strings.TrimSpace(f[1])
	}
	return out
}

// ParseRpmQA parses rpm -qa output ("name\tepoch:version-release").
func ParseRpmQA(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		name, v, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		v = strings.TrimPrefix(strings.TrimSpace(v), "0:")
		if old, seen := out[name]; !seen || CompareVersions(v, old) > 0 {
			out[name] = v // kernels: several installed, newest wins
		}
	}
	return out
}

func (c *checker) loadPackages() {
	c.facts.packages = map[string]string{}
	var all map[string]string
	if res, err := c.env.Run(c.ctx, CmdDpkgQuery); err == nil && res.Exit == 0 {
		all, c.facts.pkgSource = ParseDpkgQuery(res.Stdout), "dpkg"
	} else if res, err := c.env.Run(c.ctx, CmdRpmQA); err == nil && res.Exit == 0 {
		all, c.facts.pkgSource = ParseRpmQA(res.Stdout), "rpm"
	}
	for n, v := range all {
		if relevantPackage.MatchString(n) {
			c.facts.packages[n] = v
		}
	}
}

func (c *checker) checkSoftware() {
	src := c.facts.pkgSource
	pk := make([]string, 0, len(c.facts.packages))
	for n := range c.facts.packages {
		pk = append(pk, n)
	}
	sort.Strings(pk)
	type comp struct {
		kind, name, version, source string
		digits                      int
	}
	found := map[string]comp{} // by name: newest wins
	for _, n := range pk {
		v := c.facts.packages[n]
		if pn := strings.ToLower(n); packageNameRe.MatchString(pn) && cleanVersion(v) != "" {
			c.inv = append(c.inv, hc.InventoryItem{Kind: "os_package", Name: pn, Version: cleanVersion(v), Source: src})
		}
		for _, cl := range pkgClasses {
			if !cl.re.MatchString(n) {
				continue
			}
			up := Upstream(v)
			if up == "" || Cycle(up, cl.digits) == "" || (cl.digits > 1 && !strings.Contains(up, ".")) {
				continue // metapackages such as php-common 2:93
			}
			if old, ok := found[cl.name]; !ok || CompareVersions(up, old.version) > 0 {
				found[cl.name] = comp{cl.kind, cl.name, up, src, cl.digits}
			}
		}
	}
	// Runtimes installed outside the package manager (binaries in PATH).
	for _, b := range []struct {
		cmd    Command
		name   string
		digits int
		re     *regexp.Regexp
	}{
		{CmdNodeVersion, "node", 1, regexp.MustCompile(`^v?([0-9]+\.[0-9]+\.[0-9]+)`)},
		{CmdPHPVersion, "php", 2, regexp.MustCompile(`^PHP ([0-9]+\.[0-9]+\.[0-9]+)`)},
		{CmdPythonVersion, "python", 2, regexp.MustCompile(`^Python ([0-9]+\.[0-9]+\.[0-9]+)`)},
		{CmdJavaVersion, "java", 1, regexp.MustCompile(`version "([0-9]+(?:\.[0-9]+)*)`)},
	} {
		if _, ok := found[b.name]; ok {
			continue
		}
		if b.name == "java" {
			// The JDK/JRE release file names the version without starting
			// a JVM (which writes perf data and cannot start under
			// MemoryDenyWriteExecute).
			if v := c.javaReleaseVersion(); v != "" {
				found["java"] = comp{"runtime", "java", v, "binary", 1}
				continue
			}
		}
		res, err := c.env.Run(c.ctx, b.cmd)
		if err != nil || res.Exit != 0 {
			continue
		}
		out := append(append([]byte{}, res.Stdout...), res.Stderr...)
		line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		if m := b.re.FindStringSubmatch(line); m != nil {
			found[b.name] = comp{"runtime", b.name, m[1], "binary", b.digits}
		}
	}
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	ids := map[string]string{"runtime": "software.runtime_eol", "server": "software.server_eol", "database": "software.database_eol"}
	reported := map[string]bool{}
	now := c.env.Now()
	for _, n := range names {
		x := found[n]
		cycle := Cycle(x.version, x.digits)
		if n == "java" {
			cycle = javaMajor(x.version)
		}
		eol := Table().LookupCycle(n, cycle)
		item := hc.InventoryItem{Kind: x.kind, Name: n, Version: x.version, Source: x.source}
		if eol != "" {
			item.EOL = sp(eol)
		}
		c.inv = append(c.inv, item)
		if eol == "" {
			continue
		}
		id := ids[x.kind]
		reported[id] = true
		subject := n + "-" + cycle
		ev := hc.Evidence{Source: "eol_table", Package: n, InstalledVersion: x.version, Date: eol}
		label := displayName(n) + " " + cycle
		if !past(eol, now) {
			c.add(sub(ok(id, "software", label+" wird noch gepflegt", label+" bekommt bis "+eol+" Sicherheitskorrekturen.", ev), subject))
			continue
		}
		sev, expl := "high", label+" bekommt seit "+eol+" keine Sicherheitskorrekturen mehr vom Projekt. Neue Lücken bleiben offen; plane den Wechsel auf eine gepflegte Version."
		if x.source != "binary" && c.facts.osSupported {
			sev = "low"
			expl = label + " ist beim Projekt seit " + eol + " ohne Pflege. Die Version kommt aus den Paketquellen der Distribution, die oft noch Sicherheitskorrekturen nachliefert, solange die Distribution unterstützt wird. Plane trotzdem den Wechsel auf eine gepflegte Version."
		}
		c.add(sub(finding(id, "software", sev, label+" ohne Pflege", expl, "", ev), subject))
	}
	for _, id := range []string{"software.runtime_eol", "software.server_eol", "software.database_eol"} {
		if !reported[id] {
			c.add(ok(id, "software", "Nichts ohne Pflege gefunden", "Unter den erkannten Komponenten ist keine, deren Supportende in der mitgelieferten Liste steht und erreicht ist.", hc.Evidence{Source: "eol_table"}))
		}
	}
	c.checkApps()
}

var javaReleaseRe = regexp.MustCompile(`(?m)^JAVA_VERSION="([0-9]+(?:\.[0-9]+)*)`)

// javaReleaseVersion finds `java` in the command PATH, resolves links and
// reads JAVA_VERSION from <java home>/release ("" when there is none).
func (c *checker) javaReleaseVersion() string {
	for _, d := range strings.Split(safePath, ":") {
		p := d + "/java"
		if _, err := c.env.Stat(p); err != nil {
			continue
		}
		real, err := c.env.EvalSymlinks(p)
		if err != nil {
			return ""
		}
		home := path.Dir(path.Dir(real)) // <home>/bin/java (JDK 8 JRE: <jdk>/jre/bin/java)
		for _, rel := range []string{home + "/release", path.Dir(home) + "/release"} {
			if b, err := c.env.ReadFile(rel, 64<<10); err == nil {
				if m := javaReleaseRe.FindSubmatch(b); m != nil {
					return string(m[1])
				}
			}
		}
		return ""
	}
	return ""
}

func javaMajor(v string) string {
	parts := strings.Split(Upstream(v), ".")
	if len(parts) >= 2 && parts[0] == "1" {
		return parts[1] // 1.8.0 -> 8
	}
	return parts[0]
}

func displayName(n string) string {
	switch n {
	case "php":
		return "PHP"
	case "node":
		return "Node.js"
	case "python":
		return "Python"
	case "java":
		return "Java"
	case "tomcat":
		return "Tomcat"
	case "mariadb":
		return "MariaDB"
	case "mysql":
		return "MySQL"
	case "postgresql":
		return "PostgreSQL"
	case "typo3":
		return "TYPO3"
	case "laravel":
		return "Laravel"
	case "nextcloud":
		return "Nextcloud"
	case "wordpress":
		return "WordPress"
	}
	return n
}

// ---------------------------------------------------------------- apps

// App is an application found under a configured path.
type App struct {
	Name    string // wordpress, typo3, laravel, nextcloud
	Version string
	Path    string
	Plugins []hc.InventoryItem
}

var (
	wpVersionRe   = regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)
	ncVersionRe   = regexp.MustCompile(`\$OC_VersionString\s*=\s*'([^']+)'`)
	typo3VerRe    = regexp.MustCompile(`'version'\s*=>\s*'([^']+)'`)
	pluginNameRe  = regexp.MustCompile(`(?m)^[ \t/*#@]*Plugin Name:`)
	pluginVerRe   = regexp.MustCompile(`(?m)^[ \t/*#@]*Version:\s*([A-Za-z0-9.+~_-]+)`)
	pluginSlugRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	maxPlugins    = 300
	headerMaxRead = int64(8 << 10)
)

// DetectApp looks for a known application at dir. Only version markers are
// parsed (a version line, a plugin header); nothing else is kept.
func DetectApp(env Env, dir string) (*App, error) {
	if _, err := env.Stat(dir); err != nil {
		return nil, err
	}
	if b, err := env.ReadFile(path.Join(dir, "wp-includes/version.php"), 64<<10); err == nil {
		a := &App{Name: "wordpress", Path: dir}
		if m := wpVersionRe.FindSubmatch(b); m != nil {
			a.Version = cleanVersion(string(m[1]))
		}
		a.Plugins = wpPlugins(env, dir)
		return a, nil
	}
	if b, err := env.ReadFile(path.Join(dir, "version.php"), 64<<10); err == nil {
		if m := ncVersionRe.FindSubmatch(b); m != nil {
			return &App{Name: "nextcloud", Path: dir, Version: cleanVersion(string(m[1]))}, nil
		}
	}
	for _, p := range []string{"typo3/sysext/core/ext_emconf.php", "vendor/typo3/cms-core/ext_emconf.php", "public/typo3/sysext/core/ext_emconf.php"} {
		if b, err := env.ReadFile(path.Join(dir, p), 64<<10); err == nil {
			a := &App{Name: "typo3", Path: dir}
			if m := typo3VerRe.FindSubmatch(b); m != nil {
				a.Version = cleanVersion(string(m[1]))
			}
			return a, nil
		}
	}
	if b, err := env.ReadFile(path.Join(dir, "composer.lock"), 8<<20); err == nil && exists(env, path.Join(dir, "artisan")) {
		var lock struct {
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"packages"`
		}
		if json.Unmarshal(b, &lock) == nil {
			for _, p := range lock.Packages {
				if p.Name == "laravel/framework" {
					return &App{Name: "laravel", Path: dir, Version: cleanVersion(strings.TrimPrefix(p.Version, "v"))}, nil
				}
			}
		}
		return &App{Name: "laravel", Path: dir}, nil
	}
	return nil, nil
}

func wpPlugins(env Env, dir string) []hc.InventoryItem {
	root := path.Join(dir, "wp-content/plugins")
	es, err := env.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []hc.InventoryItem
	for _, e := range es {
		if !e.IsDir() || len(out) >= maxPlugins {
			continue
		}
		slug := strings.ToLower(e.Name())
		if !pluginSlugRe.MatchString(slug) {
			continue
		}
		pdir := path.Join(root, e.Name())
		cands := []string{path.Join(pdir, e.Name()+".php")}
		if more, _ := env.Glob(path.Join(pdir, "*.php")); len(more) > 0 {
			sort.Strings(more)
			cands = append(cands, more...)
		}
		version := ""
		for i, f := range cands {
			if i > 20 {
				break
			}
			b, err := env.ReadFile(f, headerMaxRead)
			if err != nil || !pluginNameRe.Match(b) {
				continue
			}
			if m := pluginVerRe.FindSubmatch(b); m != nil {
				version = cleanVersion(string(m[1]))
			}
			break
		}
		if version == "" {
			continue
		}
		item := hc.InventoryItem{Kind: "app", Name: slug, Version: version, Source: "app_path", Parent: "wordpress"}
		if absPathRe.MatchString(dir) {
			item.Path = dir
		}
		out = append(out, item)
	}
	return out
}

func (c *checker) checkApps() {
	const id, area = "software.app_outdated", "software"
	if len(c.opts.Apps) == 0 {
		c.add(ok(id, area, "Keine App-Pfade eingerichtet", "Apps wie WordPress werden nur in Pfaden gesucht, die du angibst (--app /var/www/shop). Es wurde keiner angegeben.", hc.Evidence{Source: "app_path"}))
		return
	}
	now := c.env.Now()
	for _, dir := range c.opts.Apps {
		dir = path.Clean(dir)
		if !absPathRe.MatchString(dir) {
			continue
		}
		a, err := DetectApp(c.env, dir)
		subject := "path:" + dir
		if len(subject) > 128 {
			subject = subject[:128]
		}
		ev := hc.Evidence{Source: "app_path", Path: dir}
		if err != nil {
			needs := ""
			if readErr(err) == ReasonPermission {
				needs = NeedsRoot
			}
			c.add(sub(unreadable(id, area, "Der App-Pfad "+dir+" ließ sich nicht lesen.", readErr(err), needs, ev), subject))
			continue
		}
		if a == nil {
			c.add(sub(unreadable(id, area, "Unter "+dir+" wurde keine bekannte App erkannt (WordPress, TYPO3, Laravel, Nextcloud).", ReasonNotSupported, "", ev), subject))
			continue
		}
		version := a.Version
		if version == "" {
			version = "unknown"
		}
		c.inv = append(c.inv, hc.InventoryItem{Kind: "app", Name: a.Name, Version: version, Source: "app_path", Path: dir})
		c.inv = append(c.inv, a.Plugins...)
		label := displayName(a.Name)
		ev.Package, ev.InstalledVersion = a.Name, cleanVersion(version)
		if len(a.Plugins) > 0 {
			ev.Count = i64p(int64(len(a.Plugins)))
		}
		const digits = 1 // major versions: Nextcloud 28, TYPO3 12, Laravel 11
		eol := ""
		if a.Version != "" {
			eol = Table().LookupCycle(a.Name, Cycle(a.Version, digits))
		}
		if eol != "" {
			ev.Date = eol
		}
		switch {
		case eol != "" && past(eol, now):
			c.add(sub(finding(id, area, "high", label+" "+a.Version+" ohne Sicherheitskorrekturen",
				label+" "+Cycle(a.Version, digits)+" bekommt seit "+eol+" keine Sicherheitskorrekturen mehr. Plane das Update auf eine gepflegte Hauptversion.", "", ev), subject))
		case a.Version == "":
			c.add(sub(unreadable(id, area, label+" unter "+dir+" erkannt, aber die Version ließ sich nicht lesen.", ReasonParse, "", ev), subject))
		default:
			expl := label + " " + a.Version + " ist im Inventar erfasst."
			if a.Name == "wordpress" {
				expl += " Der Abgleich mit bekannten Lücken in WordPress und den " + strconv.Itoa(len(a.Plugins)) + " Plugins folgt in einem späteren Schritt; halte Kern und Plugins aktuell."
			}
			c.add(sub(ok(id, area, label+" "+a.Version+" erkannt", expl, ev), subject))
		}
	}
}
