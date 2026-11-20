package hostcheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
)

// Area logs (v0.5, D38, MVP-11 addendum "Log-Hygiene"). Read only like
// every other check: it stats files, reads the listed config files (Docker
// daemon.json and the containers' hostconfig.json, journald.conf, logrotate
// configuration, schild's Caddyfile) and the mtime of logrotate's status
// file. It never runs logrotate or docker, never talks to the Docker socket
// and never reads a log file's content. Evidence is paths, sizes, growth and
// booleans; fix_config is rendered only from hc.FixTemplates.

const areaLogs = "logs"

const (
	kib = int64(1) << 10
	mib = int64(1) << 20
	gib = int64(1) << 30
)

// Bounds of the walk of /var/log (variables for tests).
var (
	logWalkDepth   = 4
	logWalkEntries = 5000
	logWalkBudget  = 200 * time.Millisecond
)

// Thresholds of the spec.
const (
	largeCandidate   = 100 * mib // files at least this big are tracked (growth, logrotate_missing)
	largeLow         = gib       // logs.large_file low
	largeMediumPct   = 5         // logs.large_file medium: over 5 % of the file system
	fillDaysMedium   = 14        // logs.large_file medium: growth fills the fs in under 14 days
	journalMax       = 4 * gib   // journald default cap
	journalMaxPct    = 10        // journald default cap: 10 % of the file system
	dockerLogMedium  = gib       // logs.docker_unbounded medium
	staleAfter       = 48 * time.Hour
	bootGrace        = 2 * time.Hour // logrotate.timer is Persistent=true and catches up after boot
	maxLargeResults  = 50
	maxDeniedResults = 10
	maxContainers    = 1000
)

const (
	fixJournaldRestart = "sudo systemctl restart systemd-journald"
	fixLogrotateApt    = "sudo apt install logrotate"
	fixLogrotateDnf    = "sudo dnf install logrotate"
	fixLogrotateTimer  = "sudo systemctl enable --now logrotate.timer"
	fixLogrotateDebug  = "sudo logrotate -d /etc/logrotate.conf"
)

// logState is shared between the logs checks of one run.
type logState struct {
	conf        lrConf
	caddy       map[string]bool // roll_disabled outputs of schild's Caddyfile
	walk        logWalk
	largeFinds  int
	sawLargeAny bool // a plain file under /var/log is over 100 MiB
}

func (c *checker) checkLogs() {
	st := &logState{conf: c.loadLogrotate(), caddy: map[string]bool{}}
	st.walk = c.walkLogs()
	for _, f := range st.walk.files {
		if f.size > largeCandidate && strings.HasPrefix(f.path, "/var/log/") {
			st.sawLargeAny = true
		}
	}
	c.checkDockerLogs()
	c.checkJournald()
	c.checkLogrotateConfig(st)
	c.checkLargeFiles(st)
	c.checkLogrotateRuns(st)
}

// ---------------------------------------------------------------- formatting

// humanSize formats bytes in German (binary units, as df -h).
func humanSize(n int64) string {
	switch {
	case n >= gib:
		return strings.Replace(fmt.Sprintf("%.1f GB", float64(n)/float64(gib)), ".", ",", 1)
	case n >= mib:
		return fmt.Sprintf("%d MB", n/mib)
	case n >= kib:
		return fmt.Sprintf("%d KB", n/kib)
	}
	return fmt.Sprintf("%d Bytes", n)
}

func germanDate(t time.Time) string { return t.UTC().Format("02.01.2006") }

func pct(n, total int64) int {
	if total <= 0 {
		return 0
	}
	p := n * 100 / total
	return int(min(max(p, 0), 100))
}

// evPath returns p when it fits the contract's path pattern, else "".
func evPath(p string) string {
	if absPathRe.MatchString(p) {
		return p
	}
	return ""
}

var slugBad = regexp.MustCompile(`[^a-z0-9]+`)

// logSlug names /etc/logrotate.d/schild-<slug> after the log file: the
// file name without .log, prefixed with its directory unless that is a
// generic "log" or "logs" (/var/log/caddy/access.log: caddy-access).
func logSlug(p string) string {
	base := strings.TrimSuffix(path.Base(p), ".log")
	dir := path.Base(path.Dir(p))
	s := base
	if dir != "log" && dir != "logs" && dir != "/" && dir != "." {
		s = dir + "-" + base
	}
	s = strings.Trim(slugBad.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 48 {
		s = strings.TrimRight(s[:48], "-")
	}
	if s == "" {
		s = "log"
	}
	return s
}

// logrotateFix renders the logrotate template for one log file and checks
// the rendering against the contract (nil when the path is no valid
// template variable, e.g. outside the allowed roots).
func logrotateFix(id, file string, rotate, maxSizeMB int) *hc.FixConfig {
	ts := hc.FixTemplates[id]
	if len(ts) == 0 {
		return nil
	}
	fc := hc.RenderFix(ts[0], map[string]string{"slug": logSlug(file), "file": file, "rotate": strconv.Itoa(rotate), "max_size_mb": strconv.Itoa(maxSizeMB)})
	if !hc.FixConfigKnown(id, fc.Path, fc.Content) {
		return nil
	}
	return &fc
}

func renderedFix(id string, vars map[string]string) *hc.FixConfig {
	ts := hc.FixTemplates[id]
	if len(ts) == 0 {
		return nil
	}
	fc := hc.RenderFix(ts[0], vars)
	if !hc.FixConfigKnown(id, fc.Path, fc.Content) {
		return nil
	}
	return &fc
}

// ---------------------------------------------------------------- walk

type logFile struct {
	path string
	size int64
}

type logWalk struct {
	files     []logFile // regular files over largeCandidate, biggest first
	denied    []string  // directories that answered permission denied
	truncated bool      // the walk hit its entry or time bound
	entries   int
}

var rotatedRe = regexp.MustCompile(`(\.[0-9]+|-[0-9]{8}|\.gz|\.xz|\.bz2|\.zst|\.lz4|\.old)$`)

// skipLog: login records (wtmp, btmp, lastlog) are not logs to rotate here,
// and files that are already the product of a rotation are not tracked.
func skipLog(name string) bool {
	for _, n := range []string{"wtmp", "btmp", "lastlog", "faillog"} {
		if name == n || strings.HasPrefix(name, n+".") || strings.HasPrefix(name, n+"-") {
			return true
		}
	}
	return rotatedRe.MatchString(name)
}

// walkLogs walks /var/log by stat only (depth 4, at most 5000 entries,
// 200 ms; the journal is checked by logs.journald_size) and, for configured
// app paths, the usual app log files. Symbolic links are not followed.
func (c *checker) walkLogs() logWalk {
	var w logWalk
	start := time.Now()
	type dir struct {
		path  string
		depth int
	}
	stack := []dir{{"/var/log", 0}}
	add := func(p string) {
		st, err := c.env.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			return
		}
		if sz := factsOf(st).Alloc; sz >= largeCandidate {
			w.files = append(w.files, logFile{p, sz})
		}
	}
walk:
	for len(stack) > 0 {
		if time.Since(start) > logWalkBudget || w.entries >= logWalkEntries {
			w.truncated = true
			break
		}
		d := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		es, err := c.env.ReadDir(d.path)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				w.denied = append(w.denied, d.path)
			}
			continue
		}
		for _, e := range es {
			w.entries++
			if w.entries > logWalkEntries || w.entries%256 == 0 && time.Since(start) > logWalkBudget {
				w.truncated = true
				break walk
			}
			p := d.path + "/" + e.Name()
			switch {
			case e.Type()&fs.ModeSymlink != 0:
			case e.IsDir():
				if p != "/var/log/journal" && d.depth+1 < logWalkDepth {
					stack = append(stack, dir{p, d.depth + 1})
				}
			case e.Type().IsRegular():
				if !skipLog(e.Name()) {
					add(p)
				}
			}
		}
	}
	// Configured app paths only (Laravel, TYPO3, Nextcloud log files).
	for _, app := range c.opts.Apps {
		app = path.Clean(app)
		if !strings.HasPrefix(app, "/") {
			continue
		}
		for _, g := range []string{"/storage/logs/*.log", "/var/log/*.log", "/data/*.log"} {
			ms, _ := c.env.Glob(app + g)
			for i, m := range ms {
				if i >= 100 {
					break
				}
				add(m)
			}
		}
	}
	sort.SliceStable(w.files, func(i, j int) bool { return w.files[i].size > w.files[j].size })
	return w
}

// ---------------------------------------------------------------- docker

type dockerLogConfig struct {
	Type   string            `json:"Type"`
	Config map[string]string `json:"Config"`
}

// boundedLog: only json-file without max-size grows without limit; local
// and journald are bounded, remote drivers write nothing locally.
func boundedLog(typ string, opts map[string]string) bool {
	if typ != "json-file" {
		return true
	}
	ms, ok := opts["max-size"]
	return ok && ms != "" && ms != "-1"
}

var containerIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (c *checker) checkDockerLogs() {
	const id = "logs.docker_unbounded"
	const daemonPath = "/etc/docker/daemon.json"
	const containers = "/var/lib/docker/containers"
	db, derr := c.env.ReadFile(daemonPath, 64<<10)
	_, lerr := c.env.Stat("/var/lib/docker")
	if errors.Is(derr, fs.ErrNotExist) && lerr != nil && !errors.Is(lerr, fs.ErrPermission) {
		for _, p := range []string{"/usr/bin/podman", "/usr/bin/dockerd-rootless.sh"} {
			if exists(c.env, p) {
				c.add(unreadable(id, areaLogs, "Die Container-Logs von rootless Docker oder Podman liegen an anderen Orten.", ReasonNotSupported, "", hc.Evidence{Source: "docker_daemon", Path: p}))
				return
			}
		}
		c.add(ok(id, areaLogs, "Container-Logs", "Auf diesem Server läuft kein Docker.", hc.Evidence{Source: "docker_daemon", Path: daemonPath, Enabled: bp(false)}))
		return
	}
	driver, opts := "json-file", map[string]string{}
	onlyLogKeys := true
	daemonMissing := errors.Is(derr, fs.ErrNotExist)
	if derr == nil {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(db, &m); err != nil {
			c.add(unreadable(id, areaLogs, "Die Docker-Einstellungen in /etc/docker/daemon.json ließen sich nicht lesen.", ReasonParse, "", hc.Evidence{Source: "docker_daemon", Path: daemonPath}))
			return
		}
		for k, v := range m {
			switch k {
			case "log-driver":
				_ = json.Unmarshal(v, &driver)
			case "log-opts":
				_ = json.Unmarshal(v, &opts)
			default:
				onlyLogKeys = false
			}
		}
	} else if !daemonMissing {
		c.add(unreadable(id, areaLogs, "Die Docker-Einstellungen in /etc/docker/daemon.json ließen sich nicht lesen.", readErr(derr), NeedsRoot, hc.Evidence{Source: "docker_daemon", Path: daemonPath}))
		return
	}
	daemonBounded := boundedLog(driver, opts)
	es, err := c.env.ReadDir(containers)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		c.add(unreadable(id, areaLogs, "Die Log-Einstellungen der Docker-Container ließen sich nicht lesen.", readErr(err), NeedsRoot, hc.Evidence{Source: "docker_container", Path: containers}))
		return
	}
	type unb struct {
		id      string
		size    int64
		running bool
	}
	var bad []unb
	checked := 0
	for _, e := range es {
		if checked >= maxContainers {
			break
		}
		cid := e.Name()
		if !e.IsDir() || !containerIDRe.MatchString(cid) {
			continue
		}
		hb, err := c.env.ReadFile(containers+"/"+cid+"/hostconfig.json", 256<<10)
		if err != nil {
			continue
		}
		checked++
		var hcfg struct {
			LogConfig dockerLogConfig `json:"LogConfig"`
		}
		if json.Unmarshal(hb, &hcfg) != nil {
			continue
		}
		typ, cfg := hcfg.LogConfig.Type, hcfg.LogConfig.Config
		if typ == "" {
			typ, cfg = driver, opts
		}
		if boundedLog(typ, cfg) {
			continue
		}
		u := unb{id: cid}
		if st, err := c.env.Stat(containers + "/" + cid + "/" + cid + "-json.log"); err == nil {
			u.size = factsOf(st).Alloc
		}
		u.running = exists(c.env, "/run/containerd/io.containerd.runtime.v2.task/moby/"+cid) || exists(c.env, "/run/docker/containerd/"+cid)
		bad = append(bad, u)
	}
	if len(bad) == 0 {
		expl := "Alle Container schreiben ihre Logs mit Obergrenze."
		if checked == 0 {
			expl = "Es gibt keine Container, deren Logs wachsen könnten."
		}
		c.add(ok(id, areaLogs, "Container-Logs", expl, hc.Evidence{Source: "docker_container", Path: daemonPath, Count: i64p(int64(checked)), Enabled: bp(daemonBounded)}))
		return
	}
	sort.SliceStable(bad, func(i, j int) bool { return bad[i].size > bad[j].size })
	big := bad[0]
	sev := "low"
	for _, b := range bad {
		if b.running || b.size > dockerLogMedium {
			sev = "medium"
		}
	}
	expl := fmt.Sprintf("Die Logs von %d Containern haben keine Obergrenze. Das größte ist %s groß (Container %s). Mit einer Grenze behält Docker nur die letzten Dateien.",
		len(bad), humanSize(big.size), big.id[:12])
	var fix *hc.FixConfig
	switch {
	case daemonBounded:
		expl += " Docker selbst hat schon eine Grenze, diese Container wurden aber vorher angelegt."
	case daemonMissing || onlyLogKeys:
		fix = renderedFix(id, map[string]string{"max_size_mb": "10", "max_files": "5"})
	default:
		expl += " Ergänze in /etc/docker/daemon.json die Schlüssel log-driver (local) und log-opts (max-size 10m, max-file 5)."
	}
	expl += ` Mit Kamal gehört für die App und jedes Accessory in deploy.yml: logging: {options: {max-size: 10m, max-file: "5"}}.`
	expl += " Die Grenze gilt nur für neu gestartete Container, deploye danach also neu."
	f := finding(id, areaLogs, sev, "Container-Logs ohne Obergrenze", expl, "",
		hc.Evidence{Source: "docker_container", Path: evPath(containers + "/" + big.id + "/" + big.id + "-json.log"), Count: i64p(int64(len(bad))), SizeBytes: i64p(big.size), Enabled: bp(big.running)})
	f.FixConfig = fix
	c.add(f)
}

// ---------------------------------------------------------------- journald

// parseSystemdSize parses a journald size ("1G", "512M", "infinity").
// ok is false for anything else (percentages, garbage).
func parseSystemdSize(v string) (n int64, infinite, ok bool) {
	v = strings.TrimSpace(v)
	if v == "infinity" {
		return 0, true, true
	}
	if v == "" {
		return 0, false, false
	}
	mult := int64(1)
	switch v[len(v)-1] {
	case 'K':
		mult = kib
	case 'M':
		mult = mib
	case 'G':
		mult = gib
	case 'T':
		mult = 1 << 40
	case 'P':
		mult = 1 << 50
	case 'E':
		mult = 1 << 60
	}
	num := v
	if mult > 1 {
		num = v[:len(v)-1]
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
	if err != nil || f < 0 {
		return 0, false, false
	}
	return int64(f * float64(mult)), false, true
}

// journaldSettings reads Storage and SystemMaxUse from journald.conf and
// its drop-ins (later files win; /etc beats /run beats /usr/lib).
func (c *checker) journaldSettings() (storage, maxUse string, found bool) {
	files := []string{}
	if exists(c.env, "/etc/systemd/journald.conf") {
		files = append(files, "/etc/systemd/journald.conf")
		found = true
	}
	drop := map[string]string{}
	for _, d := range []string{"/usr/lib/systemd/journald.conf.d", "/run/systemd/journald.conf.d", "/etc/systemd/journald.conf.d"} {
		ms, _ := c.env.Glob(d + "/*.conf")
		for _, m := range ms {
			drop[path.Base(m)] = m
		}
	}
	names := make([]string, 0, len(drop))
	for n := range drop {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		files = append(files, drop[n])
	}
	for _, f := range files {
		b, err := c.env.ReadFile(f, 64<<10)
		if err != nil {
			continue
		}
		section := ""
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || l[0] == '#' || l[0] == ';' {
				continue
			}
			if strings.HasPrefix(l, "[") {
				section = l
				continue
			}
			if section != "[Journal]" {
				continue
			}
			k, v, okk := strings.Cut(l, "=")
			if !okk {
				continue
			}
			switch strings.TrimSpace(k) {
			case "Storage":
				storage = strings.TrimSpace(v)
			case "SystemMaxUse":
				maxUse = strings.TrimSpace(v)
			}
		}
	}
	return storage, maxUse, found
}

func (c *checker) checkJournald() {
	const id = "logs.journald_size"
	const jdir = "/var/log/journal"
	storage, maxUse, found := c.journaldSettings()
	if !found && !exists(c.env, jdir) && !exists(c.env, "/usr/lib/systemd/systemd-journald") && !exists(c.env, "/lib/systemd/systemd-journald") {
		c.add(unreadable(id, areaLogs, "Auf diesem Server gibt es kein systemd-Journal.", ReasonNotInstalled, "", hc.Evidence{Source: "journald_conf"}))
		return
	}
	if storage == "" {
		storage = "auto"
	}
	persistent := storage == "persistent" || storage == "auto" && exists(c.env, jdir)
	if !persistent {
		c.add(ok(id, areaLogs, "Größe des Journals", "Das Journal liegt nur im Arbeitsspeicher und wächst nicht auf der Platte.",
			hc.Evidence{Source: "journald_conf", Setting: "Storage", Value: tokp(storage)}))
		return
	}
	size, err := c.dirSize(jdir, 2)
	if err != nil {
		c.add(unreadable(id, areaLogs, "Die Größe des Journals ließ sich nicht lesen.", readErr(err), NeedsGroupJournal, hc.Evidence{Source: "stat", Path: jdir}))
		return
	}
	ev := hc.Evidence{Source: "journald_conf", Path: jdir, SizeBytes: i64p(size)}
	fsst, haveFS := statFS(c.env, jdir)
	share := ""
	if haveFS {
		p := pct(size, fsst.Total)
		ev.FSPercent, ev.Mount = ip(p), evPath(fsst.Mount)
		share = fmt.Sprintf(" (%d %% von %s)", p, fsst.Mount)
	}
	n, inf, parsed := parseSystemdSize(maxUse)
	raised := maxUse != "" && parsed && (inf || n > journalMax)
	if raised {
		ev.Setting, ev.Value = "SystemMaxUse", tokp(maxUse)
	}
	over := size > journalMax || haveFS && size*100 > int64(journalMaxPct)*fsst.Total
	if !over && !raised {
		c.add(ok(id, areaLogs, "Größe des Journals", fmt.Sprintf("Das Journal belegt %s%s und bleibt unter der Grenze von journald.", humanSize(size), share), ev))
		return
	}
	expl := fmt.Sprintf("Das Journal belegt %s%s. Eine feste Obergrenze hält es kleiner.", humanSize(size), share)
	if raised {
		expl += " In der Konfiguration ist SystemMaxUse auf " + maxUse + " gesetzt."
	}
	expl += " Danach journald neu starten."
	f := finding(id, areaLogs, "low", "Das Journal ist groß", expl, fixJournaldRestart, ev)
	f.FixConfig = renderedFix(id, map[string]string{"max_use_mb": "1024", "keep_free_mb": "2048"})
	c.add(f)
}

// dirSize sums the allocated size of the files below dir (stat only,
// bounded like the walk).
func (c *checker) dirSize(dir string, depth int) (int64, error) {
	var total int64
	entries := 0
	start := time.Now()
	var rec func(d string, lvl int) error
	rec = func(d string, lvl int) error {
		es, err := c.env.ReadDir(d)
		if err != nil {
			return err
		}
		for _, e := range es {
			entries++
			if entries > logWalkEntries || time.Since(start) > logWalkBudget {
				return nil
			}
			p := d + "/" + e.Name()
			switch {
			case e.Type()&fs.ModeSymlink != 0:
			case e.IsDir():
				if lvl+1 < depth {
					if err := rec(p, lvl+1); err != nil && !errors.Is(err, fs.ErrPermission) {
						return err
					}
				}
			default:
				if st, err := c.env.Stat(p); err == nil {
					total += factsOf(st).Alloc
				}
			}
		}
		return nil
	}
	err := rec(dir, 0)
	return total, err
}

// ---------------------------------------------------------------- logrotate

// logrotateScheduled finds logrotate and how it is started (timer link or
// cron.daily, the link logic of updates.automatic).
func (c *checker) logrotateScheduled() (installed bool, sched string) {
	installed = exists(c.env, "/usr/sbin/logrotate") || exists(c.env, "/sbin/logrotate")
	for _, d := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
		if p := d + "/timers.target.wants/logrotate.timer"; exists(c.env, p) {
			return installed, p
		}
	}
	if p := "/etc/cron.daily/logrotate"; exists(c.env, p) {
		return installed, p
	}
	return installed, ""
}

func (c *checker) checkLogrotateRuns(st *logState) {
	installed, sched := c.logrotateScheduled()
	// logs.logrotate_missing
	const mid = "logs.logrotate_missing"
	if installed && sched != "" {
		src := "systemd"
		expl := "Der Timer von logrotate ist aktiv."
		if strings.HasPrefix(sched, "/etc/cron") {
			src, expl = "logrotate_conf", "logrotate läuft täglich über cron."
		}
		c.add(ok(mid, areaLogs, "logrotate läuft täglich", expl, hc.Evidence{Source: src, Path: sched, Enabled: bp(true)}))
	} else {
		sev := "info"
		if st.sawLargeAny {
			sev = "medium"
		}
		fix := fixLogrotateTimer
		if !installed {
			fix = fixLogrotateApt
			if c.facts.family == "rhel" {
				fix = fixLogrotateDnf
			}
		}
		ev := hc.Evidence{Source: "systemd", Path: "/usr/sbin/logrotate", Enabled: bp(false)}
		c.add(finding(mid, areaLogs, sev, "logrotate läuft nicht", "logrotate ist nicht installiert oder läuft nicht regelmäßig. Logdateien unter /var/log werden dann nicht gekürzt.", fix, ev))
	}
	// logs.logrotate_stale
	const sid = "logs.logrotate_stale"
	if !installed || sched == "" {
		c.add(unreadable(sid, areaLogs, "Wann logrotate zuletzt lief, lässt sich nur prüfen, wenn es regelmäßig läuft.", ReasonNotConfigured, "", hc.Evidence{Source: "logrotate_status"}))
		return
	}
	var status string
	var mt time.Time
	for _, p := range []string{"/var/lib/logrotate/status", "/var/lib/logrotate/logrotate.status"} {
		fi, err := c.env.Stat(p)
		if err == nil {
			status, mt = p, fi.ModTime()
			break
		}
		if errors.Is(err, fs.ErrPermission) {
			c.add(unreadable(sid, areaLogs, "Wann logrotate zuletzt lief, ließ sich nicht lesen.", ReasonPermission, NeedsRoot, hc.Evidence{Source: "logrotate_status", Path: p}))
			return
		}
	}
	now := c.env.Now()
	if status == "" {
		c.add(ok(sid, areaLogs, "logrotate ist noch nicht gelaufen", "logrotate hat noch keine Statusdatei angelegt, etwa auf einem frisch installierten Server.", hc.Evidence{Source: "logrotate_status"}))
		return
	}
	ev := hc.Evidence{Source: "logrotate_status", Path: status, Date: mt.UTC().Format("2006-01-02")}
	recentBoot := false
	if bt, err := bootTime(c.env); err == nil && now.Sub(time.Unix(bt, 0)) < bootGrace {
		recentBoot = true
	}
	if now.Sub(mt) <= staleAfter || recentBoot {
		c.add(ok(sid, areaLogs, "logrotate läuft", fmt.Sprintf("logrotate ist zuletzt am %s gelaufen.", germanDate(mt)), ev))
		return
	}
	sev := "low"
	if st.largeFinds > 0 {
		sev = "medium"
	}
	c.add(finding(sid, areaLogs, sev, "logrotate ist länger nicht gelaufen",
		fmt.Sprintf("logrotate ist zuletzt am %s gelaufen. Normal ist einmal am Tag. %s zeigt, woran es hängt.", germanDate(mt), fixLogrotateDebug), fixLogrotateDebug, ev))
}

var lrConfName = regexp.MustCompile(`^/etc/logrotate\.(conf|d/[A-Za-z0-9._@+-]{1,64})$`)

// checkLogrotateConfig: config files logrotate skips, duplicate log paths,
// writable log directories without su, and the cross-check with schild's
// Caddyfile.
func (c *checker) checkLogrotateConfig(st *logState) {
	const id = "logs.logrotate_config"
	if st.conf.dirErr != "" {
		c.add(unreadable(id, areaLogs, "Die Regeln in /etc/logrotate.d ließen sich nicht lesen.", st.conf.dirErr, NeedsRoot, hc.Evidence{Source: "logrotate_conf", Path: logrotateDir}))
		return
	}
	seen := map[string]bool{}
	n := 0
	add := func(f hc.Finding) {
		if seen[f.Subject] || !subjectRe.MatchString(f.Subject) || n >= 100 {
			return
		}
		seen[f.Subject] = true
		n++
		c.add(f)
	}
	// Caddy (schild's own Caddyfile) first: medium.
	if p := c.opts.Caddyfile; p != "" {
		b, err := c.env.ReadFile(p, 1<<20)
		switch {
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			f := unreadable(id, areaLogs, "Das Caddyfile von schild ließ sich nicht lesen.", readErr(err), NeedsRoot, hc.Evidence{Source: "caddyfile", Path: evPath(p)})
			f.Subject = p
			add(f)
		case err == nil:
			for _, o := range parseCaddyOutputs(string(b)) {
				if !subjectRe.MatchString(o.path) {
					continue
				}
				st.caddy[o.path] = o.rollDisabled
				rules := st.conf.coveringRules(o.path)
				ev := hc.Evidence{Source: "caddyfile", Path: evPath(o.path), Setting: "roll_disabled", Enabled: bp(o.rollDisabled)}
				var f hc.Finding
				switch {
				case o.rollDisabled && len(rules) == 0:
					f = finding(id, areaLogs, "medium", "Caddy-Log wird nicht richtig rotiert",
						"Caddy schreibt "+o.path+" selbst und öffnet die Datei nach dem Umbenennen nicht neu. Ohne copytruncate landet das Log weiter in der alten Datei. Bisher erfasst keine logrotate-Regel die Datei.", "", ev)
					f.FixConfig = logrotateFix(id, o.path, 14, 200)
				case o.rollDisabled && !rules[0].copytruncate:
					f = finding(id, areaLogs, "medium", "Caddy-Log wird nicht richtig rotiert",
						"Caddy schreibt "+o.path+" selbst und öffnet die Datei nach dem Umbenennen nicht neu. Ohne copytruncate landet das Log weiter in der alten Datei. Ergänze copytruncate in der Regel in "+rules[0].file+".", "", ev)
				case !o.rollDisabled && len(rules) > 0:
					f = finding(id, areaLogs, "medium", "Caddy-Log wird doppelt rotiert",
						"Caddy rotiert "+o.path+" selbst, und die logrotate-Regel in "+rules[0].file+" tut es auch. Eine von beiden reicht: roll_disabled im Caddyfile oder die Regel entfernen.", "", ev)
				default:
					what := "Caddy rotiert " + o.path + " selbst."
					if o.rollDisabled {
						what = "Eine logrotate-Regel mit copytruncate rotiert " + o.path + "."
					}
					f = ok(id, areaLogs, "Rotation des Caddy-Logs", what, ev)
				}
				f.Subject = o.path
				add(f)
			}
		}
	}
	for _, s := range st.conf.skipped {
		ev := hc.Evidence{Source: "logrotate_conf", Path: evPath(s.file)}
		var f hc.Finding
		fixable := lrConfName.MatchString(s.file)
		switch s.reason {
		case "mode":
			fix := ""
			if fixable {
				fix = "sudo chmod 0644 " + s.file
			}
			f = finding(id, areaLogs, "low", "logrotate überspringt eine Regeldatei", "logrotate überspringt "+s.file+", weil andere sie beschreiben dürfen. Die Regeln darin wirken nicht.", fix, ev)
		case "owner":
			fix := ""
			if fixable {
				fix = "sudo chown root:root " + s.file
			}
			f = finding(id, areaLogs, "low", "logrotate überspringt eine Regeldatei", "logrotate überspringt "+s.file+", weil sie nicht root gehört. Die Regeln darin wirken nicht.", fix, ev)
		default:
			f = finding(id, areaLogs, "low", "logrotate überspringt eine Regeldatei", "logrotate überspringt "+s.file+" wegen der Dateiendung. Die Regeln darin wirken nicht.", "", ev)
		}
		f.Subject = s.file
		add(f)
	}
	// Duplicate log paths and writable log directories without su.
	owner := map[string]string{}
	dirChecked := map[string]bool{}
	for _, r := range st.conf.rules {
		for _, p := range c.expand(r) {
			if first, dup := owner[p]; dup {
				f := finding(id, areaLogs, "low", "Logdatei in zwei logrotate-Regeln",
					p+" steht in zwei logrotate-Regeln ("+first+" und "+r.file+"). logrotate meldet dann bei jedem Lauf einen Fehler und lässt die zweite Regel aus.", "",
					hc.Evidence{Source: "logrotate_conf", Path: evPath(r.file)})
				f.Subject = p
				add(f)
				continue
			}
			owner[p] = r.file
			if r.su {
				continue
			}
			d := path.Dir(p)
			if dirChecked[d] || !exists(c.env, p) {
				continue
			}
			dirChecked[d] = true
			dst, err := c.env.Stat(d)
			if err != nil {
				continue
			}
			m := dst.Mode().Perm()
			if m&0o002 != 0 || m&0o020 != 0 && factsOf(dst).GID != 0 {
				f := finding(id, areaLogs, "low", "logrotate rotiert eine Logdatei nicht",
					"logrotate rotiert "+p+" nicht, weil andere das Verzeichnis "+d+" beschreiben dürfen und die Regel in "+r.file+" kein su hat.", "",
					hc.Evidence{Source: "stat", Path: evPath(d), Setting: "su", Enabled: bp(false)})
				f.Subject = p
				add(f)
			}
		}
	}
	if n == 0 {
		ev := hc.Evidence{Source: "logrotate_conf", Path: logrotateDir, Count: i64p(int64(len(st.conf.rules)))}
		if !st.conf.confFound && len(st.conf.rules) == 0 {
			c.add(ok(id, areaLogs, "Regeln von logrotate", "Es gibt keine logrotate-Regeln, die sich prüfen ließen.", ev))
			return
		}
		c.add(ok(id, areaLogs, "Regeln von logrotate", "logrotate liest alle Regeldateien, keine Logdatei steht doppelt.", ev))
	}
}

// ---------------------------------------------------------------- large files

// previousSizes reads the sizes of large files from the previous kept
// report (growth per day).
func (c *checker) previousSizes() (map[string]int64, time.Time) {
	prev := c.opts.Previous
	if prev == nil {
		return nil, time.Time{}
	}
	t, err := time.Parse(time.RFC3339, prev.Run.StartedAt)
	if err != nil {
		return nil, time.Time{}
	}
	out := map[string]int64{}
	for _, f := range prev.Findings {
		if f.ID == "logs.large_file" && f.Subject != "" && f.Evidence.SizeBytes != nil && f.Status != hc.StatusUnreadable {
			out[f.Subject] = *f.Evidence.SizeBytes
		}
	}
	return out, t
}

func (c *checker) checkLargeFiles(st *logState) {
	const id = "logs.large_file"
	prev, prevAt := c.previousSizes()
	now := c.env.Now()
	elapsed := now.Sub(prevAt)
	emitted := 0
	for _, lf := range st.walk.files {
		if emitted >= maxLargeResults {
			break
		}
		if _, ok := st.caddy[lf.path]; ok || !subjectRe.MatchString(lf.path) {
			continue // Caddy outputs: logs.logrotate_config
		}
		ev := hc.Evidence{Source: "stat", Path: evPath(lf.path), SizeBytes: i64p(lf.size)}
		fsst, haveFS := statFS(c.env, lf.path)
		if haveFS {
			ev.FSPercent, ev.Mount = ip(pct(lf.size, fsst.Total)), evPath(fsst.Mount)
		}
		var growth int64
		known := false
		if p, ok := prev[lf.path]; ok && elapsed >= time.Hour {
			growth = int64(float64(lf.size-p) * float64(24*time.Hour) / float64(elapsed))
			known = true
			ev.GrowthBytesPerDay = i64p(growth)
		}
		covered := len(st.conf.coveringRules(lf.path)) > 0
		sev := ""
		if lf.size > largeLow {
			sev = "low"
		}
		if haveFS && lf.size*100 > largeMediumPct*fsst.Total || haveFS && growth > 0 && fsst.Avail/growth < fillDaysMedium {
			sev = "medium"
		}
		if known && growth <= 0 {
			sev = "" // a one-off dump, not a growing log
		}
		ev.Enabled = bp(covered)
		var f hc.Finding
		if covered || sev == "" {
			what := lf.path + " ist " + humanSize(lf.size) + " groß."
			if covered {
				what += " Eine logrotate-Regel erfasst die Datei."
			}
			f = ok(id, areaLogs, "Große Logdatei", what, ev)
		} else {
			expl := lf.path + " ist " + humanSize(lf.size) + " groß"
			if known {
				expl += " und wächst um etwa " + humanSize(growth) + " pro Tag"
			}
			expl += ". Keine logrotate-Regel erfasst die Datei."
			f = finding(id, areaLogs, sev, "Große Logdatei ohne Rotation", expl, "", ev)
			f.FixConfig = logrotateFix(id, lf.path, 7, 500)
			st.largeFinds++
		}
		f.Subject = lf.path
		c.add(f)
		emitted++
	}
	for i, d := range st.walk.denied {
		if i >= maxDeniedResults || !subjectRe.MatchString(d) {
			break
		}
		f := unreadable(id, areaLogs, "Ein Teil von /var/log ist nur für root lesbar.", ReasonPermission, NeedsRoot, hc.Evidence{Source: "stat", Path: evPath(d)})
		f.Title = "Logverzeichnis nicht lesbar"
		f.Subject = d
		c.add(f)
	}
	if st.walk.truncated {
		f := unreadable(id, areaLogs, "/var/log hat mehr Einträge, als die Prüfung in der vorgesehenen Zeit ansieht.", ReasonTimeout, "", hc.Evidence{Source: "stat", Path: "/var/log", Count: i64p(int64(st.walk.entries))})
		f.Subject = "/var/log"
		c.add(f)
	}
	if emitted == 0 {
		c.add(ok(id, areaLogs, "Große Logdateien", "Unter /var/log ist keine Datei größer als 100 MB.", hc.Evidence{Source: "stat", Path: "/var/log", Count: i64p(int64(st.walk.entries))}))
	}
}
