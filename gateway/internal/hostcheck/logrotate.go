package hostcheck

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Parsing of logrotate configuration and of the output files of schild's
// Caddyfile (area logs, D38). Only rules are kept (log paths and the
// directives the checks need: copytruncate, su); scripts are skipped and no
// text of a config file ever reaches a report.

const (
	logrotateConf = "/etc/logrotate.conf"
	logrotateDir  = "/etc/logrotate.d"
	maxConfBytes  = 256 << 10
	maxConfFiles  = 500
	maxGlobNames  = 1000
)

// lrRule is one logrotate rule: the log path patterns before "{".
type lrRule struct {
	file         string
	patterns     []string
	copytruncate bool
	su           bool
}

// lrSkipped is a config file logrotate ignores.
type lrSkipped struct {
	file   string
	reason string // "mode", "owner", "taboo"
}

// lrConf is what the check knows about logrotate's configuration.
type lrConf struct {
	rules   []lrRule
	skipped []lrSkipped
	// dirErr: /etc/logrotate.d could not be listed (reason), "" if fine.
	dirErr string
	// confFound: /etc/logrotate.conf exists.
	confFound bool
}

// lrTaboo are logrotate's default taboo extensions: files ending in them
// are skipped when it reads an include directory.
var lrTaboo = []string{",v", ".bak", ".cfsaved", ".disabled", ".dpkg-bak", ".dpkg-del", ".dpkg-dist", ".dpkg-new", ".dpkg-old", ".dpkg-tmp",
	".rpmnew", ".rpmorig", ".rpmsave", ".swp", ".ucf-dist", ".ucf-new", ".ucf-old", "~"}

func lrTabooBase(name string) (string, bool) {
	for _, t := range lrTaboo {
		if strings.HasSuffix(name, t) && len(name) > len(t) {
			return strings.TrimSuffix(name, t), true
		}
	}
	return "", false
}

// lrBadMode applies logrotate's own test: owner may read (and write), no
// execute bits, nobody else may write, no setuid/setgid/sticky.
func lrBadMode(m fs.FileMode) bool {
	perm := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 || m&fs.ModeSetgid != 0 || m&fs.ModeSticky != 0 {
		return true
	}
	return perm&0o533 != 0o400
}

// loadLogrotate reads /etc/logrotate.conf and the files of
// /etc/logrotate.d (world-readable on every supported distribution).
func (c *checker) loadLogrotate() lrConf {
	var out lrConf
	var glob struct{ copytruncate, su bool }
	if b, err := c.env.ReadFile(logrotateConf, maxConfBytes); err == nil {
		out.confFound = true
		if st, err := c.env.Stat(logrotateConf); err == nil {
			if r := lrSkipReason(st); r != "" {
				out.skipped = append(out.skipped, lrSkipped{file: logrotateConf, reason: r})
			}
		}
		rules, ct, su := parseLogrotate(string(b), logrotateConf, false, false)
		out.rules = append(out.rules, rules...)
		glob.copytruncate, glob.su = ct, su
	}
	es, err := c.env.ReadDir(logrotateDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			out.dirErr = readErr(err)
		}
		return out
	}
	names := map[string]bool{}
	for _, e := range es {
		names[e.Name()] = true
	}
	n := 0
	for _, e := range es {
		if n >= maxConfFiles {
			break
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || e.IsDir() {
			continue
		}
		p := logrotateDir + "/" + name
		st, err := c.env.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		n++
		if base, ok := lrTabooBase(name); ok {
			// A backup next to the live file is normal; a taboo file
			// alone holds rules that never apply.
			if !names[base] {
				out.skipped = append(out.skipped, lrSkipped{file: p, reason: "taboo"})
			}
			continue
		}
		if r := lrSkipReason(st); r != "" {
			out.skipped = append(out.skipped, lrSkipped{file: p, reason: r})
			continue
		}
		b, err := c.env.ReadFile(p, maxConfBytes)
		if err != nil {
			continue
		}
		rules, _, _ := parseLogrotate(string(b), p, glob.copytruncate, glob.su)
		out.rules = append(out.rules, rules...)
	}
	return out
}

func lrSkipReason(st fs.FileInfo) string {
	if lrBadMode(st.Mode()) {
		return "mode"
	}
	if f := factsOf(st); f.HasOwner && f.UID != 0 {
		return "owner"
	}
	return ""
}

// lrFields splits a line into words; double or single quotes group words.
func lrFields(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	in := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, in = r, true
		case r == ' ' || r == '\t':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}

// parseLogrotate returns the rules of one config file and the global
// copytruncate and su state at its end. Global directives before a rule
// apply to it (ct, su: the state inherited from logrotate.conf).
func parseLogrotate(text, file string, ct, su bool) ([]lrRule, bool, bool) {
	var rules []lrRule
	var pending []string
	var cur *lrRule
	script := false
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if script {
			if w := firstWord(l); w == "endscript" {
				script = false
			}
			continue
		}
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if cur == nil {
			before, after, open := strings.Cut(l, "{")
			if open {
				pending = append(pending, lrFields(before)...)
				cur = &lrRule{file: file, patterns: pending, copytruncate: ct, su: su}
				pending = nil
				l = strings.TrimSpace(after)
				if l == "" {
					continue
				}
				// Directives on the same line as "{" (rare): fall through.
			} else {
				w := firstWord(l)
				switch {
				case strings.HasPrefix(w, "/") || strings.HasPrefix(w, "\"/") || strings.HasPrefix(w, "'/"):
					pending = append(pending, lrFields(l)...)
				case w == "copytruncate":
					ct = true
				case w == "nocopytruncate":
					ct = false
				case w == "su":
					su = true
				}
				continue
			}
		}
		if strings.HasPrefix(l, "}") {
			rules = append(rules, *cur)
			cur = nil
			continue
		}
		switch firstWord(l) {
		case "postrotate", "prerotate", "firstaction", "lastaction", "preremove":
			script = true
		case "copytruncate":
			cur.copytruncate = true
		case "nocopytruncate":
			cur.copytruncate = false
		case "su":
			cur.su = true
		}
		if strings.HasSuffix(l, "}") && !script {
			rules = append(rules, *cur)
			cur = nil
		}
	}
	return rules, ct, su
}

func firstWord(l string) string {
	if f := strings.Fields(l); len(f) > 0 {
		return f[0]
	}
	return ""
}

// covers reports whether a rule pattern matches the log path p (glob(3)
// semantics: "*" stays within one path segment).
func (r lrRule) covers(p string) bool {
	for _, pat := range r.patterns {
		if pat == p {
			return true
		}
		if ok, err := path.Match(pat, p); err == nil && ok {
			return true
		}
	}
	return false
}

// coveringRules returns the rules that match p.
func (l lrConf) coveringRules(p string) []lrRule {
	var out []lrRule
	for _, r := range l.rules {
		if r.covers(p) {
			out = append(out, r)
		}
	}
	return out
}

func hasGlobMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

// expand returns the log files a rule names: literal paths as they are,
// globs as they match now (globs that match nothing are fine).
func (c *checker) expand(r lrRule) []string {
	var out []string
	for _, p := range r.patterns {
		if !strings.HasPrefix(p, "/") {
			continue
		}
		if !hasGlobMeta(p) {
			out = append(out, path.Clean(p))
			continue
		}
		ms, _ := c.env.Glob(p)
		if len(ms) > maxGlobNames {
			ms = ms[:maxGlobNames]
		}
		out = append(out, ms...)
	}
	sort.Strings(out)
	return out
}

// caddyOutput is one "output file" of a Caddyfile log directive.
type caddyOutput struct {
	path         string
	rollDisabled bool
}

// parseCaddyOutputs finds every `output file <path> [{ ... }]` and whether
// its block holds roll_disabled. Nothing else of the Caddyfile is used.
func parseCaddyOutputs(text string) []caddyOutput {
	var out []caddyOutput
	seen := map[string]int{}
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		f := lrFields(strings.TrimSpace(stripCaddyComment(lines[i])))
		if len(f) < 3 || f[0] != "output" || f[1] != "file" || !strings.HasPrefix(f[2], "/") {
			continue
		}
		o := caddyOutput{path: path.Clean(f[2])}
		if f[len(f)-1] == "{" {
			depth := 1
			for i++; i < len(lines) && depth > 0; i++ {
				l := strings.TrimSpace(stripCaddyComment(lines[i]))
				if firstWord(l) == "roll_disabled" && depth == 1 {
					o.rollDisabled = true
				}
				depth += strings.Count(l, "{") - strings.Count(l, "}")
			}
			i--
		}
		if j, ok := seen[o.path]; ok {
			out[j].rollDisabled = out[j].rollDisabled || o.rollDisabled
			continue
		}
		seen[o.path] = len(out)
		out = append(out, o)
	}
	return out
}

func stripCaddyComment(l string) string {
	if i := strings.Index(l, "#"); i == 0 || i > 0 && (l[i-1] == ' ' || l[i-1] == '\t') {
		return l[:i]
	}
	return l
}
