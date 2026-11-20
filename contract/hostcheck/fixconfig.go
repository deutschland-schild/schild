package hostcheck

import (
	"regexp"
	"strconv"
	"strings"
)

// Fix templates (v0.5, D38, MVP-11 addendum "Log-Hygiene"). A finding may
// suggest a config file (fix_config {path, content}) instead of a command.
// The text always comes from these gateway-side templates; the only
// variable parts are checked paths, slugs and numbers. A report whose
// fix_config is not a rendering of a template of its finding id is
// rejected (code schema), so an agent can never get arbitrary file content
// shown as a fix. The Python cross-check holds the same table.

// FixTemplate is one template: ${name} marks a variable (FixVars).
type FixTemplate struct {
	Path    string
	Content string
}

// logrotateRule is the rule for a log file schild's check found unrotated
// (Caddy roll_disabled output without copytruncate, a large file without a
// rule). copytruncate because the writer (the embedded Caddy, most apps)
// does not reopen the file.
const logrotateRule = "${file} {\n  daily\n  rotate ${rotate}\n  maxsize ${max_size_mb}M\n  missingok\n  notifempty\n  compress\n  delaycompress\n  copytruncate\n}\n"

// FixTemplates by finding id.
var FixTemplates = map[string][]FixTemplate{
	"logs.docker_unbounded": {{
		Path:    "/etc/docker/daemon.json",
		Content: `{"log-driver": "local", "log-opts": {"max-size": "${max_size_mb}m", "max-file": "${max_files}"}}` + "\n",
	}},
	"logs.journald_size": {{
		Path:    "/etc/systemd/journald.conf.d/50-schild-size.conf",
		Content: "[Journal]\nSystemMaxUse=${max_use_mb}M\nSystemKeepFree=${keep_free_mb}M\nMaxRetentionSec=1month\n",
	}},
	"logs.logrotate_config": {{Path: "/etc/logrotate.d/schild-${slug}", Content: logrotateRule}},
	"logs.large_file":       {{Path: "/etc/logrotate.d/schild-${slug}", Content: logrotateRule}},
}

// FixVar is the type of a template variable: a pattern, and for numbers
// inclusive bounds.
type FixVar struct {
	Pattern  string
	Min, Max int64 // numbers only (Max 0: not a number)
}

const numPattern = `[1-9][0-9]{0,6}`

// FixVars are the variables templates may use.
var FixVars = map[string]FixVar{
	"slug":         {Pattern: `[a-z0-9][a-z0-9-]{0,47}`},
	"file":         {Pattern: `/[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,63}(?:/[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,63}){0,7}`},
	"max_size_mb":  {Pattern: numPattern, Min: 1, Max: 10240},
	"max_files":    {Pattern: numPattern, Min: 1, Max: 20},
	"max_use_mb":   {Pattern: numPattern, Min: 64, Max: 65536},
	"keep_free_mb": {Pattern: numPattern, Min: 64, Max: 1048576},
	"rotate":       {Pattern: numPattern, Min: 1, Max: 365},
}

// FixFileRoots: a log file in a logrotate template lies below one of these
// directories; outside /var/log/ its name also ends in ".log" (so a rule
// with copytruncate never truncates a system or config file). Segments
// never start with '.', so there is no "..".
var FixFileRoots = []string{"/var/log/", "/srv/", "/opt/", "/var/www/"}

var fixPlaceholder = regexp.MustCompile(`\$\{([a-z_]{1,32})\}`)

type compiledTemplate struct {
	rx    *regexp.Regexp
	names []string
}

func compileTemplate(t string) compiledTemplate {
	var b strings.Builder
	var names []string
	b.WriteString("^")
	rest := t
	for {
		loc := fixPlaceholder.FindStringSubmatchIndex(rest)
		if loc == nil {
			break
		}
		name := rest[loc[2]:loc[3]]
		b.WriteString(regexp.QuoteMeta(rest[:loc[0]]))
		b.WriteString("(" + FixVars[name].Pattern + ")")
		names = append(names, name)
		rest = rest[loc[1]:]
	}
	b.WriteString(regexp.QuoteMeta(rest))
	b.WriteString("$")
	return compiledTemplate{regexp.MustCompile(b.String()), names}
}

// match returns the variables of s, or false.
func (c compiledTemplate) match(s string, vars map[string]string) bool {
	m := c.rx.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	for i, n := range c.names {
		v := m[i+1]
		if old, ok := vars[n]; ok && old != v {
			return false
		}
		vars[n] = v
	}
	return true
}

func fixVarOK(name, v string) bool {
	fv := FixVars[name]
	if fv.Max > 0 {
		n, err := strconv.ParseInt(v, 10, 64)
		return err == nil && n >= fv.Min && n <= fv.Max
	}
	if name == "file" {
		for _, r := range FixFileRoots {
			if strings.HasPrefix(v, r) && len(v) > len(r) {
				return r == "/var/log/" || strings.HasSuffix(v, ".log")
			}
		}
		return false
	}
	return true
}

var compiledTemplates = func() map[string][][2]compiledTemplate {
	out := map[string][][2]compiledTemplate{}
	for id, ts := range FixTemplates {
		for _, t := range ts {
			out[id] = append(out[id], [2]compiledTemplate{compileTemplate(t.Path), compileTemplate(t.Content)})
		}
	}
	return out
}()

// FixConfigKnown reports whether (path, content) renders a template of the
// finding id with valid variables (the same variable has one value in path
// and content).
func FixConfigKnown(id, path, content string) bool {
	for _, t := range compiledTemplates[id] {
		vars := map[string]string{}
		if !t[0].match(path, vars) || !t[1].match(content, vars) {
			continue
		}
		ok := true
		for n, v := range vars {
			if !fixVarOK(n, v) {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// RenderFix renders a template with the given variables (for checks that
// produce a fix_config). It does not validate; FixConfigKnown does.
func RenderFix(t FixTemplate, vars map[string]string) FixConfig {
	r := func(s string) string {
		return fixPlaceholder.ReplaceAllStringFunc(s, func(m string) string { return vars[m[2:len(m)-1]] })
	}
	return FixConfig{Path: r(t.Path), Content: r(t.Content)}
}
