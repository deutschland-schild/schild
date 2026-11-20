package waf

import (
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/crs/v4"
)

// CRSRule is one detection rule of the embedded CRS, for the rule list (D48).
type CRSRule struct {
	ID       int
	Msg      string
	Paranoia int
	// Text is the rule as the CRS file has it, with the rules chained to it;
	// File is the name of that file.
	Text string
	File string
}

var (
	crsActionID    = regexp.MustCompile(`\bid:(\d+)`)
	crsActionMsg   = regexp.MustCompile(`\bmsg:'([^']*)'`)
	crsActionPL    = regexp.MustCompile(`tag:'?paranoia-level/(\d)`)
	crsMsgMacro    = regexp.MustCompile(`\s*\(?[^()]*%\{[^}]*\}[^()]*\)?`)
	crsActionChain = regexp.MustCompile(`[,"\s]chain"?\s*$`)
	crsCatalogue   []CRSRule
	crsCatalogOne  sync.Once
)

// The ids between the initialisation of the CRS and its correlation report.
const (
	crsFirstFinding = 911000
	crsLastFinding  = 959999
)

// CRSRules lists the rules up to the paranoia level, by number. The files are read
// once: they are part of the binary.
func CRSRules(paranoia int) []CRSRule {
	crsCatalogOne.Do(func() { crsCatalogue = readCRSRules(coreruleset.FS) })
	out := make([]CRSRule, 0, len(crsCatalogue))
	for _, r := range crsCatalogue {
		if r.Paranoia <= paranoia {
			out = append(out, r)
		}
	}
	return out
}

func readCRSRules(fsys fs.FS) []CRSRule {
	files, _ := fs.Glob(fsys, "@owasp_crs/*.conf")
	var out []CRSRule
	for _, f := range files {
		text, err := fs.ReadFile(fsys, f)
		if err != nil {
			continue
		}
		rules := parseCRSRules(string(text))
		for i := range rules {
			rules[i].File = path.Base(f)
		}
		out = append(out, rules...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// parseCRSRules takes the rules with an id and a msg: what has none is flow control
// or the setup of a score, and no finding, as are the check of the setup and the
// correlation report outside crsFirstFinding and crsLastFinding. A chained rule has both on its first line;
// the rules chained to it belong to its text.
func parseCRSRules(text string) []CRSRule {
	var out []CRSRule
	stmts := crsStatements(text)
	for i := 0; i < len(stmts); i++ {
		line := strings.TrimSpace(strings.ReplaceAll(stmts[i], "\\\n", " "))
		if !strings.HasPrefix(line, "SecRule") && !strings.HasPrefix(line, "SecAction") {
			continue
		}
		raw := []string{stmts[i]}
		for crsChains(stmts[i]) && i+1 < len(stmts) {
			i++
			raw = append(raw, stmts[i])
		}
		id, msg := crsActionID.FindStringSubmatch(line), crsActionMsg.FindStringSubmatch(line)
		if id == nil || msg == nil {
			continue
		}
		n, err := strconv.Atoi(id[1])
		if err != nil || n < crsFirstFinding || n > crsLastFinding {
			continue
		}
		pl := 1
		if m := crsActionPL.FindStringSubmatch(line); m != nil {
			pl, _ = strconv.Atoi(m[1])
		}
		out = append(out, CRSRule{ID: n, Msg: strings.TrimSpace(crsMsgMacro.ReplaceAllString(msg[1], "")), Paranoia: pl,
			Text: strings.Join(raw, "\n")})
	}
	return out
}

// crsStatements splits a file into its directives, each with its continuation
// lines as written. Comments and empty lines are left out.
func crsStatements(text string) []string {
	var out []string
	var cur []string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, " \t\r")
		if cur == nil && (strings.TrimSpace(l) == "" || strings.HasPrefix(strings.TrimSpace(l), "#")) {
			continue
		}
		cur = append(cur, l)
		if !strings.HasSuffix(l, "\\") {
			out = append(out, strings.Join(cur, "\n"))
			cur = nil
		}
	}
	if cur != nil {
		out = append(out, strings.Join(cur, "\n"))
	}
	return out
}

// crsChains reports whether the directive ends with the action chain, so the
// next directive belongs to it.
func crsChains(stmt string) bool {
	return crsActionChain.MatchString(stmt)
}
