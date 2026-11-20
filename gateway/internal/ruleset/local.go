package ruleset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// localRule is one rule of rules.d: a SecRule or SecAction with an id and the
// rules chained to it.
type localRule struct {
	id   int
	file string
	msg  string
	text string
}

// localSet is what rules.d holds at one moment.
type localSet struct {
	text  string // the directive text the WAF gets
	files []LocalFile
	rules []localRule
}

var (
	localIDRe    = regexp.MustCompile(`\bid:'?(\d+)`)
	localMsgRe   = regexp.MustCompile(`\bmsg:'([^']*)'`)
	localChainRe = regexp.MustCompile(`[",]\s*chain\s*[,"']`)
)

// readLocal reads the *.conf files of dir in name order.
func readLocal(dir string) (localSet, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
	sort.Strings(files)
	var set localSet
	var b strings.Builder
	set.files = []LocalFile{}
	for _, f := range files {
		c, err := os.ReadFile(f)
		if err != nil {
			return localSet{}, err
		}
		name := filepath.Base(f)
		b.WriteString("# " + name + "\n")
		b.Write(c)
		b.WriteString("\n")
		rs := parseLocal(name, string(c))
		set.rules = append(set.rules, rs...)
		set.files = append(set.files, LocalFile{Name: name, Rules: len(rs)})
	}
	set.text = b.String()
	return set, nil
}

// parseLocal finds the rules of one file: every SecRule or SecAction with an
// id, with the rules chained to it. Continuation lines are joined first.
func parseLocal(file, text string) []localRule {
	var out []localRule
	var cur *localRule
	inChain := false
	for _, line := range strings.Split(strings.ReplaceAll(text, "\\\n", " "), "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "SecRule") && !strings.HasPrefix(l, "SecAction") {
			continue
		}
		if m := localIDRe.FindStringSubmatch(l); m != nil {
			id, _ := strconv.Atoi(m[1])
			out = append(out, localRule{id: id, file: file, text: l})
			cur = &out[len(out)-1]
			if mm := localMsgRe.FindStringSubmatch(l); mm != nil {
				cur.msg = mm[1]
			}
		} else if inChain && cur != nil {
			cur.text += "\n    " + l
			if cur.msg == "" {
				if mm := localMsgRe.FindStringSubmatch(l); mm != nil {
					cur.msg = mm[1]
				}
			}
		} else {
			inChain = false
			continue
		}
		inChain = localChainRe.MatchString(l)
	}
	return out
}

// localRepo is the repository local: the operator's files in rules.d.
type localRepo struct {
	reg *Registry
	mu  sync.Mutex
	set localSet
	// loaded: the set was read; lastReload, lastErr: the last sync.
	loaded     bool
	lastReload time.Time
	lastErr    string
	// syncMu keeps one sync at a time.
	syncMu sync.Mutex
}

func (l *localRepo) ID() string { return rules.RepoLocal }

func (l *localRepo) dir() string {
	if d := l.reg.cfg().Rules.Local.Dir; d != "" {
		return d
	}
	return config.LocalRulesDirDefault
}

// load reads rules.d at start: a directory that is not there is an empty one.
func (l *localRepo) load() error {
	set, err := readLocal(l.dir())
	if err != nil {
		return fmt.Errorf("rules.d: %w", err)
	}
	l.mu.Lock()
	l.set, l.loaded, l.lastReload = set, true, l.reg.now()
	l.mu.Unlock()
	return nil
}

func (l *localRepo) current() localSet {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.set
}

func version(text string) string {
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:6])
}

func (l *localRepo) Rules() []Entry {
	set := l.current()
	out := make([]Entry, 0, len(set.rules))
	for _, r := range set.rules {
		out = append(out, Entry{ID: strconv.Itoa(r.id), Msg: r.msg, Version: version(r.text), File: r.file, SecLang: r.text,
			Input: rules.Input{Origin: rules.OriginOperator}})
	}
	return out
}

func (l *localRepo) Describe(v *RepositoryView, _ string) {
	v.Name, v.Origin = "Eigene Regeln", "operator"
	l.mu.Lock()
	defer l.mu.Unlock()
	info := &LocalInfo{Dir: l.dir(), Files: append([]LocalFile{}, l.set.files...), LastError: l.lastErr}
	if l.loaded {
		at := msg.FormatTime(l.lastReload)
		info.LastReloadAt, v.LastChangeAt = &at, &at
	}
	v.Local = info
}

func (l *localRepo) Apply(cfg *waf.Config, state string, disabled []int) {
	cfg.LocalRules, cfg.LocalRemove = "", nil
	if state == rules.StateOff {
		return
	}
	cfg.LocalRules, cfg.LocalRemove = l.current().text, disabled
}

func (l *localRepo) Reset(context.Context) error { return ErrNotSupported }

// Sync loads rules.d again and swaps the WAF without a restart (D46). The new
// set is compiled in full next to the running one, with the other
// repositories, so it can only go live when it would also pass a start.
// Whatever goes wrong before the swap leaves the running rules in place.
func (l *localRepo) Sync(context.Context) (SyncResult, error) {
	l.syncMu.Lock()
	defer l.syncMu.Unlock()
	res, err := l.sync()
	m := l.reg.o.Metrics
	switch {
	case err != nil:
		if m != nil {
			m.LocalRulesReloads.WithLabelValues(bodylimit.ReloadRefused).Inc()
		}
		l.reg.log().Error("local rules not reloaded, the running rules stay", "dir", l.dir(), "err", err)
	case res.Unchanged:
		if m != nil {
			m.LocalRulesReloads.WithLabelValues(bodylimit.ReloadUnchanged).Inc()
		}
		l.reg.log().Info("local rules unchanged", "dir", l.dir(), "local_rules", res.Rules)
	default:
		if m != nil {
			m.LocalRulesReloads.WithLabelValues(bodylimit.ReloadApplied).Inc()
		}
		l.reg.log().Info("local rules reloaded", "dir", l.dir(), "local_rules", res.Rules)
	}
	return res, err
}

func (l *localRepo) sync() (SyncResult, error) {
	old := l.current()
	dir := l.dir()
	// A volume that went away looks like an empty directory to the glob, and
	// that would take every exception and every local block off in silence.
	if _, err := os.Stat(dir); err != nil && old.text != "" {
		return SyncResult{}, l.refuse(old, &SyncError{Code: CodeDirMissing, Err: err})
	}
	set, err := readLocal(dir)
	if err != nil {
		return SyncResult{}, l.refuse(old, &SyncError{Code: CodeReadFailed, Err: err})
	}
	if set.text == old.text {
		l.mu.Lock()
		l.lastErr = ""
		l.mu.Unlock()
		return SyncResult{Rules: len(set.rules), Unchanged: true}, nil
	}
	reg := l.reg
	state := reg.State(rules.RepoLocal)
	if state != rules.StateOff {
		disabled := reg.removeIDs(rules.RepoLocal, l.idsOf(set))
		if _, err := reg.o.Composer.Rebuild(func(cfg *waf.Config) { cfg.LocalRules, cfg.LocalRemove = set.text, disabled }); err != nil {
			code := CodeCompileFailed
			if errors.Is(err, ErrIDRange) {
				code = CodeIDRange
			}
			return SyncResult{}, l.refuse(old, &SyncError{Code: code, Err: err})
		}
	} else if err := CheckRanges(waf.Config{LocalRules: set.text}); err != nil {
		return SyncResult{}, l.refuse(old, &SyncError{Code: CodeIDRange, Err: err})
	}
	now := reg.now()
	l.mu.Lock()
	l.set, l.loaded, l.lastReload, l.lastErr = set, true, now, ""
	l.mu.Unlock()
	if reg.o.OnLocal != nil {
		reg.o.OnLocal(set.text)
	}
	added, removed := diffIDs(old.rules, set.rules)
	reg.emitUpdated(now, events.RepositoryUpdated{Repository: rules.RepoLocal, Outcome: "reloaded", RulesLoaded: len(set.rules)}, added, nil, removed,
		"local rules reloaded")
	return SyncResult{Rules: len(set.rules)}, nil
}

func (l *localRepo) idsOf(set localSet) map[int]bool {
	m := make(map[int]bool, len(set.rules))
	for _, r := range set.rules {
		m[r.id] = true
	}
	return m
}

// refuse notes a refused sync and writes its event.
func (l *localRepo) refuse(old localSet, e *SyncError) error {
	l.mu.Lock()
	l.lastErr = e.Error()
	if len(l.lastErr) > 512 {
		l.lastErr = l.lastErr[:512]
	}
	l.mu.Unlock()
	l.reg.emitUpdated(l.reg.now(), events.RepositoryUpdated{Repository: rules.RepoLocal, Outcome: "refused", Code: e.Code, RulesLoaded: len(old.rules)},
		nil, nil, nil, "local rules refused: "+e.Code)
	return e
}

func diffIDs(old, cur []localRule) (added, removed []string) {
	was := map[int]bool{}
	for _, r := range old {
		was[r.id] = true
	}
	is := map[int]bool{}
	for _, r := range cur {
		is[r.id] = true
		if !was[r.id] {
			added = append(added, strconv.Itoa(r.id))
		}
	}
	for _, r := range old {
		if !is[r.id] {
			removed = append(removed, strconv.Itoa(r.id))
		}
	}
	return added, removed
}

// emitUpdated writes schild.rule.repository_updated.v1 with lists of at most
// 100 entries.
func (r *Registry) emitUpdated(now time.Time, ev events.RepositoryUpdated, added, changed, removed []string, summary string) {
	if r.o.Events == nil {
		return
	}
	cut := func(x []string) []string {
		if len(x) > 100 {
			ev.Truncated = true
			return x[:100]
		}
		return x
	}
	ev.Added, ev.Changed, ev.Removed = cut(added), cut(changed), cut(removed)
	r.o.Events.Emit(events.RuleRepositoryUpdated, now, ev, eventlog.Index{Summary: summary})
}
