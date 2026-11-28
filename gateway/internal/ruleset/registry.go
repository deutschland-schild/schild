package ruleset

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/metrics"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// Settings is where the state of a repository lives: schild.yaml and the
// settings overlay of the app.
type Settings interface {
	// Config is the effective configuration, overlay included.
	Config() *config.Site
	// RuleState returns the state in schild.yaml ("" when absent), the
	// overlay value ("" when none) and who set it.
	RuleState(repository string) (base, overlay string, owner Owner)
	// SetRuleState writes the overlay value (or drops it with reset) and its
	// owner, validates the result like schild.yaml and makes it effective.
	SetRuleState(ctx context.Context, repository, state string, reset bool, owner Owner) error
	// CRSSettings returns paranoia level and blocking threshold of
	// schild.yaml (zero when absent).
	CRSSettings() CRSSettings
	// SetCRSSettings replaces the overlay values of rules.crs (zero drops
	// one), validates the result like schild.yaml and makes it effective.
	SetCRSSettings(ctx context.Context, s CRSSettings) error
}

// Options of a Registry.
type Options struct {
	Store    *store.Store
	Composer *Composer
	Settings Settings
	Events   *eventlog.Log
	Log      *slog.Logger
	Metrics  *metrics.Metrics
	Now      func() time.Time
	// Mode is the gateway mode of the rule lists.
	Mode func() string
	// Hits are the rule hits of the last 24 h by rule id and the requests
	// of that window.
	Hits       func(now time.Time) (map[string]int64, int64)
	CRSVersion string
	// OnLocal is called with the text of rules.d after a sync changed it.
	OnLocal func(text string)
	// Hub are the options of the crowdsec source; Store, Config, Events,
	// Log, Now, Builder and Decisions are set here.
	Hub hub.Options
}

// Registry holds the repositories, answers what a rule does now and is the
// one write path of states, syncs, resets and decisions, for the dashboard
// and the agent API alike.
type Registry struct {
	o        Options
	crs      *crsRepo
	crowdsec *crowdsecRepo
	local    *localRepo
	repos    []Repository

	mu        sync.Mutex
	decisions map[string]map[string]store.RuleDecision // repository/rule -> kind
	// opMu serialises the writes of the APIs.
	opMu sync.Mutex
}

// New loads the decisions and the repositories. rules.d is read here: a file
// that cannot be read stops the start.
func New(ctx context.Context, o Options) (*Registry, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Mode == nil {
		o.Mode = func() string { return o.Settings.Config().Mode }
	}
	r := &Registry{o: o, decisions: map[string]map[string]store.RuleDecision{}}
	ds, err := o.Store.RuleDecisions(ctx)
	if err != nil {
		return nil, fmt.Errorf("rule decisions: %w", err)
	}
	for _, d := range ds {
		if d.Kind == store.DecisionDisabled { // D89: approvals stored before mean nothing
			r.setDecision(d)
		}
	}
	r.crs = &crsRepo{reg: r, version: o.CRSVersion}
	r.local = &localRepo{reg: r}
	if err := r.local.load(); err != nil {
		return nil, err
	}
	ho := o.Hub
	ho.Store, ho.Config, ho.Events, ho.Log, ho.Now = o.Store, o.Settings.Config, o.Events, o.Log, o.Now
	ho.Builder, ho.Decisions = o.Composer.HubBuilder(), crowdsecDecisions{r}
	r.crowdsec = &crowdsecRepo{reg: r, src: hub.New(ho)}
	r.repos = []Repository{r.crs, r.crowdsec, r.local}
	return r, nil
}

// Hub is the source of the repository crowdsec.
func (r *Registry) Hub() *hub.Source { return r.crowdsec.src }

func (r *Registry) cfg() *config.Site    { return r.o.Settings.Config() }
func (r *Registry) now() time.Time       { return r.o.Now().UTC().Truncate(time.Second) }
func (r *Registry) log() *slog.Logger    { return r.o.Log }
func key(repository, rule string) string { return repository + "\x00" + rule }
func (r *Registry) repo(id string) Repository {
	for _, x := range r.repos {
		if x.ID() == id {
			return x
		}
	}
	return nil
}

// State is the effective state of a repository.
func (r *Registry) State(repository string) string { return r.cfg().Rules.State(repository) }

// Prepare puts crs and local into the first build and chooses the crowdsec
// set; Start builds. A start never fails because of crowdsec.
func (r *Registry) Prepare(ctx context.Context) {
	r.o.Composer.Init(func(cfg *waf.Config) {
		r.crs.Apply(cfg, r.State(rules.RepoCRS), r.removeIDs(rules.RepoCRS, nil))
		set := r.local.current()
		r.local.Apply(cfg, r.State(rules.RepoLocal), r.removeIDs(rules.RepoLocal, r.local.idsOf(set)))
	})
	r.crowdsec.src.Prepare(ctx)
}

// Start builds the first WAF.
func (r *Registry) Start() error {
	if err := r.o.Composer.Start(); err != nil {
		return err
	}
	r.crowdsec.src.AfterStart()
	return nil
}

// Run updates the crowdsec rules until ctx ends.
func (r *Registry) Run(ctx context.Context) { r.crowdsec.src.Run(ctx) }

// LocalText is the text of the running local rules.
func (r *Registry) LocalText() string { return r.local.current().text }

// LocalRules counts the local rules.
func (r *Registry) LocalRules() int { return len(r.local.current().rules) }

// ---------------------------------------------------------------- decisions

func (r *Registry) setDecision(d store.RuleDecision) {
	k := key(d.Repository, d.Rule)
	m := r.decisions[k]
	if m == nil {
		m = map[string]store.RuleDecision{}
		r.decisions[k] = m
	}
	m[d.Kind] = d
}

func (r *Registry) dropDecision(repository, rule, kind string) {
	if m := r.decisions[key(repository, rule)]; m != nil {
		delete(m, kind)
	}
}

func (r *Registry) decision(repository, rule, kind string) (store.RuleDecision, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.decisions[key(repository, rule)][kind]
	return d, ok
}

// disabledBy says whether a person or an agent disabled the rule.
func (r *Registry) disabledBy(repository, rule string) (string, bool) {
	d, ok := r.decision(repository, rule, store.DecisionDisabled)
	return d.By, ok
}

// crowdsecDecisions are the decisions as internal/hub reads them.
type crowdsecDecisions struct{ r *Registry }

func (c crowdsecDecisions) Disabled(rule string) (string, bool) {
	return c.r.disabledBy(rules.RepoCrowdsec, rule)
}

// configDisabled are the disabled_rules of schild.yaml.
func (r *Registry) configDisabled(repository string) map[string]bool {
	list := r.cfg().Rules.Disabled(repository)
	m := make(map[string]bool, len(list))
	for _, x := range list {
		m[x] = true
	}
	return m
}

// removeIDs are the disabled rules of crs or local as SecRule ids, those of
// present only when present is not nil.
func (r *Registry) removeIDs(repository string, present map[int]bool) []int {
	set := map[int]bool{}
	for id := range r.configDisabled(repository) {
		if n, err := strconv.Atoi(id); err == nil {
			set[n] = true
		}
	}
	r.mu.Lock()
	prefix := repository + "\x00"
	for k, m := range r.decisions {
		if rule, ok := strings.CutPrefix(k, prefix); ok {
			if _, dis := m[store.DecisionDisabled]; dis {
				if n, err := strconv.Atoi(rule); err == nil {
					set[n] = true
				}
			}
		}
	}
	r.mu.Unlock()
	var out []int
	for id := range set {
		if present == nil || present[id] {
			out = append(out, id)
		}
	}
	sort.Ints(out)
	return out
}

// facts are the facts of contract/rules for one rule: crowdsec brings its
// own, crs and local get the decisions here.
func (r *Registry) facts(repository string, e Entry) rules.Input {
	in := e.Input
	if repository == rules.RepoCrowdsec {
		return in
	}
	switch by, ok := r.disabledBy(repository, e.ID); {
	case r.configDisabled(repository)[e.ID]:
		in.Disabled, in.DisabledBy = true, rules.ByConfig
	case ok:
		in.Disabled, in.DisabledBy = true, by
	}
	return in
}

// ---------------------------------------------------------------- request path

// Effect says what a matched rule does right now: the one per-request lookup
// of the gate (contract/rules). For crs and local the rule is the
// repository's: their disabled rules are not in the WAF. For crowdsec id is
// the base id. An atomic read and a pure function, nothing else.
func (r *Registry) Effect(repository string, id int, mode string, now time.Time) rules.Rule {
	var in rules.Input
	switch repository {
	case rules.RepoCRS:
		in = rules.Input{Origin: rules.OriginRelease}
	case rules.RepoLocal:
		in = rules.Input{Origin: rules.OriginOperator}
	case rules.RepoCrowdsec:
		in = r.crowdsec.src.Lookup(id)
	default:
		return rules.Rule{Status: rules.StatusActive, Effect: rules.EffectDetect}
	}
	in.Mode, in.State, in.Now = mode, r.State(repository), now.Unix()
	return rules.Compute(in)
}

// ---------------------------------------------------------------- reads

func (r *Registry) rule(repository string, e Entry, mode string, now time.Time, hits map[string]int64, total int64) Rule {
	in := r.facts(repository, e)
	in.Mode, in.State, in.Now = mode, r.State(repository), now.Unix()
	c := rules.Compute(in)
	return Rule{Repository: repository, ID: e.ID, Name: e.Name, Msg: e.Msg, Version: e.Version, Origin: in.Origin, Status: c.Status, Effect: c.Effect,
		LimitedBy: c.LimitedBy, DisabledBy: c.DisabledBy, Hits24h: hits[e.ID], MatchShare24h: share(hits[e.ID], total), ParanoiaLevel: e.Paranoia,
		Crowdsec: e.Crowdsec}
}

func share(hits, total int64) *float64 {
	if total <= 0 {
		return nil
	}
	v := math.Round(float64(hits)/float64(total)*1e6) / 1e6
	return &v
}

func (r *Registry) hits(now time.Time) (map[string]int64, int64) {
	if r.o.Hits == nil {
		return map[string]int64{}, 0
	}
	return r.o.Hits(now)
}

// view builds the RuleRepository of one repository.
func (r *Registry) view(repo Repository, mode string, now time.Time) RepositoryView {
	id := repo.ID()
	base, overlay, owner := r.o.Settings.RuleState(id)
	st, src := rules.EffectiveState(id, base, overlay, owner.By)
	sw := rules.ApplySwitch(id, base, overlay, owner.By, "", owner.By, false)
	cs := base
	if cs == "" {
		cs = rules.DefaultState(id)
	}
	v := RepositoryView{ID: id, State: st, ConfigState: cs, StateSource: src, Differs: sw.Differs}
	if overlay != "" && owner.At != "" {
		at := owner.At
		v.StateSetAt = &at
	}
	if src == rules.ByAgent {
		v.StateSetBy = &TokenRef{TokenID: owner.TokenID, Label: owner.Label}
	}
	e := rules.EffectOfRepository(st, mode)
	v.Effect, v.LimitedBy = e.Effect, e.LimitedBy
	repo.Describe(&v, st)
	for _, x := range repo.Rules() {
		in := r.facts(id, x)
		in.Mode, in.State, in.Now = mode, st, now.Unix()
		v.Counts.Rules++
		switch rules.Compute(in).Status {
		case rules.StatusDisabled:
			v.Counts.Disabled++
		case rules.StatusSettling:
			v.Counts.Settling++
		}
	}
	return v
}

// Repositories lists every repository: crs, crowdsec, local.
func (r *Registry) Repositories() RepositoryList {
	mode, now := r.o.Mode(), r.now()
	out := RepositoryList{Items: make([]RepositoryView, 0, len(r.repos))}
	for _, x := range r.repos {
		out.Items = append(out.Items, r.view(x, mode, now))
	}
	return out
}

// Repository returns one repository.
func (r *Registry) Repository(id string) (RepositoryView, error) {
	x := r.repo(id)
	if x == nil {
		return RepositoryView{}, ErrNotFound
	}
	return r.view(x, r.o.Mode(), r.now()), nil
}

// Filter of the rule list.
type Filter struct {
	Repository string
	Status     string
}

var repoOrder = map[string]int{rules.RepoCRS: 0, rules.RepoCrowdsec: 1, rules.RepoLocal: 2}

// Rules lists every rule of every repository: rules with hits first, then by
// repository and id.
func (r *Registry) Rules(f Filter) []Rule {
	mode, now := r.o.Mode(), r.now()
	hits, total := r.hits(now)
	var out []Rule
	for _, x := range r.repos {
		if f.Repository != "" && x.ID() != f.Repository {
			continue
		}
		for _, e := range x.Rules() {
			rl := r.rule(x.ID(), e, mode, now, hits, total)
			if f.Status == "" || rl.Status == f.Status {
				out = append(out, rl)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Hits24h != b.Hits24h {
			return a.Hits24h > b.Hits24h
		}
		if a.Repository != b.Repository {
			return repoOrder[a.Repository] < repoOrder[b.Repository]
		}
		x, _ := strconv.Atoi(a.ID)
		y, _ := strconv.Atoi(b.ID)
		return x < y
	})
	return out
}

func (r *Registry) entry(repository, id string) (Entry, bool) {
	x := r.repo(repository)
	if x == nil {
		return Entry{}, false
	}
	for _, e := range x.Rules() {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// HasRule reports whether a repository has the rule.
func (r *Registry) HasRule(repository, id string) bool {
	_, ok := r.entry(repository, id)
	return ok
}

// Rule returns one rule with its SecLang and the decisions on it.
func (r *Registry) Rule(repository, id string) (RuleDetail, error) {
	e, ok := r.entry(repository, id)
	if !ok {
		return RuleDetail{}, ErrNotFound
	}
	now := r.now()
	hits, total := r.hits(now)
	d := RuleDetail{Rule: r.rule(repository, e, r.o.Mode(), now, hits, total), SecLang: e.SecLang, File: e.File}
	if repository == rules.RepoCrowdsec && r.configDisabled(repository)[e.Name] || repository != rules.RepoCrowdsec && r.configDisabled(repository)[id] {
		d.Decisions = append(d.Decisions, Decision{Kind: store.DecisionDisabled, By: rules.ByConfig})
	}
	for _, k := range []string{store.DecisionDisabled} {
		if x, ok := r.decision(repository, id, k); ok {
			dec := Decision{Kind: k, Version: x.Version, By: x.By, Note: x.Note, At: msg.FormatTime(x.At)}
			if x.By == rules.ByAgent {
				dec.Token = &TokenRef{TokenID: x.TokenID, Label: x.TokenLabel}
			}
			if k == store.DecisionDisabled && len(d.Decisions) > 0 {
				continue // schild.yaml decides
			}
			d.Decisions = append(d.Decisions, dec)
		}
	}
	return d, nil
}

// ---------------------------------------------------------------- writes

// SetState sets the state of a repository, or drops the value set in the
// dashboard or through the agent API with reset. No password on any
// transition. off against the others rebuilds the WAF; detect against block
// changes only the decision.
func (r *Registry) SetState(ctx context.Context, id, state string, reset bool, a Actor) (RepositoryView, error) {
	x := r.repo(id)
	if x == nil {
		return RepositoryView{}, ErrNotFound
	}
	if !reset && state != rules.StateOff && state != rules.StateDetect && state != rules.StateBlock {
		return RepositoryView{}, ErrInvalid
	}
	r.opMu.Lock()
	defer r.opMu.Unlock()
	base, overlay, owner := r.o.Settings.RuleState(id)
	before, _ := rules.EffectiveState(id, base, overlay, owner.By)
	sw := rules.ApplySwitch(id, base, overlay, owner.By, state, a.Kind, reset)
	now := r.now()
	o := Owner{}
	if !reset {
		o = Owner{By: a.Kind, At: msg.FormatTime(now), TokenID: a.TokenID, Label: a.Label}
	}
	if err := r.o.Settings.SetRuleState(ctx, id, state, reset, o); err != nil {
		return RepositoryView{}, err
	}
	if sw.Changed {
		r.log().Info("rule repository state changed", "repository", id, "from", before, "to", sw.State, "actor", a.Kind, "token", a.TokenID)
		ev := events.RepositorySwitched{Repository: id, From: before, To: sw.State, Actor: a.Kind, StateSource: sw.Source, Reset: reset}
		if a.Kind == rules.ByAgent {
			ev.TokenID, ev.TokenLabel = a.TokenID, a.Label
		}
		if r.o.Events != nil {
			r.o.Events.Emit(events.RuleRepositorySwitched, now, ev, eventlog.Index{Summary: id + " rules " + before + " to " + sw.State})
		}
	}
	// The state stands; a rebuild that fails leaves the running rules until
	// the next change.
	switch id {
	case rules.RepoCrowdsec:
		if err := r.crowdsec.src.SetState(ctx, sw.Rebuild); err != nil {
			r.log().Error("crowdsec state: WAF not rebuilt", "state", sw.State, "err", err)
		}
	default:
		if sw.Rebuild {
			if err := r.rebuild(id); err != nil {
				r.log().Error("rule repository state: WAF not rebuilt", "repository", id, "state", sw.State, "err", err)
			}
		}
	}
	return r.view(x, r.o.Mode(), r.now()), nil
}

// SetCRSSettings sets the paranoia level and the blocking threshold of the
// CRS from the dashboard (D101). The values replace what was set before, a
// zero falls back to schild.yaml or the built-in default. A change builds the
// WAF again next to the running one; a build that fails leaves the running
// rules until the next change, as for a state.
func (r *Registry) SetCRSSettings(ctx context.Context, id string, s CRSSettings) (RepositoryView, error) {
	x := r.repo(id)
	if x == nil {
		return RepositoryView{}, ErrNotFound
	}
	if id != rules.RepoCRS {
		return RepositoryView{}, ErrNotSupported
	}
	r.opMu.Lock()
	defer r.opMu.Unlock()
	before := r.cfg().Rules.CRS
	if err := r.o.Settings.SetCRSSettings(ctx, s); err != nil {
		return RepositoryView{}, err
	}
	after := r.cfg().Rules.CRS
	if before.ParanoiaLevel != after.ParanoiaLevel || before.InboundAnomalyThreshold != after.InboundAnomalyThreshold {
		r.log().Info("CRS settings changed in the dashboard", "paranoia_level", after.ParanoiaLevel, "inbound_anomaly_threshold", after.InboundAnomalyThreshold,
			"paranoia_level_before", before.ParanoiaLevel, "inbound_anomaly_threshold_before", before.InboundAnomalyThreshold)
		if r.State(id) != rules.StateOff {
			if err := r.rebuild(id); err != nil {
				r.log().Error("CRS settings: WAF not rebuilt", "err", err)
			}
		}
	}
	return r.view(x, r.o.Mode(), r.now()), nil
}

// Reload takes what another node of the group changed (MVP-27): the
// disabled rules from the store and the states and CRS settings of the
// configuration, and builds the rules again. A build that fails leaves the
// running rules.
func (r *Registry) Reload(ctx context.Context) error {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	ds, err := r.o.Store.RuleDecisions(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.decisions = map[string]map[string]store.RuleDecision{}
	for _, d := range ds {
		if d.Kind == store.DecisionDisabled {
			r.setDecision(d)
		}
	}
	r.mu.Unlock()
	var first error
	for _, id := range []string{rules.RepoCRS, rules.RepoLocal} {
		if err := r.rebuild(id); err != nil && first == nil {
			first = err
		}
	}
	if err := r.crowdsec.src.SetState(ctx, true); err != nil && first == nil {
		first = err
	}
	return first
}

// rebuild builds crs or local again with their state and disabled rules.
func (r *Registry) rebuild(id string) error {
	state := r.State(id)
	var change func(*waf.Config)
	switch id {
	case rules.RepoCRS:
		disabled := r.removeIDs(id, nil)
		change = func(cfg *waf.Config) { r.crs.Apply(cfg, state, disabled) }
	case rules.RepoLocal:
		set := r.local.current()
		disabled := r.removeIDs(id, r.local.idsOf(set))
		change = func(cfg *waf.Config) { r.local.Apply(cfg, state, disabled) }
	default:
		return nil
	}
	_, err := r.o.Composer.Rebuild(change)
	return err
}

// Sync loads what the repository's source has now: crowdsec checks the hub,
// local reads rules.d. crs: ErrNotSupported.
func (r *Registry) Sync(ctx context.Context, id string) (SyncResult, error) {
	x := r.repo(id)
	if x == nil {
		return SyncResult{}, ErrNotFound
	}
	return x.Sync(ctx)
}

// Reset goes back to what the image shipped: crowdsec only.
func (r *Registry) Reset(ctx context.Context, id string) error {
	x := r.repo(id)
	if x == nil {
		return ErrNotFound
	}
	return x.Reset(ctx)
}

// SetDisabled disables or enables one rule. crs and local are rebuilt
// without it before this returns; a crowdsec rule stops at once. A rule
// disabled in schild.yaml cannot be enabled here (ErrConfigLimit). Asking for
// what is already so changes nothing and writes no event.
func (r *Registry) SetDisabled(ctx context.Context, repository, id string, disabled bool, note string, a Actor) (RuleDetail, error) {
	e, ok := r.entry(repository, id)
	if !ok {
		return RuleDetail{}, ErrNotFound
	}
	r.opMu.Lock()
	defer r.opMu.Unlock()
	in := r.facts(repository, e)
	now := r.now()
	switch {
	case disabled == in.Disabled:
		return r.Rule(repository, id)
	case !disabled && in.DisabledBy == rules.ByConfig:
		return RuleDetail{}, ErrConfigLimit
	}
	d := store.RuleDecision{Repository: repository, Rule: id, Kind: store.DecisionDisabled, By: a.Kind, TokenID: a.TokenID, TokenLabel: a.Label, Note: note, At: now}
	old, had := r.decision(repository, id, store.DecisionDisabled)
	// The decision is stored once the WAF is built with it: a change that
	// fails is stored nowhere, so whoever listens to the store (the audit
	// log) hears of a change that stands and of no other.
	inMemory := func(on bool, d store.RuleDecision) {
		r.mu.Lock()
		if on {
			r.setDecision(d)
		} else {
			r.dropDecision(repository, id, store.DecisionDisabled)
		}
		r.mu.Unlock()
	}
	apply := func() error {
		if repository == rules.RepoCrowdsec {
			r.crowdsec.src.Refresh()
			return nil
		}
		return r.rebuild(repository)
	}
	inMemory(disabled, d)
	if err := apply(); err != nil {
		// The WAF did not build: take the decision back.
		inMemory(had, old)
		return RuleDetail{}, err
	}
	var err error
	if disabled {
		err = r.o.Store.PutRuleDecision(ctx, d)
	} else {
		err = r.o.Store.DeleteRuleDecision(ctx, repository, id, store.DecisionDisabled)
	}
	if err != nil {
		inMemory(had, old)
		if berr := apply(); berr != nil {
			return RuleDetail{}, errors.Join(err, berr)
		}
		return RuleDetail{}, err
	}
	typ, verb := events.RuleEnabled, "enabled"
	if disabled {
		typ, verb = events.RuleDisabled, "disabled"
	}
	ev := events.RuleDisabledChange{Repository: repository, Rule: id, Name: e.Name, Actor: a.Kind, Note: note}
	if a.Kind == rules.ByAgent {
		ev.TokenID, ev.TokenLabel = a.TokenID, a.Label
	}
	r.log().Info("rule "+verb, "repository", repository, "rule", id, "actor", a.Kind, "token", a.TokenID)
	if r.o.Events != nil {
		r.o.Events.Emit(typ, now, ev, eventlog.Index{Summary: repository + " rule " + id + " " + verb})
	}
	return r.Rule(repository, id)
}
