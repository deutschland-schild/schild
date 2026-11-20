// Package hub runs the public CrowdSec Hub rules of the rule repository
// crowdsec (D39, D73, contracts/crowdsec-hub.md): which set loads, the hourly
// update, the reset to the image snapshot and the per-rule facts the effect
// needs (origin, settling, decisions). The rules themselves are
// contract/crowdsec, the effect is contract/rules, the repository around it is
// internal/ruleset.
//
// No account, no Central API, no IP lists, nothing is sent to CrowdSec: one
// public file is fetched, and the only thing its host learns is the address of
// the server. Nothing here runs on a request path except Lookup, an atomic
// read. A failed, slow or hostile update never touches the running rules, and
// a start never fails because of this source.
package hub

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/events"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/eventlog"
	"github.com/deutschland-schild/schild/gateway/internal/store"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// Store rows next to crowdsec.StoreKey. The row of the dashboard's disabled
// rules (D39) is gone: decisions live in the rule_decisions table (D73).
const statusKey = "crowdsec_hub_status_v1"

// maxListItems is the cap of the event and API schemas.
const maxListItems = 16

//go:embed snapshot.json
var imageSnapshot []byte

// ErrNoSnapshot: Reset has no image snapshot to go back to.
var ErrNoSnapshot = errors.New("hub: no image snapshot")

// Builder puts hub rules into the running WAF (the composer of
// internal/ruleset). PrepareHub runs outside every lock of the request path.
type Builder interface {
	SetHub(hub []waf.HubRule)
	HubLoaded() int
	PrepareHub(hub []waf.HubRule) (*waf.Instance, uint64, error)
	CommitHub(inst *waf.Instance, gen uint64, hub []waf.HubRule) bool
}

// Options of a Source.
type Options struct {
	Store   *store.Store
	Builder Builder
	Config  func() *config.Site
	Events  *eventlog.Log
	Log     *slog.Logger
	Now     func() time.Time
	// Decisions are the decisions of people and agents on single rules
	// (internal/ruleset); nil: none.
	Decisions Decisions
	// Image is the snapshot of the image (nil: the embedded one).
	Image []byte
	// Tests only.
	Client         *http.Client
	CompileTimeout time.Duration
	Check          func([]waf.HubRule) error
	// Cost measures a candidate against the snapshot (nil: waf.MeasureHubCost).
	Cost func(ctx context.Context, reference, candidate []waf.HubRule) (crowdsec.CostSample, error)
}

// Decisions are the disabled rules of the repository crowdsec, by base id as
// a string.
type Decisions interface {
	// Disabled says whether a person or an agent disabled the rule, and who.
	Disabled(rule string) (by string, ok bool)
}

// Refusal is the last refused update.
type Refusal struct {
	At   string `json:"at"`
	Code string `json:"code"`
}

// Change counts the last change of the running set.
type Change struct {
	Added   int `json:"added"`
	Changed int `json:"changed"`
	Removed int `json:"removed"`
}

// RuleView is the CrowdsecRule of both APIs.
type RuleView struct {
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Licence       string   `json:"licence"`
	Label         string   `json:"label,omitempty"`
	Description   string   `json:"description,omitempty"`
	CVEs          []string `json:"cves,omitempty"`
	CWEs          []string `json:"cwes,omitempty"`
	Attack        []string `json:"attack,omitempty"`
	Notes         []string `json:"notes,omitempty"`
	FirstSeen     string   `json:"first_seen,omitempty"`
	ChangedAt     string   `json:"changed_at,omitempty"`
	SettlingUntil *string  `json:"settling_until,omitempty"`
}

// Rule is one loaded rule for the rule lists.
type Rule struct {
	BaseID int
	Msg    string
	View   RuleView
	// Facts of contract/rules: origin, the decisions and settling. Mode and
	// state are the caller's.
	Input rules.Input
	// SecLang of every group, for the detail.
	SecLang []string
}

// Info is the crowdsec object of a RuleRepository in both APIs.
type Info struct {
	UpdateState     string                 `json:"update_state"`
	AutoUpdate      bool                   `json:"auto_update"`
	IntervalS       int                    `json:"interval_s,omitempty"`
	Pin             string                 `json:"pin,omitempty"`
	SettlingS       int                    `json:"settling_s"`
	SetSource       string                 `json:"set_source"`
	Skipped         []crowdsec.SkippedRule `json:"skipped"`
	IndexSHA256     string                 `json:"index_sha256,omitempty"`
	HubCommit       string                 `json:"hub_commit,omitempty"`
	LastCheckAt     *string                `json:"last_check_at,omitempty"`
	LastChange      *Change                `json:"last_change,omitempty"`
	LastRefusal     *Refusal               `json:"last_refusal,omitempty"`
	SnapshotAt      *string                `json:"snapshot_at,omitempty"`
	SnapshotAgeDays *int                   `json:"snapshot_age_days,omitempty"`
}

// Summary is what the shared fields of the repository need from the source.
type Summary struct {
	Info         Info
	Loaded       int
	Skipped      int
	LastChangeAt *string
}

// loaded is a set that runs or could run. The hub items are not kept: every
// load converts them again, and an update reads them from the new index.
type loaded struct {
	source      string // crowdsec.SetStored | SetImage
	etag        string
	indexDigest string
	commit      string
	fetchedAt   string
	notSelected int
	rules       []crowdsec.SetRule
	skipped     []crowdsec.SkippedRule
	extra       []crowdsec.SkippedRule // skipped before the set was written
}

// storedRow is the row crowdsec.StoreKey: the set with the ETag beside it.
// IndexSkipped lists what cannot be part of a set (a digest that does not fit,
// a deprecated version), so a restart still shows it. CostChecked says the set
// passed the measured cost check (D43); a row without it does not load.
type storedRow struct {
	Set          json.RawMessage        `json:"set"`
	ETag         string                 `json:"etag,omitempty"`
	IndexSkipped []crowdsec.SkippedRule `json:"index_skipped,omitempty"`
	CostChecked  bool                   `json:"cost_checked,omitempty"`
}

// persisted is the row statusKey: what a restart must not forget.
type persisted struct {
	LastCheck  string   `json:"last_check,omitempty"`
	LastChange string   `json:"last_change,omitempty"`
	Change     *Change  `json:"change,omitempty"`
	Refusal    *Refusal `json:"refusal,omitempty"`
	Failing    bool     `json:"failing,omitempty"` // the last check was refused
}

// view is the immutable state the request path reads: the facts of every
// loaded rule (contract/rules, without mode and state).
type view struct {
	rules map[int]rules.Input
}

// Source is the CrowdSec Hub rule source.
type Source struct {
	o       Options
	v       atomic.Pointer[view]
	sem     chan struct{} // one build at a time, also an abandoned one
	wake    chan struct{}
	timeout time.Duration
	check   func([]waf.HubRule) error
	cost    func(ctx context.Context, reference, candidate []waf.HubRule) (crowdsec.CostSample, error)
	img     *crowdsec.Set

	// imgOnce loads imgSet: what the image snapshot runs, the mark of the
	// shrink and cost checks. Nil without a valid snapshot.
	imgOnce sync.Once
	imgSet  *loaded
	// release are the name and version of every item of the image snapshot:
	// these rules have origin release, everything else came as an update.
	release map[string]string

	// opMu serialises what changes the running set: updates and the switch.
	opMu sync.Mutex
	// mu guards the fields below; never held across a build or a fetch.
	mu   sync.Mutex
	cur  *loaded
	st   persisted
	seen map[int]bool // base ids loaded in this process
}

// New returns a source. Call Prepare before the first WAF build.
func New(o Options) *Source {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Image == nil {
		o.Image = imageSnapshot
	}
	s := &Source{o: o, sem: make(chan struct{}, 1), wake: make(chan struct{}, 1), timeout: o.CompileTimeout, check: o.Check,
		seen: map[int]bool{}, release: map[string]string{}}
	if s.timeout <= 0 {
		s.timeout = crowdsec.CompileTimeoutS * time.Second
	}
	if s.check == nil {
		s.check = waf.CheckHub
	}
	s.cost = o.Cost
	if s.cost == nil {
		s.cost = func(ctx context.Context, reference, candidate []waf.HubRule) (crowdsec.CostSample, error) {
			return waf.MeasureHubCost(ctx, reference, candidate, crowdsec.CostBudgetS*time.Second)
		}
	}
	return s
}

func (s *Source) cfg() config.CrowdsecRules { return s.o.Config().Rules.Crowdsec }

func (s *Source) now() time.Time { return s.o.Now().UTC().Truncate(time.Second) }

// Prepare restores the state and chooses the set of the first WAF build. It
// logs what goes wrong and never fails.
func (s *Source) Prepare(ctx context.Context) {
	defer func() {
		if v := recover(); v != nil {
			s.o.Log.Error("crowdsec hub: start without rules", "panic", v)
		}
	}()
	if raw, err := s.o.Store.Get(ctx, statusKey); err == nil {
		_ = json.Unmarshal(raw, &s.st)
	}
	s.img = parseImage(s.o.Image)
	if s.img != nil {
		for _, it := range s.img.Rules {
			s.release[it.Name] = it.Version
		}
	}
	l := s.chooseSet(ctx)
	s.setCurrent(l)
	if l != nil {
		s.o.Builder.SetHub(wafRules(l.rules))
		s.o.Log.Info("crowdsec rules", "state", s.cfg().State, "set", l.source, "loaded", len(l.rules), "skipped", len(l.skipped))
	}
}

// AfterStart notes a first WAF build that had to leave the hub rules out.
func (s *Source) AfterStart() {
	if s.running() != nil && s.o.Builder.HubLoaded() == 0 {
		s.setCurrent(nil)
	}
}

func parseImage(raw []byte) *crowdsec.Set {
	if len(raw) == 0 {
		return nil
	}
	set, err := crowdsec.ParseSet(raw)
	if err != nil {
		return nil
	}
	return set
}

// candidate is one set that could load at start.
type candidate struct {
	present bool
	l       *loaded
	commit  string
	time    string // Set.Time
}

func (c candidate) contract() crowdsec.Candidate {
	return crowdsec.Candidate{Present: c.present, Valid: c.l != nil, Commit: c.commit, Time: c.time}
}

// chooseSet decides which set runs. This is the one place of that decision:
// everything about the precedence lives in crowdsec.SelectSet and here.
func (s *Source) chooseSet(ctx context.Context) *loaded {
	cfg := s.cfg()
	if cfg.State == crowdsec.StateOff {
		return nil
	}
	stored, image := s.readStored(ctx), s.readImage()
	switch crowdsec.SelectSet(cfg.State, cfg.Pin, stored.contract(), image.contract(), s.now()).Set {
	case crowdsec.SetStored:
		return stored.l
	case crowdsec.SetImage:
		return image.l
	}
	return nil
}

func (s *Source) readStored(ctx context.Context) candidate {
	raw, err := s.o.Store.Get(ctx, crowdsec.StoreKey)
	if err != nil {
		return candidate{}
	}
	c := candidate{present: true}
	var row storedRow
	if err := json.Unmarshal(raw, &row); err != nil {
		s.o.Log.Warn("crowdsec hub: stored set unreadable, not used", "err", err)
		return c
	}
	set, err := crowdsec.ParseSet(row.Set)
	if err != nil {
		s.o.Log.Warn("crowdsec hub: stored set invalid, not used", "err", err)
		return c
	}
	c.commit, c.time = set.HubCommit, set.Time()
	if !row.CostChecked {
		s.o.Log.Warn("crowdsec hub: stored set has no cost check, not used", "index", set.IndexDigest)
		return c
	}
	c.l = s.load(set, crowdsec.SetStored, row.ETag, row.IndexSkipped)
	if c.l != nil {
		if code := crowdsec.CheckSetBounds(c.l.rules); code != "" {
			s.o.Log.Warn("crowdsec hub: stored set above the bounds, not used", "index", set.IndexDigest, "code", code)
			c.l = nil
		}
	}
	return c
}

func (s *Source) readImage() candidate {
	if s.img == nil {
		return candidate{present: len(s.o.Image) > 0}
	}
	return candidate{present: true, commit: s.img.HubCommit, time: s.img.Time(), l: s.load(s.img, crowdsec.SetImage, "", nil)}
}

// image returns what the image snapshot runs, nil without a valid one. The
// first call converts and compiles it, on an update or a reset, never on a
// request path.
func (s *Source) image() *loaded {
	s.imgOnce.Do(func() {
		if s.img != nil {
			s.imgSet = s.load(s.img, crowdsec.SetImage, "", nil)
		}
	})
	return s.imgSet
}

// load converts a set again (a newer contract applies to an old set) and
// returns nil when no rule of it would run.
func (s *Source) load(set *crowdsec.Set, source, etag string, extra []crowdsec.SkippedRule) *loaded {
	rules := make([]crowdsec.SetRule, 0, len(set.Rules))
	skipped := append([]crowdsec.SkippedRule{}, extra...)
	taken := map[int]bool{}
	for _, it := range set.Rules {
		body, err := base64.StdEncoding.DecodeString(it.Content)
		if err != nil {
			continue
		}
		r, sk := crowdsec.Convert(it.Name, it.Version, it.Digest, body, it.Description)
		if sk != nil {
			skipped = append(skipped, crowdsec.SkippedRule{Name: it.Name, Version: it.Version, Code: sk.Code})
			continue
		}
		if taken[r.BaseID] {
			skipped = append(skipped, crowdsec.SkippedRule{Name: it.Name, Version: it.Version, Code: crowdsec.SkipIDCollision})
			continue
		}
		taken[r.BaseID] = true
		rules = append(rules, crowdsec.SetRule{Rule: *r, FirstSeen: it.FirstSeen, ChangedAt: it.ChangedAt})
	}
	rules, skipped = s.screen(rules, skipped)
	rules, skipped, err := s.compile(rules, skipped)
	if err != nil || len(rules) == 0 {
		s.o.Log.Warn("crowdsec hub: set does not load", "set", source, "index", set.IndexDigest, "err", err)
		return nil
	}
	sortSkipped(skipped)
	return &loaded{source: source, etag: etag, indexDigest: set.IndexDigest, commit: set.HubCommit, fetchedAt: set.FetchedAt,
		notSelected: set.NotSelected, rules: rules, skipped: skipped, extra: extra}
}

func sortSkipped(s []crowdsec.SkippedRule) {
	sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
}

var (
	lineRe = regexp.MustCompile(`^SecRule (\S+) "(.*)" "`)
	rxOpRe = regexp.MustCompile(`^!?@rx (.*)$`)
)

// patterns returns every @rx operator and /regex/ selector of a rule.
func patterns(r *crowdsec.SetRule) []string {
	var out []string
	for _, group := range r.SecLang {
		for _, line := range strings.Split(group, "\n") {
			m := lineRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if rx := rxOpRe.FindStringSubmatch(m[2]); rx != nil {
				out = append(out, rx[1])
			}
			for _, v := range strings.Split(m[1], "|") {
				if _, sel, ok := strings.Cut(v, ":"); ok && len(sel) > 2 && sel[0] == '/' && sel[len(sel)-1] == '/' {
					out = append(out, sel[1:len(sel)-1])
				}
			}
		}
	}
	return out
}

// screen applies what CheckIndex cannot know: the cost of every regex. Local
// rules cannot take a crowdsec id: the composer keeps every repository in its
// own range (D73).
func (s *Source) screen(rules []crowdsec.SetRule, skipped []crowdsec.SkippedRule) ([]crowdsec.SetRule, []crowdsec.SkippedRule) {
	kept := rules[:0:0]
next:
	for i := range rules {
		r := &rules[i]
		for _, p := range patterns(r) {
			if crowdsec.CheckRegexCost(p) != nil {
				skipped = append(skipped, crowdsec.SkippedRule{Name: r.Name, Version: r.Version, Code: crowdsec.SkipRegexCost})
				continue next
			}
		}
		kept = append(kept, *r)
	}
	return kept, skipped
}

// compile checks the rules alone. If the whole set fails, the rules are tried
// one by one, those that fail are skipped, and the rest must compile together.
func (s *Source) compile(rules []crowdsec.SetRule, skipped []crowdsec.SkippedRule) ([]crowdsec.SetRule, []crowdsec.SkippedRule, error) {
	if len(rules) == 0 {
		return rules, skipped, nil
	}
	if s.check(wafRules(rules)) == nil {
		return rules, skipped, nil
	}
	kept := rules[:0:0]
	for _, r := range rules {
		if err := s.check(wafRules([]crowdsec.SetRule{r})); err != nil {
			skipped = append(skipped, crowdsec.SkippedRule{Name: r.Name, Version: r.Version, Code: crowdsec.SkipCompileFailed})
			continue
		}
		kept = append(kept, r)
	}
	if err := s.check(wafRules(kept)); err != nil {
		return nil, skipped, err
	}
	return kept, skipped, nil
}

func clip(x []string) []string {
	if len(x) > maxListItems {
		return x[:maxListItems]
	}
	return x
}

func wafRules(rs []crowdsec.SetRule) []waf.HubRule {
	out := make([]waf.HubRule, len(rs))
	for i := range rs {
		r := &rs[i]
		out[i] = waf.HubRule{Name: r.Name, Version: r.Version, Label: r.Label, CVEs: clip(r.CVEs), BaseID: r.BaseID, Groups: r.SecLang}
	}
	return out
}

func (s *Source) running() *loaded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

func (s *Source) setCurrent(l *loaded) {
	s.mu.Lock()
	s.cur = l
	if l != nil {
		for i := range l.rules {
			s.seen[l.rules[i].BaseID] = true
		}
	}
	s.mu.Unlock()
	s.publish()
}

// publish rebuilds the view of the request path.
func (s *Source) publish() {
	v := &view{rules: map[int]rules.Input{}}
	for _, r := range s.Rules() {
		v.rules[r.BaseID] = r.Input
	}
	s.v.Store(v)
}

func configDisabled(cfg config.CrowdsecRules) map[string]bool {
	m := make(map[string]bool, len(cfg.DisabledRules))
	for _, n := range cfg.DisabledRules {
		m[n] = true
	}
	return m
}

// Lookup returns the facts of a matched rule on the request path: origin,
// decisions and settling (contract/rules without mode and state). A rule that
// left the set while its request was running counts as an update that waits,
// so it never blocks.
func (s *Source) Lookup(baseID int) rules.Input {
	if v := s.v.Load(); v != nil {
		if in, ok := v.rules[baseID]; ok {
			return in
		}
	}
	return rules.Input{Origin: rules.OriginUpdate, SettlingUntil: math.MaxInt64}
}

// IsHub reports whether id is the base id of a rule loaded in this process:
// its hits stay in the 24 h counters after it left the set.
func (s *Source) IsHub(baseID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[baseID]
}

// origin says where a rule comes from: release when its name and version are
// in the image snapshot, else update.
func (s *Source) origin(name, version string) string {
	if v, ok := s.release[name]; ok && v == version {
		return rules.OriginRelease
	}
	return rules.OriginUpdate
}

// Rules lists the loaded rules by base id, with the facts of contract/rules.
func (s *Source) Rules() []Rule {
	cfg := s.cfg()
	conf := configDisabled(cfg)
	settling := int64(0)
	if cfg.SettlingS != nil {
		settling = int64(*cfg.SettlingS)
	}
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if cur == nil {
		return nil
	}
	out := make([]Rule, 0, len(cur.rules))
	for i := range cur.rules {
		r := &cur.rules[i]
		v := RuleView{Name: r.Name, Version: r.Version, Licence: crowdsec.Licence, Label: r.Label, Description: r.Description,
			CVEs: clip(r.CVEs), CWEs: clip(r.CWEs), Attack: clip(r.Attack), Notes: r.Notes, FirstSeen: r.FirstSeen, ChangedAt: r.ChangedAt}
		id := strconv.Itoa(r.BaseID)
		in := rules.Input{Origin: s.origin(r.Name, r.Version)}
		switch by, ok := s.decided(id); {
		case conf[r.Name]:
			in.Disabled, in.DisabledBy = true, rules.ByConfig
		case ok:
			in.Disabled, in.DisabledBy = true, by
		}
		if in.Origin == rules.OriginUpdate {
			if t, err := msg.ParseTime(r.ChangedAt); err == nil && settling > 0 {
				in.SettlingUntil = t.Unix() + settling
				u := msg.FormatTime(t.Add(time.Duration(settling) * time.Second))
				v.SettlingUntil = &u
			}
		}
		out = append(out, Rule{BaseID: r.BaseID, Msg: "crowdsec hub " + r.Name, View: v, Input: in, SecLang: r.SecLang})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BaseID < out[j].BaseID })
	return out
}

func (s *Source) decided(id string) (string, bool) {
	if s.o.Decisions == nil {
		return "", false
	}
	return s.o.Decisions.Disabled(id)
}

// Rule returns one loaded rule.
func (s *Source) Rule(baseID int) (Rule, bool) {
	for _, r := range s.Rules() {
		if r.BaseID == baseID {
			return r, true
		}
	}
	return Rule{}, false
}

// Refresh publishes a changed configuration or decision that needs no
// rebuild.
func (s *Source) Refresh() { s.publish() }

// SetState applies a switch that already went into the configuration (App).
// The state counts at once for the next request; off against detect or block
// also builds a new instance in the background and swaps it. Requests in
// flight keep theirs, detect against block needs no build. Changes in a row
// coalesce: whoever gets the lock looks at the state of now, so one build runs
// at a time and the last state wins.
func (s *Source) SetState(ctx context.Context, rebuild bool) error {
	s.publish()
	if !rebuild {
		return nil
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if s.cfg().State == crowdsec.StateOff {
		if s.running() == nil && s.o.Builder.HubLoaded() == 0 {
			return nil
		}
		if code := s.swap(nil); code != "" {
			return errors.New(code)
		}
		s.setCurrent(nil)
		return nil
	}
	if s.running() != nil {
		return nil
	}
	l := s.chooseSet(ctx)
	if l == nil {
		return nil
	}
	if code := s.swap(wafRules(l.rules)); code != "" {
		return errors.New(code)
	}
	s.setCurrent(l)
	select {
	case s.wake <- struct{}{}: // the set may be old: check soon
	default:
	}
	return nil
}

// Reset goes back to the image snapshot (D43): it drops the stored set and
// runs the snapshot, without a restart. The state of the switch stays. In state
// off only the stored set goes: nothing runs that could be replaced. Without a
// snapshot nothing changes. The operator's way back when a stored set is the
// problem, with or without automatic updates. They go on afterwards, so a
// check is due soon; it passes the same checks as any other.
func (s *Source) Reset(ctx context.Context) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	l := s.image()
	if l == nil {
		return ErrNoSnapshot
	}
	off := s.cfg().State == crowdsec.StateOff
	if !off {
		if code := s.swap(wafRules(l.rules)); code != "" {
			return errors.New(code)
		}
	}
	if err := s.o.Store.Delete(ctx, crowdsec.StoreKey); err != nil {
		s.o.Log.Error("crowdsec hub: stored set not dropped, it may come back at the next restart", "err", err)
	}
	now := s.now()
	ev := events.RepositoryUpdated{Repository: rules.RepoCrowdsec, Outcome: "reset", SetSource: crowdsec.SetNone}
	if !off {
		s.setCurrent(l)
		ev.SetSource, ev.IndexSHA256, ev.HubCommit, ev.RulesLoaded, ev.RulesSkipped = l.source, l.indexDigest, l.commit, len(l.rules), len(l.skipped)
	}
	s.mu.Lock()
	s.st.Failing = false
	s.mu.Unlock()
	s.saveStatus(ctx)
	s.emit(now, ev, nil, nil, nil)
	s.o.Log.Info("crowdsec rules reset to the image snapshot", "state", s.cfg().State, "loaded", ev.RulesLoaded)
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// Summary returns the crowdsec object and the counts of the repository.
// state is its effective state.
func (s *Source) Summary(state string) Summary {
	cfg := s.cfg()
	now := s.now()
	info := Info{SetSource: crowdsec.SetNone, AutoUpdate: *cfg.AutoUpdate, IntervalS: cfg.IntervalS, Pin: cfg.Pin, Skipped: []crowdsec.SkippedRule{}}
	if cfg.SettlingS != nil {
		info.SettlingS = *cfg.SettlingS
	}
	if s.img != nil {
		if t, err := msg.ParseTime(s.img.FetchedAt); err == nil {
			at, days := msg.FormatTime(t), max(0, int(now.Sub(t).Hours()/24))
			info.SnapshotAt, info.SnapshotAgeDays = &at, &days
		}
	}
	var sum Summary
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		l := s.cur
		info.SetSource, info.IndexSHA256, info.HubCommit = l.source, l.indexDigest, l.commit
		sum.Loaded, sum.Skipped = len(l.rules), len(l.skipped)
		if len(l.skipped) > 0 {
			info.Skipped = append(info.Skipped, l.skipped...)
		}
	}
	if s.st.LastCheck != "" {
		v := s.st.LastCheck
		info.LastCheckAt = &v
	}
	if s.st.LastChange != "" {
		v := s.st.LastChange
		sum.LastChangeAt, info.LastChange = &v, s.st.Change
	}
	info.LastRefusal = s.st.Refusal
	switch {
	case state == crowdsec.StateOff:
		info.UpdateState = "off"
	case cfg.Pin != "" && info.HubCommit == cfg.Pin:
		info.UpdateState = "pinned"
	case cfg.Pin != "":
		info.UpdateState = "pin_pending"
	case !*cfg.AutoUpdate:
		info.UpdateState = "updates_off"
	case s.st.Failing && s.st.Refusal != nil && (s.st.Refusal.Code == crowdsec.RefuseFetchFailed || s.st.Refusal.Code == crowdsec.RefuseFetchStatus):
		info.UpdateState = "unreachable"
	case s.st.Failing:
		info.UpdateState = "refused"
	default:
		info.UpdateState = "current"
	}
	sum.Info = info
	return sum
}
