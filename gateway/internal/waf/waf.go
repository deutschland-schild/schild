// Package waf builds Coraza WAF instances from the rules of the three rule
// repositories (D73): the OWASP CRS (embedded via coraza-coreruleset), the
// operator's local rules and the CrowdSec Hub rules, and analyses the matches
// of a transaction. Which rules go in is internal/ruleset's business.
//
// Coraza runs in DetectionOnly mode: every rule is evaluated and recorded,
// and Schild decides afterwards (contract/rules, package decide) what
// happens, per repository and mode. The CRS score is recomputed here from CRS rules only, so
// no other rule can push CRS over its threshold, and hard limits are
// independent of the rule engine mode.
//
// Instances are immutable. A rule change builds a new instance in the
// background and swaps it atomically (Engine.Swap); requests in flight keep
// the instance they started with, so no request is dropped (B07).
package waf

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	coreruleset "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/rules"
)

// Rule id ranges.
const (
	InternalBodyError      = 200002 // REQBODY_ERROR: body could not be parsed
	InternalMultipartError = 200003 // MULTIPART_STRICT_ERROR
	InternalArgsLimitGet   = 200004 // ARGUMENTS_LIMIT_REACHED in phase 1 (query, path)
	InternalArgsLimitPost  = 200005 // ARGUMENTS_LIMIT_REACHED in phase 2 (urlencoded or JSON body)
	InternalURIParseError  = 200009 // URI_PARSE_ERROR
	InternalLivewire       = 200010 // built-in Livewire exception (D52)
	// NetworkMin..NetworkMax stays reserved for the Schild network (D72):
	// no rule of this gateway may use it.
	NetworkMin = 7700000
	NetworkMax = 7799999
	crsMin     = 900000
	crsMax     = 999999
	// Match sources: the repositories, and internal for the built-in rules
	// of the engine (200000..200099).
	SourceCRS      = rules.RepoCRS
	SourceLocal    = rules.RepoLocal
	SourceCrowdsec = rules.RepoCrowdsec
	SourceInternal = "internal"
)

// HubRule is one CrowdSec Hub rule of repository crowdsec loaded into the WAF
// (D39). It is the same for every AND-group: group g has the SecRule id
// BaseID+g.
type HubRule struct {
	Name    string
	Version string
	Label   string   // third-party text
	CVEs    []string // at most the 16 of the event schema
	BaseID  int
	Groups  []string // validated SecLang (contract/crowdsec, hub profile), one per group
}

// Key is the stable id of the rule in rule lists, counters and decision
// sources: the base id, the same for every group, image and update.
func (r *HubRule) Key() string { return strconv.Itoa(r.BaseID) }

// Config of one WAF instance.
type Config struct {
	CRS              bool
	ParanoiaLevel    int
	AnomalyThreshold int
	BodyLimit        int64 // hard limit, enforced by the gate; Coraza gets limit+1
	ArgsLimit        int
	LocalRules       string // operator SecLang (not restricted to the subset)
	Exceptions       string // rule exceptions set by agents (D54), SecLang we rendered
	Livewire         bool   // built-in exception for /livewire/update (D52)
	Hub              []HubRule
	// CRSRemove and LocalRemove are disabled rules of crs and local (D73):
	// SecRuleRemoveById after the rules of their repository.
	CRSRemove   []int
	LocalRemove []int
}

// removeLine renders SecRuleRemoveById for ids ("" for none).
func removeLine(ids []int) string {
	if len(ids) == 0 {
		return ""
	}
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = strconv.Itoa(id)
	}
	return "SecRuleRemoveById " + strings.Join(s, " ") + "\n"
}

// livewireException is the rule of D52. The snapshot is signed by the
// application and holds its state, which a client cannot change without the
// APP_KEY, so CRS skips it. Updates and calls are what a client really sends:
// they keep every rule, a text field needs a local exception for its domain.
var livewireException = fmt.Sprintf(`SecRule REQUEST_FILENAME "@streq /livewire/update" "id:%d,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:/^json\.components\.\d+\.snapshot$/"
`, InternalLivewire)

// Instance is an immutable compiled WAF.
type Instance struct {
	WAF           coraza.WAF
	Config        Config
	Hub           map[int]*HubRule // by SecRule id of every group
	LocalBlocking map[int]bool     // local rule ids with deny/block/drop
	// LocalException: local rule ids that are exceptions, not findings
	// (LocalRuleKind.Exception).
	LocalException map[int]bool
	LocalMsg       map[int]string
	BuiltAt        time.Time
	BuildTime      time.Duration
	Gen            uint64
	cancels        *cancelRegistry
}

var gen atomic.Uint64

// Directives renders the full directive text of an instance (exported for tests and `schild status --rules`).
func Directives(cfg Config) string {
	var b strings.Builder
	limit := cfg.BodyLimit
	if limit <= 0 {
		limit = 13107200
	}
	args := cfg.ArgsLimit
	if args <= 0 {
		args = 1000
	}
	// The body limit of Coraza stays above the gate limit (D41): the gate ends
	// a body at limit+1 bytes with an error, and Coraza's io.CopyN only returns
	// that error while it still wants more bytes. At limit+1 the copy looks
	// finished, and Coraza runs phase 2 itself on the partial body, without a
	// slot, a budget or a cancel.
	// Rules 200002-200009 follow coraza.conf-recommended (v3.8.1). Since
	// Coraza 3.8 arguments beyond SecArgumentsLimit (query, urlencoded and
	// JSON bodies) are dropped and only ARGUMENTS_LIMIT_REACHED is set, so
	// 200004/200005 are required: without them the tail of a long JSON
	// array would never be inspected. The gate maps them to too_many_args.
	// Responses are not inspected: the gate runs phases 1 and 2 only, so the
	// CRS response rules (RESPONSE-95x, data leakage) never match.
	fmt.Fprintf(&b, `SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyNoFilesLimit %d
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
SecArgumentsLimit %d
SecAuditEngine Off
SecRule REQUEST_HEADERS:Content-Type "@rx ^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/[a-z0-9.-]+[+]xml" "id:200007,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/[a-z0-9.-]+[+]json" "id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body',severity:2"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,t:none,log,deny,status:400,msg:'Multipart request body failed strict validation',severity:2"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:200004,phase:1,t:none,log,deny,status:400,msg:'Argument limit reached (query or path)',severity:2"
SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:200005,phase:2,t:none,log,deny,status:400,msg:'Argument limit reached (request body)',severity:2"
SecRule URI_PARSE_ERROR "@eq 1" "id:200009,phase:1,t:none,log,deny,status:400,msg:'Request URI failed to parse',severity:2"
`, limit+2, limit+2, args)
	if cfg.CRS {
		pl := cfg.ParanoiaLevel
		if pl < 1 || pl > 4 {
			pl = 1
		}
		th := cfg.AnomalyThreshold
		if th <= 0 {
			th = 5
		}
		b.WriteString("Include @crs-setup.conf.example\n")
		fmt.Fprintf(&b, "SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d\"\n", pl, pl)
		fmt.Fprintf(&b, "SecAction \"id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4\"\n", th)
		b.WriteString("SecAction \"id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'\"\n")
		if cfg.Livewire {
			b.WriteString(livewireException)
		}
		b.WriteString("Include @owasp_crs/*.conf\n")
		b.WriteString(removeLine(cfg.CRSRemove))
	}
	if strings.TrimSpace(cfg.LocalRules) != "" {
		b.WriteString(cfg.LocalRules)
		b.WriteString("\n")
		b.WriteString(removeLine(cfg.LocalRemove))
	}
	if cfg.Exceptions != "" {
		b.WriteString(cfg.Exceptions)
		b.WriteString("\n")
	}
	for _, r := range cfg.Hub {
		for _, g := range r.Groups {
			b.WriteString(g)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// CheckHub compiles hub rules alone, without the CRS: the check of a set or a
// single rule before it goes near a running instance.
func CheckHub(rs []HubRule) error {
	var b strings.Builder
	b.WriteString("SecRuleEngine DetectionOnly\n")
	for _, r := range rs {
		for _, g := range r.Groups {
			b.WriteString(g)
			b.WriteString("\n")
		}
	}
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDebugLogger(debuglog.Noop()).WithDirectives(b.String()))
	if err != nil {
		return fmt.Errorf("waf: %w", err)
	}
	if c, ok := w.(experimental.WAFCloser); ok {
		_ = c.Close()
	}
	return nil
}

// Build compiles an instance.
func Build(cfg Config) (*Instance, error) {
	start := time.Now()
	inst := &Instance{Config: cfg, Hub: map[int]*HubRule{}, LocalBlocking: map[int]bool{}, LocalException: map[int]bool{}, LocalMsg: map[int]string{}}
	if err := checkEngineSettings(cfg.LocalRules + "\n" + cfg.Exceptions); err != nil {
		return nil, fmt.Errorf("waf: %w", err)
	}
	for id, k := range LocalRuleKinds(cfg.LocalRules + "\n" + cfg.Exceptions) {
		if id >= NetworkMin && id <= NetworkMax {
			return nil, fmt.Errorf("waf: local rule id %d is in the range reserved for the Schild network", id)
		}
		inst.LocalBlocking[id] = k.Blocking
		if k.Exception {
			inst.LocalException[id] = true
		}
	}
	for i := range cfg.Hub {
		r := &cfg.Hub[i]
		for g := range r.Groups {
			id := r.BaseID + g
			if id < contract.HubRuleIDMin || id > contract.HubRuleIDMax {
				return nil, fmt.Errorf("waf: hub rule %s has id %d outside %d..%d", r.Name, id, contract.HubRuleIDMin, contract.HubRuleIDMax)
			}
			if _, dup := inst.Hub[id]; dup {
				return nil, fmt.Errorf("waf: duplicate hub SecRule id %d", id)
			}
			if _, dup := inst.LocalBlocking[id]; dup {
				return nil, fmt.Errorf("waf: hub rule %s uses the id %d of a local rule", r.Name, id)
			}
			inst.Hub[id] = r
		}
	}
	inst.cancels = &cancelRegistry{}
	wc := coraza.NewWAFConfig().WithDebugLogger(cancelLogger{inner: debuglog.Noop(), reg: inst.cancels}).WithDirectives(Directives(cfg))
	if cfg.CRS {
		wc = wc.WithRootFS(coreruleset.FS)
	}
	w, err := coraza.NewWAF(wc)
	if err != nil {
		return nil, fmt.Errorf("waf: %w", err)
	}
	inst.WAF = w
	inst.BuiltAt = time.Now()
	inst.BuildTime = time.Since(start)
	inst.Gen = gen.Add(1)
	return inst, nil
}

var (
	idRe        = regexp.MustCompile(`\bid:'?(\d+)`)
	blockRe     = regexp.MustCompile(`[",]\s*(deny|block|drop)\s*[,"']`)
	chainRe     = regexp.MustCompile(`[",]\s*chain\s*[,"']`)
	exceptionRe = regexp.MustCompile(`\bctl:|[",]\s*allow(:[a-z]+)?\s*[,"']`)
	setvarRe    = regexp.MustCompile(`\bsetvar:'?([^,"']+)`)
)

var (
	engineDirectiveRe = regexp.MustCompile(`(?i)^Sec(RuleEngine|RequestBodyAccess|RequestBodyLimit|RequestBodyNoFilesLimit|RequestBodyInMemoryLimit|RequestBodyLimitAction)\b`)
	includeRe         = regexp.MustCompile(`(?i)^Include\b`)
	engineCtlRe       = regexp.MustCompile(`(?i)\bctl\s*:\s*(ruleEngine|requestBodyAccess|requestBodyLimit)\b`)
)

// checkEngineSettings refuses operator SecLang that takes the rule engine or
// the request body away from schild. The gate forwards the body Coraza has
// buffered: with the engine or the body access off (for every request or,
// with ctl:, for one), Coraza buffers nothing, the hard limits never see the
// body and the backend gets an empty one. The mode is schild's setting, and
// the body limits are too (limits in schild.yaml). Include is refused with
// them: an included file would pass this check and the checks of the id
// ranges unseen.
func checkEngineSettings(text string) error {
	joined := strings.ReplaceAll(text, "\\\n", " ")
	for _, line := range strings.Split(joined, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if m := engineDirectiveRe.FindString(l); m != "" {
			return fmt.Errorf("%s is not allowed in operator rules: schild sets the rule engine and the request body limits itself (mode and limits in schild.yaml)", m)
		}
		if includeRe.MatchString(l) {
			return fmt.Errorf("Include is not allowed in operator rules: schild checks every rule it loads, and a file outside the rules directory would go unchecked. Put the file into the rules directory instead")
		}
		if m := engineCtlRe.FindStringSubmatch(l); m != nil {
			return fmt.Errorf("ctl:%s is not allowed in operator rules: without the engine or the body schild could not pass the request body on. To leave a path out of the rules, add an exception in the dashboard or use ctl:ruleRemoveByTag=OWASP_CRS", m[1])
		}
	}
	return nil
}

// LocalRuleKind classifies one operator rule (with its chained rules).
type LocalRuleKind struct {
	// Blocking: deny, block or drop.
	Blocking bool
	// Exception: not blocking, and the rule tunes the WAF instead of
	// detecting something: a ctl: action (ruleRemoveById,
	// ruleRemoveTargetById, ruleEngine, …) or allow anywhere in the chain, a
	// SecAction (it matches every request), or a rule whose only effect is
	// setvar on variables other than an anomaly score (CRS exclusion
	// switches). Such a rule is no finding: it never counts as a WAF hit for
	// waf_repeat or a request shape (MVP-19 measurement, finding 3b). nolog
	// says nothing either way (MVP-19 re-measurement): a rule with deny,
	// block or drop is a detection with or without nolog, and so is a pass
	// rule that raises an anomaly score or only logs.
	Exception bool
}

// LocalRuleKinds classifies the operator rules by id. A chained rule's
// actions count for the rule that starts the chain (the chained lines carry
// no id). Continuation lines are joined first.
func LocalRuleKinds(text string) map[int]LocalRuleKind {
	type acc struct{ blocking, exception, action, setvar, score bool }
	out := map[int]LocalRuleKind{}
	cur, inChain := 0, false
	var a acc
	flush := func() {
		if cur != 0 {
			tuning := a.exception || a.action || (a.setvar && !a.score)
			out[cur] = LocalRuleKind{Blocking: a.blocking, Exception: !a.blocking && tuning}
		}
	}
	joined := strings.ReplaceAll(text, "\\\n", " ")
	for _, line := range strings.Split(joined, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "SecRule") && !strings.HasPrefix(l, "SecAction") {
			continue
		}
		m := idRe.FindStringSubmatch(l)
		switch {
		case m != nil:
			flush()
			cur, _ = strconv.Atoi(m[1])
			a = acc{action: strings.HasPrefix(l, "SecAction")}
		case inChain && cur != 0:
			// chained rule of cur
		default:
			inChain = false
			continue
		}
		a.blocking = a.blocking || blockRe.MatchString(l)
		a.exception = a.exception || exceptionRe.MatchString(l)
		for _, sv := range setvarRe.FindAllStringSubmatch(l, -1) {
			a.setvar = true
			if strings.Contains(strings.ToLower(sv[1]), "anomaly_score") {
				a.score = true
			}
		}
		inChain = chainRe.MatchString(l)
	}
	flush()
	return out
}

// Engine holds the current instance.
type Engine struct{ cur atomic.Pointer[Instance] }

// Current returns the active instance (never nil after the first Swap).
func (e *Engine) Current() *Instance { return e.cur.Load() }

// Swap activates inst atomically and returns the previous one. The previous
// instance is closed: since Coraza 3.5 compiled patterns live in a global
// memoize cache with one owner per WAF, and without Close every rule swap
// would keep its owner entries forever. Transactions in flight keep working
// (they hold their own references to the compiled rules).
func (e *Engine) Swap(inst *Instance) *Instance {
	old := e.cur.Swap(inst)
	if old != nil && old != inst {
		old.Close()
	}
	return old
}

// Close releases the instance's entries in Coraza's pattern cache. The
// instance stays usable; closing twice is harmless.
func (inst *Instance) Close() {
	if c, ok := inst.WAF.(experimental.WAFCloser); ok {
		_ = c.Close()
	}
}

// Match is one analysed rule match.
type Match struct {
	ID         int
	Source     string   // crs | local | internal | crowdsec
	Hub        *HubRule // only with source crowdsec
	Msg        string
	Severity   string // critical | error | warning | notice | ""
	Points     int
	Tags       []string
	Location   string // matchShape location, "" when not representable
	ValueLen   int
	Disruptive bool
	Exception  bool // a local exception (LocalRuleKind), not a finding
	// Counts: the match may feed behaviour counters (waf_repeat, request
	// shapes). Set by the gate from contract/rules: a crowdsec match only when
	// it really blocked, a crs or local match unless its repository detects.
	Counts bool
}

// Key is the id of a match in rule lists and counters: the base id of a hub
// rule (the same for all its groups), else the SecRule id.
func (m *Match) Key() string {
	if m.Hub != nil {
		return m.Hub.Key()
	}
	return strconv.Itoa(m.ID)
}

// Analysis summarises all matches of a transaction.
type Analysis struct {
	Matches    []Match
	CRSAnomaly int  // recomputed from CRS detection rules only
	CRSBlock   bool // CRSAnomaly >= threshold
	LocalBlock bool
	BodyError  bool // 200002, 200003 or 200009: the body or URI could not be inspected
	ArgsLimit  bool // 200004 or 200005: Coraza dropped arguments beyond SecArgumentsLimit
	Category   string
	Score      int // 0..100, >= 40 when CRS would block
	CRSInbound bool
	MatchedIDs []int // ascending, unique, excluding internal ids
	TopMsg     string
	Threshold  int
	HasHub     bool // at least one crowdsec entry in Matches
}

var severityPoints = map[types.RuleSeverity]int{
	types.RuleSeverityCritical: 5,
	types.RuleSeverityError:    4,
	types.RuleSeverityWarning:  3,
	types.RuleSeverityNotice:   2,
}

func severityName(s types.RuleSeverity) string {
	switch s {
	case types.RuleSeverityCritical:
		// Emergency (0) is also the zero value of rules without a
		// severity, so only Critical maps to "critical".
		return "critical"
	case types.RuleSeverityError:
		return "error"
	case types.RuleSeverityWarning:
		return "warning"
	case types.RuleSeverityNotice:
		return "notice"
	}
	return ""
}

var shapeVars = map[string]bool{
	"ARGS": true, "ARGS_GET": true, "ARGS_POST": true, "ARGS_NAMES": true, "ARGS_GET_NAMES": true, "ARGS_POST_NAMES": true,
	"REQUEST_URI": true, "REQUEST_FILENAME": true, "REQUEST_BASENAME": true,
	"QUERY_STRING": true, "REQUEST_BODY": true, "REQUEST_COOKIES": true, "REQUEST_COOKIES_NAMES": true, "REQUEST_HEADERS": true,
	"REQUEST_HEADERS_NAMES": true, "FILES": true, "FILES_NAMES": true,
}

var (
	keyRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	noLeakRe = []*regexp.Regexp{
		regexp.MustCompile(`[0-9]{1,3}[._/-][0-9]{1,3}[._/-][0-9]{1,3}[._/-][0-9]{1,3}`),
		regexp.MustCompile(`[0-9]{7,}`),
		regexp.MustCompile(`[0-9a-f]{8,}`),
		regexp.MustCompile(`[0-9a-f]{1,4}([._/-][0-9a-f]{0,4}){4,}`),
	}
)

// NoLeak mirrors common.schema.json#/$defs/noLeak.
func NoLeak(s string) bool {
	for _, re := range noLeakRe {
		if re.MatchString(s) {
			return false
		}
	}
	return true
}

func location(md types.MatchData) (string, int) {
	if md == nil {
		return "", 0
	}
	name := md.Variable().Name()
	if name == "ARGS_GET_NAMES" || name == "ARGS_POST_NAMES" {
		name = "ARGS_NAMES"
	}
	if !shapeVars[name] {
		return "", len(md.Value())
	}
	loc := name
	if k := md.Key(); k != "" && keyRe.MatchString(k) && NoLeak(k) {
		loc += ":" + k
	}
	if !NoLeak(loc) {
		loc = name
	}
	return loc, len(md.Value())
}

// Analyze classifies the matched rules of a finished transaction.
func (inst *Instance) Analyze(mrs []types.MatchedRule) *Analysis {
	a := &Analysis{Threshold: inst.Config.AnomalyThreshold}
	if a.Threshold <= 0 {
		a.Threshold = 5
	}
	seen := map[int]bool{}
	var hubSeen map[int]bool
	best := -1
	for _, mr := range mrs {
		md := mr.Rule()
		id := md.ID()
		if id == 0 || seen[id] {
			continue
		}
		m := Match{ID: id, Msg: mr.Message(), Severity: severityName(md.Severity()), Tags: md.Tags(), Disruptive: mr.Disruptive()}
		if mds := mr.MatchedDatas(); len(mds) > 0 {
			m.Location, m.ValueLen = location(mds[0])
		}
		switch {
		case id == InternalBodyError || id == InternalMultipartError || id == InternalURIParseError:
			m.Source = SourceInternal
			a.BodyError = true
		case id == InternalArgsLimitGet || id == InternalArgsLimitPost:
			m.Source = SourceInternal
			a.ArgsLimit = true
		case id >= 200000 && id <= InternalLivewire:
			continue // body processor selection or built-in exception, not a finding
		case id >= crsMin && id <= crsMax && inst.Config.CRS:
			m.Source = "crs"
			// Only CRS detection rules count; the evaluation and
			// correlation rules (949/959/980) and initialisation rules
			// (901-905) carry no points of their own.
			if id >= 910000 && id < 949000 {
				m.Points = severityPoints[md.Severity()]
				a.CRSAnomaly += m.Points
			}
		case inst.Hub[id] != nil:
			// D39: a hub match is a finding of its own kind. No points, no
			// Score, no MatchedIDs, no LocalBlock; the gate decides per rule. Several groups of one
			// hub rule count once.
			hr := inst.Hub[id]
			seen[id] = true
			if hubSeen[hr.BaseID] {
				continue
			}
			if hubSeen == nil {
				hubSeen = map[int]bool{}
			}
			hubSeen[hr.BaseID] = true
			m.Source, m.Hub = SourceCrowdsec, hr
			a.Matches = append(a.Matches, m)
			a.HasHub = true
			continue
		default:
			m.Source = "local"
			m.Exception = inst.LocalException[id]
			if inst.LocalBlocking[id] {
				a.LocalBlock = true
			}
		}
		if m.Source == "crs" && m.Points == 0 && (id < 949000 || m.Msg == "") {
			continue // flow control (paranoia skips, initialisation) is not a finding
		}
		seen[id] = true
		a.Matches = append(a.Matches, m)
		if m.Source != SourceInternal {
			a.MatchedIDs = append(a.MatchedIDs, id)
		}
		if best < 0 || m.Points > a.Matches[best].Points {
			best = len(a.Matches) - 1
		}
	}
	sort.Ints(a.MatchedIDs)
	a.CRSBlock = a.CRSAnomaly >= a.Threshold
	if best >= 0 {
		a.TopMsg = a.Matches[best].Msg
		a.Category = category(a.Matches[best])
	} else if a.HasHub {
		// No category for a hub match alone.
		a.TopMsg = a.Matches[0].Msg
	}
	// Score 0..100: 40 is exactly the CRS blocking threshold, so "score >=
	// 40" means "CRS would block".
	s := a.CRSAnomaly * 40 / a.Threshold
	if a.LocalBlock && s < 40 {
		s = 40
	}
	if s > 100 {
		s = 100
	}
	a.Score = s
	return a
}

var catClean = regexp.MustCompile(`[^a-z0-9-]+`)

func category(m Match) string {
	if m.Source == "local" {
		return "local-rule"
	}
	for _, t := range m.Tags {
		t = strings.ToLower(t)
		if c, ok := strings.CutPrefix(t, "attack-"); ok {
			c = catClean.ReplaceAllString(c, "-")
			c = strings.Trim(c, "-")
			if c != "" && len(c) <= 48 && NoLeak(c) {
				return c
			}
		}
	}
	return "anomaly"
}
