// Package rules is the contract of the rule repositories of the gateway (D73):
// the one vocabulary of repositories and rules, and the one pure function that
// says what a rule does right now (Compute) and what a matched rule does to one
// request (Apply). Every repository (OWASP CRS, CrowdSec Hub, the operator's
// rules.d) uses the same function, in the gate, both APIs and the rule lists.
// contracts/tools/crosscheck.py implements the same rules independently; the
// rule-effect vectors keep both in step.
package rules

// Schema is the name of the vector input schema.
const Schema = "rule-effect"

// MaxInputBytes of a rule-effect vector.
const MaxInputBytes = 4 << 10

// Repository ids, the same in schild.yaml, both APIs, events and the dashboard.
const (
	RepoCRS      = "crs"      // OWASP CRS, built into the binary
	RepoCrowdsec = "crowdsec" // CrowdSec Hub virtual patches: image snapshot plus updates
	RepoLocal    = "local"    // the operator's files in rules.d
)

// Repositories lists every repository in the order of the lists.
var Repositories = []string{RepoCRS, RepoCrowdsec, RepoLocal}

// KnownRepository reports whether id names a repository of this gateway.
func KnownRepository(id string) bool {
	return id == RepoCRS || id == RepoCrowdsec || id == RepoLocal
}

// The three states of a repository.
const (
	StateOff    = "off"    // no rules, nothing fetched
	StateDetect = "detect" // rules match and are logged, never block
	StateBlock  = "block"
)

// DefaultState is the state of a repository that neither schild.yaml nor the
// settings overlay set: crs and local block, crowdsec detects.
func DefaultState(repository string) string {
	if repository == RepoCrowdsec {
		return StateDetect
	}
	return StateBlock
}

// The two values of the mode input (D89): there is no protection mode to set.
// observe is the dry run of the test profile, in which nothing blocks;
// autoblock is every other gateway, where the repository states decide.
const (
	ModeObserve   = "observe"
	ModeAutoblock = "autoblock"
)

// Origins of a rule.
const (
	OriginRelease  = "release"  // ships with the image
	OriginUpdate   = "update"   // received while the gateway runs
	OriginOperator = "operator" // the operator's own file
)

// Status of a rule.
const (
	StatusActive   = "active"
	StatusSettling = "settling" // an update waits for settling_s
	StatusDisabled = "disabled"
)

// Statuses lists every status in the order of the API enum.
var Statuses = []string{StatusActive, StatusSettling, StatusDisabled}

// Effects of a rule and of a repository.
const (
	EffectOff        = "off"
	EffectDetect     = "detect"
	EffectWouldBlock = "would_block"
	EffectBlock      = "block"
)

// Why an effect is lower than what the rule would do.
const (
	LimitGatewayObserve   = "gateway_observe" // the test profile: nothing blocks
	LimitRepositoryDetect = "repository_detect"
	LimitSettling         = "settling"
)

// Who disabled a rule or set a repository state.
const (
	ByConfig    = "config"
	ByDashboard = "dashboard"
	ByAgent     = "agent"
	ByDefault   = "default" // state_source only
)

// Input is one rule of one repository at one moment.
type Input struct {
	Mode       string // observe (test profile) | autoblock
	State      string // repository state: off | detect | block
	Origin     string // release | update | operator
	Disabled   bool
	DisabledBy string // config | dashboard | agent, with Disabled
	// SettlingUntil is the unix second an update has settled (0: none).
	SettlingUntil int64
	Now           int64
}

// Rule is what a rule does right now: the same for every request.
type Rule struct {
	Status     string `json:"status"`
	Effect     string `json:"effect"`
	LimitedBy  string `json:"limited_by,omitempty"`
	DisabledBy string `json:"disabled_by,omitempty"`
}

// Compute is the one function of status and effect. The repository state
// comes first (off loads nothing, detect never blocks), then what holds an
// update back (settling_s, D89: no approvals), then the test profile (observe
// only logs what it would block). A disabled rule does nothing in any state.
func Compute(in Input) Rule {
	var r Rule
	switch {
	case in.Disabled:
		r.Status, r.DisabledBy = StatusDisabled, in.DisabledBy
		if r.DisabledBy == "" {
			r.DisabledBy = ByDashboard
		}
	case in.Origin == OriginUpdate && in.Mode != ModeObserve && in.Now < in.SettlingUntil:
		r.Status = StatusSettling
	default:
		r.Status = StatusActive
	}
	switch {
	case r.Status == StatusDisabled, in.State == StateOff:
		r.Effect = EffectOff
	case in.State == StateDetect:
		r.Effect, r.LimitedBy = EffectDetect, LimitRepositoryDetect
	case r.Status == StatusSettling:
		r.Effect, r.LimitedBy = EffectDetect, LimitSettling
	case in.Mode == ModeObserve:
		r.Effect, r.LimitedBy = EffectWouldBlock, LimitGatewayObserve
	default:
		r.Effect = EffectBlock
	}
	return r
}

// Actions of a matched rule on one request.
const (
	ActionNone       = "none"        // the rule does nothing here
	ActionWouldBlock = "would_block" // the rule would block; its switch (Erkennen), a settling update, the test profile or an allowlist entry holds it back
	ActionBlock      = "block"
	ActionExcepted   = "excepted" // the rule would block, an unblock excepts this client
)

// Why a would_block request was passed.
const (
	WouldBlockGatewayObserve = "gateway_observe"
	WouldBlockSiteObserve    = "site_observe"
	WouldBlockAllowlist      = "allowlist"
	// D90: a source on detect (Erkennen) or an update that still settles
	// shows as "Erkannt", like every other match that was held back.
	WouldBlockSourceDetect = "source_detect"
	WouldBlockSettling     = "settling"
)

// Request is what one request adds to the effect of a rule.
type Request struct {
	SiteMode string // "" | observe: the website is set to observe
	Allow    string // "" | no_block | bypass_waf
	Excepted bool   // an unblock excepts this client from the rule's source
}

// Action is the verdict for one matched rule on one request.
type Action struct {
	Action           string `json:"action"`
	Outcome          string `json:"outcome"`
	Reason           string `json:"reason,omitempty"`
	WouldBlockReason string `json:"would_block_reason,omitempty"`
	// CountsAsHit is true only for a block that happened: nothing else may
	// feed a behaviour counter, or a rule that only detects could lead to a
	// block indirectly.
	CountsAsHit bool `json:"counts_as_hit"`
}

// Apply decides what a matched rule with effect r does to one request. The
// CRS blocks by anomaly score: its rules come here as one, with the effect of
// their repository, when the score reached the threshold.
func Apply(r Rule, q Request) Action {
	switch {
	case q.Allow == "bypass_waf", r.Effect == EffectOff:
		return Action{Action: ActionNone, Outcome: "passed"}
	case r.Effect == EffectDetect:
		wb := WouldBlockSourceDetect
		if r.LimitedBy == LimitSettling {
			wb = WouldBlockSettling
		}
		return Action{Action: ActionWouldBlock, Outcome: "would_block", Reason: r.LimitedBy, WouldBlockReason: wb}
	case q.Excepted:
		return Action{Action: ActionExcepted, Outcome: "logged"}
	case r.Effect == EffectWouldBlock:
		return Action{Action: ActionWouldBlock, Outcome: "would_block", WouldBlockReason: WouldBlockGatewayObserve}
	case q.SiteMode == ModeObserve:
		return Action{Action: ActionWouldBlock, Outcome: "would_block", WouldBlockReason: WouldBlockSiteObserve}
	case q.Allow == "no_block":
		return Action{Action: ActionWouldBlock, Outcome: "would_block", WouldBlockReason: WouldBlockAllowlist}
	}
	return Action{Action: ActionBlock, Outcome: "blocked", CountsAsHit: true}
}

// RepositoryEffect says what a repository does on this gateway right now: its
// state after the test profile. Settling rules are counted, not in here: they
// are rules, not the repository.
type RepositoryEffect struct {
	Effect    string `json:"effect"`
	LimitedBy string `json:"limited_by,omitempty"`
}

// EffectOfRepository computes effect and limited_by of a repository.
func EffectOfRepository(state, mode string) RepositoryEffect {
	switch {
	case state != StateBlock:
		return RepositoryEffect{Effect: state}
	case mode == ModeObserve:
		return RepositoryEffect{Effect: EffectWouldBlock, LimitedBy: LimitGatewayObserve}
	}
	return RepositoryEffect{Effect: EffectBlock}
}

// Switch is one evaluation of a repository's state.
type Switch struct {
	State   string `json:"state"`
	Source  string `json:"source"`  // default | config | dashboard | agent
	Changed bool   `json:"changed"` // the effective state changed: write the change history
	Rebuild bool   `json:"rebuild"` // off against the others: the WAF is built again
	Differs bool   `json:"differs"` // the overlay value and schild.yaml differ
}

// EffectiveState resolves the state of a repository: the settings overlay
// wins over schild.yaml. overlayBy is ByDashboard
// or ByAgent; "" counts as the dashboard.
func EffectiveState(repository, config, overlay, overlayBy string) (string, string) {
	switch {
	case overlay != "" && overlayBy == ByAgent:
		return overlay, ByAgent
	case overlay != "":
		return overlay, ByDashboard
	case config != "":
		return config, ByConfig
	}
	return DefaultState(repository), ByDefault
}

// ApplySwitch computes the state after a change by actor (ByDashboard or
// ByAgent; "" counts as the dashboard). requested "" keeps the overlay and who
// set it, reset drops both. No password on any transition. A rebuild is
// needed only when the rules load or unload (off against the others): detect
// and block run the same instance.
func ApplySwitch(repository, config, overlay, overlayBy, requested, actor string, reset bool) Switch {
	before, _ := EffectiveState(repository, config, overlay, overlayBy)
	if reset {
		overlay, overlayBy = "", ""
	} else if requested != "" {
		overlay, overlayBy = requested, actor
	}
	after, src := EffectiveState(repository, config, overlay, overlayBy)
	cfg := config
	if cfg == "" {
		cfg = DefaultState(repository)
	}
	return Switch{State: after, Source: src, Changed: before != after,
		Rebuild: (before == StateOff) != (after == StateOff), Differs: overlay != "" && after != cfg}
}
