// Package events defines the local event catalogue schild.<thing>.<verb>.v1
// (concept 21 §2.1) as CloudEvents 1.0 in structured JSON. Local events stay
// on the server: they keep the full visitor IP and location in plaintext
// (E7). Nothing in this package is ever sent to a lab.
package events

import (
	"crypto/rand"
	"time"

	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/verify"
)

// Event types.
const (
	RequestEvaluated   = "schild.request.evaluated.v1"
	RequestBlocked     = "schild.request.blocked.v1"
	RequestUnblocked   = "schild.request.unblocked.v1"
	SessionFlagged     = "schild.session.flagged.v1"
	EnvironmentChanged = "schild.environment.changed.v1"
	EnvironmentAnomaly = "schild.environment.anomaly.v1"
	AdvisoryAssessed   = "schild.advisory.assessed.v1"
	// v0.4 (MVP-17): behaviour across requests and rate limits, local only.
	BehaviourTriggered = "schild.behaviour.triggered.v1"
	RateLimitExceeded  = "schild.ratelimit.exceeded.v1"
	// v0.4 (MVP-18): distributed attacks, address-free, local only.
	DistributedDetected = "schild.distributed.detected.v1"
	DistributedEnded    = "schild.distributed.ended.v1"
	// v0.5 (D38, MVP-09 addendum): audit record of `schild dashboard
	// reset-password`.
	DashboardAccessReset = "schild.dashboard.access_reset.v1"
	// v0.5 (D51): an incident left the gateway as a download.
	IncidentExported = "schild.incident.exported.v1"
	// D73: the rules of a repository changed or a change was refused (an
	// update, a refusal, a reset, a reload of local).
	RuleRepositoryUpdated = "schild.rule.repository_updated.v1"
	// D73: the state of a repository changed, from the dashboard or through
	// the agent API. The change history of the state.
	RuleRepositorySwitched = "schild.rule.repository_switched.v1"
	// D73: one rule disabled or enabled, one version of an update approved
	// or rejected.
	RuleDisabled = "schild.rule.disabled.v1"
	RuleEnabled  = "schild.rule.enabled.v1"
	RuleApproved = "schild.rule.approved.v1"
	RuleRejected = "schild.rule.rejected.v1"
	// D42: a block set or lifted through the agent API.
	BlockSet    = "schild.block.set.v1"
	BlockLifted = "schild.block.lifted.v1"
	// D54: a rule exception set or removed through the agent API.
	RuleExceptionSet     = "schild.rule.exception_set.v1"
	RuleExceptionRemoved = "schild.rule.exception_removed.v1"
	// D56 (MVP-14 step 1): the access lock.
	AccessProtectionSet     = "schild.access.protection_set.v1"
	AccessProtectionRemoved = "schild.access.protection_removed.v1"
	AccessLogin             = "schild.access.login.v1"
	AccessPrefixLocked      = "schild.access.prefix_locked.v1"
	// D57 (MVP-29): the crawler policy of a website changed.
	CrawlerPolicySet = "schild.crawler.policy_set.v1"
)

// Types lists all local event types.
var Types = []string{RequestEvaluated, RequestBlocked, RequestUnblocked, SessionFlagged, EnvironmentChanged, EnvironmentAnomaly, AdvisoryAssessed, BehaviourTriggered, RateLimitExceeded, DistributedDetected, DistributedEnded, DashboardAccessReset, IncidentExported, RuleRepositoryUpdated, RuleRepositorySwitched, RuleDisabled, RuleEnabled, RuleApproved, RuleRejected, BlockSet, BlockLifted, RuleExceptionSet, RuleExceptionRemoved, AccessProtectionSet, AccessProtectionRemoved, AccessLogin, AccessPrefixLocked, CrawlerPolicySet}

// Event is a CloudEvent 1.0 (structured mode).
type Event struct {
	SpecVersion     string `json:"specversion"`
	ID              string `json:"id"`
	Source          string `json:"source"`
	Type            string `json:"type"`
	Time            string `json:"time"`
	Subject         string `json:"subject,omitempty"`
	DataContentType string `json:"datacontenttype"`
	Data            any    `json:"data"`
}

// New builds an event for node (source schild://<node>) at time t.
func New(typ, node string, t time.Time, data any) *Event {
	return &Event{
		SpecVersion:     "1.0",
		ID:              msg.NewID(),
		Source:          "schild://" + node,
		Type:            typ,
		Time:            t.UTC().Format("2006-01-02T15:04:05.000Z"),
		DataContentType: "application/json",
		Data:            data,
	}
}

// Marshal returns the JSON form.
func (e *Event) Marshal() ([]byte, error) { return jsonx.Marshal(e) }

// Validate checks the event against events.schema.json.
func (e *Event) Validate() error {
	b, err := e.Marshal()
	if err != nil {
		return err
	}
	_, err = verify.Document(verify.DocEvent, b, &verify.Context{})
	return err
}

// Client is the visitor as seen locally: full IP and location (E7).
type Client struct {
	IP          string `json:"ip"`
	Port        int    `json:"port,omitempty"`
	Attribution string `json:"attribution"` // tcp_peer | trusted_proxy | untrusted_header
	Geo         Geo    `json:"geo"`
	Allowlisted bool   `json:"allowlisted,omitempty"`
}

// Geo is derived from the bundled geo database, never looked up remotely.
type Geo struct {
	Country  string `json:"country"`
	City     string `json:"city,omitempty"`
	ASN      uint32 `json:"asn"`
	ASOrg    string `json:"as_org,omitempty"`
	NetClass string `json:"net_class"`
}

// MatchedRule is one rule that matched a request.
type MatchedRule struct {
	ID         int              `json:"id"`
	Repository string           `json:"repository"`         // crs | local | crowdsec
	Crowdsec   *CrowdsecRuleRef `json:"crowdsec,omitempty"` // only with repository crowdsec
	Msg        string           `json:"msg,omitempty"`
	Severity   string           `json:"severity,omitempty"`
	MatchShape *msg.MatchShape  `json:"match_shape,omitempty"`
}

// CrowdsecRuleRef names the CrowdSec Hub rule of a match. Third-party text:
// show it, never interpret it.
type CrowdsecRuleRef struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Label   string   `json:"label,omitempty"`
	CVEs    []string `json:"cves,omitempty"`
}

// RepositorySwitched is the data of schild.rule.repository_switched.v1 (D73):
// the change history of the state of a repository. The event keeps the token
// name after the token is revoked.
type RepositorySwitched struct {
	Repository  string `json:"repository"`
	From        string `json:"from"`
	To          string `json:"to"`
	Actor       string `json:"actor"` // dashboard | agent
	StateSource string `json:"state_source"`
	Reset       bool   `json:"reset,omitempty"`
	TokenID     string `json:"token_id,omitempty"`
	TokenLabel  string `json:"token_label,omitempty"`
}

// AgentBlockSet is the data of schild.block.set.v1 (D42): an agent set a block,
// or would have (Effect would_block, in a gateway that observes: no incident,
// no until). A block is never named by address (D42); the address is in the answers that list
// events (D99). The event keeps
// the token name after the token is revoked. D88: or the operator in the
// dashboard (Actor dashboard, TargetKind address, no token, no evidence).
type AgentBlockSet struct {
	Actor      string `json:"actor,omitempty"` // dashboard | agent; empty: agent
	Effect     string `json:"effect"`          // block | would_block
	Client     Client `json:"client"`
	KeyBits    int    `json:"key_bits"` // 32 or 64
	DurationS  int    `json:"duration_s"`
	Until      string `json:"until,omitempty"`
	Persisted  bool   `json:"persisted,omitempty"`
	Incident   string `json:"incident,omitempty"`
	TargetKind string `json:"target_kind"` // event | incident | pseudonym | address (D88)
	// EvidenceEventID is the event the address was resolved from.
	EvidenceEventID string `json:"evidence_event_id,omitempty"`
	TokenID         string `json:"token_id,omitempty"`
	TokenLabel      string `json:"token_label,omitempty"`
	Reason          string `json:"reason"`
}

// AgentBlockLifted is the data of schild.block.lifted.v1 (D42): an agent ended
// a running block. No exception, no allowlist entry.
type AgentBlockLifted struct {
	Incident   string `json:"incident"`
	Source     string `json:"source"` // of the block
	TokenID    string `json:"token_id"`
	TokenLabel string `json:"token_label"`
	Reason     string `json:"reason"`
}

// RuleDisabledChange is the data of schild.rule.disabled.v1 and
// schild.rule.enabled.v1 (D73).
type RuleDisabledChange struct {
	Repository string `json:"repository"`
	Rule       string `json:"rule"`
	Name       string `json:"name,omitempty"`
	Actor      string `json:"actor"` // dashboard | agent
	TokenID    string `json:"token_id,omitempty"`
	TokenLabel string `json:"token_label,omitempty"`
	Note       string `json:"note,omitempty"`
}

// RuleApprovalChange is the data of schild.rule.approved.v1 and
// schild.rule.rejected.v1 (D73).
type RuleApprovalChange struct {
	Repository string `json:"repository"`
	Rule       string `json:"rule"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version"`
	Actor      string `json:"actor"` // dashboard | agent
	TokenID    string `json:"token_id,omitempty"`
	TokenLabel string `json:"token_label,omitempty"`
	Note       string `json:"note,omitempty"`
}

// RuleExceptionChange is the data of schild.rule.exception_set.v1 and
// schild.rule.exception_removed.v1 (D54, D73). Actor is agent or dashboard
// (D84); only an agent names a token, and only its reason is required.
type RuleExceptionChange struct {
	ID         int      `json:"id"`
	Website    string   `json:"website"`
	Path       string   `json:"path"`
	Target     string   `json:"target"`
	Repository string   `json:"repository"` // crs | crowdsec
	Rules      []string `json:"rules"`
	Actor      string   `json:"actor,omitempty"`
	TokenID    string   `json:"token_id,omitempty"`
	TokenLabel string   `json:"token_label,omitempty"`
	Reason     string   `json:"reason"`
}

// AccessProtectionChange is the data of schild.access.protection_set.v1
// (D56). Addresses are counted, never listed.
type AccessProtectionChange struct {
	Website     string   `json:"website"`
	Scope       string   `json:"scope"`
	Paths       []string `json:"paths,omitempty"`
	Except      []string `json:"except,omitempty"`
	Password    bool     `json:"password"`
	Addresses   int      `json:"addresses"`
	OwnNetworks bool     `json:"own_networks"`
	Until       string   `json:"until,omitempty"`
	Actor       string   `json:"actor"` // dashboard | cli
	User        string   `json:"user,omitempty"`
}

// CrawlerPolicyChange is the data of schild.crawler.policy_set.v1 (D57):
// the whole policy after the change, who changed it and, from the agent
// API, the token and the agent's reason (sanitised, untrusted text).
type CrawlerPolicyChange struct {
	Website    string            `json:"website"`
	Categories map[string]string `json:"categories"`
	Bots       map[string]string `json:"bots"`
	// Impersonators is allow or block.
	Impersonators string `json:"impersonators"`
	Preset        string `json:"preset,omitempty"`
	Actor         string `json:"actor"` // dashboard | agent
	User          string `json:"user,omitempty"`
	TokenID       string `json:"token_id,omitempty"`
	TokenLabel    string `json:"token_label,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// AccessProtectionEnded is the data of schild.access.protection_removed.v1
// (D56).
type AccessProtectionEnded struct {
	Website string `json:"website"`
	Scope   string `json:"scope"`
	Actor   string `json:"actor"` // dashboard | cli | system
	User    string `json:"user,omitempty"`
	Reason  string `json:"reason"` // removed | expired
}

// AccessLoginData is the data of schild.access.login.v1 (D56).
type AccessLoginData struct {
	Website       string `json:"website"`
	AddressPrefix string `json:"address_prefix"`
}

// AccessPrefixLockedData is the data of schild.access.prefix_locked.v1 (D56).
type AccessPrefixLockedData struct {
	Website       string `json:"website"`
	AddressPrefix string `json:"address_prefix"`
	Until         string `json:"until"`
}

// RepositoryUpdated is the data of schild.rule.repository_updated.v1 (D73): a
// crowdsec set was swapped in, refused or reset to the image snapshot, or the
// local rules were reloaded or a reload was refused.
type RepositoryUpdated struct {
	Repository   string   `json:"repository"`
	Outcome      string   `json:"outcome"` // accepted | refused | reset | reloaded
	Code         string   `json:"code,omitempty"`
	SetSource    string   `json:"set_source,omitempty"` // crowdsec: stored | image | none
	IndexSHA256  string   `json:"index_sha256,omitempty"`
	HubCommit    string   `json:"hub_commit,omitempty"`
	RulesLoaded  int      `json:"rules_loaded"`
	RulesSkipped int      `json:"rules_skipped,omitempty"`
	Added        []string `json:"added,omitempty"`
	Changed      []string `json:"changed,omitempty"`
	Removed      []string `json:"removed,omitempty"`
	Truncated    bool     `json:"truncated,omitempty"`
}

// Request is the data of schild.request.evaluated.v1 and schild.request.blocked.v1.
type Request struct {
	RequestID  string        `json:"request_id"`
	Incident   string        `json:"incident,omitempty"`
	Client     Client        `json:"client"`
	Method     string        `json:"method"`
	Host       string        `json:"host"`
	Path       string        `json:"path"`
	Query      string        `json:"query,omitempty"`
	Protocol   string        `json:"protocol,omitempty"`
	Status     int           `json:"status"`
	UserAgent  string        `json:"user_agent,omitempty"`
	SessionID  string        `json:"session_id,omitempty"`
	Rules      []MatchedRule `json:"rules"`
	Score      int           `json:"score"`
	Outcome    string        `json:"outcome"` // passed | logged | challenged | blocked | would_block
	Mode       string        `json:"mode"`
	DurationMS float64       `json:"duration_ms"`
	WAFMS      float64       `json:"waf_ms"`
	Sampled    bool          `json:"sampled,omitempty"`
	// WouldBlockReason (v0.5, D36 open items): why a would_block request
	// was passed (WouldBlockReasons); only with outcome would_block.
	WouldBlockReason string `json:"would_block_reason,omitempty"`
}

// WouldBlockReasons (v0.5, D36 open items) in precedence order: when
// several apply, the first wins.
var WouldBlockReasons = []string{"gateway_observe", "site_observe", "learning", "scenario_observe", "source_detect", "settling", "allowlist", "shared_address"}

// AccessReset is the data of schild.dashboard.access_reset.v1 (D38): no
// password, hash, setup code or session id, only what happened.
type AccessReset struct {
	Via           string `json:"via"` // host_cli | control_path
	UsersRemoved  int    `json:"users_removed"`
	SessionsEnded int    `json:"sessions_ended"`
	HostUser      string `json:"host_user,omitempty"`
}

// IncidentExportedData is the data of schild.incident.exported.v1 (D51).
type IncidentExportedData struct {
	Incident string `json:"incident"`
	By       string `json:"by"`
	Events   int    `json:"events"`
}

// Unblocked is the data of schild.request.unblocked.v1.
type Unblocked struct {
	Incident       string `json:"incident"`
	RequestID      string `json:"request_id"`
	By             string `json:"by"` // operator | cli
	FalsePositive  bool   `json:"false_positive"`
	AllowlistEntry string `json:"allowlist_entry,omitempty"`
}

// SessionFlaggedData is the data of schild.session.flagged.v1.
type SessionFlaggedData struct {
	SessionID string  `json:"session_id"`
	Client    Client  `json:"client"`
	Reason    string  `json:"reason"` // rate | error_rate | path_sequence | waf_hits
	Requests  int     `json:"requests"`
	WindowS   int     `json:"window_s"`
	Threshold float64 `json:"threshold,omitempty"`
}

// EnvironmentChangedData is the data of schild.environment.changed.v1.
type EnvironmentChangedData struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version,omitempty"`
}

// Factor contributes points to the compromise index.
type Factor struct {
	Name   string `json:"name"`
	Points int    `json:"points"`
}

// EnvironmentAnomalyData is the data of schild.environment.anomaly.v1.
type EnvironmentAnomalyData struct {
	Level   string   `json:"level"` // normal | elevated | suspicious
	Index   int      `json:"index"`
	Factors []Factor `json:"factors"`
}

// AdvisoryAssessedData is the data of schild.advisory.assessed.v1.
type AdvisoryAssessedData struct {
	AdvisoryID string   `json:"advisory_id"`
	Result     string   `json:"result"`
	Components []string `json:"components,omitempty"`
}

// BehaviourTriggeredData is the data of schild.behaviour.triggered.v1 (v0.4,
// MVP-17). It never carries a user name, a hash of one, a password or a body.
type BehaviourTriggeredData struct {
	Scenario    string  `json:"scenario"`
	Scope       string  `json:"scope"` // client | site
	Client      *Client `json:"client,omitempty"`
	KeyBits     int     `json:"key_bits,omitempty"`
	Host        string  `json:"host,omitempty"`
	Route       string  `json:"route,omitempty"`
	Preset      string  `json:"preset,omitempty"`
	Count       int     `json:"count"`
	Threshold   int     `json:"threshold"`
	WindowS     int     `json:"window_s"`
	Baseline    float64 `json:"baseline,omitempty"`
	Mode        string  `json:"mode"`   // observe | challenge | block
	Action      string  `json:"action"` // observe | challenge | block
	WouldAction string  `json:"would_action,omitempty"`
	Reason      string  `json:"reason,omitempty"`
	Level       int     `json:"level,omitempty"`
	DurationS   int     `json:"duration_s,omitempty"`
	Until       string  `json:"until,omitempty"`
	Incident    string  `json:"incident,omitempty"`
}

// Reasons of BehaviourTriggeredData and RateLimitExceededData
// (events.schema.json behaviourReason). ReasonLearning (v0.4 addendum
// 2026-10-28) is for behaviour scenarios only: rate limits act from day 0 and
// the schema rejects it on schild.ratelimit.exceeded.v1.
const (
	ReasonNetClass             = "net_class"
	ReasonAllowlisted          = "allowlisted"
	ReasonReleased             = "released"
	ReasonChallengeUnavailable = "challenge_unavailable"
	ReasonUnverifiedBot        = "unverified_bot"
	ReasonSiteScope            = "site_scope"
	ReasonLearning             = "learning"
)

// RateLimitExceededData is the data of schild.ratelimit.exceeded.v1 (v0.4).
type RateLimitExceededData struct {
	LimitID     string   `json:"limit_id"`
	Source      string   `json:"source"` // config | dashboard | preset
	Route       string   `json:"route"`
	Methods     []string `json:"methods,omitempty"`
	Host        string   `json:"host,omitempty"`
	Path        string   `json:"path,omitempty"`
	Client      Client   `json:"client"`
	KeyBits     int      `json:"key_bits"`
	Limit       int      `json:"limit"`
	PerS        int      `json:"per_s"`
	Burst       int      `json:"burst"`
	Count       int      `json:"count"`
	Mode        string   `json:"mode"`
	Action      string   `json:"action"`
	Reason      string   `json:"reason,omitempty"`
	RetryAfterS int      `json:"retry_after_s,omitempty"`
}

// DistributedDetectedData is the data of schild.distributed.detected.v1
// (v0.4, MVP-18). It names no client, user name or account.
type DistributedDetectedData struct {
	WaveID          string  `json:"wave_id"`
	Detector        string  `json:"detector"`
	Host            string  `json:"host,omitempty"`
	Route           string  `json:"route"`
	Senders         int     `json:"senders"`
	Count           int     `json:"count"`
	Threshold       int     `json:"threshold"`
	WindowS         int     `json:"window_s"`
	Baseline        float64 `json:"baseline,omitempty"`
	Fingerprint     string  `json:"fingerprint,omitempty"`
	FingerprintKind string  `json:"fingerprint_kind,omitempty"`
	UserAgents      int     `json:"user_agents,omitempty"`
	RequestSig      string  `json:"request_sig,omitempty"`
	WAFRules        []int   `json:"waf_rules,omitempty"`
	Response        string  `json:"response"`
	Mode            string  `json:"mode"`
	Action          string  `json:"action"`
	Reason          string  `json:"reason,omitempty"`
	Until           string  `json:"until,omitempty"`
}

// DistributedEndedData is the data of schild.distributed.ended.v1.
type DistributedEndedData struct {
	WaveID    string `json:"wave_id"`
	Detector  string `json:"detector"`
	Host      string `json:"host,omitempty"`
	Route     string `json:"route"`
	Reason    string `json:"reason"` // expired | operator
	DurationS int    `json:"duration_s"`
	Stopped   int    `json:"stopped"`
}

// incidentAlphabet avoids look-alike characters (no 0/O, 1/I).
const incidentAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// NewIncident returns an incident number like K7QM-4XWD for block pages.
func NewIncident() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, incidentAlphabet[int(c)%len(incidentAlphabet)])
	}
	return string(out)
}
