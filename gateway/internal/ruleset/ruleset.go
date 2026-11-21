// Package ruleset holds the rule repositories of the gateway behind one
// interface (D73): crs (OWASP CRS, built into the binary), crowdsec (CrowdSec
// Hub virtual patches, internal/hub) and local (the operator's rules.d). One
// Composer builds and swaps the WAF from their rules and checks the id range
// of each repository; one Registry answers what a rule does right now
// (contract/rules) on the request path and in both APIs, and is the one write
// path for repository states, syncs, resets and the decisions on single rules.
package ruleset

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// Errors of the registry; the APIs map them to problem codes.
var (
	// ErrNotSupported: the repository has no such operation (sync of crs,
	// reset of crs and local).
	ErrNotSupported = errors.New("ruleset: not supported by this repository")
	// ErrNotFound: no such repository or rule.
	ErrNotFound = errors.New("ruleset: not found")
	// ErrConfigLimit: the rule is disabled in schild.yaml and only the file
	// can enable it.
	ErrConfigLimit = errors.New("ruleset: disabled in schild.yaml")
	// ErrInvalid: a state outside off, detect and block.
	ErrInvalid = errors.New("ruleset: invalid value")
)

// SyncError is a refused sync of local: the running rules stay. Code is the
// refusal code of schild.rule.repository_updated.v1.
type SyncError struct {
	Code string
	Err  error
}

func (e *SyncError) Error() string { return "rules.d: " + e.Err.Error() }
func (e *SyncError) Unwrap() error { return e.Err }

// Codes of a refused sync of local.
const (
	CodeDirMissing    = "dir_missing"
	CodeReadFailed    = "read_failed"
	CodeIDRange       = "id_range"
	CodeCompileFailed = "compile_failed"
)

// Entry is one rule of a repository with the facts of contract/rules that do
// not depend on mode and state.
type Entry struct {
	ID       string
	Name     string
	Msg      string
	Version  string
	Paranoia int
	File     string
	SecLang  string
	// Input carries origin, settling and, for crowdsec, the decisions. The
	// registry adds the decisions of crs and local.
	Input    rules.Input
	Crowdsec *hub.RuleView
}

// SyncResult is what a sync did.
type SyncResult struct {
	Rules     int
	Unchanged bool
}

// Repository is one source of WAF rules. Every repository implements it; a
// later one (the Schild network, signed CRS packages) comes only through
// schild.yaml and its own decision.
type Repository interface {
	// ID is crs, crowdsec or local.
	ID() string
	// Rules lists every rule the repository has, running or waiting.
	Rules() []Entry
	// Describe fills the repository's own object of the API (crs, crowdsec or
	// local), its name, origin, licence, last change and skipped count.
	Describe(v *RepositoryView, state string)
	// Apply puts the repository's rules into a WAF configuration for its
	// state, without the rules in disabled. Rules that arrive at run time
	// (crowdsec) go through the composer on their own and leave cfg alone.
	Apply(cfg *waf.Config, state string, disabled []int)
	// Sync loads what the repository's source has now; Reset goes back to
	// what the image shipped. ErrNotSupported where it means nothing.
	Sync(ctx context.Context) (SyncResult, error)
	Reset(ctx context.Context) error
}

// Actor is who writes: the dashboard or an agent with its token.
type Actor struct {
	Kind    string // rules.ByDashboard | rules.ByAgent
	TokenID string
	Label   string
}

// Owner is who set the overlay value of a repository's state.
type Owner struct {
	By      string `json:"by"`
	At      string `json:"at"`
	TokenID string `json:"token_id,omitempty"`
	Label   string `json:"label,omitempty"`
}

// TokenRef names an agent token in the APIs.
type TokenRef struct {
	TokenID string `json:"token_id"`
	Label   string `json:"label"`
}

// Counts of a repository.
type Counts struct {
	Rules    int `json:"rules"`
	Disabled int `json:"disabled"`
	Settling int `json:"settling"`
	Skipped  int `json:"skipped"`
}

// RepositoryView is the RuleRepository of both APIs.
type RepositoryView struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	State        string     `json:"state"`
	ConfigState  string     `json:"config_state"`
	StateSource  string     `json:"state_source"`
	StateSetAt   *string    `json:"state_set_at,omitempty"`
	StateSetBy   *TokenRef  `json:"state_set_by,omitempty"`
	Differs      bool       `json:"differs"`
	Effect       string     `json:"effect"`
	LimitedBy    string     `json:"limited_by,omitempty"`
	Origin       string     `json:"origin"`
	Counts       Counts     `json:"counts"`
	LastChangeAt *string    `json:"last_change_at,omitempty"`
	Licence      string     `json:"licence,omitempty"`
	CRS          *CRSInfo   `json:"crs,omitempty"`
	Crowdsec     *hub.Info  `json:"crowdsec,omitempty"`
	Local        *LocalInfo `json:"local,omitempty"`
}

// RepositoryList is the answer of listRuleRepositories.
type RepositoryList struct {
	Items []RepositoryView `json:"items"`
}

// CRSInfo is the crs object of a RuleRepository.
type CRSInfo struct {
	ParanoiaLevel           int `json:"paranoia_level"`
	InboundAnomalyThreshold int `json:"inbound_anomaly_threshold"`
	// The values of schild.yaml or their defaults: what holds without the
	// dashboard (D101).
	ConfigParanoiaLevel           int    `json:"config_paranoia_level"`
	ConfigInboundAnomalyThreshold int    `json:"config_inbound_anomaly_threshold"`
	LivewireException             bool   `json:"livewire_exception"`
	Version                       string `json:"version"`
}

// CRSSettings are the values of the crs repository the dashboard sets
// (D101). Zero: not set, schild.yaml or the built-in default holds.
type CRSSettings struct {
	ParanoiaLevel           int
	InboundAnomalyThreshold int
}

// SettingsPatch is the body of updateRuleRepositorySettings. A field left
// out falls back to schild.yaml or the built-in default.
type SettingsPatch struct {
	ParanoiaLevel           *int `json:"paranoia_level,omitempty"`
	InboundAnomalyThreshold *int `json:"inbound_anomaly_threshold,omitempty"`
}

// Check returns the settings of the body; field names the first value
// outside the bounds of the config schema.
func (p SettingsPatch) Check() (s CRSSettings, field string) {
	if p.ParanoiaLevel != nil {
		if *p.ParanoiaLevel < 1 || *p.ParanoiaLevel > 4 {
			return s, "paranoia_level"
		}
		s.ParanoiaLevel = *p.ParanoiaLevel
	}
	if p.InboundAnomalyThreshold != nil {
		if *p.InboundAnomalyThreshold < 1 || *p.InboundAnomalyThreshold > 100 {
			return s, "inbound_anomaly_threshold"
		}
		s.InboundAnomalyThreshold = *p.InboundAnomalyThreshold
	}
	return s, ""
}

// LocalInfo is the local object of a RuleRepository.
type LocalInfo struct {
	Dir          string      `json:"dir"`
	Files        []LocalFile `json:"files"`
	LastReloadAt *string     `json:"last_reload_at,omitempty"`
	LastError    string      `json:"last_error,omitempty"`
}

// LocalFile is one file of rules.d.
type LocalFile struct {
	Name  string `json:"name"`
	Rules int    `json:"rules"`
}

// RepositoryPatch is the body of updateRuleRepository: exactly one of state
// and reset_state.
type RepositoryPatch struct {
	State      *string `json:"state,omitempty"`
	ResetState *bool   `json:"reset_state,omitempty"`
}

// Check returns the requested state or the reset; ok is false for a body the
// contract does not allow.
func (p RepositoryPatch) Check() (state string, reset, ok bool) {
	switch {
	case p.State != nil && p.ResetState == nil:
		s := *p.State
		return s, false, s == rules.StateOff || s == rules.StateDetect || s == rules.StateBlock
	case p.State == nil && p.ResetState != nil && *p.ResetState:
		return "", true, true
	}
	return "", false, false
}

// Rule is one rule of the APIs.
type Rule struct {
	Repository    string        `json:"repository"`
	ID            string        `json:"id"`
	Name          string        `json:"name,omitempty"`
	Msg           string        `json:"msg,omitempty"`
	Version       string        `json:"version,omitempty"`
	Origin        string        `json:"origin"`
	Status        string        `json:"status"`
	Effect        string        `json:"effect"`
	LimitedBy     string        `json:"limited_by,omitempty"`
	DisabledBy    string        `json:"disabled_by,omitempty"`
	Hits24h       int64         `json:"hits_24h"`
	MatchShare24h *float64      `json:"match_share_24h,omitempty"`
	ParanoiaLevel int           `json:"paranoia_level,omitempty"`
	Crowdsec      *hub.RuleView `json:"crowdsec,omitempty"`
}

// RuleDetail is one rule with its SecLang and the decisions on it.
type RuleDetail struct {
	Rule
	SecLang   string     `json:"seclang,omitempty"`
	File      string     `json:"file,omitempty"`
	Decisions []Decision `json:"decisions,omitempty"`
}

// Decision is a decision on a rule in the APIs.
type Decision struct {
	Kind    string    `json:"kind"`
	Version string    `json:"version,omitempty"`
	By      string    `json:"by"`
	Token   *TokenRef `json:"token,omitempty"`
	Note    string    `json:"note,omitempty"`
	At      string    `json:"at,omitempty"`
}

// RulePage is one page of listRules.
type RulePage struct {
	Items      []Rule  `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// RulePatch is the body of updateRule.
type RulePatch struct {
	Disabled *bool  `json:"disabled"`
	Note     string `json:"note,omitempty"`
}

// MaxNote bounds the note of a decision.
const MaxNote = 500

// ErrCursor: a cursor that is not one of this list.
var ErrCursor = errors.New("ruleset: bad cursor")

// Page cuts one page of limit rules at cursor ("" or "o<offset>").
func Page(items []Rule, cursor string, limit int) (RulePage, error) {
	off := 0
	if cursor != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(cursor, "o"))
		if err != nil || n < 0 || !strings.HasPrefix(cursor, "o") {
			return RulePage{}, ErrCursor
		}
		off = n
	}
	page := RulePage{Items: []Rule{}}
	if off < len(items) {
		end := min(off+limit, len(items))
		page.Items = append(page.Items, items[off:end]...)
		if end < len(items) {
			c := "o" + strconv.Itoa(end)
			page.NextCursor = &c
		}
	}
	return page, nil
}
