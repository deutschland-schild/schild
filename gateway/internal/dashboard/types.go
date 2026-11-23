package dashboard

import (
	"encoding/json"

	cr "github.com/deutschland-schild/schild/contract/requests"
	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/ruleset"
)

// The types mirror contracts/api/client-dashboard.openapi.yaml. Nullable
// fields are pointers without omitempty (they are sent as null); optional
// fields use omitempty. The API contract tests validate every response
// against the OpenAPI component schemas.

// Problem is RFC 9457 problem details.
type Problem struct {
	Type     string       `json:"type"`
	Title    string       `json:"title"`
	Status   int          `json:"status"`
	Detail   string       `json:"detail,omitempty"`
	Instance string       `json:"instance,omitempty"`
	Code     string       `json:"code,omitempty"`
	Errors   []FieldError `json:"errors,omitempty"`
}

// FieldError points at an invalid input field.
type FieldError struct {
	Pointer string `json:"pointer"`
	Detail  string `json:"detail"`
}

// Session is the auth state.
type Session struct {
	Authenticated bool   `json:"authenticated"`
	FirstRun      bool   `json:"first_run"`
	User          string `json:"user,omitempty"`
	Role          string `json:"role,omitempty"`
	CSRFToken     string `json:"csrf_token,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	Via           string `json:"via,omitempty"`
}

// SetupRequest sets the first password.
type SetupRequest struct {
	SetupCode string `json:"setup_code,omitempty"`
	Password  string `json:"password"`
}

// LoginRequest logs in.
type LoginRequest struct {
	User     string `json:"user,omitempty"`
	Password string `json:"password"`
}

// PasswordChange changes the password.
type PasswordChange struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// Overview is the start screen.
type Overview struct {
	GeneratedAt string        `json:"generated_at"`
	Profile     string        `json:"profile"`
	Baseline    Baseline      `json:"baseline"`
	Counters24h Counters      `json:"counters_24h"`
	Rules       OverviewRules `json:"rules"`
	GeoDB       *GeoDB        `json:"geo_db,omitempty"`
	Version     string        `json:"version,omitempty"`
	Series24h   *Series24h    `json:"series_24h,omitempty"`
	// Servers is the v0.3 Server card (MVP-11); nil until host_check is
	// configured and implemented.
	Servers *ServersSummary `json:"servers,omitempty"`
}

// ServersSummary is Overview.servers (contracts v0.3, host-check.md).
type ServersSummary struct {
	Hosts         int64          `json:"hosts"`
	Findings      SeverityCounts `json:"findings"`
	Silent        int64          `json:"silent"`
	Unreadable    int64          `json:"unreadable"`
	PendingAgents *int64         `json:"pending_agents,omitempty"`
}

// SeverityCounts counts open findings by severity (contracts v0.3).
type SeverityCounts struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Info     int64 `json:"info"`
}

// Series24h holds hourly counts for the overview sparklines (contracts
// v0.1): 24 buckets each, oldest first, the last ending at generated_at.
type Series24h struct {
	Requests   []int64 `json:"requests"`
	Blocked    []int64 `json:"blocked"`
	WouldBlock []int64 `json:"would_block"`
}

// Baseline is the local baseline protection ("Grundschutz aktiv" in the dashboard).
type Baseline struct {
	State   string   `json:"state"`
	Reasons []Reason `json:"reasons"`
}

// Reason is one degradation reason.
type Reason struct {
	Code  string `json:"code"`
	Since string `json:"since"`
}

// Counters are 24 h counters.
type Counters struct {
	Requests      int64    `json:"requests"`
	Evaluated     int64    `json:"evaluated"`
	Blocked       int64    `json:"blocked"`
	WouldBlock    int64    `json:"would_block"`
	Incidents     int64    `json:"incidents"`
	P95OverheadMS *float64 `json:"p95_overhead_ms,omitempty"`
	// Partial and Since (v0.5, D36 open items): the counters do not cover
	// the full 24 h, and the start of the counted window when later than
	// generated_at - 24 h.
	Partial bool   `json:"partial,omitempty"`
	Since   string `json:"since,omitempty"`
}

// OverviewRules summarises rules.
type OverviewRules struct {
	CRSVersion string `json:"crs_version"`
}

// GeoDB describes the geo database (v0.5: provider and download state, see
// geodb.go; the token is never part of it).
type GeoDB struct {
	Source         string   `json:"source,omitempty"`
	BuiltAt        string   `json:"built_at,omitempty"`
	Provider       string   `json:"provider,omitempty"`
	Databases      []string `json:"databases,omitempty"`
	OptionalFields []string `json:"optional_fields,omitempty"`
	// RefreshedAt only with a downloading provider; null until the first
	// successful download.
	RefreshedAt *NullTime `json:"refreshed_at,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt string    `json:"last_error_at,omitempty"`
}

// Geo of an event.
type Geo struct {
	Country  string `json:"country"`
	City     string `json:"city,omitempty"`
	ASN      uint32 `json:"asn"`
	ASOrg    string `json:"as_org,omitempty"`
	NetClass string `json:"net_class"`
}

// EventSummary is one list row.
type EventSummary struct {
	ID        string   `json:"id"`
	Time      string   `json:"time"`
	Type      string   `json:"type"`
	Outcome   string   `json:"outcome,omitempty"`
	IP        string   `json:"ip,omitempty"`
	Geo       *Geo     `json:"geo,omitempty"`
	Method    string   `json:"method,omitempty"`
	Host      string   `json:"host,omitempty"`
	Path      string   `json:"path,omitempty"`
	Status    *int     `json:"status,omitempty"`
	Score     *int     `json:"score,omitempty"`
	Rules     []string `json:"rules,omitempty"`
	Incident  string   `json:"incident,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
	Site      string   `json:"site,omitempty"`
	// WouldBlockReason (v0.5, D36 open items): why a would_block request
	// was passed; only with outcome would_block.
	WouldBlockReason string `json:"would_block_reason,omitempty"`
	Summary          string `json:"summary,omitempty"`
}

// EventPage is a page of events.
type EventPage struct {
	Items         []EventSummary `json:"items"`
	NextCursor    *string        `json:"next_cursor"`
	TotalEstimate *int           `json:"total_estimate,omitempty"`
}

// EventDetail is one event.
type EventDetail struct {
	Event   json.RawMessage `json:"event"`
	Related []EventSummary  `json:"related,omitempty"`
}

// Incident is a block with its incident number.
type Incident struct {
	Incident       string       `json:"incident"`
	Status         string       `json:"status"`
	Time           string       `json:"time"`
	Request        EventSummary `json:"request"`
	Reason         string       `json:"reason,omitempty"`
	UnblockedAt    *string      `json:"unblocked_at"`
	AllowlistEntry *string      `json:"allowlist_entry"`
	// v0.5 (D36): the website of the blocked request and the websites the
	// client touched; the block itself is gateway-wide.
	Site          string                  `json:"site,omitempty"`
	SitesAffected *websites.SitesAffected `json:"sites_affected,omitempty"`
	// Count, FirstSeen and LastSeen (v0.5, D38): the blocked requests of an
	// aggregated incident (per client, rule key and UTC minute); Request is
	// the first of them.
	Count     int64  `json:"count,omitempty"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	// Block (D36 amendment 2026-10-29) is the timed block behind a
	// behaviour incident: how long and why. nil for a single request the
	// WAF blocked.
	Block *BehaviourBlock `json:"block,omitempty"`
}

// UnblockRequest unblocks an incident.
type UnblockRequest struct {
	FalsePositive bool   `json:"false_positive"`
	AllowIP       bool   `json:"allow_ip"`
	AllowTTL      string `json:"allow_ttl"`
	Note          string `json:"note"`
}

// The rule repositories and their rules (D73): the types of internal/ruleset,
// served unchanged by both APIs.
type (
	RuleRepository     = ruleset.RepositoryView
	RuleRepositoryList = ruleset.RepositoryList
	Rule               = ruleset.Rule
	RuleDetail         = ruleset.RuleDetail
	RulePage           = ruleset.RulePage
)

// AllowlistEntry is one entry.
type AllowlistEntry struct {
	ID        string   `json:"id"`
	IP        string   `json:"ip,omitempty"`
	CIDR      string   `json:"cidr,omitempty"`
	Host      string   `json:"host,omitempty"`
	Resolved  []string `json:"resolved,omitempty"`
	Label     string   `json:"label"`
	Level     string   `json:"level"`
	Expires   string   `json:"expires"`
	Expired   bool     `json:"expired"`
	CreatedAt string   `json:"created_at"`
	Source    string   `json:"source"`
}

// AllowlistPage is a page of entries.
type AllowlistPage struct {
	Items      []AllowlistEntry `json:"items"`
	NextCursor *string          `json:"next_cursor"`
}

// AllowlistInput adds an entry.
type AllowlistInput struct {
	IP            string `json:"ip"`
	CIDR          string `json:"cidr"`
	Host          string `json:"host"`
	Label         string `json:"label"`
	Level         string `json:"level"`
	TTL           string `json:"ttl"`
	ConfirmBypass bool   `json:"confirm_bypass"`
}

// MyIP is the caller's address.
type MyIP struct {
	IP          string `json:"ip"`
	Attribution string `json:"attribution"`
	Allowlisted bool   `json:"allowlisted"`
}

// AllowMineRequest allowlists the caller.
type AllowMineRequest struct {
	Label string `json:"label"`
	TTL   string `json:"ttl"`
}

// Settings are the editable settings.
type Settings struct {
	Profile   string            `json:"profile"`
	Retention SettingsRetention `json:"retention"`
}

// SettingsRetention is retention.
type SettingsRetention struct {
	RawIPDays     int `json:"raw_ip_days"`
	EventsDays    int `json:"events_days"`
	MaxSizeMB     int `json:"max_size_mb"`
	SummariesDays int `json:"summaries_days"`
}

// SettingsPatch is a partial update.
type SettingsPatch struct {
	Retention *RetentionPatch `json:"retention,omitempty"`
}

// RetentionPatch changes retention.
type RetentionPatch struct {
	RawIPDays     *int `json:"raw_ip_days,omitempty"`
	EventsDays    *int `json:"events_days,omitempty"`
	SummariesDays *int `json:"summaries_days,omitempty"`
}

// PrivacySummary is what is stored about one IP.
type PrivacySummary struct {
	IP               string   `json:"ip"`
	Events           int      `json:"events"`
	Sessions         int      `json:"sessions"`
	Incidents        []string `json:"incidents"`
	FirstSeen        *string  `json:"first_seen"`
	LastSeen         *string  `json:"last_seen"`
	IPTruncatedAfter *string  `json:"ip_truncated_after"`
	Allowlisted      bool     `json:"allowlisted"`
}

// PrivacyRequest names an IP.
type PrivacyRequest struct {
	IP string `json:"ip"`
}

// PrivacyExport is the export.
// IncidentExport is the download of one incident (D51).
type IncidentExport struct {
	Incident   Incident          `json:"incident"`
	ExportedAt string            `json:"exported_at"`
	Events     []json.RawMessage `json:"events"`
	Truncated  bool              `json:"truncated"`
	Context    *cr.Context       `json:"context,omitempty"`
}

type PrivacyExport struct {
	IP         string            `json:"ip"`
	ExportedAt string            `json:"exported_at"`
	Events     []json.RawMessage `json:"events"`
	Requests   []cr.Record       `json:"requests,omitempty"`
}

// PrivacyDeleteRequest deletes by IP.
type PrivacyDeleteRequest struct {
	IP            string `json:"ip"`
	Confirm       bool   `json:"confirm"` // set by the UI after its dialog, no password
	KeepIncidents bool   `json:"keep_incidents"`
}

// PrivacyDeleteResult counts deletions.
type PrivacyDeleteResult struct {
	IP                      string `json:"ip"`
	DeletedEvents           int    `json:"deleted_events"`
	DeletedSessions         int    `json:"deleted_sessions"`
	DeletedAllowlistEntries int    `json:"deleted_allowlist_entries"`
	ErasedRequests          int    `json:"erased_requests,omitempty"`
	// Nodes: in a group, how far the erasure got.
	Nodes *ErasureNodes `json:"nodes,omitempty"`
}
