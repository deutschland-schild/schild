package hosts

import "encoding/json"

// API types of the client dashboard API v0.3 (contracts/api/
// client-dashboard.openapi.yaml, schemas HostSummary ... Enrolment). The
// dashboard package serves them unchanged.

// SeverityCounts are open findings by severity.
type SeverityCounts struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Info     int64 `json:"info"`
}

// HostOS is HostSummary.os.
type HostOS struct {
	Name string  `json:"name"`
	EOL  *string `json:"eol"`
}

// HostSummary is one host in the list.
type HostSummary struct {
	ID              string         `json:"id"`
	Hostname        string         `json:"hostname"`
	Role            string         `json:"role"`
	AgentID         *string        `json:"agent_id"`
	Status          string         `json:"status"`
	Silent          bool           `json:"silent"`
	LastReportAt    *string        `json:"last_report_at"`
	ReceivedAt      *string        `json:"received_at"`
	IntervalMinutes *int           `json:"interval_minutes"`
	DurationMS      *int64         `json:"duration_ms"`
	Counts          SeverityCounts `json:"counts"`
	// Accepted: findings of the newest report that are accepted (D102)
	// and therefore not in Counts.
	Accepted   int64   `json:"accepted"`
	Unreadable int64   `json:"unreadable"`
	OS         *HostOS `json:"os"`
}

// HostPage is listHosts.
type HostPage struct {
	Items      []HostSummary `json:"items"`
	NextCursor *string       `json:"next_cursor"`
}

// HostReportRef is one kept report.
type HostReportRef struct {
	ReportID   string         `json:"report_id"`
	StartedAt  string         `json:"started_at"`
	ReceivedAt string         `json:"received_at"`
	Counts     SeverityCounts `json:"counts"`
}

// Rejected is the newest rejected delivery of an agent.
type Rejected struct {
	At     string `json:"at"`
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// HostDetail is getHost. Report is the stored report bytes unchanged.
type HostDetail struct {
	Host         HostSummary     `json:"host"`
	Report       json.RawMessage `json:"report"`
	History      []HostReportRef `json:"history"`
	LastRejected *Rejected       `json:"last_rejected"`
	// Accepted findings of this host (D102), newest first.
	Accepted []AcceptedFinding `json:"accepted"`
	// Annotations (agent hosts only, v0.3 amendment): the gateway's own
	// text per finding, same order as report.findings.
	Annotations []FindingAnnotation `json:"annotations,omitempty"`
}

// FindingAnnotation is the gateway-side text of one agent finding.
type FindingAnnotation struct {
	ID          string  `json:"id"`
	Subject     *string `json:"subject"`
	Title       *string `json:"title"`
	Explanation *string `json:"explanation"`
	FixVerified bool    `json:"fix_verified"`
}

// LocalCheckRun is runLocalCheck.
type LocalCheckRun struct {
	RequestedAt string `json:"requested_at"`
	State       string `json:"state"`
}

// Agent is one enrolled, pending or revoked agent.
type Agent struct {
	ID           string  `json:"id"`
	Hostname     string  `json:"hostname"`
	Label        *string `json:"label"`
	KeyID        string  `json:"keyid"`
	Fingerprint  string  `json:"fingerprint"`
	Status       string  `json:"status"`
	Source       string  `json:"source"`
	CreatedAt    string  `json:"created_at"`
	ConfirmedAt  *string `json:"confirmed_at"`
	RevokedAt    *string `json:"revoked_at"`
	LastReportAt *string `json:"last_report_at"`
	Silent       bool    `json:"silent"`
}

// AgentPage is listAgents.
type AgentPage struct {
	Items      []Agent `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// Enrolment is createEnrolment's answer (the code is shown once).
type Enrolment struct {
	Code        string  `json:"code"`
	ExpiresAt   string  `json:"expires_at"`
	Label       *string `json:"label"`
	GatewayURL  string  `json:"gateway_url"`
	GatewayName string  `json:"gateway_name"`
	GatewayPin  string  `json:"gateway_pin"`
	Command     string  `json:"command"`
}

// ServersSummary is Overview.servers.
type ServersSummary struct {
	// Reported: at least one host has a report. Not part of the API: the
	// overview shows no Server card before the first report (D100), a
	// card saying "keine offenen Befunde" would claim a check that never ran.
	Reported      bool           `json:"-"`
	Hosts         int64          `json:"hosts"`
	Findings      SeverityCounts `json:"findings"`
	Silent        int64          `json:"silent"`
	Unreadable    int64          `json:"unreadable"`
	PendingAgents *int64         `json:"pending_agents,omitempty"`
}
