package websites

import "github.com/deutschland-schild/schild/contract/monitoring"

// Wire types of the website operations (client dashboard and agent API,
// tag websites). Field names and optionality follow the OpenAPI schemas of
// the same name.

// Website sources.
const (
	SourceCaddyfile = "caddyfile"
	SourceProxy     = "proxy"
)

// StatusReason is OpenAPI WebsiteStatusReason (= Reason).
type StatusReason = Reason

// ServerHealth is one server a website runs on.
type ServerHealth struct {
	Node     string                  `json:"node"`
	This     bool                    `json:"this"`
	Status   string                  `json:"status"`
	Baseline string                  `json:"baseline_protection,omitempty"`
	Hints    []monitoring.HealthHint `json:"hints"`
}

// Summary is OpenAPI WebsiteSummary.
type Summary struct {
	ID         string                 `json:"id"`
	Label      string                 `json:"label"`
	Hosts      []string               `json:"hosts"`
	HostsTotal int                    `json:"hosts_total"`
	Source     string                 `json:"source"`
	Protection string                 `json:"protection"`
	Tracked    bool                   `json:"tracked"`
	Status     string                 `json:"status"`
	Reasons    []Reason               `json:"reasons"`
	Now        *monitoring.TrafficNow `json:"now"`
	RunsOn     []ServerHealth         `json:"runs_on"`
}

// Other sums the untracked websites.
type Other struct {
	Websites int                    `json:"websites"`
	Now      *monitoring.TrafficNow `json:"now"`
}

// List is OpenAPI WebsiteList (listWebsites).
type List struct {
	GeneratedAt string        `json:"generated_at"`
	Node        string        `json:"node"`
	Server      *ServerHealth `json:"server,omitempty"`
	Websites    []Summary     `json:"websites"`
	Other       *Other        `json:"other,omitempty"`
}

// Detail is OpenAPI WebsiteDetail (getWebsite).
type Detail struct {
	GeneratedAt string                      `json:"generated_at"`
	Website     Summary                     `json:"website"`
	Traffic24h  *monitoring.TrafficCounters `json:"traffic_24h"`
	// Traffic24hPartial and Traffic24hSince (D36 open items 2026-10-29):
	// traffic_24h does not cover the full 24 h, and from when it counts.
	Traffic24hPartial bool   `json:"traffic_24h_partial,omitempty"`
	Traffic24hSince   string `json:"traffic_24h_since,omitempty"`
	Incidents24h      int64  `json:"incidents_24h"`
}

// SitesAffected is OpenAPI SitesAffected: which websites one client touched.
type SitesAffected struct {
	Sites []string `json:"sites"`
	Count int      `json:"count"`
	Total int      `json:"total"`
}

// MaxHostsListed in Summary.Hosts.
const MaxHostsListed = 100
