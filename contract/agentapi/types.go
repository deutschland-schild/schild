package agentapi

// Wire types of gateway-agent.openapi.yaml. No field carries a full IP
// address: clients are ClientPseudonym pseudonyms and ClientNet networks.
// Untrusted fields are Sanitize'd and capped by the gateway.

// Geo of a client without the city.
type Geo struct {
	Country  string `json:"country"`
	ASN      uint32 `json:"asn"`
	ASOrg    string `json:"as_org,omitempty"`
	NetClass string `json:"net_class"`
}

// RuleMatch is a matched rule of an event (detail only).
type RuleMatch struct {
	ID         string `json:"id"`
	Repository string `json:"repository"`    // crs | local | crowdsec
	Msg        string `json:"msg,omitempty"` // untrusted
	Severity   string `json:"severity,omitempty"`
	// Crowdsec: which CrowdSec Hub rule matched; only with repository
	// crowdsec. Third-party text.
	Crowdsec *CrowdsecRule `json:"crowdsec,omitempty"`
}

// CrowdsecRule names a CrowdSec Hub rule.
type CrowdsecRule struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Label   string   `json:"label,omitempty"` // untrusted
	CVEs    []string `json:"cves,omitempty"`
}

// Event is an event for agents.
type Event struct {
	ID              string   `json:"id"`
	Time            string   `json:"time"`
	Type            string   `json:"type"`
	Outcome         string   `json:"outcome,omitempty"`
	ClientPseudonym string   `json:"client_pseudonym,omitempty"`
	ClientNet       string   `json:"client_net,omitempty"`
	Geo             *Geo     `json:"geo,omitempty"`
	Method          string   `json:"method,omitempty"`
	Site            string   `json:"site,omitempty"`       // v0.5 (D36)
	Host            string   `json:"host,omitempty"`       // untrusted
	Path            string   `json:"path,omitempty"`       // untrusted
	UserAgent       string   `json:"user_agent,omitempty"` // untrusted
	Status          int      `json:"status,omitempty"`
	Score           int      `json:"score,omitempty"`
	Rules           []string `json:"rules,omitempty"`
	Incident        string   `json:"incident,omitempty"`
	Sampled         bool     `json:"sampled,omitempty"`
	// WouldBlockReason (v0.5, D36 open items): why a would_block request
	// was passed.
	WouldBlockReason string      `json:"would_block_reason,omitempty"`
	DurationMS       *float64    `json:"duration_ms,omitempty"`
	WAFMS            *float64    `json:"waf_ms,omitempty"`
	Summary          string      `json:"summary,omitempty"`
	Matches          []RuleMatch `json:"matches,omitempty"`
}

// EventPage is the answer of listAgentEvents.
type EventPage struct {
	Items      []Event `json:"items"`
	NextCursor *string `json:"next_cursor"`
	ScanCapped bool    `json:"scan_capped"`
}

// Incident is an incident for agents.
type Incident struct {
	Incident        string   `json:"incident"`
	Status          string   `json:"status"` // blocked | unblocked
	Time            string   `json:"time"`
	EventID         string   `json:"event_id"`
	ClientPseudonym string   `json:"client_pseudonym,omitempty"`
	ClientNet       string   `json:"client_net,omitempty"`
	Reason          string   `json:"reason,omitempty"` // untrusted
	Sources         []string `json:"sources"`
	// v0.5 (D36): the website of the blocked request and the websites the
	// client touched (blocks themselves are gateway-wide).
	Site          string         `json:"site,omitempty"`
	SitesAffected *SitesAffected `json:"sites_affected,omitempty"`
	UnblockedAt   *string        `json:"unblocked_at,omitempty"`
	// v0.5 (D38): aggregated incidents (per client, rule key and minute).
	Count     int64  `json:"count,omitempty"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	// D42: the timed block behind the incident; shows who set it.
	Block *IncidentBlock `json:"block,omitempty"`
}

// IncidentPage is the answer of listAgentIncidents.
type IncidentPage struct {
	Items      []Incident `json:"items"`
	NextCursor *string    `json:"next_cursor"`
	ScanCapped bool       `json:"scan_capped"`
}

// Request is a request of the ring for agents (v0.5, MVP-22): the
// client dashboard record with the visitor as VisitorPseudonym; host, path
// and referrer are Sanitize'd and capped.
type Request struct {
	T            string   `json:"t"`
	Site         string   `json:"site"`
	Host         string   `json:"host"` // untrusted
	Path         string   `json:"path"` // untrusted
	PathKind     string   `json:"path_kind"`
	Method       string   `json:"method"`
	Status       int      `json:"status"`
	Outcome      string   `json:"outcome"`
	AnomalyScore int      `json:"anomaly_score"`
	Rules        []string `json:"rules,omitempty"`
	EventID      string   `json:"event_id,omitempty"`
	Country      string   `json:"country"`
	ASN          uint32   `json:"asn"`
	NetClass     string   `json:"net_class,omitempty"`
	Browser      string   `json:"browser"`
	OS           string   `json:"os"`
	Device       string   `json:"device"`
	Bot          string   `json:"bot,omitempty"`
	BotCategory  string   `json:"bot_category"`
	Verification string   `json:"verification,omitempty"`
	Referrer     string   `json:"referrer"` // untrusted
	DurationMS   float64  `json:"duration_ms"`
	BytesOut     uint32   `json:"bytes_out"`
	PageView     bool     `json:"page_view"`
	Visitor      string   `json:"visitor"` // VisitorPseudonym
}

// RequestPage is the answer of queryRequests.
type RequestPage struct {
	From       string    `json:"from"`
	To         string    `json:"to"`
	Items      []Request `json:"items"`
	NextCursor *string   `json:"next_cursor"`
	Scanned    int       `json:"scanned"`
	ScanCapped bool      `json:"scan_capped"`
	SampleRate float64   `json:"sample_rate"`
}

// VisitorSummary counts the requests of the visitor in a context window.
type VisitorSummary struct {
	Requests  int    `json:"requests"`
	PageViews int    `json:"page_views"`
	Status2xx int    `json:"status_2xx"`
	Alerts    int    `json:"alerts"`
	Pattern   string `json:"pattern"`
}

// StripPoint is one 10 s step of the site-wide strip.
type StripPoint struct {
	T          string `json:"t"`
	Requests   int64  `json:"requests"`
	Stopped    int64  `json:"stopped"`
	WouldBlock int64  `json:"would_block"`
	Detections int64  `json:"detections"`
}

// RequestContext is the answer of getRequestContext.
type RequestContext struct {
	EventID         string          `json:"event_id"`
	State           string          `json:"state"`
	From            string          `json:"from"`
	To              string          `json:"to"`
	Anchor          *Request        `json:"anchor"`
	VisitorRequests []Request       `json:"visitor_requests"`
	Truncated       bool            `json:"truncated"`
	VisitorSummary  *VisitorSummary `json:"visitor_summary,omitempty"`
	SiteStrip       []StripPoint    `json:"site_strip"`
	SitesAffected   *SitesAffected  `json:"sites_affected,omitempty"` // v0.5 (D36)
}

// TokenInfo describes the calling token (never the token itself).
type TokenInfo struct {
	ID        string `json:"id"`
	Scope     string `json:"scope"`
	Label     string `json:"label,omitempty"`
	ExpiresAt string `json:"expires_at"`
}

// SitesAffected (v0.5, D36): which websites of the gateway one client
// touched ("betrifft 3 von 4 Websites"); OpenAPI SitesAffected.
type SitesAffected struct {
	Sites []string `json:"sites"`
	Count int      `json:"count"`
	Total int      `json:"total"`
}
