// Package requests is the v0.5 (MVP-22, D35) contract of the request ring:
// the wire types of the client dashboard tag `requests`
// (contracts/api/client-dashboard.openapi.yaml), the visitor key, the fixed
// outcome and verification values and the caps of the ring and its queries.
// Tests keep the types equal to the OpenAPI schemas.
//
// Nothing in here carries a query string, a full referrer, or a key valid longer
// than a day. A record holds the client address and the user agent (D49, D50),
// for the dashboard of this gateway only.
package requests

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"time"
)

// Outcomes of a request (RequestOutcome), the classes of TrafficCounters.
const (
	Passed           = "passed"
	WouldBlock       = "would_block"
	BlockedWAF       = "blocked_waf"
	BlockedBehaviour = "blocked_behaviour"
	RateLimited      = "rate_limited"
	RejectedLimit    = "rejected_limit"
	FailClosed       = "fail_closed"
	// BlockedCrawler (D57, MVP-29): 403 from the crawler policy of the
	// website. Appended, so stored indices keep their meaning.
	BlockedCrawler = "blocked_crawler"
)

// Outcomes in the order of the OpenAPI enum.
var Outcomes = []string{Passed, WouldBlock, BlockedWAF, BlockedBehaviour, RateLimited, RejectedLimit, FailClosed, BlockedCrawler}

// Visitor patterns (VisitorPattern).
var Patterns = []string{"alert_only", "in_session", "no_alert"}

// Caps of the ring and its queries.
const (
	MaxKeepHours        = 30 * 24 // D66: as long as retention.raw_ip_days may keep an address
	SampleBudgetHours   = 48      // D66: a 10 min segment may use 1/(48 x 6) of max_size_mb before it samples
	DefaultMaxSizeMB    = 512
	SegmentStep         = 10 * time.Minute
	MaxRules            = 3                // rule ids per record
	ContextWindow       = 5 * time.Minute  // before and after the event
	ContextRingBytes    = 16 << 20         // in-memory ring of the last 10 min
	ContextRingWindow   = 10 * time.Minute //
	MaxQueryWindow      = 6 * time.Hour    // dashboard queryRequests
	MaxScan             = 100000           // records read per dashboard request
	MaxContextRequests  = 1000             // RequestContext.visitor_requests
	MaxFalsePositives   = 50
	MaxUserAgentMatched = 512 // bytes of the User-Agent the bot match reads
	StripStep           = 10 * time.Second
)

// Visitor keys. The daily key is 32 random bytes held in memory only and
// replaced at 00:00 UTC and at every start.
const (
	VisitorPrefix = "v1-"
	visitorDomain = "schild-visitor-v1\x00"
)

var visitorRe = regexp.MustCompile(`^v1-[0-9a-f]{16}$`)

// VisitorKey returns the visitor key of a client address under the daily
// key: HMAC-SHA256 over the client key of the behaviour engine (IPv4
// address, IPv6 /64), first 8 bytes as hex.
func VisitorKey(daily []byte, a netip.Addr) string {
	a = a.Unmap()
	p := netip.PrefixFrom(a, a.BitLen())
	if a.Is6() {
		p, _ = a.Prefix(64)
	}
	m := hmac.New(sha256.New, daily)
	m.Write([]byte(visitorDomain + p.String()))
	return VisitorPrefix + hex.EncodeToString(m.Sum(nil)[:8])
}

// ValidVisitorKey reports whether s has the visitor key format.
func ValidVisitorKey(s string) bool { return visitorRe.MatchString(s) }

// Record is one request of the ring (RequestRecord).
type Record struct {
	T            string   `json:"t"`
	IP           string   `json:"ip,omitempty"`
	UserAgent    string   `json:"user_agent,omitempty"`
	Site         string   `json:"site"`
	Host         string   `json:"host"`
	Path         string   `json:"path"`
	PathKind     string   `json:"path_kind"` // template | redacted
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
	Referrer     string   `json:"referrer"`
	DurationMS   float64  `json:"duration_ms"`
	BytesOut     uint32   `json:"bytes_out"`
	PageView     bool     `json:"page_view"`
	Visitor      string   `json:"visitor"`
}

// Page is the answer of queryRequests.
type Page struct {
	From       string   `json:"from"`
	To         string   `json:"to"`
	Items      []Record `json:"items"`
	NextCursor *string  `json:"next_cursor"`
	Scanned    int      `json:"scanned"`
	ScanCapped bool     `json:"scan_capped"`
	SampleRate float64  `json:"sample_rate"`
	KeepHours  int      `json:"keep_hours,omitempty"` // D66: the ring's window
	KeptFrom   *string  `json:"kept_from,omitempty"`  // D66: start of the oldest segment kept
}

// StripPoint is one 10 s step of the site-wide strip.
type StripPoint struct {
	T          string `json:"t"`
	Requests   int64  `json:"requests"`
	Stopped    int64  `json:"stopped"`
	WouldBlock int64  `json:"would_block"`
	Detections int64  `json:"detections"`
}

// VisitorSummary counts the requests of the visitor in the window.
type VisitorSummary struct {
	Requests  int    `json:"requests"`
	PageViews int    `json:"page_views"`
	Status2xx int    `json:"status_2xx"`
	Alerts    int    `json:"alerts"`
	Pattern   string `json:"pattern"`
}

// Context is the answer of getRequestContext.
type Context struct {
	EventID         string          `json:"event_id"`
	State           string          `json:"state"` // complete | sampled | expired
	From            string          `json:"from"`
	To              string          `json:"to"`
	Anchor          *Record         `json:"anchor"`
	VisitorRequests []Record        `json:"visitor_requests"`
	Truncated       bool            `json:"truncated"`
	VisitorSummary  *VisitorSummary `json:"visitor_summary,omitempty"`
	SiteStrip       []StripPoint    `json:"site_strip"`
	// SitesAffected (v0.5, D36): the websites the visitor touched.
	SitesAffected *SitesAffected `json:"sites_affected,omitempty"`
}

// SitesAffected is OpenAPI SitesAffected (v0.5, D36).
type SitesAffected struct {
	Sites []string `json:"sites"`
	Count int      `json:"count"`
	Total int      `json:"total"`
}

// BotCounts are requests per verification state.
type BotCounts struct {
	Verified     int64 `json:"verified"`
	Claimed      int64 `json:"claimed"`
	Mismatch     int64 `json:"mismatch"`
	UnknownStale int64 `json:"unknown_stale"`
}

// Robots is the robots.txt view of one bot (observation only).
type Robots struct {
	Token              string  `json:"token"`
	ReadAt             *string `json:"read_at"`
	DisallowedRequests int64   `json:"disallowed_requests"`
	Respects           string  `json:"respects"` // yes | no | unclear
}

// BotEntry is one bot of the overview.
type BotEntry struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Operator     string    `json:"operator"`
	Category     string    `json:"category"`
	Requests     int64     `json:"requests"`
	BytesOut     int64     `json:"bytes_out"`
	LastSeen     string    `json:"last_seen"`
	Verification BotCounts `json:"verification"`
	Robots       *Robots   `json:"robots,omitempty"`
	// Blocked and WouldBlock (D57, optional, absent = 0): requests the
	// crawler policy of the website blocked, or would have blocked in
	// observe mode or for an allowlisted address.
	Blocked    int64 `json:"blocked,omitempty"`
	WouldBlock int64 `json:"would_block,omitempty"`
}

// CategoryEntry is one bot category of the overview.
type CategoryEntry struct {
	Category string `json:"category"`
	Requests int64  `json:"requests"`
	BytesOut int64  `json:"bytes_out"`
	Bots     int    `json:"bots"`
}

// RangeInfo describes one range snapshot in use.
type RangeInfo struct {
	ID        string `json:"id"`
	Operator  string `json:"operator"`
	FetchedAt string `json:"fetched_at"`
	Stale     bool   `json:"stale"`
	Source    string `json:"source"` // release | bundle | fetch
}

// VerificationSettings are the bots switches as running.
type VerificationSettings struct {
	Ranges      bool `json:"ranges"`
	FCrDNS      bool `json:"fcrdns"`
	RangesFetch bool `json:"ranges_fetch"`
}

// BotOverview is the answer of getBotOverview.
type BotOverview struct {
	From             string               `json:"from"`
	To               string               `json:"to"`
	Site             string               `json:"site,omitempty"`
	CatalogueVersion string               `json:"catalogue_version"`
	Verification     VerificationSettings `json:"verification"`
	Ranges           []RangeInfo          `json:"ranges"`
	Categories       []CategoryEntry      `json:"categories"`
	Bots             []BotEntry           `json:"bots"`
	SampleRate       float64              `json:"sample_rate"`
}

// RulePage is one page a rule fires on.
type RulePage struct {
	Path       string  `json:"path"`
	Detections int64   `json:"detections"`
	Requests   int64   `json:"requests"`
	Rate       float64 `json:"rate"`
}

// RuleClients splits the hit visitors by pattern.
type RuleClients struct {
	Hit       int64 `json:"hit"`
	AlertOnly int64 `json:"alert_only"`
	InSession int64 `json:"in_session"`
}

// RuleAlert is one rule of getRuleAlerts.
type RuleAlert struct {
	RuleID                string      `json:"rule_id"`
	Detections            int64       `json:"detections"`
	Blocked               int64       `json:"blocked"`
	WouldBlock            int64       `json:"would_block"`
	Error                 int64       `json:"error"`
	Pages                 []RulePage  `json:"pages"`
	Clients               RuleClients `json:"clients"`
	PossibleFalsePositive bool        `json:"possible_false_positive"`
}

// RuleAlerts is the answer of getRuleAlerts.
type RuleAlerts struct {
	From       string      `json:"from"`
	To         string      `json:"to"`
	Site       string      `json:"site,omitempty"`
	Resolution string      `json:"resolution"`
	RingFrom   *string     `json:"ring_from"`
	Items      []RuleAlert `json:"items"`
}

// StatusClasses as in the monitoring contract.
type StatusClasses struct {
	S1xx int64 `json:"s1xx"`
	S2xx int64 `json:"s2xx"`
	S3xx int64 `json:"s3xx"`
	S4xx int64 `json:"s4xx"`
	S5xx int64 `json:"s5xx"`
}

// RuleCount is a rule with its detections on a page.
type RuleCount struct {
	RuleID     string `json:"rule_id"`
	Detections int64  `json:"detections"`
}

// PageAlert is one page of getPageAlerts.
type PageAlert struct {
	Path                 string         `json:"path"`
	Requests             int64          `json:"requests"`
	Detections           int64          `json:"detections"`
	Rate                 float64        `json:"rate"`
	Blocked              int64          `json:"blocked"`
	WouldBlock           int64          `json:"would_block"`
	Error                int64          `json:"error"`
	Status               *StatusClasses `json:"status,omitempty"`
	LatencyP95MS         *float64       `json:"latency_p95_ms,omitempty"`
	ObserveFollowedBy2xx *int64         `json:"observe_followed_by_2xx,omitempty"`
	Rules                []RuleCount    `json:"rules,omitempty"`
	Review               bool           `json:"review"`
}

// PageAlerts is the answer of getPageAlerts.
type PageAlerts struct {
	From       string      `json:"from"`
	To         string      `json:"to"`
	Site       string      `json:"site,omitempty"`
	Resolution string      `json:"resolution"`
	RingFrom   *string     `json:"ring_from"`
	Items      []PageAlert `json:"items"`
}

// Exception is a narrow local rule to copy, never applied by schild.
type Exception struct {
	Language string `json:"language"` // seclang
	// Scope (v0.5, D36): website (Host condition with the website's hosts,
	// contract/websites.ExceptionSnippet) or gateway (a website without
	// hosts).
	Scope   string `json:"scope,omitempty"`
	File    string `json:"file"`
	Snippet string `json:"snippet"`
}

// FalsePositiveHint is one "möglicher Fehlalarm".
type FalsePositiveHint struct {
	RuleID           string    `json:"rule_id"`
	Path             string    `json:"path"`
	Target           string    `json:"target,omitempty"`
	Detections       int64     `json:"detections"`
	ClientsHit       int64     `json:"clients_hit"`
	ClientsInSession int64     `json:"clients_in_session"`
	Since            string    `json:"since"`
	Site             string    `json:"site,omitempty"` // v0.5 (D36)
	Exception        Exception `json:"exception"`
}

// FalsePositiveHintList is the answer of listFalsePositiveHints.
type FalsePositiveHintList struct {
	From  string              `json:"from"`
	To    string              `json:"to"`
	Items []FalsePositiveHint `json:"items"`
}
