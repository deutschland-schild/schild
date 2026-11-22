package websites

import (
	"strconv"

	"github.com/deutschland-schild/schild/contract/monitoring"
)

// Wire types of the website overview (v0.5, D36 addendum: modelled on
// Plausible): KPI row, Echtzeit, annotations, "Letzte Alarme". OpenAPI
// schemas of the same name.

// KpiValue is one KPI. Exact says how the number is made (counted from
// every request vs an estimate); Partial (D36 fix round 2026-10-29) says
// the window was not fully covered (a partial bucket, a gap or a schild
// start inside it). The two are independent: a gap never clears Exact.
type KpiValue struct {
	Value   *float64 `json:"value"`
	Exact   bool     `json:"exact"`
	Partial bool     `json:"partial,omitempty"`
	// GapKind (initiator 2026-10-29): only with Partial, GapRestart or
	// GapLost (monitoring); "" = unknown.
	GapKind     string  `json:"gap_kind,omitempty"`
	ErrorBound  float64 `json:"error_bound,omitempty"`
	Unavailable string  `json:"unavailable,omitempty"`
}

// KpiSet is the KPI row of one period. Visitors are people (D36 amendment
// 2026-10-29, monitoring.Visitor): "Besucher ohne erkannte Bots".
type KpiSet struct {
	Visitors     KpiValue `json:"visitors"`
	PageViews    KpiValue `json:"page_views"`
	Requests     KpiValue `json:"requests"`
	Stopped      KpiValue `json:"stopped"`
	WouldBlock   KpiValue `json:"would_block"`
	LatencyP95MS KpiValue `json:"latency_p95_ms"`
	ErrorRate    KpiValue `json:"error_rate"`
}

// Kpis is OpenAPI WebsiteKpis (getWebsiteKpis).
type Kpis struct {
	Site         string   `json:"site"`
	From         string   `json:"from"`
	To           string   `json:"to"`
	PreviousFrom string   `json:"previous_from"`
	PreviousTo   string   `json:"previous_to"`
	Filters      []string `json:"filters,omitempty"`
	Source       string   `json:"source"`
	Current      KpiSet   `json:"current"`
	Previous     KpiSet   `json:"previous"`
	// Cluster: in a group of gateways, the nodes the answer adds up.
	Cluster *monitoring.ClusterScope `json:"cluster,omitempty"`
}

// RealtimePoint is one minute of WebsiteRealtime.
type RealtimePoint struct {
	T          string `json:"t"`
	Requests   int64  `json:"requests"`
	Stopped    int64  `json:"stopped"`
	WouldBlock int64  `json:"would_block"`
	Visitors   *int64 `json:"visitors"`
	Partial    bool   `json:"partial"`
}

// Realtime is OpenAPI WebsiteRealtime (getWebsiteRealtime). Visitors5m and
// the points' Visitors count people only (monitoring.Visitor); requests
// count everything.
type Realtime struct {
	Site         string          `json:"site"`
	GeneratedAt  string          `json:"generated_at"`
	Visitors5m   *int64          `json:"visitors_5m"`
	Requests5m   int64           `json:"requests_5m"`
	Stopped5m    int64           `json:"stopped_5m"`
	WouldBlock5m int64           `json:"would_block_5m"`
	Points       []RealtimePoint `json:"points"`
	// Cluster: in a group of gateways, the nodes the answer adds up.
	Cluster *monitoring.ClusterScope `json:"cluster,omitempty"`
}

// Annotation kinds.
const (
	AnnWaveDetected  = "wave_detected"
	AnnWaveEnded     = "wave_ended"
	AnnIncident      = "incident"
	AnnBlockLong     = "block_long"
	AnnModeChanged   = "mode_changed"
	AnnConfigChanged = "config_changed"
	AnnRestart       = "restart"
	AnnMonitoringGap = "monitoring_gap"
	// AnnRuleRepository (D73): the state of a rule repository changed.
	AnnRuleRepository = "rule_repository_changed"
	// D42: an agent set or lifted a block.
	AnnAgentBlockSet    = "agent_block_set"
	AnnAgentBlockLifted = "agent_block_lifted"
	// MaxAnnotations per listAnnotations answer.
	MaxAnnotations = 200
)

// Annotation is one chart marker.
type Annotation struct {
	T            string `json:"t"`
	Until        string `json:"until,omitempty"`
	Kind         string `json:"kind"`
	Ref          string `json:"ref,omitempty"`
	Detector     string `json:"detector,omitempty"`
	Count        int64  `json:"count,omitempty"`
	NetClass     string `json:"net_class,omitempty"`
	DurationS    int64  `json:"duration_s,omitempty"`
	ModeFrom     string `json:"mode_from,omitempty"`
	ModeTo       string `json:"mode_to,omitempty"`
	ConfigSHA256 string `json:"config_sha256,omitempty"`
	// D73: kind rule_repository_changed.
	Repository string `json:"repository,omitempty"`
	StateFrom  string `json:"state_from,omitempty"`
	StateTo    string `json:"state_to,omitempty"`
	Actor      string `json:"actor,omitempty"`
	TokenLabel string `json:"token_label,omitempty"`
	// Effect (D42): block or would_block on agent_block_set.
	Effect string `json:"effect,omitempty"`
}

// AnnotationList is OpenAPI AnnotationList (listAnnotations).
type AnnotationList struct {
	Site      string       `json:"site"`
	From      string       `json:"from"`
	To        string       `json:"to"`
	Items     []Annotation `json:"items"`
	Truncated bool         `json:"truncated"`
}

// AlertItem is one entry of "Letzte Alarme".
type AlertItem struct {
	T               string   `json:"t"`
	EventID         string   `json:"event_id"`
	Kind            string   `json:"kind"`    // waf | behaviour | rate_limit
	Outcome         string   `json:"outcome"` // blocked | would_block | rate_limited | would_rate_limit
	Category        string   `json:"category"`
	Rules           []string `json:"rules,omitempty"`
	Scenario        string   `json:"scenario,omitempty"`
	Path            string   `json:"path,omitempty"`
	Country         string   `json:"country,omitempty"`
	NetClass        string   `json:"net_class,omitempty"`
	ClientPseudonym string   `json:"client_pseudonym,omitempty"`
	Incident        string   `json:"incident,omitempty"`
	// WouldBlockReason (D36 open items 2026-10-29): why a would_block or
	// would_rate_limit alert was passed (events.WouldBlockReasons).
	WouldBlockReason string `json:"would_block_reason,omitempty"`
	// PossibleFalsePositive (D36 amendment 2026-10-29): a FalsePositiveHint
	// of this website names one of Rules on Path (WAF alerts only).
	PossibleFalsePositive bool `json:"possible_false_positive,omitempty"`
}

// AlertFeed is OpenAPI AlertFeed (listAlerts).
type AlertFeed struct {
	Site    string      `json:"site"`
	Filters []string    `json:"filters,omitempty"`
	Items   []AlertItem `json:"items"`
}

// MaxAlerts per listAlerts answer.
const MaxAlerts = 50

// crsFamilies maps the CRS rule id family (first three digits of a
// six-digit id) to RuleCategory.
var crsFamilies = map[int]string{
	913: "scanner", 920: "protocol", 921: "protocol_attack", 930: "lfi", 931: "rfi", 932: "rce", 933: "php",
	934: "generic", 941: "xss", 942: "sqli", 943: "session_fixation", 944: "java", 949: "anomaly", 959: "anomaly", 980: "anomaly",
}

// RuleCategory returns the short label source of a WAF rule id (OpenAPI
// RuleCategory): the CRS family for six-digit ids 913xxx..980xxx, local
// otherwise.
func RuleCategory(id string) string {
	n, err := strconv.Atoi(id)
	switch {
	case err != nil || n <= 0:
		return "local"
	case n >= 100000 && n <= 999999:
		if c, ok := crsFamilies[n/1000]; ok {
			return c
		}
	}
	return "local"
}
