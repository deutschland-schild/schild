package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
)

// Behaviour is the v0.4 section `behaviour` (MVP-17): fixed scenarios over
// several requests and per-route rate limits. Everything it configures is
// decided and kept locally; nothing from it is ever sent.
type Behaviour struct {
	Presets []string `json:"presets"`
	// PresetLimits is one mode for every preset limit without an entry in
	// PresetLimitModes. Empty: each preset limit takes its recommended mode
	// (D95).
	PresetLimits string `json:"preset_limits,omitempty"`
	// PresetLimitModes is the mode per preset limit id (D95).
	PresetLimitModes map[string]string  `json:"preset_limit_modes,omitempty"`
	Scenarios        BehaviourScenarios `json:"scenarios"`
	RateLimits       []RateLimit        `json:"rate_limits"`
	Distributed      Distributed        `json:"distributed"`
	// LegacyChallenge lists the scenarios schild.yaml set to the old mode
	// challenge, read as observe (D92), for the warning at the start.
	LegacyChallenge []string `json:"-"`
}

// Distributed is behaviour.distributed (v0.4, MVP-18): attacks through
// residential proxies, answered per route or account, never per address.
type Distributed struct {
	LearningDays int                  `json:"learning_days"`
	Routes       []string             `json:"routes,omitempty"`
	Detectors    DistributedDetectors `json:"detectors"`
	Responses    DistributedResponses `json:"responses"`
	Fingerprint  FingerprintConfig    `json:"fingerprint"`
}

// DistributedDetectors holds the five fixed detectors.
type DistributedDetectors struct {
	RouteWave          Detector `json:"route_wave"`
	AccountWave        Detector `json:"account_wave"`
	ShapeWave          Detector `json:"shape_wave"`
	FingerprintCluster Detector `json:"fingerprint_cluster"`
	Inconsistency      Detector `json:"inconsistency"`
}

// Detector is the operator setting of one detector.
type Detector struct {
	Mode       string             `json:"mode"`
	Thresholds DetectorThresholds `json:"thresholds"`
}

// DetectorThresholds (zero = built-in default).
type DetectorThresholds struct {
	Count   int     `json:"count,omitempty"`
	WindowS int     `json:"window_s,omitempty"`
	Factor  float64 `json:"factor,omitempty"`
}

// DistributedResponses configures the time-boxed responses.
type DistributedResponses struct {
	RouteTighten    RouteTighten    `json:"route_tighten"`
	AccountSlowdown AccountSlowdown `json:"account_slowdown"`
}

// RouteTighten is the strict route-wide limit while a wave runs.
type RouteTighten struct {
	Minutes        int `json:"minutes"`
	MaxMinutes     int `json:"max_minutes"`
	LimitPerMinute int `json:"limit_per_minute"`
}

// AccountSlowdown is the growing wait for an attacked account.
type AccountSlowdown struct {
	StartS int `json:"start_s"`
	MaxS   int `json:"max_s"`
}

// FingerprintConfig names the JA4 header of a trusted TLS terminator.
type FingerprintConfig struct {
	JA4Header string `json:"ja4_header,omitempty"`
}

// Distributed modes and detector ids.
const (
	DistributedOff     = "off"
	DistributedObserve = "observe"
	DistributedRespond = "respond"

	DetectorRouteWave          = "route_wave"
	DetectorAccountWave        = "account_wave"
	DetectorShapeWave          = "shape_wave"
	DetectorFingerprintCluster = "fingerprint_cluster"
	DetectorInconsistency      = "inconsistency"
)

// DetectorIDs lists the detectors in display order.
var DetectorIDs = []string{DetectorRouteWave, DetectorAccountWave, DetectorShapeWave, DetectorFingerprintCluster, DetectorInconsistency}

// Get returns the detector by id.
func (d *DistributedDetectors) Get(id string) *Detector {
	switch id {
	case DetectorRouteWave:
		return &d.RouteWave
	case DetectorAccountWave:
		return &d.AccountWave
	case DetectorShapeWave:
		return &d.ShapeWave
	case DetectorFingerprintCluster:
		return &d.FingerprintCluster
	case DetectorInconsistency:
		return &d.Inconsistency
	}
	return nil
}

// BehaviourScenarios holds the five fixed scenarios.
type BehaviourScenarios struct {
	LoginBruteforce    Scenario `json:"login_bruteforce"`
	CredentialStuffing Scenario `json:"credential_stuffing"`
	PathProbing        Scenario `json:"path_probing"`
	AggressiveCrawl    Scenario `json:"aggressive_crawl"`
	WAFRepeat          Scenario `json:"waf_repeat"`
}

// Scenario is the operator setting of one scenario. Zero thresholds mean
// the built-in default of the client.
type Scenario struct {
	Mode       string     `json:"mode"`
	Thresholds Thresholds `json:"thresholds"`
}

// Thresholds of a scenario (all optional).
type Thresholds struct {
	Count          int     `json:"count,omitempty"`
	WindowS        int     `json:"window_s,omitempty"`
	SlowCount      int     `json:"slow_count,omitempty"`
	SlowWindowS    int     `json:"slow_window_s,omitempty"`
	BaselineFactor float64 `json:"baseline_factor,omitempty"`
}

// RateLimit is one token-bucket limit per route and client key.
type RateLimit struct {
	ID              string   `json:"id"`
	Label           string   `json:"label,omitempty"`
	Route           string   `json:"route"`
	Methods         []string `json:"methods,omitempty"`
	Limit           int      `json:"limit"`
	Per             string   `json:"per"`
	Burst           int      `json:"burst"`
	Mode            string   `json:"mode"`
	Site            string   `json:"site,omitempty"`
	ConfirmSiteWide bool     `json:"confirm_site_wide,omitempty"`
}

// Behaviour modes. The old mode challenge (a browser check that was never
// built) is read as observe (D92).
const (
	BehaviourOff     = "off"
	BehaviourObserve = "observe"
	BehaviourBlock   = "block"

	behaviourChallenge = "challenge"
)

// Scenario ids (fixed, MVP-17).
const (
	ScenarioLoginBruteforce    = "login_bruteforce"
	ScenarioCredentialStuffing = "credential_stuffing"
	ScenarioPathProbing        = "path_probing"
	ScenarioAggressiveCrawl    = "aggressive_crawl"
	ScenarioWAFRepeat          = "waf_repeat"
)

// ScenarioIDs lists the scenarios in display order.
var ScenarioIDs = []string{ScenarioLoginBruteforce, ScenarioCredentialStuffing, ScenarioPathProbing, ScenarioAggressiveCrawl, ScenarioWAFRepeat}

// ScenarioRecommended is the recommended mode of every scenario and its
// default when schild.yaml sets none (D92). aggressive_crawl observes: search
// tools, monitoring and offices behind one address crawl fast too.
var ScenarioRecommended = map[string]string{
	ScenarioLoginBruteforce:    BehaviourBlock,
	ScenarioCredentialStuffing: BehaviourBlock,
	ScenarioPathProbing:        BehaviourBlock,
	ScenarioAggressiveCrawl:    BehaviourObserve,
	ScenarioWAFRepeat:          BehaviourBlock,
}

// BehaviourPresets lists every preset (the default when none is configured).
var BehaviourPresets = []string{"wordpress", "joomla", "drupal", "nextcloud", "typo3", "laravel", "generic"}

// Get returns the scenario by id.
func (b *BehaviourScenarios) Get(id string) *Scenario {
	switch id {
	case ScenarioLoginBruteforce:
		return &b.LoginBruteforce
	case ScenarioCredentialStuffing:
		return &b.CredentialStuffing
	case ScenarioPathProbing:
		return &b.PathProbing
	case ScenarioAggressiveCrawl:
		return &b.AggressiveCrawl
	case ScenarioWAFRepeat:
		return &b.WAFRepeat
	}
	return nil
}

func (b *Behaviour) defaults() {
	if len(b.Presets) == 0 {
		b.Presets = append([]string(nil), BehaviourPresets...)
	}
	b.LegacyChallenge = nil
	for _, id := range ScenarioIDs {
		sc := b.Scenarios.Get(id)
		if sc.Mode == behaviourChallenge {
			b.LegacyChallenge = append(b.LegacyChallenge, id)
			sc.Mode = BehaviourObserve
		}
		orStr(&sc.Mode, ScenarioRecommended[id])
	}
	d := &b.Distributed
	orInt(&d.LearningDays, 14)
	for _, id := range DetectorIDs {
		orStr(&d.Detectors.Get(id).Mode, DistributedObserve)
	}
	orInt(&d.Responses.RouteTighten.Minutes, 20)
	orInt(&d.Responses.RouteTighten.MaxMinutes, 120)
	orInt(&d.Responses.RouteTighten.LimitPerMinute, 10)
	orInt(&d.Responses.AccountSlowdown.StartS, 5)
	orInt(&d.Responses.AccountSlowdown.MaxS, 60)
	for i := range b.RateLimits {
		l := &b.RateLimits[i]
		orStr(&l.ID, "config-"+strconv.Itoa(i+1))
		orStr(&l.Mode, BehaviourObserve)
		orInt(&l.Burst, l.Limit)
	}
}

// check enforces what the schema cannot: unique limit ids (also generated
// ones) and the confirm flag for limits on the whole site.
func (b *Behaviour) check() error {
	if r := b.Distributed.Responses; r.RouteTighten.Minutes > r.RouteTighten.MaxMinutes || r.AccountSlowdown.StartS > r.AccountSlowdown.MaxS {
		return contract.Errf(contract.CodeConfig, "distributed responses: minutes above max_minutes or start_s above max_s")
	}
	ids := map[string]bool{}
	for _, l := range b.RateLimits {
		if ids[l.ID] {
			return contract.Errf(contract.CodeConfig, "duplicate rate limit id %q", l.ID)
		}
		ids[l.ID] = true
		if SiteWideRoute(l.Route) && !l.ConfirmSiteWide {
			return contract.Errf(contract.CodeConfig, "rate limit %q applies to the whole site without confirm_site_wide", l.ID)
		}
		if _, err := ParsePer(l.Per); err != nil {
			return contract.Errf(contract.CodeConfig, "rate limit %q: %v", l.ID, err)
		}
	}
	return nil
}

// SiteWideRoute reports whether a route pattern consists of wildcards only
// (schema: ^/*[*][/*]*$), i.e. matches every path of the site.
func SiteWideRoute(route string) bool {
	return strings.Contains(route, "*") && strings.Trim(route, "/*") == ""
}

// ParsePer parses the `per` of a rate limit ("10s", "1m", "1h"; at most 24 h).
func ParsePer(per string) (time.Duration, error) {
	if len(per) < 2 {
		return 0, fmt.Errorf("per %q", per)
	}
	n, err := strconv.Atoi(per[:len(per)-1])
	if err != nil || n < 1 {
		return 0, fmt.Errorf("per %q", per)
	}
	var unit time.Duration
	switch per[len(per)-1] {
	case 's':
		unit = time.Second
	case 'm':
		unit = time.Minute
	case 'h':
		unit = time.Hour
	default:
		return 0, fmt.Errorf("per %q", per)
	}
	d := time.Duration(n) * unit
	if d > 24*time.Hour {
		return 0, fmt.Errorf("per %q longer than 24h", per)
	}
	return d, nil
}
