// Package config loads schild.yaml (client) and lab.yaml (lab):
// YAML 1.2 -> JSON -> contracts/config/*.schema.json -> strict typed decode
// -> defaults -> checks that live in code, not only in the schema
// (test profile never in release builds).
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/bodylimit"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/verify"
)

// Default paths and environment variables (contracts/conventions.md).
const (
	SitePathDefault = "/etc/schild/schild.yaml"
	SitePathEnv     = "SCHILD_CONFIG"
	LabPathDefault  = "/etc/schild-lab/lab.yaml"
	LabPathEnv      = "SCHILD_LAB_CONFIG"
)

// ErrTestProfileInRelease is returned when a release build sees profile test.
var ErrTestProfileInRelease = errors.New("config: profile test is not available in release builds")

// Site is schild.yaml.
type Site struct {
	ConfigVersion int    `json:"config_version"`
	Profile       string `json:"profile"`
	// Mode is not a setting any more (D89): ParseSite sets it to observe for
	// the test profile, in which nothing blocks, and to autoblock otherwise.
	// LegacyMode keeps what schild.yaml said, for the warning at the start.
	Mode        string      `json:"mode"`
	LegacyMode  string      `json:"-"`
	NodeName    string      `json:"node_name"`
	Listen      SiteListen  `json:"listen"`
	Upstream    Upstream    `json:"upstream"`
	Ingress     Ingress     `json:"ingress"`
	WAF         WAF         `json:"waf"`
	Geo         Geo         `json:"geo"`
	Storage     Storage     `json:"storage"`
	Retention   Retention   `json:"retention"`
	Dashboard   Dashboard   `json:"dashboard"`
	Allowlist   []Allow     `json:"allowlist"`
	HostCheck   *HostCheck  `json:"host_check,omitempty"` // v0.3 (MVP-11)
	Behaviour   Behaviour   `json:"behaviour"`            // v0.4 (MVP-17)
	Monitoring  Monitoring  `json:"monitoring"`           // v0.4 (MVP-21)
	AgentAPI    AgentAPI    `json:"agent_api"`            // v0.4 (MVP-21)
	Bots        Bots        `json:"bots"`                 // v0.5 (MVP-22)
	WaitingPage WaitingPage `json:"waiting_page"`         // v0.5 (D37, MVP-23 step 1)
	Rules       Rules       `json:"rules"`                // v0.6 (D73)
	Cluster     Cluster     `json:"cluster"`              // MVP-27, D105
}

// Rules are the rule repositories (D73, contract/rules).
type Rules struct {
	CRS      CRS           `json:"crs"`
	Crowdsec CrowdsecRules `json:"crowdsec"`
	Local    LocalRules    `json:"local"`
}

// Defaults of rules.crs, also what the dashboard falls back to (D101).
const (
	DefaultParanoiaLevel           = 1
	DefaultInboundAnomalyThreshold = 5
)

// CRS is the OWASP CRS repository.
type CRS struct {
	State                   string `json:"state"`
	ParanoiaLevel           int    `json:"paranoia_level"`
	InboundAnomalyThreshold int    `json:"inbound_anomaly_threshold"`
	// LivewireException (D52): built-in exception for /livewire/update, default on.
	LivewireException *bool    `json:"livewire_exception"`
	DisabledRules     []string `json:"disabled_rules"`
}

// CrowdsecRules is the CrowdSec Hub repository (contract/crowdsec,
// contracts/crowdsec-hub.md).
type CrowdsecRules struct {
	State         string   `json:"state"`
	AutoUpdate    *bool    `json:"auto_update"`
	IntervalS     int      `json:"interval_s"`
	Pin           string   `json:"pin"`
	DisabledRules []string `json:"disabled_rules"`
	SettlingS     *int     `json:"settling_s"`
}

// LocalRules is the repository of the operator's files.
type LocalRules struct {
	State         string   `json:"state"`
	Dir           string   `json:"dir"`
	DisabledRules []string `json:"disabled_rules"`
}

// LocalRulesDirDefault is the default of rules.local.dir.
const LocalRulesDirDefault = "/etc/schild/rules.d"

// State returns the state of a repository from schild.yaml with defaults.
func (r *Rules) State(repository string) string {
	switch repository {
	case "crs":
		return r.CRS.State
	case "crowdsec":
		return r.Crowdsec.State
	case "local":
		return r.Local.State
	}
	return ""
}

// Disabled returns the disabled_rules of a repository.
func (r *Rules) Disabled(repository string) []string {
	switch repository {
	case "crs":
		return r.CRS.DisabledRules
	case "crowdsec":
		return r.Crowdsec.DisabledRules
	case "local":
		return r.Local.DisabledRules
	}
	return nil
}

// WaitingPage is the v0.5 (D37, MVP-23 step 1) switch of the waiting page
// for schild's own overload answers (contract/waitingpage).
type WaitingPage struct {
	Enabled *bool `json:"enabled"`
}

// On reports whether the waiting page is served (default true).
func (w *WaitingPage) On() bool { return w.Enabled == nil || *w.Enabled }

type SiteListen struct {
	Proxy     string `json:"proxy"`
	Dashboard string `json:"dashboard"`
	Metrics   string `json:"metrics"`
}

type Upstream struct {
	URL       string `json:"url"`
	TimeoutMS int    `json:"timeout_ms"`
	// SiteHosts (v0.5, D36): public host names of the one website behind
	// the proxy; the first names it (contract/websites).
	SiteHosts []string `json:"site_hosts,omitempty"`
}

// IsZero reports whether no upstream key is set.
func (u Upstream) IsZero() bool {
	return u.URL == "" && u.TimeoutMS == 0 && len(u.SiteHosts) == 0
}

// Ingress is client address handling and, since v0.4 (MVP-19, D31), the
// operator's Caddyfile. With Caddyfile set, listen.proxy and upstream are
// absent (schema) and the Caddyfile decides listeners and backends.
type Ingress struct {
	Caddyfile           string   `json:"caddyfile,omitempty"`
	CaddyStorage        string   `json:"storage,omitempty"`
	UnprotectedSites    []string `json:"unprotected_sites,omitempty"`
	TrustedProxies      []string `json:"trusted_proxies"`
	ClientIPHeaders     []string `json:"client_ip_headers"`
	ExposeServerHeaders bool     `json:"expose_server_headers"`
}

type WAF struct {
	RequestBodyLimitBytes int `json:"request_body_limit_bytes"`
	EvalTimeoutMS         int `json:"eval_timeout_ms"`
	// v0.4 addendum (2026-10-28): bounded WAF evaluation. MaxConcurrentEvals
	// 0 = derived at run time (GOMAXPROCS, at least 2). The environment
	// variables SCHILD_WAF_MAX_EVALS and SCHILD_WAF_QUEUE_WAIT_MS stay as
	// overrides for the test lab and win over these keys.
	MaxConcurrentEvals int `json:"max_concurrent_evals,omitempty"`
	QueueWaitMS        int `json:"queue_wait_ms"`
	// v0.5 (D41): resource limits of request bodies (contract/bodylimit).
	Body WAFBody `json:"body"`
	// v0.5 (D45): requests waiting for the backend (contract/bodylimit).
	Requests WAFRequests `json:"requests"`
	// v0.5 (D46): open connections (contract/bodylimit).
	Connections       WAFConnections `json:"connections"`
	RawBodyLimitBytes int64          `json:"raw_body_limit_bytes"`
}

// WAFConnections limits the open connections (D46). MaxOpen 0 = derived from the
// memory at run time (bodylimit.ConnLimit).
type WAFConnections struct {
	MaxPerClient  int `json:"max_per_client"`
	MaxPerNetwork int `json:"max_per_network"`
	MaxOpen       int `json:"max_open,omitempty"`
}

// WAFRequests limits the requests waiting for the backend (D45). MaxWaiting 0 =
// derived from the memory at run time (bodylimit.RequestLimit).
type WAFRequests struct {
	MaxWaitingPerClient  int `json:"max_waiting_per_client"`
	MaxWaitingPerNetwork int `json:"max_waiting_per_network"`
	MaxWaiting           int `json:"max_waiting,omitempty"`
}

// WAFBody limits the request bodies being read (D41). MaxInFlight 0 = derived
// from the memory at run time (bodylimit.InFlightLimit).
type WAFBody struct {
	MaxPerClient     int   `json:"max_per_client"`
	MaxPerNetwork    int   `json:"max_per_network"`
	MaxInFlight      int   `json:"max_in_flight,omitempty"`
	MaxInFlightBytes int64 `json:"max_in_flight_bytes"`
	// D44: memory of bodies waiting for the backend. MaxWaitingBytes 0 =
	// derived from the memory at run time (bodylimit.WaitingLimit).
	MaxWaitingBytesPerClient  int64 `json:"max_waiting_bytes_per_client"`
	MaxWaitingBytesPerNetwork int64 `json:"max_waiting_bytes_per_network"`
	MaxWaitingBytes           int64 `json:"max_waiting_bytes,omitempty"`
	// D45: large bodies being read. 0 = derived from the memory at run time
	// (bodylimit.LargeInFlightLimit).
	MaxLargeInFlight int `json:"max_large_in_flight,omitempty"`
}

// Geo is the local geo lookup. v0.5 (MVP-22, D35): with Provider ipinfo or
// maxmind the gateway downloads the provider's database with the operator's
// own token (from TokenFile or $SCHILD_GEO_TOKEN, never from schild.yaml).
type Geo struct {
	DBPath       string   `json:"db_path"`
	Provider     string   `json:"provider,omitempty"`
	TokenFile    string   `json:"token_file,omitempty"`
	Database     []string `json:"database,omitempty"`
	RefreshHours int      `json:"refresh_hours,omitempty"`
}

// Geo providers and defaults (v0.5).
const (
	GeoDBIP             = "dbip"
	GeoIPInfo           = "ipinfo"
	GeoMaxMind          = "maxmind"
	GeoTokenEnv         = "SCHILD_GEO_TOKEN"
	DefaultGeoRefreshHr = 24
)

// GeoDefaultDatabases per downloading provider.
var GeoDefaultDatabases = map[string][]string{
	GeoIPInfo:  {"ipinfo_lite"},
	GeoMaxMind: {"GeoLite2-Country", "GeoLite2-ASN"},
}

// Downloads reports whether the gateway downloads a database (BYOK).
func (g *Geo) Downloads() bool { return g.Provider == GeoIPInfo || g.Provider == GeoMaxMind }

func (g *Geo) defaults() {
	orStr(&g.DBPath, "/var/lib/schild/geo/geo.mmdb")
	orStr(&g.Provider, GeoDBIP)
	if g.Downloads() {
		orInt(&g.RefreshHours, DefaultGeoRefreshHr)
		if len(g.Database) == 0 {
			g.Database = append([]string(nil), GeoDefaultDatabases[g.Provider]...)
		}
	}
}

type Storage struct {
	Path string `json:"path"`
}

type Retention struct {
	RawIPDays     int `json:"raw_ip_days"`
	EventsDays    int `json:"events_days"`
	MaxSizeMB     int `json:"max_size_mb"`
	SummariesDays int `json:"summaries_days"`
}

type Dashboard struct {
	Enabled           *bool `json:"enabled"`
	SessionTTLMinutes int   `json:"session_ttl_minutes"`
	// AllowedHosts are further host names under which the dashboard is
	// opened (D76). localhost, IP addresses and the host of listen.dashboard
	// need no entry.
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
}

// HostCheck is the v0.3 server check and agent section (host-check.md).
type HostCheck struct {
	ReportDir   string      `json:"report_dir"`
	KeepReports int         `json:"keep_reports"`
	Agents      AgentConfig `json:"agents"`
}

// AgentConfig is the gateway side of `schild-agent`.
type AgentConfig struct {
	Enabled              *bool      `json:"enabled"`
	Listen               string     `json:"listen"`
	TLSCert              string     `json:"tls_cert,omitempty"`
	TLSKey               string     `json:"tls_key,omitempty"`
	IntervalMinutes      int        `json:"interval_minutes"`
	EnrolmentCodeMinutes int        `json:"enrolment_code_minutes"`
	Keys                 []AgentKey `json:"keys"`
}

// AgentKey is an agent enrolled by explicit public key.
type AgentKey struct {
	KeyID     string `json:"keyid"`
	PublicKey string `json:"public_key"`
	Hostname  string `json:"hostname,omitempty"`
	Revoked   bool   `json:"revoked,omitempty"`
}

type Allow struct {
	IP      string `json:"ip,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	Host    string `json:"host,omitempty"`
	Label   string `json:"label"`
	Level   string `json:"level"`
	Expires string `json:"expires"`
}

func boolp(b bool) *bool      { return &b }
func intp(i int) *int         { return &i }
func f64p(f float64) *float64 { return &f }
func orStr(s *string, d string) {
	if *s == "" {
		*s = d
	}
}
func orInt(i *int, d int) {
	if *i == 0 {
		*i = d
	}
}

func (s *Site) defaults() {
	orStr(&s.Profile, "production")
	if !s.CaddyIngress() {
		// The plain proxy only exists without a Caddyfile.
		orStr(&s.Listen.Proxy, "0.0.0.0:8080")
		orInt(&s.Upstream.TimeoutMS, 30000)
	}
	orStr(&s.Listen.Dashboard, "127.0.0.1:8788")
	orStr(&s.Listen.Metrics, "127.0.0.1:9101")
	if s.Ingress.TrustedProxies == nil {
		s.Ingress.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
	}
	orInt(&s.WAF.RequestBodyLimitBytes, 13107200)
	orInt(&s.WAF.EvalTimeoutMS, 1000)
	orInt(&s.WAF.QueueWaitMS, 100)
	orInt(&s.WAF.Body.MaxPerClient, bodylimit.DefaultMaxPerClient)
	orInt(&s.WAF.Body.MaxPerNetwork, bodylimit.DefaultMaxPerNetwork)
	if s.WAF.Body.MaxInFlightBytes == 0 {
		s.WAF.Body.MaxInFlightBytes = bodylimit.DefaultMaxInFlightBytes
	}
	if s.WAF.Body.MaxWaitingBytesPerClient == 0 {
		s.WAF.Body.MaxWaitingBytesPerClient = bodylimit.DefaultMaxWaitingBytesPerClient
	}
	if s.WAF.Body.MaxWaitingBytesPerNetwork == 0 {
		s.WAF.Body.MaxWaitingBytesPerNetwork = bodylimit.DefaultMaxWaitingBytesPerNetwork
	}
	orInt(&s.WAF.Requests.MaxWaitingPerClient, bodylimit.DefaultMaxWaitingPerClient)
	orInt(&s.WAF.Requests.MaxWaitingPerNetwork, bodylimit.DefaultMaxWaitingPerNetwork)
	orInt(&s.WAF.Connections.MaxPerClient, bodylimit.DefaultMaxConnsPerClient)
	orInt(&s.WAF.Connections.MaxPerNetwork, bodylimit.DefaultMaxConnsPerNetwork)
	if s.WAF.RawBodyLimitBytes == 0 {
		s.WAF.RawBodyLimitBytes = bodylimit.DefaultRawLimitBytes
	}
	s.Geo.defaults()
	s.Bots.defaults() // v0.5 (MVP-22)
	orStr(&s.Storage.Path, "/var/lib/schild")
	orInt(&s.Retention.RawIPDays, 14)
	orInt(&s.Retention.EventsDays, 14)
	orInt(&s.Retention.MaxSizeMB, 100)
	orInt(&s.Retention.SummariesDays, 90)
	if s.Dashboard.Enabled == nil {
		s.Dashboard.Enabled = boolp(true)
	}
	orInt(&s.Dashboard.SessionTTLMinutes, 720)
	s.Behaviour.defaults()
	s.Monitoring.defaults()
	s.AgentAPI.defaults()
	if s.WaitingPage.Enabled == nil {
		s.WaitingPage.Enabled = boolp(true) // D37: default on (decided by the initiator 2026-10-29)
	}
	s.Rules.defaults()
	if h := s.HostCheck; h != nil {
		orStr(&h.ReportDir, "/var/lib/schild/host-check")
		orInt(&h.KeepReports, 30)
		if h.Agents.Enabled == nil {
			h.Agents.Enabled = boolp(false)
		}
		// No default for agents.listen: the agent listener only starts on
		// an address the operator chose (v0.3 amendment, host-check.md 6).
		orInt(&h.Agents.IntervalMinutes, 1440)
		orInt(&h.Agents.EnrolmentCodeMinutes, 30)
	}
}

// defaults of the rule repositories (D73): crs and local block, crowdsec
// detects, also in automatic blocking mode.
func (r *Rules) defaults() {
	orStr(&r.CRS.State, "block")
	orInt(&r.CRS.ParanoiaLevel, DefaultParanoiaLevel)
	orInt(&r.CRS.InboundAnomalyThreshold, DefaultInboundAnomalyThreshold)
	if r.CRS.LivewireException == nil {
		r.CRS.LivewireException = boolp(true)
	}
	orStr(&r.Crowdsec.State, "detect")
	if r.Crowdsec.AutoUpdate == nil {
		r.Crowdsec.AutoUpdate = boolp(true)
	}
	orInt(&r.Crowdsec.IntervalS, 3600)
	if r.Crowdsec.SettlingS == nil {
		r.Crowdsec.SettlingS = intp(86400)
	}
	orStr(&r.Local.State, "block")
	orStr(&r.Local.Dir, LocalRulesDirDefault)
}

// ParseSite parses schild.yaml bytes.
func ParseSite(b []byte) (*Site, error) {
	j, err := YAMLToJSON(b)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	return ParseSiteJSON(j)
}

// ParseSiteJSON parses the JSON form (used by the dashboard settings API).
func ParseSiteJSON(j []byte) (*Site, error) {
	v, err := verify.Document(verify.DocConfigSite, j, &verify.Context{})
	if err != nil {
		return nil, err
	}
	var s Site
	if err := jsonx.Decode(v, &s); err != nil {
		return nil, contract.Errf(contract.CodeSchema, "%v", err)
	}
	s.dropMode() // before the defaults: an old mode observe fills only what rules leaves open
	s.defaults()
	if err := s.check(); err != nil {
		return nil, err
	}
	return &s, nil
}

// ModeObserve and ModeAutoblock are the values of Site.Mode (D89).
const (
	ModeObserve   = "observe"
	ModeAutoblock = "autoblock"
)

// dropMode turns the old protection mode into what it means now (D89). The
// test profile observes: nothing blocks. An old mode observe sets the rule
// repositories that rules leaves open to detect, so a gateway that only
// watched does not start to block after an update; autoblock and review mean
// nothing any more.
func (s *Site) dropMode() {
	s.LegacyMode = s.Mode
	if s.LegacyMode == ModeObserve && s.Profile != "test" {
		orStr(&s.Rules.CRS.State, "detect")
		orStr(&s.Rules.Crowdsec.State, "detect")
		orStr(&s.Rules.Local.State, "detect")
	}
	s.Mode = ModeAutoblock
	if s.Profile == "test" {
		s.Mode = ModeObserve
	}
}

// ModeWarning says what happened to an old mode in schild.yaml, "" when
// there was none (D89).
func (s *Site) ModeWarning() string {
	switch {
	case s.LegacyMode == "":
		return ""
	case s.LegacyMode == ModeObserve && s.Profile != "test":
		return "schild.yaml: mode is gone (D89); mode observe now sets every rule repository that rules does not set to detect. Remove mode and set rules.<repository>.state instead"
	}
	return "schild.yaml: mode is gone (D89) and ignored; every rule repository, scenario and limit has its own switch. Remove the line mode"
}

// ChallengeWarning names the scenarios schild.yaml set to the old mode
// challenge, "" when there are none (D92).
func (s *Site) ChallengeWarning() string {
	if len(s.Behaviour.LegacyChallenge) == 0 {
		return ""
	}
	return "schild.yaml: behaviour mode challenge is gone (D92) and read as observe for " + strings.Join(s.Behaviour.LegacyChallenge, ", ") + "; set block or observe instead"
}

// Warnings collects what schild.yaml says that no longer applies (D89, D92).
func (s *Site) Warnings() []string {
	var out []string
	for _, w := range []string{s.ModeWarning(), s.ChallengeWarning()} {
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}

// LoadSite reads path, or $SCHILD_CONFIG, or the default path.
func LoadSite(path string) (*Site, error) {
	if path == "" {
		path = os.Getenv(SitePathEnv)
	}
	if path == "" {
		path = SitePathDefault
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > contract.MaxConfigBytes {
		return nil, contract.Errf(contract.CodeOversize, "%s: %d bytes", path, len(b))
	}
	s, err := ParseSite(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// check enforces rules in code, independent of the schema.
func (s *Site) check() error {
	if s.Profile == "test" {
		if keys.Release {
			return ErrTestProfileInRelease
		}
	}
	if err := s.checkWAFBody(); err != nil {
		return err
	}
	if s.CaddyIngress() {
		if !s.Upstream.IsZero() || s.Listen.Proxy != "" {
			return contract.Errf(contract.CodeConfig, "ingress.caddyfile with upstream or listen.proxy")
		}
	} else if s.Upstream.URL == "" {
		return contract.Errf(contract.CodeConfig, "upstream required without ingress.caddyfile")
	}
	if err := s.Monitoring.check(); err != nil {
		return err
	}
	if err := s.checkAgentAPI(); err != nil {
		return err
	}
	if err := s.Cluster.check(); err != nil {
		return err
	}
	return s.Behaviour.check()
}

// CaddyIngress reports whether `schild run` loads the operator's Caddyfile
// instead of proxying listen.proxy to upstream (v0.4, MVP-19).
func (s *Site) CaddyIngress() bool {
	return s.Ingress.Caddyfile != ""
}

// AgentTrust returns the agents enrolled by explicit public key in
// host_check.agents.keys (purpose agent) and the set of revoked key ids.
// Agents enrolled by one-time code live in the gateway's state and are added
// by the caller. Release builds refuse test keys here.
func (s *Site) AgentTrust() (*keys.TrustStore, map[string]bool, error) {
	ts := keys.NewTrustStore()
	revoked := map[string]bool{}
	if s.HostCheck == nil {
		return ts, revoked, nil
	}
	for _, k := range s.HostCheck.Agents.Keys {
		pub, err := keys.ParsePublicKey(k.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("agent key %s: %w", k.KeyID, err)
		}
		if err := ts.Add(keys.TrustedKey{KeyID: k.KeyID, Public: pub, Purposes: []contract.Purpose{contract.PurposeAgent}}); err != nil {
			return nil, nil, err
		}
		if k.Revoked {
			revoked[k.KeyID] = true
		}
	}
	return ts, revoked, nil
}

// checkWAFBody: the body limits nest (D41), and one body of the largest size
// must fit max_in_flight_bytes, a multipart body counted twice.
func (s *Site) checkWAFBody() error {
	b := s.WAF.Body
	if msg := bodylimit.CheckConfig(b.MaxPerClient, b.MaxPerNetwork, b.MaxInFlight, b.MaxInFlightBytes, int64(s.WAF.RequestBodyLimitBytes),
		b.MaxWaitingBytesPerClient, b.MaxWaitingBytesPerNetwork, b.MaxWaitingBytes); msg != "" {
		return contract.Errf(contract.CodeConfig, "%s", msg)
	}
	q := s.WAF.Requests
	if msg := bodylimit.CheckRequests(q.MaxWaitingPerClient, q.MaxWaitingPerNetwork, q.MaxWaiting); msg != "" {
		return contract.Errf(contract.CodeConfig, "%s", msg)
	}
	n := s.WAF.Connections
	if msg := bodylimit.CheckConnections(n.MaxPerClient, n.MaxPerNetwork, n.MaxOpen); msg != "" {
		return contract.Errf(contract.CodeConfig, "%s", msg)
	}
	return nil
}
