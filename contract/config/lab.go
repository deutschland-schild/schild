package config

import (
	"fmt"
	"os"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/verify"
)

// LabConfig is lab.yaml.
type LabConfig struct {
	ConfigVersion int          `json:"config_version"`
	Profile       string       `json:"profile"`
	Identity      Identity     `json:"identity"`
	Listen        LabListen    `json:"listen"`
	TLS           *TLS         `json:"tls,omitempty"`
	Channel       string       `json:"channel"`
	Keys          []LabSignKey `json:"keys"`
	Ingest        Ingest       `json:"ingest"`
	Issuers       []Issuer     `json:"issuers"`
	Clients       []Client     `json:"clients"`
	Scoring       Scoring      `json:"scoring"`
	Publish       Publish      `json:"publish"`
	Peers         []Peer       `json:"peers"`
	Storage       Storage      `json:"storage"`
	Retention     LabRetention `json:"retention"`
	Dashboard     Dashboard    `json:"dashboard"`
}

type Identity struct {
	Operator string `json:"operator"`
	Lab      string `json:"lab"`
}

type LabListen struct {
	Ingest    string `json:"ingest"`
	Feed      string `json:"feed"`
	Dashboard string `json:"dashboard"`
	Metrics   string `json:"metrics"`
}

type TLS struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type LabSignKey struct {
	KeyID          string             `json:"keyid"`
	PrivateKeyFile string             `json:"private_key_file"`
	Purposes       []contract.Purpose `json:"purposes"`
}

type Ingest struct {
	MaxBodyBytes        int `json:"max_body_bytes"`
	MaxEnvelopes        int `json:"max_envelopes"`
	RatePerClientPerMin int `json:"rate_per_client_per_min"`
	QueueMaxDepth       int `json:"queue_max_depth"`
	RetryAfterMS        int `json:"retry_after_ms"`
	MaxClockSkewS       int `json:"max_clock_skew_s"`
	MaxSignalAgeS       int `json:"max_signal_age_s"`
	ReplayWindowS       int `json:"replay_window_s"`
}

type Issuer struct {
	ID          string `json:"id"`
	QuotaPerDay *int   `json:"quota_per_day"`
	Revoked     bool   `json:"revoked"`
}

type Client struct {
	KeyID       string `json:"keyid"`
	PublicKey   string `json:"public_key"`
	Issuer      string `json:"issuer"`
	QuotaPerDay *int   `json:"quota_per_day"`
	Revoked     bool   `json:"revoked"`
}

type Scoring struct {
	MinIssuers     int     `json:"min_issuers"`
	MaxIssuerShare float64 `json:"max_issuer_share"`
	WindowMinutes  int     `json:"window_minutes"`
	MinScore       *int    `json:"min_score"`
}

type Publish struct {
	BundleValidityHours  int   `json:"bundle_validity_hours"`
	CheckpointIntervalS  int   `json:"checkpoint_interval_s"`
	CheckpointTTLS       int   `json:"checkpoint_ttl_s"`
	RequireHumanApproval *bool `json:"require_human_approval"`
}

type Peer struct {
	Lab         string   `json:"lab"`
	Operator    string   `json:"operator"`
	Endpoint    string   `json:"endpoint"`
	Keys        []LabKey `json:"keys"`
	AcceptFrom  *bool    `json:"accept_from"`
	ShareWith   bool     `json:"share_with"`
	TrustWeight *float64 `json:"trust_weight"`
	ObserveOnly bool     `json:"observe_only"`
}

// LabKey is a public key of a peer lab.
type LabKey struct {
	KeyID     string             `json:"keyid"`
	PublicKey string             `json:"public_key"`
	Purposes  []contract.Purpose `json:"purposes"`
}

type LabRetention struct {
	SignalsDays    int `json:"signals_days"`
	AggregatesDays int `json:"aggregates_days"`
}

func (l *LabConfig) defaults() {
	orStr(&l.Profile, "production")
	orStr(&l.Listen.Ingest, "0.0.0.0:7443")
	orStr(&l.Listen.Feed, "0.0.0.0:7444")
	orStr(&l.Listen.Dashboard, "127.0.0.1:8789")
	orStr(&l.Listen.Metrics, "127.0.0.1:9102")
	orInt(&l.Ingest.MaxBodyBytes, 262144)
	orInt(&l.Ingest.MaxEnvelopes, 64)
	orInt(&l.Ingest.RatePerClientPerMin, 600)
	orInt(&l.Ingest.QueueMaxDepth, 1000000)
	orInt(&l.Ingest.RetryAfterMS, 5000)
	orInt(&l.Ingest.MaxClockSkewS, int(contract.MaxClockSkew.Seconds()))
	orInt(&l.Ingest.MaxSignalAgeS, int(contract.MaxSignalAge.Seconds()))
	orInt(&l.Ingest.ReplayWindowS, int(contract.MaxSignalAge.Seconds()))
	for i := range l.Issuers {
		if l.Issuers[i].QuotaPerDay == nil {
			l.Issuers[i].QuotaPerDay = intp(100000)
		}
	}
	for i := range l.Clients {
		if l.Clients[i].QuotaPerDay == nil {
			l.Clients[i].QuotaPerDay = intp(500)
		}
	}
	orInt(&l.Scoring.MinIssuers, 3)
	if l.Scoring.MaxIssuerShare == 0 {
		l.Scoring.MaxIssuerShare = 0.34
	}
	orInt(&l.Scoring.WindowMinutes, 1440)
	if l.Scoring.MinScore == nil {
		l.Scoring.MinScore = intp(40)
	}
	orInt(&l.Publish.BundleValidityHours, 168)
	orInt(&l.Publish.CheckpointIntervalS, 60)
	orInt(&l.Publish.CheckpointTTLS, 180)
	if l.Publish.RequireHumanApproval == nil {
		l.Publish.RequireHumanApproval = boolp(true)
	}
	for i := range l.Peers {
		if l.Peers[i].AcceptFrom == nil {
			l.Peers[i].AcceptFrom = boolp(true)
		}
		if l.Peers[i].TrustWeight == nil {
			l.Peers[i].TrustWeight = f64p(0.5)
		}
	}
	orStr(&l.Storage.Path, "/var/lib/schild-lab")
	orInt(&l.Retention.SignalsDays, 30)
	orInt(&l.Retention.AggregatesDays, 365)
	if l.Dashboard.Enabled == nil {
		l.Dashboard.Enabled = boolp(true)
	}
	orInt(&l.Dashboard.SessionTTLMinutes, 480)
}

// ParseLab parses lab.yaml bytes.
func ParseLab(b []byte) (*LabConfig, error) {
	j, err := YAMLToJSON(b)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	return ParseLabJSON(j)
}

// ParseLabJSON parses the JSON form.
func ParseLabJSON(j []byte) (*LabConfig, error) {
	v, err := verify.Document(verify.DocConfigLab, j, &verify.Context{})
	if err != nil {
		return nil, err
	}
	var l LabConfig
	if err := jsonx.Decode(v, &l); err != nil {
		return nil, contract.Errf(contract.CodeSchema, "%v", err)
	}
	l.defaults()
	if l.Profile == "test" && keys.Release {
		return nil, ErrTestProfileInRelease
	}
	if l.Publish.CheckpointTTLS < l.Publish.CheckpointIntervalS*2 {
		return nil, contract.Errf(contract.CodeConfig, "checkpoint_ttl_s must be at least twice checkpoint_interval_s")
	}
	return &l, nil
}

// LoadLab reads path, or $SCHILD_LAB_CONFIG, or the default path.
func LoadLab(path string) (*LabConfig, error) {
	if path == "" {
		path = os.Getenv(LabPathEnv)
	}
	if path == "" {
		path = LabPathDefault
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > contract.MaxConfigBytes {
		return nil, contract.Errf(contract.CodeOversize, "%s: %d bytes", path, len(b))
	}
	l, err := ParseLab(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

// ClientTrustStore builds the store of admitted, non-revoked site keys
// (purposes signal, feedback) with their issuer. Release builds refuse test keys.
func (l *LabConfig) ClientTrustStore() (*keys.TrustStore, error) {
	revoked := map[string]bool{}
	for _, i := range l.Issuers {
		if i.Revoked {
			revoked[i.ID] = true
		}
	}
	ts := keys.NewTrustStore()
	for _, c := range l.Clients {
		if c.Revoked || revoked[c.Issuer] {
			continue
		}
		pub, err := keys.ParsePublicKey(c.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", c.KeyID, err)
		}
		if err := ts.Add(keys.TrustedKey{KeyID: c.KeyID, Public: pub, Purposes: []contract.Purpose{contract.PurposeSignal, contract.PurposeFeedback}, Issuer: c.Issuer}); err != nil {
			return nil, err
		}
	}
	return ts, nil
}
