package rules

import (
	"encoding/json"

	"github.com/deutschland-schild/schild/contract/msg"
)

// Proposal statuses (API ProposalStatus).
const (
	StatusDraft     = "draft"
	StatusReview    = "review"
	StatusApproved  = "approved"
	StatusRejected  = "rejected"
	StatusPublished = "published"
	StatusWithdrawn = "withdrawn"
)

// Record statuses of bundles and withdrawals.
const (
	Collecting = "collecting"
	Published  = "published"
	Effective  = "effective"
	Superseded = "superseded"
	Expired    = "expired"
)

// Reproduction is one reproduction of the exploit against a target
// container (MVP-03: reproducing request + target container version).
type Reproduction struct {
	Lab           string  `json:"lab"`
	Operator      string  `json:"operator"`
	Status        string  `json:"status"` // pending | reproduced | not_reproduced | error
	Image         string  `json:"image"`
	Version       string  `json:"version"`
	RequestDigest string  `json:"request_digest,omitempty"`
	At            *string `json:"at"`
}

// Sensor is an observation by a lab's own sensors (honeypot, range).
type Sensor struct {
	Lab      string `json:"lab"`
	Operator string `json:"operator"`
	At       string `json:"at"`
}

// Corpus is the negative corpus check (G3 gate 1).
type Corpus struct {
	Version string `json:"version"`
	Matches int    `json:"matches"`
}

// Approval is one human approval.
type Approval struct {
	By        string `json:"by"`
	Org       string `json:"org"`
	At        string `json:"at"`
	MaxAction string `json:"max_action,omitempty"`
}

// Check is the SecLang subset result.
type Check struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// Target names the software of a rule.
type Target struct {
	Software string   `json:"software"`
	Versions string   `json:"versions"`
	CVE      []string `json:"cve,omitempty"`
}

// Proposal is stored with private fields; API() renders the public shape.
type Proposal struct {
	ID                 string         `json:"id"`
	RuleID             string         `json:"rule_id"`
	Status             string         `json:"status"`
	PatternID          string         `json:"pattern_id,omitempty"`
	Class              string         `json:"class"`
	Stage              string         `json:"stage"`
	SecLang            string         `json:"seclang"`
	Target             Target         `json:"target"`
	RequestedMaxAction string         `json:"requested_max_action"`
	MaxActionUntil     string         `json:"max_action_until,omitempty"`
	Reproductions      []Reproduction `json:"reproductions"`
	Sensors            []Sensor       `json:"sensors"`
	Corpus             *Corpus        `json:"corpus,omitempty"`
	Approvals          []Approval     `json:"approvals"`
	ApprovalNotes      []string       `json:"approval_notes,omitempty"`
	RejectedReason     string         `json:"rejected_reason,omitempty"`
	RejectedBy         string         `json:"rejected_by,omitempty"`
	BundleVersion      uint64         `json:"bundle_version,omitempty"`
	CreatedAt          string         `json:"created_at"`
	UpdatedAt          string         `json:"updated_at"`
	CreatedBy          string         `json:"created_by,omitempty"`
}

// EvidenceView is the API evidence object.
type EvidenceView struct {
	ReproducedOperators int            `json:"reproduced_operators"`
	SensorOperators     int            `json:"sensor_operators"`
	TipIssuers          int            `json:"tip_issuers"`
	MaxIssuerShare      float64        `json:"max_issuer_share"`
	HumanApprovalOrgs   int            `json:"human_approval_orgs"`
	NegativeCorpus      *Corpus        `json:"negative_corpus,omitempty"`
	Reproductions       []Reproduction `json:"reproductions"`
}

// ProposalView is the API Proposal.
type ProposalView struct {
	ID                 string       `json:"id"`
	RuleID             string       `json:"rule_id"`
	Status             string       `json:"status"`
	PatternID          *string      `json:"pattern_id"`
	Class              string       `json:"class"`
	Stage              string       `json:"stage"`
	SecLang            string       `json:"seclang"`
	SecLangCheck       Check        `json:"seclang_check"`
	Target             Target       `json:"target"`
	Evidence           EvidenceView `json:"evidence"`
	AllowedMaxAction   *string      `json:"allowed_max_action"`
	RequestedMaxAction string       `json:"requested_max_action"`
	MaxActionUntil     *string      `json:"max_action_until"`
	Approvals          []Approval   `json:"approvals"`
	RejectedReason     *string      `json:"rejected_reason"`
	BundleVersion      *uint64      `json:"bundle_version"`
	CreatedBy          *string      `json:"created_by"`
	CreatedAt          string       `json:"created_at"`
	UpdatedAt          string       `json:"updated_at"`
}

// Signature is the API Signature.
type Signature struct {
	KeyID    string `json:"keyid"`
	Lab      string `json:"lab"`
	Operator string `json:"operator"`
	At       string `json:"at"`
}

// RuleView is one rule line of the API Bundle.
type RuleView struct {
	RuleID    string `json:"rule_id"`
	Class     string `json:"class"`
	MaxAction string `json:"max_action"`
	Stage     string `json:"stage"`
	Change    string `json:"change,omitempty"`
}

// BundleRecord is a stored bundle (own or learned from peers).
type BundleRecord struct {
	Version     uint64            `json:"version"`
	Status      string            `json:"status"`
	IssuedAt    string            `json:"issued_at"`
	Expires     string            `json:"expires"`
	Digest      string            `json:"digest"` // payload digest
	Payload     []byte            `json:"payload"`
	Envelope    json.RawMessage   `json:"envelope"`
	Rules       []RuleView        `json:"rules"`
	SignedAt    map[string]string `json:"signed_at"` // keyid -> time first seen
	ProposedBy  string            `json:"proposed_by"`
	Source      string            `json:"source,omitempty"` // peer lab for foreign items
	Proposals   []string          `json:"proposals,omitempty"`
	CreatedAt   string            `json:"created_at"`
	PublishedAt string            `json:"published_at,omitempty"`
	Note        string            `json:"note,omitempty"`
}

// BundleView is the API Bundle.
type BundleView struct {
	Channel    string          `json:"channel"`
	Version    uint64          `json:"version"`
	Status     string          `json:"status"`
	IssuedAt   string          `json:"issued_at"`
	Expires    string          `json:"expires"`
	Digest     string          `json:"digest,omitempty"`
	Rules      []RuleView      `json:"rules"`
	Signatures []Signature     `json:"signatures"`
	Threshold  int             `json:"threshold"`
	ProposedBy string          `json:"proposed_by,omitempty"`
	Envelope   json.RawMessage `json:"envelope"`
}

// WithdrawalRecord is a stored withdrawal (own or learned from peers).
type WithdrawalRecord struct {
	Seq         uint64            `json:"seq"`
	Status      string            `json:"status"`
	Payload     []byte            `json:"payload"`
	Digest      string            `json:"digest"`
	Envelope    json.RawMessage   `json:"envelope"`
	W           msg.Withdrawal    `json:"withdrawal"`
	SignedAt    map[string]string `json:"signed_at"`
	ProposedBy  string            `json:"proposed_by"`
	Source      string            `json:"source,omitempty"`
	CreatedAt   string            `json:"created_at"`
	EffectiveAt string            `json:"effective_at,omitempty"`
}

// WithdrawalView is the API Withdrawal.
type WithdrawalView struct {
	Seq         uint64      `json:"seq"`
	Channel     string      `json:"channel"`
	Scope       string      `json:"scope"`
	RuleIDs     []string    `json:"rule_ids,omitempty"`
	Reason      string      `json:"reason"`
	Note        string      `json:"note,omitempty"`
	UpToVersion uint64      `json:"up_to_version"`
	Status      string      `json:"status"`
	Signatures  []Signature `json:"signatures"`
	Threshold   int         `json:"threshold"`
	ProposedBy  string      `json:"proposed_by"`
	CreatedAt   string      `json:"created_at"`
	EffectiveAt *string     `json:"effective_at"`
}
