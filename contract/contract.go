// Package contract holds the shared constants of the Schild contracts v0:
// payload types (DSSE domain separation), size limits, time limits and the
// error codes every verifier returns. The JSON Schemas, documentation and
// golden vectors live in contracts/; this module is their Go reference
// implementation.
package contract

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Version of the contract set. Frozen contracts change only with a new version.
const Version = "v0.6"

// Kind names a signed message type. Each kind has its own DSSE payload type
// (domain separation) and its own key purpose.
type Kind string

const (
	KindSignal     Kind = "signal"
	KindFeedback   Kind = "feedback"
	KindAck        Kind = "ack"
	KindCheckpoint Kind = "checkpoint"
	KindBundle     Kind = "rule-bundle"
	KindWithdrawal Kind = "withdrawal"
	// v0.3 (D25, host-check.md): a host report pushed by `schild-agent` to
	// the gateway schild. Never sent to labs.
	KindAgentReport Kind = "agent-report"
)

// SignedKinds lists all signed message kinds in a stable order.
var SignedKinds = []Kind{KindSignal, KindFeedback, KindAck, KindCheckpoint, KindBundle, KindWithdrawal, KindAgentReport}

// PayloadType returns the DSSE payloadType for a kind.
func (k Kind) PayloadType() string { return "application/vnd.schild." + string(k) + ".v0+json" }

// Purpose returns the key purpose that may sign this kind.
func (k Kind) Purpose() Purpose {
	switch k {
	case KindSignal:
		return PurposeSignal
	case KindFeedback:
		return PurposeFeedback
	case KindAck:
		return PurposeAck
	case KindCheckpoint:
		return PurposeCheckpoint
	case KindBundle, KindWithdrawal:
		return PurposeRules
	case KindAgentReport:
		return PurposeAgent
	}
	return ""
}

// Threshold reports whether the kind needs k-of-n signatures from distinct
// operators (rule bundles and withdrawals) instead of one trusted signature.
func (k Kind) Threshold() bool { return k == KindBundle || k == KindWithdrawal }

// SingleSigner reports whether envelopes of this kind carry exactly one
// signature (signal and feedback: one sender, one issuer; agent reports: one
// agent).
func (k Kind) SingleSigner() bool {
	return k == KindSignal || k == KindFeedback || k == KindAgentReport
}

// Purpose restricts what a key may sign.
type Purpose string

const (
	PurposeSignal     Purpose = "signal"
	PurposeFeedback   Purpose = "feedback"
	PurposeAck        Purpose = "ack"
	PurposeRules      Purpose = "rules"
	PurposeCheckpoint Purpose = "checkpoint"
	// v0.3: per-agent key, trusted only by the gateway it is enrolled at.
	PurposeAgent Purpose = "agent"
)

// Limits holds the byte limits for a kind.
type Limits struct {
	MaxEnvelopeBytes int // raw JSON envelope
	MaxPayloadBytes  int // decoded payload
}

// LimitsFor returns the size limits of a signed kind.
func LimitsFor(k Kind) Limits {
	switch k {
	case KindSignal, KindFeedback:
		return Limits{16 << 10, 4 << 10}
	case KindAck:
		return Limits{64 << 10, 48 << 10}
	case KindCheckpoint:
		return Limits{16 << 10, 4 << 10}
	case KindWithdrawal:
		return Limits{64 << 10, 32 << 10}
	case KindBundle:
		return Limits{1 << 20, 768 << 10}
	case KindAgentReport:
		return Limits{768 << 10, MaxHostReportBytes}
	}
	return Limits{}
}

// Size limits of unsigned documents.
const (
	MaxSubmissionBytes  = 1 << 20  // POST /v0/submit body
	MaxStreamEventBytes = 64 << 10 // one SSE data line
	MaxInlineEnvelope   = 32 << 10 // larger bundles travel by reference
	MaxLocalEventBytes  = 64 << 10
	MaxConfigBytes      = 1 << 20
	MaxResultsBytes     = 4 << 20
	MaxSecLangBytes     = 8 << 10
	MaxJSONDepth        = 32
	MaxLogTreeBytes     = 4 << 20   // v0.1: log copy with head (cosign.md)
	MaxPeerRequestBytes = 16 << 10  // v0.1: peer request document (vectors)
	MaxHostReportBytes  = 512 << 10 // v0.3: host report file and agent report payload
	MaxAgentAckBytes    = 4 << 10   // v0.3: gateway answer to an agent
	MaxEnrolmentBytes   = 16 << 10  // v0.3: agent enrolment envelope
	MaxEnrolmentPayload = 4 << 10   // v0.3: agent enrolment payload
)

// Time limits. All timestamps are UTC with whole seconds.
const (
	MaxClockSkew          = 120 * time.Second
	MaxSignalAge          = 24 * time.Hour
	MaxAckAge             = 5 * time.Minute
	MaxCheckpointValidity = 10 * time.Minute
	MaxBundleValidity     = 31 * 24 * time.Hour
	MaxChallengeWindow    = 7 * 24 * time.Hour
	// v0.3: agent reports and enrolment requests are accepted while
	// issued_at is in [now - 5 min, now + 120 s]; the gateway remembers every
	// accepted nonce at least until issued_at + 5 min + 120 s.
	MaxAgentMessageAge = 5 * time.Minute
)

// Operator independence (E5): the floor is fixed in code, sites may only raise it.
const (
	MinIndependentOperatorsFloor   = 2
	DefaultMinIndependentOperators = 3
)

// SecLang id range reserved for network rules.
const (
	RemoteRuleIDMin = 7700000
	RemoteRuleIDMax = 7799999
	// HubRuleIDMin..HubRuleIDMax: SecRule ids of the CrowdSec Hub source (D39,
	// contracts/crowdsec-hub.md section 4). Inside events.schema.json
	// matchedRule.id, apart from the network, CRS and internal ranges.
	HubRuleIDMin = 60000000
	HubRuleIDMax = 99999999
)

// Code is a stable, machine readable rejection reason. Vectors, Go and the
// Python cross-check must agree on it (first failing check in the order of
// contracts/vectors/README.md).
type Code string

const (
	CodeOversize       Code = "oversize"
	CodeMalformed      Code = "malformed"
	CodeEnvelope       Code = "envelope"
	CodePayloadType    Code = "payload_type"
	CodeSignature      Code = "signature"
	CodeThreshold      Code = "threshold"
	CodeForbiddenField Code = "forbidden_field"
	CodeSchema         Code = "schema"
	CodeClockSkew      Code = "clock_skew"
	CodeExpired        Code = "expired"
	CodeValidity       Code = "validity"
	CodeReplay         Code = "replay"
	CodeChannel        Code = "channel"
	CodeRollback       Code = "rollback"
	CodeEquivocation   Code = "equivocation"
	CodeDuplicateRule  Code = "duplicate_rule"
	CodeSecLang        Code = "seclang"
	CodeEvidence       Code = "evidence"
	CodeConfig         Code = "config"
	CodeTestKey        Code = "test_key"
	// v0.1: a log copy does not hash to the signed head (cosign.md).
	CodeLogRoot Code = "log_root"
	// v0.3 (host-check.md): a valid signature by an agent key the gateway
	// has revoked.
	CodeRevoked Code = "revoked"
	// v0.3: a host report value looks like a secret (PEM armour, a secret
	// assignment, an environment dump).
	CodeForbiddenContent Code = "forbidden_content"
)

// Error is a contract violation with a stable code. Msg may quote the
// offending value (for developers); Pointer is the JSON pointer of the
// offending place when known. Anything shown in a dashboard or written to a
// log on the receiving side uses SafeDetail, never Msg.
type Error struct {
	Code    Code
	Msg     string
	Pointer string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Msg }

// Errf builds an *Error.
func Errf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// WithPointer sets the JSON pointer of the offending place.
func (e *Error) WithPointer(p string) *Error {
	e.Pointer = p
	return e
}

// pointerSegment keeps only segments that cannot carry a sent value: array
// indices and short lowercase field names (every field name of the
// contracts). Anything else (a map key an attacker chose) becomes "*".
func pointerSegment(s string) string {
	if s == "" || len(s) > 40 {
		return "*"
	}
	digits, ident := true, true
	for _, c := range s {
		digits = digits && c >= '0' && c <= '9'
		ident = ident && (c >= 'a' && c <= 'z' || c == '_' || c >= '0' && c <= '9')
	}
	if digits || ident && s[0] >= 'a' && s[0] <= 'z' {
		return s
	}
	return "*"
}

// SafePointer cleans a JSON pointer with pointerSegment.
func SafePointer(p string) string {
	if p == "" || p == "/" {
		return p
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, x := range parts {
		parts[i] = pointerSegment(x)
	}
	return "/" + strings.Join(parts, "/")
}

// SafeDetail is the value-free description of err for logs and dashboards:
// the contract code and, when known, the JSON pointer of the offending
// place ("schema at /report/findings/3/evidence/value"). It never contains
// a value from the rejected message. Errors that are no contract error give
// "malformed".
func SafeDetail(err error) string {
	if err == nil {
		return ""
	}
	var ce *Error
	if !errors.As(err, &ce) {
		return string(CodeMalformed)
	}
	if ce.Pointer != "" {
		return string(ce.Code) + " at " + SafePointer(ce.Pointer)
	}
	return string(ce.Code)
}

// CodeOf extracts the code of a contract error, or "" for other errors.
func CodeOf(err error) Code {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}
