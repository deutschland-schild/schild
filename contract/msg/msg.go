// Package msg defines the Go types of the signed messages (payloads inside
// DSSE envelopes) and of the submission body. Field sets mirror the JSON
// Schemas in contracts/ exactly; decoding rejects unknown fields.
package msg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Schema identifiers inside payloads.
const (
	SchemaSignal     = "schild.signal/0.3"
	SchemaFeedback   = "schild.feedback/0.2"
	SchemaAck        = "schild.ack/0.1"
	SchemaCheckpoint = "schild.checkpoint/0.1"
	SchemaBundle     = "schild.rule-bundle/0.1"
	SchemaWithdrawal = "schild.withdrawal/0.1"
)

// TimeLayout is the only accepted timestamp format (UTC, whole seconds).
const TimeLayout = "2006-01-02T15:04:05Z"

// FormatTime renders t in TimeLayout (UTC, truncated to seconds).
func FormatTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(TimeLayout) }

// ParseTime parses TimeLayout strictly. time.Parse alone also accepts a
// fractional second after the seconds field ("12:00:00.5Z"), which is not
// whole seconds; the round trip rejects it.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(TimeLayout, s)
	if err != nil {
		return t, err
	}
	if t.Format(TimeLayout) != s {
		return time.Time{}, fmt.Errorf("msg: timestamp %q is not YYYY-MM-DDTHH:MM:SSZ", s)
	}
	return t, nil
}

// TimeBucket floors t to a bucket of the given minutes (5, 10 or 15).
func TimeBucket(t time.Time, minutes int) string {
	if minutes != 5 && minutes != 10 && minutes != 15 {
		minutes = 5
	}
	return FormatTime(t.UTC().Truncate(time.Duration(minutes) * time.Minute))
}

// NewID returns a random UUID v4 (lowercase).
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// Signal is schild.signal/0.3: the positive list of decision E4.
type Signal struct {
	Schema     string `json:"schema"`
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	TimeBucket string `json:"time_bucket"`
	ActionSig  string `json:"action_sig"`
	RequestSig string `json:"request_sig"`
	WAFRules   []int  `json:"waf_rules"`
	Score      int    `json:"score"`
	Category   string `json:"category"`
	Origin     Origin `json:"origin"`
	Agent      Agent  `json:"agent"`
	JA4        string `json:"ja4,omitempty"`
}

// Origin is the coarse, locally derived origin of a request. Never an IP.
type Origin struct {
	Country     string `json:"country"`
	ASN         uint32 `json:"asn"`
	NetClass    string `json:"net_class"`
	Attribution string `json:"attribution"`
	Protected   bool   `json:"protected"`
}

// Agent is the coarse user agent: family and major version, bot flag.
type Agent struct {
	Family string `json:"family"`
	Major  int    `json:"major"`
	Bot    bool   `json:"bot"`
}

// SignalFields is the positive list (decision E4), including framing fields.
var SignalFields = []string{"schema", "id", "kind", "time_bucket", "action_sig", "request_sig", "waf_rules", "score", "category", "origin", "agent", "ja4"}

// ForbiddenFields are key names that must never appear in a signal or
// feedback payload at any depth. They are compared after NormalizeFieldName,
// so every spelling (client_ip, Client-IP, clientIp, client.ip) is caught.
// Anything else outside the positive list is rejected by the schema.
var ForbiddenFields = []string{
	"ip", "ips", "ip_address", "ip_prefix", "ip_hash", "ip_pseudonym", "oprf", "client_ip", "remote_addr", "remote_ip",
	"remote_host", "src_ip", "source_ip", "client_address", "address", "addr", "ipv4", "ipv6", "peer", "peer_ip",
	"x_forwarded_for", "x_real_ip", "true_client_ip", "cf_connecting_ip", "forwarded",
	"user_agent", "ua", "url", "uri", "query", "query_string", "path", "headers", "header", "cookies", "cookie", "body", "request_body",
	"referer", "referrer", "host", "hostname", "site", "site_id", "site_key", "domain", "server_name", "tenant", "account", "customer",
	"email", "user", "username", "login", "password", "phone", "session_id", "client", "client_id", "keyid", "key_id",
	"city", "latitude", "longitude", "auth", "token", "presentation",
}

var forbiddenNormalized = func() map[string]bool {
	m := map[string]bool{}
	for _, f := range ForbiddenFields {
		m[NormalizeFieldName(f)] = true
	}
	return m
}()

// NormalizeFieldName lower-cases ASCII letters and drops '-', '_' and '.'.
// Only ASCII is folded, so the result never depends on Unicode tables; keys
// with other characters are not on the positive list anyway (code schema).
func NormalizeFieldName(k string) string {
	b := make([]byte, 0, len(k))
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c == '-' || c == '_' || c == '.':
			continue
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	return string(b)
}

// IsForbiddenField reports whether a payload key is on the forbidden list.
func IsForbiddenField(k string) bool { return forbiddenNormalized[NormalizeFieldName(k)] }

// RequestShape is the input of RequestSig. It contains no values, no host and no IP.
type RequestShape struct {
	Method       string   // GET, POST, ...
	PathTemplate string   // normalised path, ids replaced: /wp-json/wp/v2/users/{n}
	ParamNames   []string // query and body parameter names
	ContentType  string   // media type without parameters
	RuleIDs      []int    // matched WAF rules
}

// RequestSig computes request_sig: sha256 over a canonical, line based
// rendering of the shape (see contracts/signal.md).
func RequestSig(s RequestShape) string {
	names := append([]string(nil), s.ParamNames...)
	sort.Strings(names)
	names = dedupe(names)
	rules := append([]int(nil), s.RuleIDs...)
	sort.Ints(rules)
	rs := make([]string, 0, len(rules))
	for i, r := range rules {
		if i > 0 && rules[i-1] == r {
			continue
		}
		rs = append(rs, strconv.Itoa(r))
	}
	canon := "schild.request-shape/1\n" +
		"method:" + strings.ToUpper(s.Method) + "\n" +
		"path:" + s.PathTemplate + "\n" +
		"params:" + strings.Join(names, ",") + "\n" +
		"content_type:" + strings.ToLower(s.ContentType) + "\n" +
		"rules:" + strings.Join(rs, ",") + "\n"
	h := sha256.Sum256([]byte(canon))
	return "sha256:" + hex.EncodeToString(h[:])
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, x := range s {
		if i > 0 && s[i-1] == x {
			continue
		}
		out = append(out, x)
	}
	return out
}

// MatchShape describes where and how large a match was, never its content.
type MatchShape struct {
	Location    string `json:"location"`
	ContentType string `json:"content_type,omitempty"`
	LenBucket   string `json:"len_bucket"`
}

// LenBucket maps a length in bytes to a len_bucket value.
func LenBucket(n int) string {
	switch {
	case n < 16:
		return "0-16"
	case n < 64:
		return "16-64"
	case n < 256:
		return "64-256"
	case n < 1024:
		return "256-1k"
	case n < 4096:
		return "1k-4k"
	case n < 16384:
		return "4k-16k"
	}
	return "16k+"
}

// Feedback is schild.feedback/0.2.
type Feedback struct {
	Schema        string     `json:"schema"`
	ID            string     `json:"id"`
	TimeBucket    string     `json:"time_bucket"`
	RuleID        string     `json:"rule_id"`
	BundleVersion uint64     `json:"bundle_version"`
	Verdict       string     `json:"verdict"`
	DecidedBy     string     `json:"decided_by"`
	LocalAction   string     `json:"local_action"`
	MatchShape    MatchShape `json:"match_shape"`
}

// Submission is the body of POST /v0/submit.
type Submission struct {
	RequestID string            `json:"request_id"`
	Envelopes []json.RawMessage `json:"envelopes"`
}

// Ack is schild.ack/0.1.
type Ack struct {
	Schema    string     `json:"schema"`
	Lab       string     `json:"lab"`
	IssuedAt  string     `json:"issued_at"`
	InReplyTo string     `json:"in_reply_to"`
	Accepted  []string   `json:"accepted"`
	Duplicate []string   `json:"duplicate"`
	Rejected  []Rejected `json:"rejected"`
	Control   Control    `json:"control"`
}

// Rejected names a rejected message and the reason code.
type Rejected struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// NilID is used in Rejected when the envelope could not be parsed.
const NilID = "00000000-0000-4000-8000-000000000000"

// Control is lab flow control. retry_after_ms > 0 whenever reason != ok.
type Control struct {
	RetryAfterMS int    `json:"retry_after_ms"`
	MaxBatch     int    `json:"max_batch"`
	Reason       string `json:"reason"`
}

// Checkpoint is schild.checkpoint/0.1.
type Checkpoint struct {
	Schema        string    `json:"schema"`
	Lab           string    `json:"lab"`
	Seq           uint64    `json:"seq"`
	IssuedAt      string    `json:"issued_at"`
	Expires       string    `json:"expires"`
	Bundle        BundleRef `json:"bundle"`
	WithdrawalSeq uint64    `json:"withdrawal_seq"`
	Log           *LogState `json:"log,omitempty"`
}

// BundleRef points at a bundle version by payload digest.
type BundleRef struct {
	BundleID string `json:"bundle_id"`
	Version  uint64 `json:"version"`
	Digest   string `json:"digest"`
}

// LogState is a transparency log size and root.
type LogState struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
}

// Bundle is schild.rule-bundle/0.1: the full set of network rules of a channel.
type Bundle struct {
	Schema   string `json:"schema"`
	BundleID string `json:"bundle_id"`
	Version  uint64 `json:"version"`
	IssuedAt string `json:"issued_at"`
	Expires  string `json:"expires"`
	Rules    []Rule `json:"rules"`
}

// Rule is one network rule.
type Rule struct {
	RuleID         string   `json:"rule_id"`
	Class          string   `json:"class"`
	Stage          string   `json:"stage"`
	MaxAction      string   `json:"max_action"`
	MaxActionUntil string   `json:"max_action_until,omitempty"`
	MaxMatchShare  float64  `json:"max_match_share"`
	Target         Target   `json:"target"`
	Evidence       Evidence `json:"evidence"`
	FeedbackPolicy string   `json:"feedback_policy"`
	SecLang        string   `json:"seclang"`
}

// Target names the software a rule is for.
type Target struct {
	Software string   `json:"software"`
	Versions string   `json:"versions"`
	CVE      []string `json:"cve,omitempty"`
}

// Evidence backs the max_action of a rule (G2).
type Evidence struct {
	ReproducedOperators int      `json:"reproduced_operators"`
	SensorOperators     int      `json:"sensor_operators"`
	TipIssuers          int      `json:"tip_issuers"`
	MaxIssuerShare      float64  `json:"max_issuer_share"`
	HumanApprovalOrgs   int      `json:"human_approval_orgs"`
	ReproducedBy        []string `json:"reproduced_by,omitempty"`
	NegativeCorpus      string   `json:"negative_corpus,omitempty"`
}

// Withdrawal is schild.withdrawal/0.1.
type Withdrawal struct {
	Schema      string   `json:"schema"`
	BundleID    string   `json:"bundle_id"`
	Seq         uint64   `json:"seq"`
	IssuedAt    string   `json:"issued_at"`
	Scope       string   `json:"scope"`
	RuleIDs     []string `json:"rule_ids,omitempty"`
	UpToVersion uint64   `json:"up_to_version"`
	Reason      string   `json:"reason"`
	Note        string   `json:"note,omitempty"`
}

// Applies reports whether the withdrawal removes ruleID from a bundle version.
func (w *Withdrawal) Applies(bundleVersion uint64, ruleID string) bool {
	if bundleVersion > w.UpToVersion {
		return false
	}
	if w.Scope == "all" {
		return true
	}
	for _, r := range w.RuleIDs {
		if r == ruleID {
			return true
		}
	}
	return false
}

// Digest returns "sha256:<hex>" of b (bundle digests are over payload bytes).
func Digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// MaxActionRank orders max_action values.
func MaxActionRank(a string) int {
	switch a {
	case "observe":
		return 1
	case "challenge":
		return 2
	case "block":
		return 3
	}
	return 0
}

// EvidenceLevel returns the highest max_action the evidence allows (G2),
// or "" when the evidence does not even allow observe.
//
//	block:     class virtual_patch, reproduced by >= 2 operators, human approval in >= 2 organisations
//	challenge: reproduced by >= 1 operator, or own sensors of >= 2 operators
//	observe:   any of the above, own sensors of 1 operator, or tips from >= 3 issuers with max_issuer_share <= 0.34
func EvidenceLevel(class string, e Evidence) string {
	if class == "virtual_patch" && e.ReproducedOperators >= 2 && e.HumanApprovalOrgs >= 2 {
		return "block"
	}
	if e.ReproducedOperators >= 1 || e.SensorOperators >= 2 {
		return "challenge"
	}
	if e.SensorOperators >= 1 || (e.TipIssuers >= 3 && e.MaxIssuerShare <= 0.34) {
		return "observe"
	}
	return ""
}

// String helpers for errors.
func (r Rule) String() string { return fmt.Sprintf("%s(%s,%s)", r.RuleID, r.Class, r.MaxAction) }
