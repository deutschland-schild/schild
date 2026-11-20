// Package forge builds signed and deliberately malformed protocol artifacts
// (bundles, withdrawals, checkpoints, signals, feedback) for the red-team
// scenarios of MVP-07. It uses the TEST ONLY keys of contracts/testkeys and
// the real contract signer (contract/dsse), so every artifact is wire-correct
// except for exactly the defect a scenario is testing. Nothing here decides
// whether an artifact is accepted; that is the job of the real verifier
// (contract/verify), which is the acceptance authority the scenarios measure.
package forge

import (
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/testkeys"
)

// Channel is the test lab's default channel (schild-main).
const Channel = "schild-main"

// Clock is a fixed base time for deterministic artifacts.
var Clock = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func ts(base time.Time, d time.Duration) string { return msg.FormatTime(base.Add(d)) }

// MustJSON marshals v with the strict contract encoder.
func MustJSON(v any) []byte {
	b, err := jsonx.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// Sign wraps a payload in a DSSE envelope signed by the named TEST ONLY keys.
func Sign(payloadType string, payload []byte, keyNames ...string) *dsse.Envelope {
	signers := make([]dsse.Signer, len(keyNames))
	for i, n := range keyNames {
		signers[i] = testkeys.Signer(n)
	}
	env, err := dsse.Sign(payloadType, payload, signers...)
	if err != nil {
		panic(err)
	}
	return env
}

// SignBytes signs a payload of the given kind and returns the envelope bytes.
func SignBytes(kind contract.Kind, payload []byte, keyNames ...string) []byte {
	return MustJSON(Sign(kind.PayloadType(), payload, keyNames...))
}

// --- rules -----------------------------------------------------------------

// A genuinely harmless, specific observe rule for a known software target.
// It passes the SecLang subset and the catch-all check (@detectSQLi is a
// specific detection operator).
func ruleObserve(ruleID string, secID int) map[string]any {
	return map[string]any{
		"rule_id":         ruleID,
		"class":           "virtual_patch",
		"stage":           "general",
		"max_action":      "observe",
		"max_match_share": 0.01,
		"target":          map[string]any{"software": "acme-cms", "versions": "<=1.2.3"},
		"evidence": map[string]any{
			"reproduced_operators": 0, "sensor_operators": 1,
			"tip_issuers": 3, "max_issuer_share": 0.2, "human_approval_orgs": 0,
		},
		"feedback_policy": "narrow_only",
		"seclang":         `SecRule ARGS "@detectSQLi" "id:` + itoa(secID) + `,phase:2,pass,severity:CRITICAL,msg:'SQLi in arguments',t:none,t:urlDecodeUni"`,
	}
}

// RuleID formats a schema-valid network rule id (schild-20YY-NNNN).
func RuleID(n int) string {
	y := "2026"
	s := itoa(n)
	for len(s) < 4 {
		s = "0" + s
	}
	return "schild-" + y + "-" + s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// RuleObserve returns a harmless observe rule.
func RuleObserve(ruleID string, secID int) map[string]any { return ruleObserve(ruleID, secID) }

// RulePoison marks a legitimate request as something to block: it blocks a
// normal login POST (T07). Even if structurally valid it must never reach a
// client without k independent operators; this is the content a malicious lab
// would push. seclang here is specific (matches no benign value), so the
// defect is only the intent, not the syntax.
func RulePoison(ruleID string, secID int, action string) map[string]any {
	ev := map[string]any{
		"reproduced_operators": 2, "sensor_operators": 2,
		"tip_issuers": 9, "max_issuer_share": 0.2, "human_approval_orgs": 2,
	}
	r := map[string]any{
		"rule_id":         ruleID,
		"class":           "virtual_patch",
		"stage":           "general",
		"max_action":      action,
		"max_match_share": 0.01,
		"target":          map[string]any{"software": "acme-cms", "versions": "<=1.2.3"},
		"evidence":        ev,
		"feedback_policy": "narrow_only",
		// A specific path a login form posts to; the poison is that the lab
		// wants it blocked, not that the pattern is broad.
		"seclang": `SecRule REQUEST_FILENAME "@endsWith /wp-login.php" "id:` + itoa(secID) + `,phase:2,` + disruptive(action) + `,severity:CRITICAL,msg:'login blocked by a malicious lab'"`,
	}
	if action != "observe" {
		r["max_action_until"] = ts(Clock, 24*time.Hour)
	}
	return r
}

func disruptive(action string) string {
	if action == "observe" {
		return "pass"
	}
	return "deny,status:403"
}

// --- bundles ---------------------------------------------------------------

// BundleOpts tune a forged bundle.
type BundleOpts struct {
	Version  uint64
	BundleID string
	IssuedAt string
	Expires  string
	Rules    []map[string]any
}

// Bundle builds a rule-bundle payload (map) with the given options.
func Bundle(o BundleOpts) map[string]any {
	if o.BundleID == "" {
		o.BundleID = Channel
	}
	if o.IssuedAt == "" {
		o.IssuedAt = ts(Clock, -time.Minute)
	}
	if o.Expires == "" {
		o.Expires = ts(Clock, 7*24*time.Hour)
	}
	rules := o.Rules
	if rules == nil {
		rules = []map[string]any{}
	}
	rs := make([]any, len(rules))
	for i, r := range rules {
		rs[i] = r
	}
	return map[string]any{
		"schema":    msg.SchemaBundle,
		"bundle_id": o.BundleID,
		"version":   o.Version,
		"issued_at": o.IssuedAt,
		"expires":   o.Expires,
		"rules":     rs,
	}
}

// Withdrawal builds a withdrawal payload (map).
func Withdrawal(seq, upTo uint64, scope string, ruleIDs []string) map[string]any {
	w := map[string]any{
		"schema":        msg.SchemaWithdrawal,
		"bundle_id":     Channel,
		"seq":           seq,
		"issued_at":     ts(Clock, -time.Minute),
		"scope":         scope,
		"up_to_version": upTo,
		"reason":        "false_positives",
	}
	if len(ruleIDs) > 0 {
		ids := make([]any, len(ruleIDs))
		for i, id := range ruleIDs {
			ids[i] = id
		}
		w["rule_ids"] = ids
	}
	return w
}

// Checkpoint builds a checkpoint payload (map) for lab, naming a bundle.
func Checkpoint(lab string, seq, bundleVersion uint64, digest string, validity time.Duration) map[string]any {
	if validity == 0 {
		validity = 5 * time.Minute
	}
	return map[string]any{
		"schema":    msg.SchemaCheckpoint,
		"lab":       lab,
		"seq":       seq,
		"issued_at": ts(Clock, -time.Minute),
		"expires":   ts(Clock, validity-time.Minute),
		"bundle": map[string]any{
			"bundle_id": Channel, "version": bundleVersion, "digest": digest,
		},
		"withdrawal_seq": uint64(0),
	}
}

// --- signals ---------------------------------------------------------------

// SignalOpts tune a forged signal payload.
type SignalOpts struct {
	ID         string
	TimeBucket string
	ActionSig  string
	RequestSig string
	Score      int
	Category   string
}

// Signal builds a harmless, contract-valid signal payload (map). Used by the
// Sybil scenario: 500 fresh keys all reporting the same harmless signature.
func Signal(o SignalOpts) map[string]any {
	if o.ID == "" {
		o.ID = msg.NewID()
	}
	if o.TimeBucket == "" {
		o.TimeBucket = msg.TimeBucket(Clock, 5)
	}
	if o.ActionSig == "" {
		o.ActionSig = "scanner-probe/other"
	}
	if o.RequestSig == "" {
		o.RequestSig = msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: "/", RuleIDs: []int{949110}})
	}
	if o.Category == "" {
		o.Category = "anomaly"
	}
	if o.Score == 0 {
		o.Score = 42
	}
	return map[string]any{
		"schema":      msg.SchemaSignal,
		"id":          o.ID,
		"kind":        "tip",
		"time_bucket": o.TimeBucket,
		"action_sig":  o.ActionSig,
		"request_sig": o.RequestSig,
		"waf_rules":   []any{949110},
		"score":       o.Score,
		"category":    o.Category,
		"origin": map[string]any{
			"country": "DE", "asn": 64496, "net_class": "hosting", "attribution": "tcp_peer", "protected": false,
		},
		"agent": map[string]any{"family": "curl", "major": 8, "bot": true},
	}
}
