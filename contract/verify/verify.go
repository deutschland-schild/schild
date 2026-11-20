// Package verify is the reference verification pipeline for every signed
// message kind and every unsigned contract document. The order of checks is
// part of the contract (contracts/vectors/README.md): the first failing check
// determines the error code, and the Python cross-check must agree on it.
package verify

import (
	"crypto/ed25519"
	"fmt"
	"slices"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/schema"
	"github.com/deutschland-schild/schild/contract/seclang"
)

// State is what a verifier remembers between messages (rollback protection).
type State struct {
	BundleVersion    uint64
	BundleDigest     string
	WithdrawalSeq    uint64
	WithdrawalDigest string
	CheckpointSeq    map[string]uint64 // by lab
	CheckpointDigest map[string]string // by lab
}

// Context carries everything a verification needs besides the bytes.
type Context struct {
	Now   time.Time
	Trust *keys.TrustStore
	// Threshold is k for bundles and withdrawals: valid signatures from k
	// distinct operators. 0 means the default (3); values below the floor (2)
	// are raised to the floor.
	Threshold int
	// Channel is the expected bundle_id; empty accepts any.
	Channel string
	// Seen reports whether a signal or feedback id was already processed.
	Seen func(id string) bool
	// ExpectedInReplyTo binds an ack to the submission it answers.
	ExpectedInReplyTo string
	State             State
	// OperatorOf maps a trusted key to the operator counted for
	// independence. nil means TrustedKey.Operator. The client test profile
	// (E5) plugs in simulated operators here; never in release builds.
	OperatorOf func(k *keys.TrustedKey) string
	// SkipState disables rollback/equivocation checks (stream inspection).
	SkipState bool
	// Revoked reports whether a key id was revoked (v0.3, agent keys at the
	// gateway). A valid signature by a revoked key yields code revoked.
	Revoked func(keyid string) bool
	// Gateway is the expected agent_report / enrolment gateway (the
	// gateway's node_name); empty accepts any (v0.3).
	Gateway string
}

// EffectiveThreshold returns k after applying default and floor.
func (c *Context) EffectiveThreshold() int {
	k := c.Threshold
	if k == 0 {
		k = contract.DefaultMinIndependentOperators
	}
	if k < contract.MinIndependentOperatorsFloor {
		k = contract.MinIndependentOperatorsFloor
	}
	return k
}

func (c *Context) operator(k *keys.TrustedKey) string {
	// Simulated operators (E5) never count in release builds, whatever the
	// caller plugged in: defence in depth next to config.ErrTestProfileInRelease.
	if c.OperatorOf != nil && !keys.Release {
		return c.OperatorOf(k)
	}
	return k.Operator
}

// Result of a successful verification of a signed message.
type Result struct {
	Kind      contract.Kind
	Envelope  *dsse.Envelope
	Payload   []byte
	Digest    string             // sha256 of the payload bytes
	Signers   []*keys.TrustedKey // trusted keys with a valid signature
	Operators []string           // distinct operators among Signers
	Value     any                // *msg.Signal, *msg.Feedback, *msg.Ack, *msg.Checkpoint, *msg.Bundle, *msg.Withdrawal
}

// Signed verifies raw envelope bytes of the given kind.
func Signed(kind contract.Kind, raw []byte, ctx *Context) (*Result, error) {
	lim := contract.LimitsFor(kind)
	if lim.MaxEnvelopeBytes == 0 {
		return nil, fmt.Errorf("verify: unknown kind %q", kind)
	}
	if len(raw) > lim.MaxEnvelopeBytes {
		return nil, contract.Errf(contract.CodeOversize, "envelope %d bytes > %d", len(raw), lim.MaxEnvelopeBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	return signedValue(kind, v, ctx)
}

// SignedValue verifies an envelope that is already parsed (for example
// embedded in a stream event). The raw size check is skipped.
func SignedValue(kind contract.Kind, v map[string]any, ctx *Context) (*Result, error) {
	return signedValue(kind, v, ctx)
}

func signedValue(kind contract.Kind, v map[string]any, ctx *Context) (*Result, error) {
	lim := contract.LimitsFor(kind)
	if err := schema.Validate(schema.Envelope, v); err != nil {
		return nil, contract.Errf(contract.CodeEnvelope, "%v", err)
	}
	var env dsse.Envelope
	if err := jsonx.Decode(v, &env); err != nil {
		return nil, contract.Errf(contract.CodeEnvelope, "%v", err)
	}
	payload, err := env.DecodePayload()
	if err != nil {
		return nil, contract.Errf(contract.CodeEnvelope, "payload: %v", err)
	}
	sigs := make([][]byte, len(env.Signatures))
	for i, s := range env.Signatures {
		if sigs[i], err = dsse.DecodeBase64(s.Sig); err != nil {
			return nil, contract.Errf(contract.CodeEnvelope, "signature %d: %v", i, err)
		}
	}
	if kind.SingleSigner() && len(env.Signatures) != 1 {
		// One sender per signal or feedback: a lab credits exactly one key
		// and issuer, never several (no ambiguity, no double counting).
		return nil, contract.Errf(contract.CodeEnvelope, "%s envelope carries %d signatures, exactly 1 allowed", kind, len(env.Signatures))
	}
	if len(payload) > lim.MaxPayloadBytes {
		return nil, contract.Errf(contract.CodeOversize, "payload %d bytes > %d", len(payload), lim.MaxPayloadBytes)
	}
	if env.PayloadType != kind.PayloadType() {
		return nil, contract.Errf(contract.CodePayloadType, "got %q, want %q", env.PayloadType, kind.PayloadType())
	}
	res := &Result{Kind: kind, Envelope: &env, Payload: payload, Digest: msg.Digest(payload)}
	pae := dsse.PAE(env.PayloadType, payload)
	seen := map[string]bool{}
	revoked := false
	for i, s := range env.Signatures {
		if seen[s.KeyID] {
			continue
		}
		k, ok := ctx.Trust.Lookup(s.KeyID)
		if !ok || !k.Allows(kind.Purpose()) {
			continue
		}
		if keys.Release && keys.IsTestKey(k.KeyID, k.Public) {
			return nil, contract.Errf(contract.CodeTestKey, "%s", k.KeyID)
		}
		if !ed25519.Verify(k.Public, pae, sigs[i]) {
			continue
		}
		if ctx.Revoked != nil && ctx.Revoked(s.KeyID) {
			revoked = true
			continue
		}
		seen[s.KeyID] = true
		res.Signers = append(res.Signers, k)
		if op := ctx.operator(k); op != "" && !slices.Contains(res.Operators, op) {
			res.Operators = append(res.Operators, op)
		}
	}
	if kind.Threshold() {
		if k := ctx.EffectiveThreshold(); len(res.Operators) < k {
			return nil, contract.Errf(contract.CodeThreshold, "valid signatures from %d distinct operators, need %d", len(res.Operators), k)
		}
	} else if len(res.Signers) == 0 {
		if revoked {
			return nil, contract.Errf(contract.CodeRevoked, "the only valid signature is by a revoked %s key", kind.Purpose())
		}
		return nil, contract.Errf(contract.CodeSignature, "no valid signature by a trusted %s key", kind.Purpose())
	}
	pv, err := jsonx.ParseObject(payload)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "payload: %v", err)
	}
	if kind == contract.KindSignal || kind == contract.KindFeedback {
		if err := CheckForbidden(pv); err != nil {
			return nil, err
		}
	}
	if kind == contract.KindAgentReport {
		if err := hostcheck.CheckForbidden(pv); err != nil {
			return nil, err
		}
	}
	if err := schema.Validate(string(kind), pv); err != nil {
		return nil, err
	}
	if err := semantic(kind, pv, res, ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// CheckForbidden rejects forbidden key names at any depth (signal, feedback).
// Keys are compared after msg.NormalizeFieldName (ASCII lower case, without
// '-', '_' and '.'), so client_ip, Client-IP and clientIp are all caught.
func CheckForbidden(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if msg.IsForbiddenField(k) {
				return contract.Errf(contract.CodeForbiddenField, "field %q is never allowed", k)
			}
			if err := CheckForbidden(x); err != nil {
				return err
			}
		}
	case []any:
		for _, x := range t {
			if err := CheckForbidden(x); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseTime(field, s string) (time.Time, error) {
	t, err := msg.ParseTime(s)
	if err != nil {
		return t, contract.Errf(contract.CodeSchema, "%s: %v", field, err)
	}
	return t, nil
}

func checkIssued(ctx *Context, at time.Time) error {
	if at.After(ctx.Now.Add(contract.MaxClockSkew)) {
		return contract.Errf(contract.CodeClockSkew, "issued %s is in the future", msg.FormatTime(at))
	}
	return nil
}

func semantic(kind contract.Kind, pv map[string]any, res *Result, ctx *Context) error {
	switch kind {
	case contract.KindSignal:
		var s msg.Signal
		if err := jsonx.Decode(pv, &s); err != nil {
			return contract.Errf(contract.CodeSchema, "%v", err)
		}
		res.Value = &s
		for i := 1; i < len(s.WAFRules); i++ {
			if s.WAFRules[i] <= s.WAFRules[i-1] {
				return contract.Errf(contract.CodeSchema, "waf_rules must be strictly ascending")
			}
		}
		return checkBucket(ctx, s.TimeBucket, s.ID)
	case contract.KindFeedback:
		var f msg.Feedback
		if err := jsonx.Decode(pv, &f); err != nil {
			return contract.Errf(contract.CodeSchema, "%v", err)
		}
		res.Value = &f
		return checkBucket(ctx, f.TimeBucket, f.ID)
	case contract.KindAck:
		var a msg.Ack
		if err := jsonx.Decode(pv, &a); err != nil {
			return contract.Errf(contract.CodeSchema, "%v", err)
		}
		res.Value = &a
		if !signedByLab(res.Signers, a.Lab) {
			return contract.Errf(contract.CodeSignature, "ack of lab %s not signed by that lab", a.Lab)
		}
		at, err := parseTime("issued_at", a.IssuedAt)
		if err != nil {
			return err
		}
		if err := checkIssued(ctx, at); err != nil {
			return err
		}
		if at.Add(contract.MaxAckAge).Before(ctx.Now) {
			return contract.Errf(contract.CodeExpired, "ack issued %s is too old", a.IssuedAt)
		}
		if ctx.ExpectedInReplyTo != "" && a.InReplyTo != ctx.ExpectedInReplyTo {
			return contract.Errf(contract.CodeReplay, "ack answers %s, expected %s", a.InReplyTo, ctx.ExpectedInReplyTo)
		}
		return nil
	case contract.KindCheckpoint:
		var c msg.Checkpoint
		if err := jsonx.Decode(pv, &c); err != nil {
			return contract.Errf(contract.CodeSchema, "%v", err)
		}
		res.Value = &c
		if !signedByLab(res.Signers, c.Lab) {
			return contract.Errf(contract.CodeSignature, "checkpoint of lab %s not signed by that lab", c.Lab)
		}
		at, err := parseTime("issued_at", c.IssuedAt)
		if err != nil {
			return err
		}
		exp, err := parseTime("expires", c.Expires)
		if err != nil {
			return err
		}
		if err := checkIssued(ctx, at); err != nil {
			return err
		}
		if !exp.After(ctx.Now) {
			return contract.Errf(contract.CodeExpired, "checkpoint expired %s", c.Expires)
		}
		if !exp.After(at) || exp.Sub(at) > contract.MaxCheckpointValidity {
			return contract.Errf(contract.CodeValidity, "checkpoint validity %s outside (0, %s]", exp.Sub(at), contract.MaxCheckpointValidity)
		}
		if ctx.SkipState {
			return nil
		}
		last := ctx.State.CheckpointSeq[c.Lab]
		if c.Seq < last {
			return contract.Errf(contract.CodeRollback, "checkpoint seq %d < %d", c.Seq, last)
		}
		if c.Seq == last && last > 0 && ctx.State.CheckpointDigest[c.Lab] != res.Digest {
			return contract.Errf(contract.CodeEquivocation, "checkpoint seq %d with a different digest", c.Seq)
		}
		return nil
	case contract.KindBundle:
		var b msg.Bundle
		if err := jsonx.Decode(pv, &b); err != nil {
			return contract.Errf(contract.CodeSchema, "%v", err)
		}
		res.Value = &b
		return checkBundle(&b, res, ctx)
	case contract.KindWithdrawal:
		var w msg.Withdrawal
		if err := jsonx.Decode(pv, &w); err != nil {
			return contract.Errf(contract.CodeSchema, "%v", err)
		}
		res.Value = &w
		at, err := parseTime("issued_at", w.IssuedAt)
		if err != nil {
			return err
		}
		if err := checkIssued(ctx, at); err != nil {
			return err
		}
		if ctx.Channel != "" && w.BundleID != ctx.Channel {
			return contract.Errf(contract.CodeChannel, "withdrawal for %s, expected %s", w.BundleID, ctx.Channel)
		}
		if ctx.SkipState {
			return nil
		}
		if w.Seq < ctx.State.WithdrawalSeq {
			return contract.Errf(contract.CodeRollback, "withdrawal seq %d < %d", w.Seq, ctx.State.WithdrawalSeq)
		}
		if w.Seq == ctx.State.WithdrawalSeq && ctx.State.WithdrawalDigest != res.Digest {
			return contract.Errf(contract.CodeEquivocation, "withdrawal seq %d with a different digest", w.Seq)
		}
		return nil
	case contract.KindAgentReport:
		return checkAgentReport(pv, res, ctx)
	}
	return fmt.Errorf("verify: no semantic check for %s", kind)
}

func signedByLab(signers []*keys.TrustedKey, lab string) bool {
	for _, k := range signers {
		if k.Lab == lab {
			return true
		}
	}
	return false
}

func checkBucket(ctx *Context, bucket, id string) error {
	t, err := parseTime("time_bucket", bucket)
	if err != nil {
		return err
	}
	if t.After(ctx.Now.Add(contract.MaxClockSkew)) {
		return contract.Errf(contract.CodeClockSkew, "time_bucket %s is in the future", bucket)
	}
	if t.Add(contract.MaxSignalAge).Before(ctx.Now) {
		return contract.Errf(contract.CodeExpired, "time_bucket %s is older than %s", bucket, contract.MaxSignalAge)
	}
	if ctx.Seen != nil && ctx.Seen(id) {
		return contract.Errf(contract.CodeReplay, "id %s already seen", id)
	}
	return nil
}

func checkBundle(b *msg.Bundle, res *Result, ctx *Context) error {
	at, err := parseTime("issued_at", b.IssuedAt)
	if err != nil {
		return err
	}
	exp, err := parseTime("expires", b.Expires)
	if err != nil {
		return err
	}
	if err := checkIssued(ctx, at); err != nil {
		return err
	}
	if !exp.After(ctx.Now) {
		return contract.Errf(contract.CodeExpired, "bundle expired %s", b.Expires)
	}
	if !exp.After(at) || exp.Sub(at) > contract.MaxBundleValidity {
		return contract.Errf(contract.CodeValidity, "bundle validity %s outside (0, %s]", exp.Sub(at), contract.MaxBundleValidity)
	}
	if ctx.Channel != "" && b.BundleID != ctx.Channel {
		return contract.Errf(contract.CodeChannel, "bundle for %s, expected %s", b.BundleID, ctx.Channel)
	}
	if !ctx.SkipState {
		if b.Version < ctx.State.BundleVersion {
			return contract.Errf(contract.CodeRollback, "bundle version %d < %d", b.Version, ctx.State.BundleVersion)
		}
		if b.Version == ctx.State.BundleVersion && ctx.State.BundleDigest != res.Digest {
			return contract.Errf(contract.CodeEquivocation, "bundle version %d with a different digest", b.Version)
		}
	}
	ruleIDs := map[string]bool{}
	secIDs := map[int]bool{}
	for i, r := range b.Rules {
		head, err := seclang.Validate(r.SecLang, seclang.Options{MaxAction: r.MaxAction})
		if err != nil {
			return fmt.Errorf("rule %d (%s): %w", i, r.RuleID, err)
		}
		lvl := msg.EvidenceLevel(r.Class, r.Evidence)
		if msg.MaxActionRank(r.MaxAction) > msg.MaxActionRank(lvl) {
			return contract.Errf(contract.CodeEvidence, "rule %s: max_action %s needs more evidence (level %q)", r.RuleID, r.MaxAction, lvl)
		}
		if r.MaxActionUntil != "" {
			until, err := parseTime("max_action_until", r.MaxActionUntil)
			if err != nil {
				return err
			}
			if !until.After(at) || until.After(exp) {
				return contract.Errf(contract.CodeValidity, "rule %s: max_action_until outside the bundle validity", r.RuleID)
			}
			if r.MaxAction == "challenge" && until.Sub(at) > contract.MaxChallengeWindow {
				return contract.Errf(contract.CodeValidity, "rule %s: challenge for more than %s", r.RuleID, contract.MaxChallengeWindow)
			}
		}
		if ruleIDs[r.RuleID] || secIDs[head.ID] {
			return contract.Errf(contract.CodeDuplicateRule, "rule %s / SecRule id %d appears twice", r.RuleID, head.ID)
		}
		ruleIDs[r.RuleID] = true
		secIDs[head.ID] = true
	}
	return nil
}
