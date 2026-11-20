package verify

import (
	"crypto/ed25519"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/schema"
)

// checkAgentReport runs the kind-specific checks of an agent report (v0.3,
// host-check.md section 3) after schema validation, in contract order:
// duplicate findings (schema), signer binding (signature), clock_skew,
// expired, channel (gateway), replay (nonce).
func checkAgentReport(pv map[string]any, res *Result, ctx *Context) error {
	report, _ := pv["report"].(map[string]any)
	if err := hostcheck.CheckReport(report); err != nil {
		return err
	}
	var a hostcheck.AgentReport
	if err := jsonx.Decode(pv, &a); err != nil {
		return contract.Errf(contract.CodeSchema, "%v", err)
	}
	res.Value = &a
	if a.Report.Host.AgentKeyID == nil || *a.Report.Host.AgentKeyID != res.Signers[0].KeyID {
		return contract.Errf(contract.CodeSignature, "report names agent key %v, signed by %s", a.Report.Host.AgentKeyID, res.Signers[0].KeyID)
	}
	return checkAgentMessage(ctx, a.IssuedAt, a.Gateway, a.Nonce)
}

func checkAgentMessage(ctx *Context, issuedAt, gateway, nonce string) error {
	at, err := parseTime("issued_at", issuedAt)
	if err != nil {
		return err
	}
	if err := checkIssued(ctx, at); err != nil {
		return err
	}
	if at.Add(contract.MaxAgentMessageAge).Before(ctx.Now) {
		return contract.Errf(contract.CodeExpired, "issued %s is older than %s", issuedAt, contract.MaxAgentMessageAge)
	}
	if ctx.Gateway != "" && gateway != ctx.Gateway {
		return contract.Errf(contract.CodeChannel, "addressed to gateway %s, this is %s", gateway, ctx.Gateway)
	}
	if ctx.Seen != nil && ctx.Seen(nonce) {
		return contract.Errf(contract.CodeReplay, "nonce %s already seen", nonce)
	}
	return nil
}

// EnrolmentResult is a verified enrolment request.
type EnrolmentResult struct {
	Enrolment *hostcheck.Enrolment
	Public    ed25519.PublicKey
	Digest    string
}

// AgentEnrolment verifies an enrolment request envelope (v0.3,
// host-check.md section 5). The envelope is signed by the new agent key
// itself (proof of possession), so it needs no trust store. The one-time
// code is checked by the gateway against its state afterwards.
//
// Order: oversize, malformed, envelope (exactly one signature), oversize
// (payload), payload_type, malformed (payload), forbidden_field,
// forbidden_content, schema, signature (keyid and public key of the payload),
// test_key (release builds), clock_skew, expired, channel, replay.
func AgentEnrolment(raw []byte, ctx *Context) (*EnrolmentResult, error) {
	if len(raw) > contract.MaxEnrolmentBytes {
		return nil, contract.Errf(contract.CodeOversize, "envelope %d bytes > %d", len(raw), contract.MaxEnrolmentBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
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
	if len(env.Signatures) != 1 {
		return nil, contract.Errf(contract.CodeEnvelope, "enrolment envelope carries %d signatures, exactly 1 allowed", len(env.Signatures))
	}
	if len(payload) > contract.MaxEnrolmentPayload {
		return nil, contract.Errf(contract.CodeOversize, "payload %d bytes > %d", len(payload), contract.MaxEnrolmentPayload)
	}
	if env.PayloadType != hostcheck.EnrolmentPayloadType {
		return nil, contract.Errf(contract.CodePayloadType, "got %q, want %q", env.PayloadType, hostcheck.EnrolmentPayloadType)
	}
	pv, err := jsonx.ParseObject(payload)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "payload: %v", err)
	}
	if err := hostcheck.CheckForbidden(pv); err != nil {
		return nil, err
	}
	if err := schema.Validate(schema.AgentEnrolment, pv); err != nil {
		return nil, err
	}
	var e hostcheck.Enrolment
	if err := jsonx.Decode(pv, &e); err != nil {
		return nil, contract.Errf(contract.CodeSchema, "%v", err)
	}
	pub, err := keys.ParsePublicKey(e.PublicKey)
	if err != nil {
		return nil, contract.Errf(contract.CodeSchema, "public_key: %v", err)
	}
	if env.Signatures[0].KeyID != e.KeyID || !ed25519.Verify(pub, dsse.PAE(env.PayloadType, payload), sigs[0]) {
		return nil, contract.Errf(contract.CodeSignature, "enrolment not signed by the key it enrols")
	}
	if keys.Release && keys.IsTestKey(e.KeyID, pub) {
		return nil, contract.Errf(contract.CodeTestKey, "%s", e.KeyID)
	}
	if err := checkAgentMessage(ctx, e.IssuedAt, e.Gateway, e.Nonce); err != nil {
		return nil, err
	}
	return &EnrolmentResult{Enrolment: &e, Public: pub, Digest: msg.Digest(payload)}, nil
}

// AgentMessageWindow is how long a gateway must remember accepted nonces.
const AgentMessageWindow = contract.MaxAgentMessageAge + contract.MaxClockSkew
