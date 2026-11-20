// Package auth makes sender authentication pluggable (decision E1,
// contracts/auth.md). The signal and feedback payloads never change with
// the scheme:
//
//   - prototype and alpha: per-site key. The payload is signed in a DSSE envelope
//     with the site's Ed25519 key; the lab knows which site sent it and
//     counts by the site's issuer.
//   - v1: unlinkable tokens (Privacy Pass / ARC) over OHTTP. The lab only
//     learns the issuer. Interface defined here; implementation is a stub.
package auth

import (
	"context"
	"errors"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/verify"
)

// Scheme names.
const (
	SchemePerSiteKey    = "site-key"
	SchemePrivacyPassAR = "privacypass-arc" // v1
)

// ErrNotImplemented is returned by the v1 token scheme stub.
var ErrNotImplemented = errors.New("auth: scheme not implemented before v1")

// Sealed is an authenticated outgoing message: the envelope and, for token
// schemes, an authorization header value.
type Sealed struct {
	Scheme        string
	Envelope      *dsse.Envelope
	Authorization string // empty for site-key; "PrivateToken token=..." in v1
}

// Signer authenticates outgoing signals and feedback on the client.
type Signer interface {
	Scheme() string
	Seal(ctx context.Context, kind contract.Kind, payload []byte) (*Sealed, error)
}

// Sender is what a lab learns about the sender after verification.
type Sender struct {
	Scheme string
	KeyID  string // site-key only; empty with tokens
	Issuer string // the guarantor counted for independence (G2)
}

// Authenticator verifies incoming signals and feedback on the lab.
type Authenticator interface {
	Scheme() string
	Open(ctx context.Context, kind contract.Kind, raw []byte, authorization string, vctx *verify.Context) (*verify.Result, *Sender, error)
}

// SiteKeySigner signs with the per-site key.
type SiteKeySigner struct{ s *keys.Signer }

// NewSiteKeySigner wraps a site key (purpose signal and feedback).
func NewSiteKeySigner(s *keys.Signer) *SiteKeySigner { return &SiteKeySigner{s: s} }

// Scheme implements Signer.
func (*SiteKeySigner) Scheme() string { return SchemePerSiteKey }

// Seal implements Signer.
func (k *SiteKeySigner) Seal(_ context.Context, kind contract.Kind, payload []byte) (*Sealed, error) {
	if kind != contract.KindSignal && kind != contract.KindFeedback {
		return nil, errors.New("auth: site keys only sign signals and feedback")
	}
	env, err := dsse.Sign(kind.PayloadType(), payload, k.s)
	if err != nil {
		return nil, err
	}
	return &Sealed{Scheme: SchemePerSiteKey, Envelope: env}, nil
}

// SiteKeyAuthenticator verifies per-site-key envelopes against the lab's
// client trust store (config.LabConfig.ClientTrustStore).
type SiteKeyAuthenticator struct{}

// Scheme implements Authenticator.
func (SiteKeyAuthenticator) Scheme() string { return SchemePerSiteKey }

// Open implements Authenticator. It runs the full contract verification.
func (SiteKeyAuthenticator) Open(_ context.Context, kind contract.Kind, raw []byte, authorization string, vctx *verify.Context) (*verify.Result, *Sender, error) {
	if authorization != "" {
		return nil, nil, contract.Errf(contract.CodeEnvelope, "unexpected authorization for site-key scheme")
	}
	if kind != contract.KindSignal && kind != contract.KindFeedback {
		return nil, nil, contract.Errf(contract.CodePayloadType, "only signals and feedback are submitted")
	}
	res, err := verify.Signed(kind, raw, vctx)
	if err != nil {
		return nil, nil, err
	}
	k := res.Signers[0]
	return res, &Sender{Scheme: SchemePerSiteKey, KeyID: k.KeyID, Issuer: k.Issuer}, nil
}

// TokenSigner is the v1 Privacy Pass / ARC scheme. Stub.
type TokenSigner struct{ Issuer string }

// Scheme implements Signer.
func (TokenSigner) Scheme() string { return SchemePrivacyPassAR }

// Seal implements Signer (not implemented before v1).
func (TokenSigner) Seal(context.Context, contract.Kind, []byte) (*Sealed, error) {
	return nil, ErrNotImplemented
}

// TokenAuthenticator is the lab side of the v1 token scheme. Stub.
type TokenAuthenticator struct{}

// Scheme implements Authenticator.
func (TokenAuthenticator) Scheme() string { return SchemePrivacyPassAR }

// Open implements Authenticator (not implemented before v1).
func (TokenAuthenticator) Open(context.Context, contract.Kind, []byte, string, *verify.Context) (*verify.Result, *Sender, error) {
	return nil, nil, ErrNotImplemented
}
