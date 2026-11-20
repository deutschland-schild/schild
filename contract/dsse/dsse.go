// Package dsse implements the DSSE v1 envelope (secure-systems-lab/dsse)
// with Ed25519 signatures as profiled in contracts/envelope.md:
// standard base64 with padding, canonical encoding only, compact JSON with
// the field order payloadType, payload, signatures.
package dsse

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/deutschland-schild/schild/contract/jsonx"
)

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signer signs PAE bytes.
type Signer interface {
	KeyID() string
	Sign(message []byte) ([]byte, error)
}

// PAE is the DSSE v1 pre-authentication encoding:
// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
func PAE(payloadType string, payload []byte) []byte {
	b := make([]byte, 0, 32+len(payloadType)+len(payload))
	b = append(b, "DSSEv1 "...)
	b = strconv.AppendInt(b, int64(len(payloadType)), 10)
	b = append(b, ' ')
	b = append(b, payloadType...)
	b = append(b, ' ')
	b = strconv.AppendInt(b, int64(len(payload)), 10)
	b = append(b, ' ')
	b = append(b, payload...)
	return b
}

// Sign creates an envelope signed by all signers (in the given order).
func Sign(payloadType string, payload []byte, signers ...Signer) (*Envelope, error) {
	if len(signers) == 0 {
		return nil, errors.New("dsse: no signer")
	}
	env := &Envelope{PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	msg := PAE(payloadType, payload)
	for _, s := range signers {
		sig, err := s.Sign(msg)
		if err != nil {
			return nil, fmt.Errorf("dsse: sign with %s: %w", s.KeyID(), err)
		}
		env.Signatures = append(env.Signatures, Signature{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	return env, nil
}

// AddSignature appends a signature over the same payload (k-of-n assembly).
func (e *Envelope) AddSignature(s Signer) error {
	payload, err := DecodeBase64(e.Payload)
	if err != nil {
		return err
	}
	sig, err := s.Sign(PAE(e.PayloadType, payload))
	if err != nil {
		return err
	}
	e.Signatures = append(e.Signatures, Signature{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)})
	return nil
}

// DecodePayload returns the payload bytes (canonical base64 only).
func (e *Envelope) DecodePayload() ([]byte, error) { return DecodeBase64(e.Payload) }

// Marshal returns compact JSON.
func (e *Envelope) Marshal() ([]byte, error) { return jsonx.Marshal(e) }

// ErrBase64 marks a non-canonical or invalid base64 string.
var ErrBase64 = errors.New("dsse: invalid or non-canonical base64")

// DecodeBase64 decodes standard padded base64 and rejects non-canonical
// encodings (non-zero padding bits), so one signature has exactly one text form.
func DecodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, ErrBase64
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, ErrBase64
	}
	return b, nil
}
