// Package label defines the secret ground-truth label that every test-lab
// traffic generator attaches to each request and that the label stripper
// removes before the request reaches a schild client.
//
// The label travels in a single HTTP header whose value is a signed,
// self-describing JSON document. The signature (HMAC-SHA256 over the JSON with
// a shared test secret) lets the stripper reject forged or leaked labels, so a
// request that reaches a site without a valid label is itself a finding: it
// means a generator forgot the label or an attacker injected the header.
//
// Nothing in this package is part of a shipping build; it exists only inside
// the test lab (SCHILD_TEST_CA world). The header is always stripped before a
// request reaches a schild client, so the client never sees ground truth.
package label

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// HeaderName is the request header carrying the signed label. The stripper
// removes it; a request that still carries it past the stripper is a leak.
const HeaderName = "X-Schild-Label"

// RequestIDHeader is the correlation id the stripper assigns and that the
// schild client echoes into its local events, so the evaluator can join an
// event back to its ground-truth label.
const RequestIDHeader = "X-Request-Id"

// EnvSecret names the environment variable holding the shared test secret.
const EnvSecret = "SCHILD_LABEL_SECRET"

// Class is the ground truth of a request: what the WAF should ideally do.
type Class string

const (
	// Benign is ordinary, legitimate traffic that must pass.
	Benign Class = "benign"
	// Malicious is an attack that the WAF should block (or at least flag).
	Malicious Class = "malicious"
	// Bypass is an attack variant crafted to slip past the WAF; it is
	// expected to be malicious but may evade detection. A bypass that passes
	// is counted separately from an ordinary missed attack.
	Bypass Class = "bypass"
	// Canary carries a unique marker value that must never leave the server
	// in any signal. Canary requests are otherwise benign.
	Canary Class = "canary"
	// GoodBot is automated but legitimate traffic (search crawlers etc.).
	GoodBot Class = "good_bot"
)

// Classes lists every valid class.
var Classes = []Class{Benign, Malicious, Bypass, Canary, GoodBot}

// Valid reports whether c is a known class.
func (c Class) Valid() bool {
	for _, k := range Classes {
		if c == k {
			return true
		}
	}
	return false
}

// Label is the ground truth attached to one request.
type Label struct {
	// Class is what the WAF ideally does with this request.
	Class Class `json:"class"`
	// Scenario is the traffic scenario that produced the request, e.g. "T01".
	Scenario string `json:"scenario"`
	// Source names the generator (e.g. "legit", "botnet", "nuclei").
	Source string `json:"source"`
	// Technique is a free-form attack/traffic sub-type, e.g. "sqli", "xss".
	Technique string `json:"technique,omitempty"`
	// ExpectBlock is true when the WAF is expected to block the request.
	// Benign/canary/good_bot are false; malicious is true; a bypass is true
	// (the WAF should block it, even though it is crafted to evade).
	ExpectBlock bool `json:"expect_block"`
	// Canary is a unique marker string that must never appear in any signal
	// leaving the server. Set only for the canary class.
	Canary string `json:"canary,omitempty"`
	// Seq is the monotonic index of the request within a run, for
	// reproducibility checks.
	Seq int `json:"seq"`
}

// ExpectedOutcome maps a class to whether the request should be blocked.
func ExpectedOutcome(c Class) bool { return c == Malicious || c == Bypass }

// Sign returns the header value for l signed with secret. The format is
// base64url(json) "." hex(hmac-sha256(secret, json)); the JSON is canonical
// (sorted keys) so the signature is reproducible.
func Sign(secret []byte, l Label) (string, error) {
	if !l.Class.Valid() {
		return "", fmt.Errorf("label: invalid class %q", l.Class)
	}
	raw, err := canonicalJSON(l)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(raw)
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(raw) + "." + sig, nil
}

// ErrNoLabel means the header was absent or empty.
var ErrNoLabel = errors.New("label: missing header")

// ErrBadSignature means the HMAC did not verify (forged or wrong secret).
var ErrBadSignature = errors.New("label: bad signature")

// Parse verifies and decodes a header value signed with secret.
func Parse(secret []byte, header string) (Label, error) {
	var l Label
	if strings.TrimSpace(header) == "" {
		return l, ErrNoLabel
	}
	dot := strings.LastIndexByte(header, '.')
	if dot <= 0 || dot == len(header)-1 {
		return l, fmt.Errorf("label: malformed header")
	}
	raw, err := base64.RawURLEncoding.DecodeString(header[:dot])
	if err != nil {
		return l, fmt.Errorf("label: base64: %w", err)
	}
	wantSig, err := hex.DecodeString(header[dot+1:])
	if err != nil {
		return l, fmt.Errorf("label: hex: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(raw)
	if !hmac.Equal(wantSig, mac.Sum(nil)) {
		return l, ErrBadSignature
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		return l, fmt.Errorf("label: json: %w", err)
	}
	if !l.Class.Valid() {
		return l, fmt.Errorf("label: invalid class %q", l.Class)
	}
	return l, nil
}

// canonicalJSON marshals l with sorted keys so Sign is deterministic
// regardless of Go's struct field order guarantees.
func canonicalJSON(l Label) ([]byte, error) {
	b, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return marshalSorted(m)
}

func marshalSorted(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		sb.Write(kb)
		sb.WriteByte(':')
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		sb.Write(vb)
	}
	sb.WriteByte('}')
	return []byte(sb.String()), nil
}
