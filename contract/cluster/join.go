package cluster

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"strings"
	"time"
)

// A join code admits one key, once, for an hour. It holds a secret of 128
// bits and the fingerprint of the node that gave it out, so the node that
// joins knows whom it talks to before it sends the secret.

// JoinCodeTTL is how long a join code is valid.
const JoinCodeTTL = time.Hour

var joinEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrJoinCode is a join code that does not parse.
var ErrJoinCode = errors.New("cluster: join code is not valid")

// Fingerprint is the part of a join code that names a node's key.
func Fingerprint(pub ed25519.PublicKey) []byte {
	h := sha256.Sum256(append([]byte("schild-join:"), pub...))
	return h[:16]
}

// NewJoinCode makes a code for the node with the key pub. hash is what that
// node keeps of it.
func NewJoinCode(pub ed25519.PublicKey) (code string, hash []byte, err error) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return "", nil, err
	}
	raw := strings.ToLower(joinEnc.EncodeToString(append(secret, Fingerprint(pub)...)))
	var b strings.Builder
	for i := 0; i < len(raw); i += 13 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(raw[i:min(i+13, len(raw))])
	}
	return b.String(), JoinHash(secret), nil
}

// ParseJoinCode returns the secret and the fingerprint of a code.
func ParseJoinCode(code string) (secret, fingerprint []byte, err error) {
	raw, err := joinEnc.DecodeString(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", "")))
	if err != nil || len(raw) != 32 {
		return nil, nil, ErrJoinCode
	}
	return raw[:16], raw[16:], nil
}

// JoinHash is what the inviting node stores of a secret.
func JoinHash(secret []byte) []byte {
	h := sha256.Sum256(append([]byte("schild-join-secret:"), secret...))
	return h[:]
}

// SameFingerprint compares in constant time.
func SameFingerprint(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
