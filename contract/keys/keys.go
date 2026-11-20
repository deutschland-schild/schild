// Package keys holds Ed25519 key handling and the trust store: which key may
// sign which message kind, and to which operator, lab or issuer it belongs.
// Test keys (contracts/testkeys) are recognised by key id prefix and by
// public key, and are refused when built with -tags release.
package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/deutschland-schild/schild/contract"
)

// TestKeyIDPrefix marks test key ids.
const TestKeyIDPrefix = "test-"

// ErrTestKey is returned when a release build meets a test key.
var ErrTestKey = errors.New("keys: test key refused in release build")

// TrustedKey is one entry of a trust store.
type TrustedKey struct {
	KeyID    string
	Public   ed25519.PublicKey
	Purposes []contract.Purpose
	Operator string // labs: operator id, counted for independence
	Lab      string // labs: lab id (checkpoint.lab must match)
	Issuer   string // sites: guarantor id, counted by labs (G2)
}

// Allows reports whether the key may sign for purpose p.
func (k *TrustedKey) Allows(p contract.Purpose) bool { return slices.Contains(k.Purposes, p) }

// TrustStore maps key ids to trusted keys. Safe for concurrent reads after
// setup. A nil store trusts no key (Lookup and Len), so a verification
// context without a store rejects every signature instead of panicking.
type TrustStore struct {
	mu   sync.RWMutex
	byID map[string]*TrustedKey
}

// NewTrustStore returns an empty store.
func NewTrustStore() *TrustStore { return &TrustStore{byID: map[string]*TrustedKey{}} }

// Add inserts a key. Release builds refuse test keys.
func (t *TrustStore) Add(k TrustedKey) error {
	if len(k.Public) != ed25519.PublicKeySize {
		return fmt.Errorf("keys: %s: bad public key size", k.KeyID)
	}
	if Release && IsTestKey(k.KeyID, k.Public) {
		return fmt.Errorf("%w: %s", ErrTestKey, k.KeyID)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, dup := t.byID[k.KeyID]; dup {
		return fmt.Errorf("keys: duplicate key id %s", k.KeyID)
	}
	for _, o := range t.byID {
		// One public key under two ids would let one signature count for two
		// operators (or issuers).
		if bytes.Equal(o.Public, k.Public) {
			return fmt.Errorf("keys: public key of %s is already trusted as %s", k.KeyID, o.KeyID)
		}
	}
	kk := k
	t.byID[k.KeyID] = &kk
	return nil
}

// Remove deletes a key (revocation).
func (t *TrustStore) Remove(keyid string) {
	t.mu.Lock()
	delete(t.byID, keyid)
	t.mu.Unlock()
}

// Lookup returns the key for a key id.
func (t *TrustStore) Lookup(keyid string) (*TrustedKey, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	k, ok := t.byID[keyid]
	return k, ok
}

// Len returns the number of keys.
func (t *TrustStore) Len() int {
	if t == nil {
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byID)
}

// ParsePublicKey parses "ed25519:<std base64>".
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	rest, ok := strings.CutPrefix(s, "ed25519:")
	if !ok {
		return nil, fmt.Errorf("keys: public key must start with ed25519:")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(rest)
	if err != nil || len(b) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(b) != rest {
		return nil, fmt.Errorf("keys: invalid ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// FormatPublicKey renders "ed25519:<std base64>".
func FormatPublicKey(pk ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pk)
}

// Signer signs with an Ed25519 private key; implements dsse.Signer.
type Signer struct {
	id   string
	priv ed25519.PrivateKey
}

// NewSigner wraps a private key. Release builds refuse test keys.
func NewSigner(keyid string, priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("keys: bad private key size")
	}
	if Release && IsTestKey(keyid, priv.Public().(ed25519.PublicKey)) {
		return nil, fmt.Errorf("%w: %s", ErrTestKey, keyid)
	}
	return &Signer{id: keyid, priv: priv}, nil
}

// KeyID implements dsse.Signer.
func (s *Signer) KeyID() string { return s.id }

// Sign implements dsse.Signer.
func (s *Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }

// Public returns the public key.
func (s *Signer) Public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

// Private key files hold one line: "ed25519-seed:<64 hex>".
const seedPrefix = "ed25519-seed:"

// ParseSeedFile parses the content of a private key file.
func ParseSeedFile(b []byte) (ed25519.PrivateKey, error) {
	s := strings.TrimSpace(string(b))
	rest, ok := strings.CutPrefix(s, seedPrefix)
	if !ok {
		return nil, errors.New("keys: key file must contain ed25519-seed:<hex>")
	}
	seed, err := hex.DecodeString(rest)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("keys: invalid seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// FormatSeedFile renders a private key file.
func FormatSeedFile(priv ed25519.PrivateKey) []byte {
	return []byte(seedPrefix + hex.EncodeToString(priv.Seed()) + "\n")
}

// LoadSigner reads a private key file (should be mode 0600) and returns a signer.
func LoadSigner(keyid, path string) (*Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	priv, err := ParseSeedFile(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return NewSigner(keyid, priv)
}

// TestKeyNames lists the fixed test keys of contracts/testkeys.
var TestKeyNames = []string{"site-a", "site-b", "site-c", "lab-a", "lab-a2", "lab-b", "lab-c", "lab-d", "evil", "lab-d-online", "agent-a", "agent-b", "agent-c"}

// Seed domains: contracts/testkeys keys use TestSeedDomain; keys the test lab
// derives itself (testlab/scripts/gen-secrets.sh) use TestlabSeedDomain and
// are listed in contracts/testkeys since v0.2 (D24) so that release checks
// recognise them as well.
const (
	TestSeedDomain    = "schild/testkey/v0/"
	TestlabSeedDomain = "schild/testlab/v0/"
)

// testlabKeyIDs maps test lab key names to their key ids (not "test-" + name).
var testlabKeyIDs = map[string]string{"lab-d-online": "testlab-lab-d-online"}

// TestSeedDomainOf returns the seed domain of a test key name.
func TestSeedDomainOf(name string) string {
	if _, ok := testlabKeyIDs[name]; ok {
		return TestlabSeedDomain
	}
	return TestSeedDomain
}

// TestKeyID returns the key id of a test key name.
func TestKeyID(name string) string {
	if id, ok := testlabKeyIDs[name]; ok {
		return id
	}
	return TestKeyIDPrefix + name
}

// TestSeed derives the fixed seed of a test key. Public by design: anyone can
// sign with test keys, which is why release builds refuse them.
func TestSeed(name string) []byte {
	h := sha256.Sum256([]byte(TestSeedDomainOf(name) + name))
	return h[:]
}

var testPublic = func() [][]byte {
	var out [][]byte
	for _, n := range TestKeyNames {
		out = append(out, ed25519.NewKeyFromSeed(TestSeed(n)).Public().(ed25519.PublicKey))
	}
	return out
}()

// IsTestKey reports whether a key is a test key, by id prefix, by a listed
// test lab key id or by public key.
func IsTestKey(keyid string, pub ed25519.PublicKey) bool {
	if strings.HasPrefix(keyid, TestKeyIDPrefix) {
		return true
	}
	for _, id := range testlabKeyIDs {
		if keyid == id {
			return true
		}
	}
	for _, p := range testPublic {
		if bytes.Equal(p, pub) {
			return true
		}
	}
	return false
}
