//go:build !release

// Package testkeys exposes the fixed TEST ONLY keys of contracts/testkeys.
// Their seeds are public (derived from the key name), so anybody can sign
// with them. The package does not exist in release builds (-tags release),
// and keys.Release builds refuse these keys anywhere.
package testkeys

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/keys"
)

// Key describes one test key.
type Key struct {
	Name     string             `json:"name"`
	KeyID    string             `json:"keyid"`
	Seed     string             `json:"seed_hex"`
	Domain   string             `json:"seed_domain,omitempty"` // only when not keys.TestSeedDomain
	Public   string             `json:"public_key"`
	Purposes []contract.Purpose `json:"purposes"`
	Operator string             `json:"operator,omitempty"`
	Lab      string             `json:"lab,omitempty"`
	Issuer   string             `json:"issuer,omitempty"`
}

var (
	site = []contract.Purpose{contract.PurposeSignal, contract.PurposeFeedback}
	lab  = []contract.Purpose{contract.PurposeAck, contract.PurposeRules, contract.PurposeCheckpoint}
)

var meta = []Key{
	{Name: "site-a", Purposes: site, Issuer: "issuer-test-1"},
	{Name: "site-b", Purposes: site, Issuer: "issuer-test-1"},
	{Name: "site-c", Purposes: site, Issuer: "issuer-test-2"},
	{Name: "lab-a", Purposes: lab, Operator: "op-test-a", Lab: "lab-a"},
	{Name: "lab-a2", Purposes: []contract.Purpose{contract.PurposeRules, contract.PurposeCheckpoint}, Operator: "op-test-a", Lab: "lab-a2"},
	{Name: "lab-b", Purposes: lab, Operator: "op-test-b", Lab: "lab-b"},
	{Name: "lab-c", Purposes: lab, Operator: "op-test-c", Lab: "lab-c"},
	{Name: "lab-d", Purposes: []contract.Purpose{contract.PurposeRules}, Operator: "op-test-d", Lab: "lab-d"},
	{Name: "evil", Purposes: []contract.Purpose{contract.PurposeSignal, contract.PurposeFeedback, contract.PurposeAck, contract.PurposeRules, contract.PurposeCheckpoint}, Operator: "op-test-evil", Lab: "evil", Issuer: "issuer-test-evil"},
	// Online key of lab-d in test lab profile t1 (testlab/scripts/gen-secrets.sh);
	// own seed domain and key id, listed since v0.2 (D24).
	{Name: "lab-d-online", Purposes: []contract.Purpose{contract.PurposeAck, contract.PurposeCheckpoint}, Operator: "op-test-d", Lab: "lab-d"},
	// v0.3 (host-check.md): agent keys of app VMs; agent-c is the one the
	// vectors revoke.
	{Name: "agent-a", Purposes: []contract.Purpose{contract.PurposeAgent}},
	{Name: "agent-b", Purposes: []contract.Purpose{contract.PurposeAgent}},
	{Name: "agent-c", Purposes: []contract.Purpose{contract.PurposeAgent}},
}

// All returns every test key with derived seed and public key.
func All() []Key {
	out := make([]Key, 0, len(meta))
	for _, m := range meta {
		priv := ed25519.NewKeyFromSeed(keys.TestSeed(m.Name))
		m.KeyID = keys.TestKeyID(m.Name)
		if d := keys.TestSeedDomainOf(m.Name); d != keys.TestSeedDomain {
			m.Domain = d
		}
		m.Seed = hex.EncodeToString(priv.Seed())
		m.Public = keys.FormatPublicKey(priv.Public().(ed25519.PublicKey))
		out = append(out, m)
	}
	return out
}

// Get returns a test key by name.
func Get(name string) Key {
	for _, k := range All() {
		if k.Name == name {
			return k
		}
	}
	panic(fmt.Sprintf("testkeys: unknown key %q", name))
}

// Private returns the private key of a test key.
func Private(name string) ed25519.PrivateKey {
	Get(name)
	return ed25519.NewKeyFromSeed(keys.TestSeed(name))
}

// Signer returns a signer for a test key.
func Signer(name string) *keys.Signer {
	s, err := keys.NewSigner(Get(name).KeyID, Private(name))
	if err != nil {
		panic(err)
	}
	return s
}

// Trusted returns the trust store entry of a test key.
func Trusted(name string) keys.TrustedKey {
	k := Get(name)
	return keys.TrustedKey{
		KeyID:    k.KeyID,
		Public:   Private(name).Public().(ed25519.PublicKey),
		Purposes: k.Purposes,
		Operator: k.Operator,
		Lab:      k.Lab,
		Issuer:   k.Issuer,
	}
}

// TrustStore builds a store with the named test keys.
func TrustStore(names ...string) *keys.TrustStore {
	ts := keys.NewTrustStore()
	for _, n := range names {
		if err := ts.Add(Trusted(n)); err != nil {
			panic(err)
		}
	}
	return ts
}

// File is the content of contracts/testkeys/keys.json.
type File struct {
	Warning string `json:"warning"`
	Keys    []Key  `json:"keys"`
}

// JSON renders contracts/testkeys/keys.json.
func JSON() []byte {
	b, err := jsonx.Marshal(File{
		Warning: "TEST ONLY. Seeds are public (sha256 of seed_domain + name, default seed_domain \"schild/testkey/v0/\"). Release builds (-tags release) refuse these keys.",
		Keys:    All(),
	})
	if err != nil {
		panic(err)
	}
	return b
}
