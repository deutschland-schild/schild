package keys

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deutschland-schild/schild/contract"
)

func TestPublicKeyRoundTrip(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(TestSeed("lab-a")).Public().(ed25519.PublicKey)
	s := FormatPublicKey(pub)
	got, err := ParsePublicKey(s)
	if err != nil || !got.Equal(pub) {
		t.Fatalf("round trip failed: %v", err)
	}
	for _, bad := range []string{"", "ed25519:", "ed448:" + s[8:], s + "A", "ed25519:AAAA"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTrustStore(t *testing.T) {
	ts := NewTrustStore()
	pub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	k := TrustedKey{KeyID: "lab-x/rules", Public: pub, Purposes: []contract.Purpose{contract.PurposeRules}, Operator: "op-x"}
	if err := ts.Add(k); err != nil {
		t.Fatal(err)
	}
	if err := ts.Add(k); err == nil {
		t.Fatal("duplicate accepted")
	}
	got, ok := ts.Lookup("lab-x/rules")
	if !ok || !got.Allows(contract.PurposeRules) || got.Allows(contract.PurposeSignal) {
		t.Fatal("lookup/purpose wrong")
	}
	ts.Remove("lab-x/rules")
	if ts.Len() != 0 {
		t.Fatal("remove failed")
	}
	if err := ts.Add(TrustedKey{KeyID: "x", Public: []byte{1}}); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestIsTestKey(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(TestSeed("site-b")).Public().(ed25519.PublicKey)
	if !IsTestKey("renamed", pub) {
		t.Fatal("test public key under another id not detected")
	}
	if !IsTestKey("test-anything", make([]byte, 32)) {
		t.Fatal("test- prefix not detected")
	}
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if IsTestKey("lab-a/rules", other) {
		t.Fatal("false positive")
	}
}

// lab-d's online key in test lab profile t1 (D24): recognised by key id and
// by public key; the public key is the one in testlab/compose/config/t1.
func TestIsTestKeyTestlabOnline(t *testing.T) {
	if TestKeyID("lab-d-online") != "testlab-lab-d-online" {
		t.Fatal("key id")
	}
	pub := ed25519.NewKeyFromSeed(TestSeed("lab-d-online")).Public().(ed25519.PublicKey)
	if got := FormatPublicKey(pub); got != "ed25519:3UV7P+fJOcSOyV0n6VD4bO442AKeNaUPHJjIbhqjSXQ=" {
		t.Fatalf("public key %s differs from testlab/scripts/gen-secrets.sh", got)
	}
	if !IsTestKey("lab-d/2026-11", pub) {
		t.Fatal("public key not detected")
	}
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if !IsTestKey("testlab-lab-d-online", other) {
		t.Fatal("key id not detected")
	}
}

func TestReleaseRefusesTestKeys(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(TestSeed("lab-a"))
	_, errSigner := NewSigner("test-lab-a", priv)
	errTrust := NewTrustStore().Add(TrustedKey{KeyID: "test-lab-a", Public: priv.Public().(ed25519.PublicKey)})
	if Release {
		if !errors.Is(errSigner, ErrTestKey) || !errors.Is(errTrust, ErrTestKey) {
			t.Fatalf("release build accepted a test key: %v %v", errSigner, errTrust)
		}
	} else if errSigner != nil || errTrust != nil {
		t.Fatalf("dev build refused test key: %v %v", errSigner, errTrust)
	}
}

func TestSeedFile(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	p := filepath.Join(t.TempDir(), "k.key")
	if err := os.WriteFile(p, FormatSeedFile(priv), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSigner("site/k", p)
	if err != nil || !s.Public().Equal(priv.Public()) {
		t.Fatalf("load: %v", err)
	}
	if _, err := ParseSeedFile([]byte("ed25519-seed:zz")); err == nil {
		t.Fatal("bad seed accepted")
	}
}

func TestTrustStoreRejectsDuplicatePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	ts := NewTrustStore()
	if err := ts.Add(TrustedKey{KeyID: "lab-x/rules/2026-10", Public: pub, Operator: "op-x"}); err != nil {
		t.Fatal(err)
	}
	if err := ts.Add(TrustedKey{KeyID: "lab-y/rules/2026-10", Public: pub, Operator: "op-y"}); err == nil {
		t.Fatal("the same public key under a second id (and operator) was accepted")
	}
}
