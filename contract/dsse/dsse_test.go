package dsse

import (
	"crypto/ed25519"
	"testing"
)

type edSigner struct {
	id   string
	priv ed25519.PrivateKey
}

func (s edSigner) KeyID() string                 { return s.id }
func (s edSigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(s.priv, m), nil }

func TestPAE(t *testing.T) {
	// Test vector from the DSSE protocol description.
	got := string(PAE("http://example.com/HelloWorld", []byte("hello world")))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if got != want {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
	if string(PAE("", nil)) != "DSSEv1 0  0 " {
		t.Fatalf("empty PAE = %q", PAE("", nil))
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	env, err := Sign("application/vnd.schild.signal.v0+json", []byte(`{"a":1}`), edSigner{"k", priv})
	if err != nil {
		t.Fatal(err)
	}
	p, err := env.DecodePayload()
	if err != nil || string(p) != `{"a":1}` {
		t.Fatalf("payload %q %v", p, err)
	}
	sig, err := DecodeBase64(env.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), PAE(env.PayloadType, p), sig) {
		t.Fatal("signature does not verify over PAE")
	}
	if ed25519.Verify(priv.Public().(ed25519.PublicKey), p, sig) {
		t.Fatal("signature must not verify over the raw payload")
	}
	if err := env.AddSignature(edSigner{"k2", ed25519.NewKeyFromSeed(make([]byte, 32))}); err != nil || len(env.Signatures) != 2 {
		t.Fatal("AddSignature failed")
	}
}

func TestDecodeBase64Canonical(t *testing.T) {
	if _, err := DecodeBase64("QQ=="); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"QR==", "QQ", "QQ=", "Q Q==", "QQ==\n", "-_8=", "QUJD\n"} {
		if _, err := DecodeBase64(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
