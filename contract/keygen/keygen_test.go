package keygen

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/preflight"
)

func TestValidateKeyID(t *testing.T) {
	for _, ok := range []string{"lab-1/2026-11", "relay-0123456789abcdef", "site-0123456789abcdef"} {
		if err := ValidateKeyID(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "test-lab", "testlab-x", "Lab-1", "-x", "a b"} {
		if err := ValidateKeyID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNewSigningKey(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "lab.key")
	k, err := NewSigningKey(out, "", "lab-1/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(k.KeyID, "lab-1/") || len(k.KeyID) != len("lab-1/")+16 {
		t.Fatalf("keyid %s", k.KeyID)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	s, err := keys.LoadSigner(k.KeyID, out)
	if err != nil || !s.Public().Equal(k.Public) {
		t.Fatalf("load: %v", err)
	}
	// The preflight accepts the new key.
	r := preflight.NewWithEnv("x", func(string) string { return "" })
	r.SystemFiles, r.SystemDirs = []string{}, []string{}
	r.PrivateKeyFile("keys", k.KeyID, out)
	if !r.OK() {
		t.Fatalf("preflight refuses a generated key: %v", r.Findings)
	}
	if _, err := NewSigningKey(out, "lab-1/x", ""); err == nil || !strings.Contains(err.Error(), "not overwritten") {
		t.Fatalf("overwrite: %v", err)
	}
	if _, err := NewSigningKey(filepath.Join(dir, "t.key"), "test-lab-1", ""); err == nil {
		t.Fatal("test key id accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "t.key")); err == nil {
		t.Fatal("file written for a refused key id")
	}
}

func TestRefusesCheckout(t *testing.T) {
	// A fake checkout: <root>/contracts/testkeys/keys.json.
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "contracts", "testkeys"), 0o755)
	os.WriteFile(filepath.Join(root, "contracts", "testkeys", "keys.json"), []byte("{}"), 0o644)
	for _, p := range []string{filepath.Join(root, "lab.key"), filepath.Join(root, "lab", "lab.key")} {
		os.MkdirAll(filepath.Dir(p), 0o755)
		if _, err := NewSigningKey(p, "lab-1/2026-11", ""); err == nil || !strings.Contains(err.Error(), "outside the repo") {
			t.Errorf("%s: %v", p, err)
		}
	}
	// This package lives in the real checkout.
	if _, ok := InsideCheckout("x.key"); !ok {
		t.Error("real checkout not detected")
	}
}

func TestNewTLSKey(t *testing.T) {
	dir := t.TempDir()
	k, err := NewTLSKey(filepath.Join(dir, "key.pem"), filepath.Join(dir, "csr.pem"), SplitHosts("relay-1.example.org, relay.example.org"))
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(k.KeyFile)
	if fi.Mode().Perm() != 0o600 || len(k.SPKISHA256) != 64 {
		t.Fatalf("mode %v spki %s", fi.Mode(), k.SPKISHA256)
	}
	b, _ := os.ReadFile(k.CSRFile)
	blk, _ := pem.Decode(b)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "relay-1.example.org" || len(csr.DNSNames) != 2 {
		t.Fatalf("csr: %v %+v", err, csr)
	}
	if _, err := NewTLSKey(k.KeyFile, filepath.Join(dir, "csr2.pem"), []string{"x"}); err == nil {
		t.Fatal("overwrote key")
	}
}
