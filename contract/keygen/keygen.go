// Package keygen creates production keys for schild, schild-lab and
// schild-relay (DECISIONS D24). Private keys are written once (never
// overwritten) with mode 0600 to a path outside any source checkout; key
// ids never start with "test", so the start-up preflight accepts them.
package keygen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/preflight"
)

// keyidRe is the keyid pattern of contracts/common.schema.json.
var keyidRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)

// ValidateKeyID checks the contract pattern and refuses test key ids.
func ValidateKeyID(id string) error {
	if !keyidRe.MatchString(id) {
		return fmt.Errorf("keygen: key id %q does not match %s", id, keyidRe)
	}
	if preflight.IsTestKeyID(id) {
		return fmt.Errorf("keygen: key id %q starts with %q; such ids are reserved for test keys and refused by the preflight", id, preflight.TestKeyIDPrefix)
	}
	return nil
}

// ShortID returns the first 16 hex characters of sha256(b).
func ShortID(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:16]
}

// InsideCheckout reports the checkout root when path lies inside a Schild
// source checkout (a directory with contracts/testkeys/keys.json). Other git
// trees (e.g. etckeeper's /etc/.git) do not count.
func InsideCheckout(path string) (string, bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	if r, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		abs = filepath.Join(r, filepath.Base(abs))
	}
	for dir := filepath.Dir(abs); ; {
		if _, err := os.Stat(filepath.Join(dir, "contracts", "testkeys", "keys.json")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// writeNew writes a new file with mode 0600; it never overwrites and
// refuses paths inside a source checkout.
func writeNew(path string, data []byte) error {
	if path == "" {
		return errors.New("keygen: -out FILE is required")
	}
	if root, ok := InsideCheckout(path); ok {
		return fmt.Errorf("keygen: %s is inside the source checkout %s; write private keys outside the repo (e.g. /etc/schild-prod/<name>/keys/)", path, root)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("keygen: %s exists, not overwritten", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Chmod(0o600); err != nil { // umask independent
		f.Close()
		return err
	}
	return f.Close()
}

// SigningKey is a new Ed25519 key written to File.
type SigningKey struct {
	KeyID  string
	File   string
	Public ed25519.PublicKey
}

// PublicString is "ed25519:<base64>".
func (k *SigningKey) PublicString() string { return keys.FormatPublicKey(k.Public) }

// NewSigningKey creates an Ed25519 key and writes its seed file
// ("ed25519-seed:<hex>", mode 0600). An empty keyid becomes
// idPrefix + 16 hex of sha256(public key).
func NewSigningKey(out, keyid, idPrefix string) (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if keyid == "" {
		keyid = idPrefix + ShortID(pub)
	}
	if err := ValidateKeyID(keyid); err != nil {
		return nil, err
	}
	if keys.IsTestKey(keyid, pub) { // cannot happen with a random key; belt and braces
		return nil, errors.New("keygen: generated a test key")
	}
	if err := writeNew(out, keys.FormatSeedFile(priv)); err != nil {
		return nil, err
	}
	return &SigningKey{KeyID: keyid, File: out, Public: pub}, nil
}

// TLSKey is a new ECDSA P-256 TLS key with a certificate signing request.
type TLSKey struct {
	KeyFile, CSRFile string
	Hosts            []string
	// SPKISHA256 is the hex SHA-256 of the public key (SubjectPublicKeyInfo),
	// for the operations log and for pinning.
	SPKISHA256 string
}

// NewTLSKey writes a PKCS#8 private key (mode 0600) to keyFile and a CSR
// for hosts (first = common name) to csrFile (mode 0644). The CSR goes to
// the CA (e.g. ACME via the host's TLS terminator, or the operator's CA).
func NewTLSKey(keyFile, csrFile string, hosts []string) (*TLSKey, error) {
	if len(hosts) == 0 || hosts[0] == "" {
		return nil, errors.New("keygen: at least one host name is required")
	}
	if csrFile == "" {
		return nil, errors.New("keygen: CSR file is required")
	}
	if _, err := os.Stat(csrFile); err == nil {
		return nil, fmt.Errorf("keygen: %s exists, not overwritten", csrFile)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts}, k)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := writeNew(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	if err := os.WriteFile(csrFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), 0o644); err != nil {
		return nil, err
	}
	h := sha256.Sum256(spki)
	return &TLSKey{KeyFile: keyFile, CSRFile: csrFile, Hosts: hosts, SPKISHA256: hex.EncodeToString(h[:])}, nil
}

// SplitHosts splits a comma-separated host list.
func SplitHosts(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}
