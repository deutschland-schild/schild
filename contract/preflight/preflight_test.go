package preflight

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/keys"
)

// env is a fake environment.
type env map[string]string

func (e env) get(k string) string { return e[k] }

// newReport returns a report that sees only e and no system roots.
func newReport(e env) *Report {
	r := NewWithEnv("test-component", e.get)
	r.SystemFiles, r.SystemDirs = []string{}, []string{}
	return r
}

func randomPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func writeSeed(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "k.key")
	if err := os.WriteFile(p, keys.FormatSeedFile(priv), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func testPriv(name string) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(keys.TestSeed(name)) }

// makeCA writes a self-signed CA (and optionally a leaf issued by it) to dir.
func makeCA(t *testing.T, dir, cn string) (caPath, leafPath string, ca *x509.Certificate) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(der)
	caPath = filepath.Join(dir, "ca.pem")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "lab-1.example.org"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"lab-1.example.org"}}
	ld, err := x509.CreateCertificate(rand.Reader, lt, ca, &lk.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leafPath = filepath.Join(dir, "cert.pem")
	os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ld}), 0o644)
	return caPath, leafPath, ca
}

func kinds(r *Report) string {
	var s []string
	for _, f := range r.Findings {
		s = append(s, f.Kind)
	}
	return strings.Join(s, ",")
}

func wantRefused(t *testing.T, r *Report, kind string) {
	t.Helper()
	if !strings.Contains(kinds(r), kind) {
		t.Fatalf("want finding %s, got %q (%v)", kind, kinds(r), r.Findings)
	}
	if r.Err() == nil {
		t.Fatal("Err() is nil without override")
	}
	if !strings.Contains(r.Err().Error(), "refusing to start") {
		t.Fatalf("unclear error: %v", r.Err())
	}
}

func TestKeyIDPrefixRefused(t *testing.T) {
	for _, id := range []string{"test-site-a", "testlab-lab-d-online", "test", "tests/2026", "Test-x"} {
		r := newReport(env{})
		r.Key("site_key", id, randomPub(t))
		wantRefused(t, r, KindTestKeyID)
	}
	for _, id := range []string{"site-0123456789abcdef", "lab-1/2026-11", "contest-1", "lab-test"} {
		r := newReport(env{})
		r.Key("site_key", id, randomPub(t))
		if !r.OK() {
			t.Errorf("%s refused: %v", id, r.Findings)
		}
	}
}

func TestTestPublicKeyRefused(t *testing.T) {
	// Every key of contracts/testkeys (including the v0.2 test lab key of
	// lab-d) under an innocent key id.
	for _, n := range keys.TestKeyNames {
		r := newReport(env{})
		r.Key("labs[lab-1].keys", "lab-1/2026-11", testPriv(n).Public().(ed25519.PublicKey))
		wantRefused(t, r, KindTestKey)
	}
	r := newReport(env{})
	r.PublicKey("clients", "site-0123456789abcdef", keys.FormatPublicKey(testPriv("site-a").Public().(ed25519.PublicKey)))
	wantRefused(t, r, KindTestKey)
}

func TestPrivateKeyFileRefused(t *testing.T) {
	r := newReport(env{})
	r.PrivateKeyFile("site_key", "site-0123456789abcdef", writeSeed(t, testPriv("site-b")))
	wantRefused(t, r, KindTestKey)

	// Unreadable file: key id still checked, noted.
	r = newReport(env{})
	r.PrivateKeyFile("site_key", "test-site-a", filepath.Join(t.TempDir(), "missing.key"))
	wantRefused(t, r, KindTestKeyID)
	if len(r.Notes) != 1 {
		t.Fatalf("notes: %v", r.Notes)
	}
	// Production key passes.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	r = newReport(env{})
	p := writeSeed(t, priv)
	r.PrivateKeyFile("site_key", "site-0123456789abcdef", p)
	if !r.OK() || r.Err() != nil || len(r.Notes) != 0 {
		t.Fatalf("production key refused: %v %v", r.Findings, r.Notes)
	}
	// A key file other users can read is noted, not refused.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	r = newReport(env{})
	r.PrivateKeyFile("site_key", "site-0123456789abcdef", p)
	if !r.OK() || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "chmod 600") {
		t.Fatalf("mode 0644: findings %v, notes %v", r.Findings, r.Notes)
	}
}

func TestTestCARefused(t *testing.T) {
	dir := t.TempDir()
	// Marker in the subject (any regenerated test lab CA).
	caPath, leaf, _ := makeCA(t, dir, "Schild test CA (TEST ONLY)")
	for _, k := range []string{"SCHILD_TEST_CA", "SSL_CERT_FILE"} {
		r := newReport(env{k: caPath})
		r.TrustAnchors()
		wantRefused(t, r, KindTestCA)
	}
	r := newReport(env{"SSL_CERT_DIR": dir})
	r.TrustAnchors()
	wantRefused(t, r, KindTestCA)
	// System bundle file.
	r = newReport(env{})
	r.SystemFiles = []string{filepath.Join(dir, "missing.pem"), caPath}
	r.TrustAnchors()
	wantRefused(t, r, KindTestCA)
	// Serving certificate issued by the test CA.
	r = newReport(env{})
	r.ServingCert("tls.cert_file", leaf)
	wantRefused(t, r, KindTestCAIssue)
}

func TestTestCAFingerprintRefused(t *testing.T) {
	dir := t.TempDir()
	caPath, leaf, ca := makeCA(t, dir, "Some CA")
	r := newReport(env{"SCHILD_TEST_CA": caPath})
	r.TrustAnchors()
	r.ServingCert("tls.cert_file", leaf)
	if !r.OK() {
		t.Fatalf("ordinary CA refused: %v", r.Findings)
	}
	old := TestCAFingerprints
	t.Cleanup(func() { TestCAFingerprints = old })
	TestCAFingerprints = append([]string{Fingerprint(ca.Raw)}, old...)
	r = newReport(env{"SCHILD_TEST_CA": caPath})
	r.TrustAnchors()
	wantRefused(t, r, KindTestCA)
}

// TestEmbeddedFingerprintMatchesSecrets checks the embedded fingerprint
// against the local test lab CA when it is the one from stage 2. A
// regenerated CA (FORCE=1) is caught by the subject marker instead.
func TestEmbeddedFingerprintMatchesSecrets(t *testing.T) {
	b, err := os.ReadFile("../../tests/testlab/compose/secrets/ca.pem")
	if err != nil {
		t.Skip("no local test lab secrets")
	}
	certs := parseCerts(b)
	if len(certs) != 1 || !IsTestCA(certs[0]) {
		t.Fatalf("local test lab CA not recognised")
	}
}

func TestOverride(t *testing.T) {
	if keys.Release {
		// Release builds refuse test material whatever the environment says.
		r := newReport(env{OverrideEnv: "1"})
		r.KeyID("site_key", "test-site-a")
		if r.Override || r.Err() == nil {
			t.Fatalf("release build honoured %s=1", OverrideEnv)
		}
		var buf bytes.Buffer
		if err := r.Enforce(slog.New(slog.NewTextHandler(&buf, nil))); err == nil || strings.Contains(buf.String(), "OVERRIDE") {
			t.Fatalf("enforce in a release build: %v %s", err, buf.String())
		}
		return
	}
	for _, v := range []string{"1"} {
		r := newReport(env{OverrideEnv: v})
		r.Key("site_key", "test-site-a", testPriv("site-a").Public().(ed25519.PublicKey))
		if r.OK() || !r.Override || r.Err() != nil {
			t.Fatalf("override %q: ok=%v override=%v err=%v", v, r.OK(), r.Override, r.Err())
		}
		var buf bytes.Buffer
		if err := r.Enforce(slog.New(slog.NewTextHandler(&buf, nil))); err != nil || !strings.Contains(buf.String(), "OVERRIDE") {
			t.Fatalf("enforce with override: %v %s", err, buf.String())
		}
	}
	for _, v := range []string{"", "0", "true", "yes", " 1"} {
		r := newReport(env{OverrideEnv: v})
		r.Key("site_key", "test-site-a", randomPub(t))
		if r.Override || r.Err() == nil {
			t.Fatalf("override %q accepted", v)
		}
	}
}

func TestEnforceAndPrint(t *testing.T) {
	r := newReport(env{})
	r.Key("site_key", "test-site-a", randomPub(t))
	var log, out bytes.Buffer
	err := r.Enforce(slog.New(slog.NewJSONHandler(&log, nil)))
	if err == nil || !strings.Contains(log.String(), `"level":"ERROR"`) || !strings.Contains(log.String(), "refusing to start test-component") {
		t.Fatalf("enforce: %v %s", err, log.String())
	}
	r.Print(&out)
	if !strings.Contains(out.String(), "REFUSE") || !strings.Contains(out.String(), "result: REFUSE") {
		t.Fatal(out.String())
	}
	ok := newReport(env{})
	out.Reset()
	ok.Print(&out)
	if !strings.Contains(out.String(), "result: PASS") || ok.Enforce(slog.New(slog.NewTextHandler(&log, nil))) != nil {
		t.Fatal(out.String())
	}
}

func TestSiteAndLab(t *testing.T) {
	prodPub := keys.FormatPublicKey(randomPub(t))
	// The gateway holds no signing key (D72): production needs no keys, but a
	// TEST ONLY agent key is refused.
	standalone := &config.Site{Profile: "production", Mode: "autoblock"}
	r := newReport(env{})
	r.Site(standalone)
	if !r.OK() {
		t.Fatalf("standalone site: %v", r.Findings)
	}
	standalone.HostCheck = &config.HostCheck{Agents: config.AgentConfig{Keys: []config.AgentKey{
		{KeyID: "agent-1/2026-11", PublicKey: keys.FormatPublicKey(testPriv("agent-a").Public().(ed25519.PublicKey))},
		{KeyID: "test-agent-c", PublicKey: prodPub, Revoked: true},
	}}}
	r = newReport(env{})
	r.Site(standalone)
	if kinds(r) != KindTestKey {
		t.Fatalf("standalone agent key findings: %v", r.Findings)
	}

	dir := t.TempDir()
	_, leaf, _ := makeCA(t, dir, "Schild test CA (TEST ONLY)")
	lab := &config.LabConfig{
		Keys:    []config.LabSignKey{{KeyID: "lab-1/2026-11", PrivateKeyFile: writeSeed(t, testPriv("lab-a"))}},
		Clients: []config.Client{{KeyID: "test-site-a", PublicKey: prodPub}, {KeyID: "test-site-b", PublicKey: prodPub, Revoked: true}},
		Peers:   []config.Peer{{Lab: "lab-2", Keys: []config.LabKey{{KeyID: "lab-2/2026-11", PublicKey: keys.FormatPublicKey(testPriv("lab-b").Public().(ed25519.PublicKey))}}}},
		TLS:     &config.TLS{CertFile: leaf},
	}
	r = newReport(env{})
	r.Lab(lab)
	if got := kinds(r); got != strings.Join([]string{KindTestKey, KindTestKeyID, KindTestKey, KindTestCAIssue}, ",") {
		t.Fatalf("lab findings %s: %v", got, r.Findings)
	}

	r = newReport(env{"SCHILD_RELAY_TLS_CERT": leaf})
	r.Relay()
	wantRefused(t, r, KindTestCAIssue)
	r = newReport(env{})
	r.Relay()
	if !r.OK() {
		t.Fatalf("relay: %v", r.Findings)
	}
}
