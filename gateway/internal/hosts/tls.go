package hosts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func tlsConfig(cert *tls.Certificate) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if cert != nil {
		c.Certificates = []tls.Certificate{*cert}
	}
	return c
}

// loadOrCreateCert loads host_check.agents.tls_cert/tls_key or, when they
// are not configured, a self-signed certificate in dir (created once, key
// mode 0600). Agents pin the certificate, so no CA is involved.
func loadOrCreateCert(certFile, keyFile, dir, nodeName string) (*tls.Certificate, error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("tls_cert and tls_key go together")
		}
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		return &c, err
	}
	cf, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if c, err := tls.LoadX509KeyPair(cf, kf); err == nil {
		return &c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	names := []string{nodeName}
	if h, err := os.Hostname(); err == nil && h != nodeName {
		names = append(names, h)
	}
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: nodeName + " schild agent listener"}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	c, err := tls.LoadX509KeyPair(cf, kf)
	return &c, err
}
