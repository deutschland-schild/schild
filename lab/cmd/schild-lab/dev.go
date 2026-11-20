//go:build !release

package main

// Development and test lab helpers. They exist only in non-release builds
// (they use the TEST ONLY keys of contracts/testkeys).
//
//	schild-lab dev-certs -out DIR -hosts lab-a,lab-b,relay-1
//	    test CA (DIR/ca.pem) and one server certificate per host (DIR/<host>/{cert,key}.pem)
//	schild-lab dev-send -url https://lab-a:7443 -lab lab-a -site site-a -n 10 [-action sqli/rest-api]
//	    submit signed signals with a TEST ONLY site key and verify the lab's ack

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/auth"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/transport"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/relay/upstream"
)

func init() {
	devCommands["dev-certs"] = devCerts
	devCommands["dev-send"] = devSend
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func devCerts(args []string) error {
	fs := flag.NewFlagSet("dev-certs", flag.ContinueOnError)
	out := fs.String("out", "", "output directory")
	hosts := fs.String("hosts", "", "comma-separated host names")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *hosts == "" {
		return errors.New("dev-certs needs -out and -hosts")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Schild test CA (TEST ONLY)"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*out, "ca.pem"), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	for i, h := range strings.Split(*hosts, ",") {
		h = strings.TrimSpace(h)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: h}, DNSNames: []string{h, "localhost"},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		kb, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		dir := filepath.Join(*out, h)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, "cert.pem"), "CERTIFICATE", der, 0o644); err != nil {
			return err
		}
		// 0644: TEST ONLY material, read by the container's nonroot user
		// through a bind mount.
		if err := writePEM(filepath.Join(dir, "key.pem"), "PRIVATE KEY", kb, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("test CA and certificates for %s in %s (TEST ONLY)\n", *hosts, *out)
	return nil
}

func devSend(args []string) error {
	fs := flag.NewFlagSet("dev-send", flag.ContinueOnError)
	url := fs.String("url", "", "lab ingest base URL, e.g. https://lab-a:7443")
	lab := fs.String("lab", "lab-a", "test key name of the lab (verifies the ack)")
	site := fs.String("site", "site-a", "test key name of the site")
	n := fs.Int("n", 4, "signals to send (one submission)")
	action := fs.String("action", "sqli/rest-api", "action_sig")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *n < 1 || *n > 64 {
		return errors.New("dev-send needs -url and 1..64 signals")
	}
	hc, err := upstream.HTTPClient()
	if err != nil {
		return err
	}
	tr := transport.NewHTTPS(10 * time.Second)
	tr.Client.Transport = hc.Transport
	signer := auth.NewSiteKeySigner(testkeys.Signer(*site))
	sub := &msg.Submission{RequestID: msg.NewID()}
	now := time.Now()
	for i := 0; i < *n; i++ {
		s := msg.Signal{Schema: msg.SchemaSignal, ID: msg.NewID(), Kind: "tip", TimeBucket: msg.TimeBucket(now, 5), ActionSig: *action,
			RequestSig: msg.RequestSig(msg.RequestShape{Method: "POST", PathTemplate: fmt.Sprintf("/api/items/{n}/%d", i), ParamNames: []string{"id"}, ContentType: "application/json", RuleIDs: []int{942100}}),
			WAFRules:   []int{942100}, Score: 80, Category: "sqli",
			Origin: msg.Origin{Country: "NL", ASN: 64500, NetClass: "hosting", Attribution: "tcp_peer"}, Agent: msg.Agent{Family: "python-requests", Major: 2}}
		payload, err := jsonx.Marshal(&s)
		if err != nil {
			return err
		}
		sealed, err := signer.Seal(context.Background(), contract.KindSignal, payload)
		if err != nil {
			return err
		}
		raw, err := sealed.Envelope.Marshal()
		if err != nil {
			return err
		}
		sub.Envelopes = append(sub.Envelopes, raw)
	}
	resp, err := tr.Submit(context.Background(), transport.Lab{ID: *lab, Endpoint: *url}, sub, "")
	if err != nil {
		return err
	}
	res, err := verify.Signed(contract.KindAck, resp.AckEnvelope, &verify.Context{Now: time.Now(), Trust: testkeys.TrustStore(*lab), ExpectedInReplyTo: sub.RequestID})
	if err != nil {
		return fmt.Errorf("ack does not verify: %w", err)
	}
	a := res.Value.(*msg.Ack)
	fmt.Printf("status %d, ack verified: accepted %d, duplicate %d, rejected %d, control %s retry_after_ms %d\n",
		resp.Status, len(a.Accepted), len(a.Duplicate), len(a.Rejected), a.Control.Reason, a.Control.RetryAfterMS)
	return nil
}
