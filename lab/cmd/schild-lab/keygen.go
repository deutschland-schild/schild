package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/keygen"
)

// labPurposes are the purposes a lab signs with: acks (ingest), rule bundles
// and withdrawals (also co-signing and the Schild-Peer-Auth requests to
// peers, which use the rules key), and checkpoints.
var labPurposes = []contract.Purpose{contract.PurposeAck, contract.PurposeRules, contract.PurposeCheckpoint}

// keygenCmd creates a production signing key of a lab (D24).
//
//	schild-lab keygen -out /out/lab.key -lab lab-1 [-operator op-1] [-keyid lab-1/2026-11]
//	                  [-purposes ack,rules,checkpoint] [-config-path /run/schild-lab/keys/lab.key]
//
// One key with all three purposes is the default. A lab that keeps its rules
// key offline creates two keys: -purposes rules (offline, co-signing with
// `schild-lab cosign`) and -purposes ack,checkpoint (online).
func keygenCmd(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "private key file to create outside the repo (mode 0600, never overwritten)")
	lab := fs.String("lab", "", "lab id of this lab (identity.lab), e.g. lab-1")
	operator := fs.String("operator", "", "operator id of this lab (identity.operator), for the printed snippets")
	keyid := fs.String("keyid", "", "key id (default <lab>/<YYYY-MM>-<16 hex of sha256(public key)>); never starting with \"test\"")
	purposes := fs.String("purposes", "ack,rules,checkpoint", "comma-separated subset of ack, rules, checkpoint")
	cfgPath := fs.String("config-path", "", "path of the key file as the container sees it, for the lab.yaml snippet (default -out)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *lab == "" {
		return errors.New("keygen needs -out FILE and -lab LAB")
	}
	var ps []contract.Purpose
	for _, p := range strings.Split(*purposes, ",") {
		pp := contract.Purpose(strings.TrimSpace(p))
		if !slices.Contains(labPurposes, pp) {
			return fmt.Errorf("keygen: purpose %q is not a lab purpose (ack, rules, checkpoint)", p)
		}
		if !slices.Contains(ps, pp) {
			ps = append(ps, pp)
		}
	}
	prefix := *lab + "/" + time.Now().UTC().Format("2006-01") + "-"
	k, err := keygen.NewSigningKey(*out, *keyid, prefix)
	if err != nil {
		return err
	}
	path := *cfgPath
	if path == "" {
		path = *out
	}
	op := *operator
	if op == "" {
		op = "<operator>"
	}
	var pl []string
	for _, p := range ps {
		pl = append(pl, string(p))
	}
	plist := strings.Join(pl, ", ")
	pub := k.PublicString()
	fmt.Fprintf(stdout, `wrote %s (mode 0600). Keep an encrypted offline copy; the private key never leaves this host.

keyid:      %s
public key: %s
purposes:   %s

lab.yaml of %s (keys[]):
  - { keyid: %s, private_key_file: %s, purposes: [%s] }

every client that verifies this lab (trusted keys of lab %s; the gateway has no lab config since D72):
  - { keyid: %s, public_key: "%s", purposes: [%s] }

lab.yaml of every peer lab (peers[] entry lab %s, operator %s, keys[]):
  - { keyid: %s, public_key: "%s", purposes: [%s] }
`, k.File, k.KeyID, pub, plist, *lab, k.KeyID, path, plist, *lab, k.KeyID, pub, plist, *lab, op, k.KeyID, pub, plist)
	if slices.Contains(ps, contract.PurposeRules) {
		fmt.Fprintf(stdout, `
Peer requests (Schild-Peer-Auth) and co-signatures use this key (purpose rules).
schild-relay watch -keys entry:
  %s=%s:%s=%s
`, *lab, op, k.KeyID, pub)
	}
	return nil
}

// tlsKeygenCmd creates the TLS key and CSR for the lab's ingest and feed
// ports (lab.yaml tls.key_file / tls.cert_file).
//
//	schild-lab tls-keygen -out-dir /out -host lab-1.example.org
func tlsKeygenCmd(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("tls-keygen", flag.ContinueOnError)
	dir := fs.String("out-dir", "", "directory for key.pem (0600) and csr.pem, outside the repo")
	hosts := fs.String("host", "", "DNS names, comma separated (first = common name)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *hosts == "" {
		return errors.New("tls-keygen needs -out-dir DIR and -host NAME")
	}
	k, err := keygen.NewTLSKey(filepath.Join(*dir, "key.pem"), filepath.Join(*dir, "csr.pem"), keygen.SplitHosts(*hosts))
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, `wrote %s (mode 0600) and %s for %s
public key sha256 (SPKI): %s

Have the CSR signed by a public CA (or your own, never the test lab CA), store the
certificate next to the key and set in lab.yaml:
  tls: { cert_file: <cert.pem>, key_file: <key.pem> }
`, k.KeyFile, k.CSRFile, strings.Join(k.Hosts, ", "), k.SPKISHA256)
	return nil
}
