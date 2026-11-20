package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/deutschland-schild/schild/contract/keygen"
)

// keygenCmd creates the relay's only secret: its TLS key, with a CSR for the
// public certificate (D24). Relays sign nothing (contracts: clients verify
// lab signatures end to end), so there is no signing key and no key id in
// any config; the key id printed here is for the operations log only.
//
//	schild-relay keygen -out-dir /out -host relay-1.example.org
func keygenCmd(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	dir := fs.String("out-dir", "", "directory for key.pem (0600) and csr.pem, outside the repo")
	hosts := fs.String("host", "", "DNS names, comma separated (first = common name)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *hosts == "" {
		return errors.New("keygen needs -out-dir DIR and -host NAME")
	}
	k, err := keygen.NewTLSKey(filepath.Join(*dir, "key.pem"), filepath.Join(*dir, "csr.pem"), keygen.SplitHosts(*hosts))
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, `wrote %s (mode 0600) and %s for %s
key id (operations log): relay-%s
public key sha256 (SPKI): %s

Have the CSR signed by a public CA (never the test lab CA), store the
certificate as cert.pem next to the key and run the relay with
  SCHILD_RELAY_TLS_CERT=<dir>/cert.pem
  SCHILD_RELAY_TLS_KEY=<dir>/key.pem
or terminate TLS in front of the relay and keep this key there.
`, k.KeyFile, k.CSRFile, strings.Join(k.Hosts, ", "), k.SPKISHA256[:16], k.SPKISHA256)
	return nil
}
