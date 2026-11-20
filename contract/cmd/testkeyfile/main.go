//go:build !release

// Command testkeyfile prints the private key file of a TEST ONLY key from
// contracts/testkeys (format "ed25519-seed:<hex>"), for test lab containers.
//
//	go run ./cmd/testkeyfile -name lab-a > lab.key
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/testkeys"
)

func main() {
	name := flag.String("name", "", "test key name, e.g. site-a, lab-a")
	pub := flag.Bool("public", false, "print keyid and public key instead")
	flag.Parse()
	for _, k := range testkeys.All() {
		if k.Name == *name {
			if *pub {
				fmt.Printf("%s %s\n", k.KeyID, k.Public)
				return
			}
			os.Stdout.Write(keys.FormatSeedFile(testkeys.Private(k.Name)))
			return
		}
	}
	fmt.Fprintf(os.Stderr, "testkeyfile: unknown key %q (have: %v)\n", *name, keys.TestKeyNames)
	os.Exit(2)
}
