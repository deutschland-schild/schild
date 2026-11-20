package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/keys"
)

func TestKeygenCmd(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "lab.key")
	var buf bytes.Buffer
	if err := keygenCmd([]string{"-out", out, "-lab", "lab-1", "-operator", "op-1", "-keyid", "lab-1/2026-11"}, &buf); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	s, err := keys.LoadSigner("lab-1/2026-11", out)
	if err != nil {
		t.Fatal(err)
	}
	pub := keys.FormatPublicKey(s.Public())
	for _, want := range []string{"keyid:      lab-1/2026-11", pub, "purposes: [ack, rules, checkpoint]", "lab-1=op-1:lab-1/2026-11=" + pub} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, buf.String())
		}
	}
	// Default key id, purpose subset.
	buf.Reset()
	if err := keygenCmd([]string{"-out", filepath.Join(dir, "online.key"), "-lab", "lab-1", "-purposes", "ack,checkpoint"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "keyid:      lab-1/20") || strings.Contains(buf.String(), "watch -keys") {
		t.Errorf("default key id / purposes:\n%s", buf.String())
	}
	for _, args := range [][]string{
		{"-out", filepath.Join(dir, "a.key"), "-lab", "lab-1", "-keyid", "test-lab-1"},
		{"-out", filepath.Join(dir, "b.key"), "-lab", "lab-1", "-purposes", "signal"},
		{"-out", out, "-lab", "lab-1"},
		{"-lab", "lab-1"},
	} {
		if err := keygenCmd(args, &buf); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	buf.Reset()
	if err := tlsKeygenCmd([]string{"-out-dir", dir, "-host", "lab-1.example.org"}, &buf); err != nil || !strings.Contains(buf.String(), "csr.pem") {
		t.Fatalf("tls-keygen: %v %s", err, buf.String())
	}
}
