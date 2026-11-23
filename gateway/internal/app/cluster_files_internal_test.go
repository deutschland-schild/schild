package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// A directory record of another node (here an ACME account) replaces the
// files of the storage the directory keeps, and leaves alone a file that is being written there:
// certmagic's temporary file (a random name without an extension) and this
// node's own `.tmp`.
func TestTakingADirectoryLeavesFilesBeingWritten(t *testing.T) {
	root := t.TempDir()
	const id = "acme/ca.example-directory/users/admin@shop.example"
	dir := filepath.Join(root, filepath.FromSlash(id))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"admin.json": "old", "admin.extra": "{}", "2837465512": "in flight", "shop.example.key.tmp": "in flight"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	rec := &contract.Record{V: contract.Version, Group: "g-00000000000000000000000000000000", Class: contract.ClassCertificates, ID: id, Origin: "n-00000000000000000000000000000001", Seq: 1, HLC: 1}
	files := &contract.Files{Node: "web-2", Files: map[string]string{
		"admin.json": base64.StdEncoding.EncodeToString([]byte("new")),
		"admin.key":  base64.StdEncoding.EncodeToString([]byte("key")),
	}}
	if err := rec.Sign(key, files); err != nil {
		t.Fatal(err)
	}
	g := &groupFiles{a: &App{log: slog.New(slog.NewTextHandler(io.Discard, nil))}, root: root}
	g.take(rec)
	want := map[string]string{"admin.json": "new", "admin.key": "key", "2837465512": "in flight", "shop.example.key.tmp": "in flight"}
	for name, body := range want {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(b) != body {
			t.Errorf("%s: %q, %v; want %q", name, b, err, body)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "admin.extra")); !os.IsNotExist(err) {
		t.Errorf("a file of the directory that the record does not name stayed: %v", err)
	}
	// What is shared of the directory is what the storage keeps.
	got, err := g.read(id, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got["admin.json"]) != "new" || string(got["admin.key"]) != "key" {
		t.Errorf("read of the directory: %v", got)
	}
}
