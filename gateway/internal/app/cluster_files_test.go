//go:build !release

package app_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
)

const groupCaddyfile = "{\n\tauto_https off\n\thttp_port {port}\n}\n\nhttp://shop.example:{port} {\n\tschild\n\treverse_proxy {backend}\n}\n"

func (g *groupNode) startIngress(t *testing.T) {
	t.Helper()
	g.h = apptest.New(t, apptest.Options{Dir: g.dir, Caddyfile: groupCaddyfile, Extra: fmt.Sprintf("cluster: {enabled: true, listen: %q}\n", g.addr)})
	if g.h.App.Cluster == nil || g.h.App.GroupFiles == nil {
		t.Fatalf("%s: no group for the certificate storage", g.name)
	}
}

func (g *groupNode) storage(path string) string {
	return filepath.Join(g.dir, "caddy", filepath.FromSlash(path))
}

// put writes a file of the storage as the Caddy module does: the file,
// then the word to the group.
func (g *groupNode) put(t *testing.T, key string, b []byte) {
	t.Helper()
	p := g.storage(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	g.h.App.GroupFiles.Changed(key)
}

func (g *groupNode) has(key string, want []byte) bool {
	b, err := os.ReadFile(g.storage(key))
	return err == nil && bytes.Equal(b, want)
}

func certPair(t *testing.T, name string) (crt, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func ingressPair(t *testing.T) (a, b *groupNode) {
	t.Helper()
	a = &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-1"}
	b = &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: "web-2"}
	if _, err := cluster.Init(a.clusterDir(), a.name, a.addr, nil); err != nil {
		t.Fatal(err)
	}
	a.startIngress(t)
	a.h.WaitFor("the mesh of web-1 listens", func() bool { return a.h.App.Cluster.Addr() != "" })
	code, _, err := cluster.Invite(a.clusterDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cluster.Join(context.Background(), b.clusterDir(), b.name, b.addr, a.addr, code, nil); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestGroupSharesCertificatesAsPairs(t *testing.T) {
	a, b := ingressPair(t)
	// web-2 has a certificate from the time before it joined.
	oldCrt, oldKey := certPair(t, "old.example")
	oldDir := "certificates/local/old.example/"
	for name, body := range map[string][]byte{"old.example.key": oldKey, "old.example.crt": oldCrt, "old.example.json": []byte("{}")} {
		p := b.storage(oldDir + name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b.startIngress(t)
	a.h.WaitFor("web-1 got the certificate web-2 brought into the group", func() bool {
		return a.has(oldDir+"old.example.crt", oldCrt) && a.has(oldDir+"old.example.key", oldKey)
	})

	// An order on web-1 writes key, certificate and metadata one after the other.
	crt, key := certPair(t, "shop.example")
	dir := "certificates/local/shop.example/"
	a.put(t, dir+"shop.example.key", key)
	a.put(t, dir+"shop.example.crt", crt)
	a.put(t, dir+"shop.example.json", []byte(`{"sans":["shop.example"]}`))
	b.h.WaitFor("web-2 holds the certificate with its key", func() bool {
		return b.has(dir+"shop.example.crt", crt) && b.has(dir+"shop.example.key", key) && b.has(dir+"shop.example.json", []byte(`{"sans":["shop.example"]}`))
	})

	// A certificate next to a key that does not fit it never leaves, and
	// what web-2 serves stays a pair.
	otherCrt, _ := certPair(t, "shop.example")
	a.put(t, dir+"shop.example.crt", otherCrt)
	time.Sleep(time.Second)
	if !b.has(dir+"shop.example.crt", crt) || !b.has(dir+"shop.example.key", key) {
		t.Fatal("web-2 took half of a certificate")
	}
	// The renewal completes: new key, new certificate.
	crt2, key2 := certPair(t, "shop.example")
	a.put(t, dir+"shop.example.key", key2)
	a.put(t, dir+"shop.example.crt", crt2)
	b.h.WaitFor("web-2 holds the renewed pair", func() bool { return b.has(dir+"shop.example.crt", crt2) && b.has(dir+"shop.example.key", key2) })

	// A challenge token is on the other node when the call returns.
	token := "acme/ca.example-directory/challenge_tokens/shop.example.json"
	if err := os.MkdirAll(filepath.Dir(a.storage(token)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.storage(token), []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("web-1 reaches web-2", func() bool { return a.h.App.Cluster.Synced() && b.h.App.Cluster.Synced() })
	time.Sleep(time.Second) // one round of calls, so each side knows how far the other is
	a.h.App.GroupFiles.ChangedNow(context.Background(), token)
	if !b.has(token, []byte("token")) {
		t.Error("the challenge token was not on web-2 when the call returned")
	}
	// The token of another name, written on the other node, is a record of
	// its own: neither replaces the other (certmagic keeps all tokens of an
	// issuer in one directory).
	token2 := "acme/ca.example-directory/challenge_tokens/blog.example.json"
	if err := os.MkdirAll(filepath.Dir(b.storage(token2)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.storage(token2), []byte("token2"), 0o600); err != nil {
		t.Fatal(err)
	}
	b.h.App.GroupFiles.ChangedNow(context.Background(), token2)
	if !a.has(token2, []byte("token2")) || !a.has(token, []byte("token")) || !b.has(token, []byte("token")) {
		t.Error("the tokens of two names did not both lie on both nodes")
	}
	// And gone on both when the challenge is over.
	if err := os.Remove(a.storage(token)); err != nil {
		t.Fatal(err)
	}
	a.h.App.GroupFiles.Changed(token)
	b.h.WaitFor("web-2 removed the token", func() bool { _, err := os.Stat(b.storage(token)); return os.IsNotExist(err) })
	// The lock files of the file storage stay on their node.
	a.put(t, "locks/issue_cert_shop.example.lock", []byte("x"))
	time.Sleep(700 * time.Millisecond)
	if _, err := os.Stat(b.storage("locks/issue_cert_shop.example.lock")); !os.IsNotExist(err) {
		t.Error("a lock file travelled")
	}
}

func TestGroupLockHoldsAcrossNodes(t *testing.T) {
	a, b := ingressPair(t)
	b.startIngress(t)
	a.h.WaitFor("the nodes reach each other", func() bool { return a.h.App.Cluster.Synced() && b.h.App.Cluster.Synced() })
	time.Sleep(time.Second)
	ctx := context.Background()
	if err := a.h.App.GroupFiles.Lock(ctx, "issue_cert_shop.example"); err != nil {
		t.Fatal(err)
	}
	got := make(chan time.Time, 1)
	go func() {
		if err := b.h.App.GroupFiles.Lock(ctx, "issue_cert_shop.example"); err == nil {
			got <- time.Now()
		}
	}()
	select {
	case <-got:
		t.Fatal("web-2 got the lock web-1 holds")
	case <-time.After(1500 * time.Millisecond):
	}
	// Another name is free.
	other, cancel := context.WithTimeout(ctx, 3*time.Second)
	if err := b.h.App.GroupFiles.Lock(other, "issue_cert_other.example"); err != nil {
		t.Errorf("another lock: %v", err)
	}
	cancel()
	b.h.App.GroupFiles.Unlock(ctx, "issue_cert_other.example")
	// What web-1 stored under the lock is on web-2 when web-2 gets it.
	crt, key := certPair(t, "shop.example")
	dir := "certificates/local/shop.example/"
	a.put(t, dir+"shop.example.key", key)
	a.put(t, dir+"shop.example.crt", crt)
	a.h.App.GroupFiles.Unlock(ctx, "issue_cert_shop.example")
	select {
	case <-got:
	case <-time.After(15 * time.Second):
		t.Fatal("web-2 did not get the lock after web-1 gave it back")
	}
	if !b.has(dir+"shop.example.crt", crt) || !b.has(dir+"shop.example.key", key) {
		t.Error("web-2 got the lock before it held the certificate web-1 stored: it would order again")
	}
	b.h.App.GroupFiles.Unlock(ctx, "issue_cert_shop.example")
}
