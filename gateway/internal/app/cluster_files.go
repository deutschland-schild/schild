package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/caddymod"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// The group of MVP-27 (D105): the storage of the embedded Caddy holds on
// every node. Certificates with their keys, ACME accounts, the local CA,
// challenge tokens and the keys of TLS session tickets are files below the
// storage root; the Caddy module caddymod.ClusterStorage writes them there
// first and tells this type, which hands them to the group, and writes what
// other nodes hand over.
//
// A certificate, its key and its metadata lie in one directory and travel
// as one record, checked as a pair before it leaves and before it is
// written: no node ever serves the certificate of one order with the key of
// another. The same holds for an ACME account and the local CA. Everything
// else is one file per record.

type groupFiles struct {
	a    *App
	node *cluster.Node
	root string

	mu      sync.Mutex
	pending map[string]time.Time // unit -> last change
	seeded  bool
}

// quiet is how long a unit has to rest before it is published: an order
// writes key, certificate and metadata one after the other.
const quiet = 300 * time.Millisecond

// unitOf returns the record a storage key belongs to, and whether that is
// a directory of files that belong together.
func unitOf(key string) (id string, dir bool) {
	if caddymod.IsChallengeToken(key) {
		return key, false
	}
	for _, p := range []string{"certificates/", "acme/", "pki/"} {
		if strings.HasPrefix(key, p) && strings.Contains(key[len(p):], "/") {
			return path.Dir(key), true
		}
	}
	return key, false
}

// local reports whether a key never leaves the node: the lock files of the
// file storage.
func localOnly(key string) bool { return key == "locks" || strings.HasPrefix(key, "locks/") }

// Changed implements caddymod.GroupFiles.
func (g *groupFiles) Changed(key string) {
	if localOnly(key) || !contract.CleanPath(key) {
		return
	}
	id, _ := unitOf(key)
	g.mu.Lock()
	g.pending[id] = time.Now()
	g.mu.Unlock()
}

// ChangedNow implements caddymod.GroupFiles.
func (g *groupFiles) ChangedNow(ctx context.Context, key string) {
	if localOnly(key) || !contract.CleanPath(key) {
		return
	}
	id, dir := unitOf(key)
	if rec := g.publish(id, dir); rec != nil {
		if !g.node.WaitAcked(ctx, rec.Seq, 2*time.Second) {
			ratelog.Warn(g.a.log, "cluster: a challenge token did not reach every node in 2 s; the check of the certificate authority may land on a node without it")
		}
	}
}

// Lock implements caddymod.GroupFiles.
//
// The lock of an order is not taken before this node knows what the group
// holds: a node that just started would find no certificate in its storage,
// take the lock from itself (it reaches nobody yet, so it keeps its own
// locks) and order what the group has, and two nodes started together would
// both order (finding F6 of the lab measurement). With the lock in hand
// certmagic looks into the storage again, which by then holds what the group
// handed over.
//
// Only the locks of an order wait. Caddy takes another lock while it starts,
// for the keys of the session tickets, before a single listener is up: a
// wait there kept the web ports of a node closed for as long as it was not
// in step, where a balancer and a person expect the readiness answer 503
// (finding N3 of the second lab run).
func (g *groupFiles) Lock(ctx context.Context, name string) error {
	if orderLock(name) {
		if err := g.a.waitInStep(ctx); err != nil {
			return err
		}
	}
	return g.node.Lock(ctx, name)
}

// orderLock reports whether a lock of the certificate storage guards an
// order at the certificate authority: the issue and the renewal of a
// certificate ("issue_cert_<name>") and the registration of the account
// ("register_acme_account..."), as certmagic names them. Every other lock
// (session ticket keys, storage cleaning, renewal information) guards work
// on what the node holds already.
func orderLock(name string) bool {
	return strings.HasPrefix(name, "issue_cert_") || strings.HasPrefix(name, "register_acme_account")
}

// Unlock implements caddymod.GroupFiles. What this node stored under the
// lock goes to the group before the lock does, so the next holder finds it.
func (g *groupFiles) Unlock(ctx context.Context, name string) {
	g.flush(true)
	g.node.Unlock(ctx, name)
}

// read returns the files of a unit as they lie in the storage; none: the
// unit is gone.
func (g *groupFiles) read(id string, dir bool) (map[string][]byte, error) {
	p := filepath.Join(g.root, filepath.FromSlash(id))
	out := map[string][]byte{}
	if !dir {
		b, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out[""] = b
		return out, nil
	}
	entries, err := os.ReadDir(p)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !storageFile(e) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(p, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = b
	}
	return out, nil
}

// storageFile reports whether a file of a directory unit is one the
// storage keeps (a certificate, a key, their metadata), as opposed to one
// that is being written: certmagic writes a file under a random name
// without an extension (os.CreateTemp) and moves it into place, and this
// node writes `<name>.tmp`. Only a kept file is shared, and only a kept
// file is removed when the group's record of the directory does not name
// it.
func storageFile(e fs.DirEntry) bool {
	n := e.Name()
	return e.Type().IsRegular() && strings.Contains(n, ".") && !strings.HasPrefix(n, ".") && !strings.HasSuffix(n, ".tmp")
}

// whole reports whether the files of a unit belong together: a certificate
// directory holds a certificate and the key that fits it. Other units need
// nothing.
func whole(id string, files map[string][]byte) bool {
	if !strings.HasPrefix(id, "certificates/") {
		return true
	}
	var crt, key []byte
	for name, b := range files {
		switch {
		case strings.HasSuffix(name, ".crt"):
			crt = b
		case strings.HasSuffix(name, ".key"):
			key = b
		}
	}
	if crt == nil || key == nil {
		return false
	}
	_, err := tls.X509KeyPair(crt, key)
	return err == nil
}

func sameFiles(rec *contract.Record, files map[string][]byte) bool {
	if rec == nil {
		return false
	}
	if rec.Deleted {
		return len(files) == 0
	}
	f, err := contract.DecodeFiles(rec)
	if err != nil || len(f.Files) != len(files) {
		return false
	}
	for name, b := range files {
		if f.Files[name] != base64.StdEncoding.EncodeToString(b) {
			return false
		}
	}
	return true
}

// publish hands a unit to the group as it lies in the storage now, unless
// the group holds exactly that. It returns the record it wrote.
func (g *groupFiles) publish(id string, dir bool) *contract.Record {
	files, err := g.read(id, dir)
	if err != nil {
		ratelog.Warn(g.a.log, "cluster: file of the certificate storage not read, it is not shared", "path", id, "err", err)
		return nil
	}
	cur, err := g.node.Get(contract.ClassCertificates, id)
	if err != nil || sameFiles(cur, files) {
		return nil
	}
	name := g.node.Name()
	if len(files) == 0 {
		if cur == nil {
			return nil
		}
		rec, err := g.node.Publish(contract.ClassCertificates, id, &contract.Files{Node: name}, true, time.Time{})
		if err != nil {
			return nil
		}
		return rec
	}
	if !whole(id, files) {
		return nil // an order in flight: its last file brings the unit here again
	}
	out := contract.Files{Files: map[string]string{}, Node: name}
	size := 0
	for n, b := range files {
		out.Files[n] = base64.StdEncoding.EncodeToString(b)
		size += len(b)
	}
	if len(files) > 16 || size > contract.MaxData/2 {
		ratelog.Warn(g.a.log, "cluster: a unit of the certificate storage is too large to share, it stays on this node", "path", id, "files", len(files), "bytes", size)
		return nil
	}
	rec, err := g.node.Publish(contract.ClassCertificates, id, &out, false, time.Time{})
	if err != nil {
		ratelog.Warn(g.a.log, "cluster: change of the certificate storage not handed to the group", "path", id, "err", err)
		return nil
	}
	return rec
}

// flush publishes the units that rested long enough; all: every one.
func (g *groupFiles) flush(all bool) {
	now := time.Now()
	g.mu.Lock()
	var due []string
	for id, at := range g.pending {
		if all || now.Sub(at) >= quiet {
			due = append(due, id)
			delete(g.pending, id)
		}
	}
	g.mu.Unlock()
	for _, id := range due {
		g.publish(id, isDirUnit(id))
	}
}

// isDirUnit reports whether a record id of the group names a directory.
func isDirUnit(id string) bool {
	u, dir := unitOf(id + "/x")
	return dir && u == id
}

// take writes the files another node handed over into the storage.
func (g *groupFiles) take(rec *contract.Record) {
	if localOnly(rec.ID) {
		return
	}
	f, err := contract.DecodeFiles(rec)
	if err != nil {
		return
	}
	p := filepath.Join(g.root, filepath.FromSlash(rec.ID))
	dir := isDirUnit(rec.ID)
	if rec.Deleted {
		if dir {
			if entries, err := os.ReadDir(p); err == nil {
				for _, e := range entries {
					if storageFile(e) {
						_ = os.Remove(filepath.Join(p, e.Name()))
					}
				}
				_ = os.Remove(p) // only when nothing else lies there
			}
		} else {
			_ = os.Remove(p)
		}
		return
	}
	files := map[string][]byte{}
	for name, c := range f.Files {
		b, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return
		}
		files[name] = b
	}
	if _, single := files[""]; single == dir {
		return // a file where a directory belongs, or the other way round
	}
	if !whole(rec.ID, files) {
		ratelog.Warn(g.a.log, "cluster: a certificate of another node does not fit its key, it is not written", "path", rec.ID, "from", f.Node)
		return
	}
	write := func(file string, b []byte) error {
		if cur, err := os.ReadFile(file); err == nil && bytes.Equal(cur, b) {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			return err
		}
		tmp := file + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, file)
	}
	if !dir {
		if err := write(p, files[""]); err != nil {
			ratelog.Error(g.a.log, "cluster: file of another node not written to the certificate storage", "path", rec.ID, "err", err)
		}
		return
	}
	// The key before the certificate, as an order writes them.
	names := make([]string, 0, len(files))
	for name := range files {
		if strings.HasSuffix(name, ".key") {
			names = append([]string{name}, names...)
		} else {
			names = append(names, name)
		}
	}
	for _, name := range names {
		if err := write(filepath.Join(p, name), files[name]); err != nil {
			ratelog.Error(g.a.log, "cluster: file of another node not written to the certificate storage", "path", rec.ID+"/"+name, "err", err)
			return
		}
	}
	if entries, err := os.ReadDir(p); err == nil {
		for _, e := range entries {
			if _, ok := files[e.Name()]; !ok && storageFile(e) {
				_ = os.Remove(filepath.Join(p, e.Name()))
			}
		}
	}
}

// seed hands the group what the storage of this node holds and the group
// does not: the certificates a gateway had before it entered a group go
// with it, none is ordered again. What the group holds of a path stands.
func (g *groupFiles) seed() {
	units := map[string]bool{}
	_ = filepath.WalkDir(g.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, rerr := filepath.Rel(g.root, p)
		if rerr != nil || rel == "." {
			return nil
		}
		key := filepath.ToSlash(rel)
		if d.IsDir() {
			if localOnly(key) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasSuffix(key, ".tmp") || !contract.CleanPath(key) {
			return nil
		}
		id, dir := unitOf(key)
		if dir && !storageFile(d) {
			return nil // a file being written, not a unit of its own
		}
		units[id] = dir
		return nil
	})
	n := 0
	for id, dir := range units {
		if cur, err := g.node.Get(contract.ClassCertificates, id); err == nil && cur == nil {
			if g.publish(id, dir) != nil {
				n++
			}
		}
	}
	if n > 0 {
		g.a.log.Info("cluster: certificates and keys of this node handed to the group", "paths", n)
	}
}

func (g *groupFiles) loop(ctx context.Context) {
	every(ctx, 100*time.Millisecond, func() {
		if !g.seeded && g.node.Synced() {
			g.seeded = true
			g.seed()
		}
		g.flush(false)
	})
}

// startGroupFiles shares the Caddy storage root with the group. A gateway
// that proxies without a Caddyfile has no certificates of its own.
func (a *App) startGroupFiles(ctx context.Context, root string) {
	g := &groupFiles{a: a, node: a.Cluster, root: root, pending: map[string]time.Time{}}
	a.GroupFiles = g
	// What the node holds from before its stop is in the storage already;
	// records that came while it was away are written now.
	if recs, err := a.Cluster.State(contract.ClassCertificates); err == nil {
		for _, rec := range recs {
			g.take(rec)
		}
	}
	a.Cluster.On(contract.ClassCertificates, g.take)
	a.goLoop(ctx, "cluster-files", g.loop)
}

// storageRoot is the Caddy storage root of this gateway, as the ingress
// uses it.
func (a *App) storageRoot() string {
	if ing, _ := a.PrepareIngress(); ing != nil && ing.StorageRoot != "" {
		return ing.StorageRoot
	}
	return caddymod.DefaultStorage(a.dataDir)
}
