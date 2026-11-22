package caddymod

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
)

// GroupFiles is the group of gateways as the certificate storage needs it
// (MVP-27, D103): told what changed here, and asked for the lock of an
// order. The gateway's app implements it.
type GroupFiles interface {
	// Changed: the file key of the storage was written or deleted on this
	// node. It returns at once; the group gets the change shortly after.
	Changed(key string)
	// ChangedNow is Changed for a challenge token: it returns when every
	// node this one reaches holds it, or after two seconds.
	ChangedNow(ctx context.Context, key string)
	Lock(ctx context.Context, name string) error
	Unlock(ctx context.Context, name string)
}

type groupBox struct{ g GroupFiles }

var groupFiles atomic.Pointer[groupBox]

// BindGroup gives the storage module of this process its group; the
// returned function takes it away again.
func BindGroup(g GroupFiles) (release func()) {
	b := &groupBox{g: g}
	groupFiles.Store(b)
	return func() { groupFiles.CompareAndSwap(b, nil) }
}

func boundGroup() GroupFiles {
	if b := groupFiles.Load(); b != nil {
		return b.g
	}
	return nil
}

const clusterStorageName = "schild_cluster"

// IsChallengeToken reports whether a storage key is the token of an ACME
// challenge. certmagic keeps them below the directory of the issuer
// (acme/<ca>/challenge_tokens/<name>.json), so the directory is looked for
// anywhere in the key. A token is one file and one record of its own, and it
// has to be on every node before the certificate authority is told to look:
// its check may land on any of them (finding F6 of the lab measurement: the
// tokens travelled as one directory of the issuer, late, and the node the
// check landed on answered with a redirect).
func IsChallengeToken(key string) bool {
	return strings.Contains("/"+key, "/challenge_tokens/")
}

// ClusterStorage is the Caddy module caddy.storage.schild_cluster: the file
// storage under Root, as a single gateway uses it, and next to it the group.
// Every write goes to the file first and is told to the group after, so a
// node that reaches no member reads and writes its certificates as ever. A
// lock is the local one and then the group's: one order per certificate
// while the nodes reach each other.
type ClusterStorage struct {
	Root string `json:"root"`

	fs *certmagic.FileStorage
}

func init() { caddy.RegisterModule(ClusterStorage{}) }

// CaddyModule implements caddy.Module.
func (ClusterStorage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "caddy.storage." + clusterStorageName, New: func() caddy.Module { return new(ClusterStorage) }}
}

// Provision implements caddy.Provisioner.
func (s *ClusterStorage) Provision(caddy.Context) error {
	s.fs = &certmagic.FileStorage{Path: s.Root}
	return nil
}

// CertMagicStorage implements caddy.StorageConverter.
func (s *ClusterStorage) CertMagicStorage() (certmagic.Storage, error) { return s, nil }

// Store implements certmagic.Storage.
func (s *ClusterStorage) Store(ctx context.Context, key string, value []byte) error {
	if err := s.fs.Store(ctx, key, value); err != nil {
		return err
	}
	if g := boundGroup(); g != nil {
		if IsChallengeToken(key) {
			g.ChangedNow(ctx, key)
		} else {
			g.Changed(key)
		}
	}
	return nil
}

// Delete implements certmagic.Storage.
func (s *ClusterStorage) Delete(ctx context.Context, key string) error {
	if err := s.fs.Delete(ctx, key); err != nil {
		return err
	}
	if g := boundGroup(); g != nil {
		g.Changed(key)
	}
	return nil
}

// Load implements certmagic.Storage.
func (s *ClusterStorage) Load(ctx context.Context, key string) ([]byte, error) {
	return s.fs.Load(ctx, key)
}

// Exists implements certmagic.Storage.
func (s *ClusterStorage) Exists(ctx context.Context, key string) bool { return s.fs.Exists(ctx, key) }

// List implements certmagic.Storage.
func (s *ClusterStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	return s.fs.List(ctx, path, recursive)
}

// Stat implements certmagic.Storage.
func (s *ClusterStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	return s.fs.Stat(ctx, key)
}

// Lock implements certmagic.Locker: the lock of this node's storage, then
// the group's.
func (s *ClusterStorage) Lock(ctx context.Context, name string) error {
	if err := s.fs.Lock(ctx, name); err != nil {
		return err
	}
	if g := boundGroup(); g != nil {
		if err := g.Lock(ctx, name); err != nil {
			_ = s.fs.Unlock(ctx, name)
			return err
		}
	}
	return nil
}

// Unlock implements certmagic.Locker.
func (s *ClusterStorage) Unlock(ctx context.Context, name string) error {
	if g := boundGroup(); g != nil {
		g.Unlock(ctx, name)
	}
	return s.fs.Unlock(ctx, name)
}

var (
	_ caddy.Provisioner      = (*ClusterStorage)(nil)
	_ caddy.StorageConverter = (*ClusterStorage)(nil)
	_ certmagic.Storage      = (*ClusterStorage)(nil)
)
