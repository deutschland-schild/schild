package hub

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/deutschland-schild/schild/contract/crowdsec"
)

// A group of gateways runs one set of hub rules (MVP-27, D103). Every node
// may download the index; the node that took a new one hands it to the
// others, which take it through the same checks as a download of their own
// (CheckIndex, the compile check, the cost check, the build), under the
// time of the first download. So the rules of every node are the same ones,
// first seen at the same moment, and settle to "block" together.
//
// A member is trusted like the operator, and still nothing is taken on its
// word: the index has the digest it was announced with, and whatever a node
// would refuse from the hub it refuses from a member.

// IndexInfo names the index a node runs from a download.
type IndexInfo struct {
	// Digest is the SHA-256 of the index, in hex.
	Digest string `json:"digest"`
	ETag   string `json:"etag,omitempty"`
	// Pin is rules.crowdsec.pin of the node that downloaded it; only nodes
	// with the same pin take it.
	Pin string `json:"pin,omitempty"`
	// FetchedAt is when the index was downloaded from the hub (RFC 3339).
	FetchedAt string `json:"fetched_at"`
}

// shared is the last index this node took, kept in memory to hand on.
type shared struct {
	info IndexInfo
	gz   []byte
}

// maxSharedAge: an index downloaded longer ago is not taken from a member;
// the node asks the hub itself.
const maxSharedAge = 30 * 24 * time.Hour

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// remember keeps raw when it is the index the running set came from.
func (s *Source) remember(raw []byte, etag, pin string) {
	cur := s.running()
	if cur == nil || cur.source != crowdsec.SetStored || cur.indexDigest != digestOf(raw) {
		return
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil || zw.Close() != nil {
		return
	}
	s.mu.Lock()
	s.share = &shared{info: IndexInfo{Digest: cur.indexDigest, ETag: etag, Pin: pin, FetchedAt: cur.fetchedAt}, gz: buf.Bytes()}
	s.mu.Unlock()
}

// SharedIndex returns the index this node can hand to the other nodes of
// its group, gzipped; ok false: it holds none (it runs the set of its image
// or of its store since the start, and downloaded nothing yet).
func (s *Source) SharedIndex() (info IndexInfo, gz []byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.share == nil {
		return IndexInfo{}, nil, false
	}
	return s.share.info, s.share.gz, true
}

// WantsIndex reports whether this node would take the index a member
// announces: the rules are on and updated, the pin is the same, the index
// is another one than it runs and was downloaded later than its own, and
// it did not refuse this very index before.
func (s *Source) WantsIndex(in IndexInfo) bool {
	cfg := s.cfg()
	if cfg.State == crowdsec.StateOff || cfg.Pin != in.Pin || (cfg.Pin == "" && !*cfg.AutoUpdate) {
		return false
	}
	at, err := time.Parse(time.RFC3339, in.FetchedAt)
	now := s.now()
	if err != nil || len(in.Digest) != 64 || at.After(now.Add(time.Minute)) || now.Sub(at) > maxSharedAge {
		return false
	}
	s.mu.Lock()
	refused := s.refusedShared == in.Digest
	resetAt := s.resetAt
	s.mu.Unlock()
	// An index downloaded before the rules were reset is what the reset
	// threw away: it does not come back from a member.
	if refused || !at.After(resetAt) {
		return false
	}
	cur := s.running()
	if cur == nil || cur.source != crowdsec.SetStored {
		return true // the image snapshot, or nothing: any download is newer
	}
	if cur.indexDigest == in.Digest {
		return false
	}
	mine, err := time.Parse(time.RFC3339, cur.fetchedAt)
	return err != nil || at.After(mine)
}

// TakeIndex takes an index a member handed over, as if this node had
// downloaded it at the time the member did. It runs the whole update: what
// does not pass is refused and the running rules stay.
func (s *Source) TakeIndex(ctx context.Context, in IndexInfo, gz []byte) error {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(zr, crowdsec.MaxIndexBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > crowdsec.MaxIndexBytes {
		return errors.New("hub index of a member is too large")
	}
	if digestOf(raw) != in.Digest {
		return errors.New("hub index of a member does not have the digest it was announced with")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !s.WantsIndex(in) {
		return nil
	}
	at, _ := time.Parse(time.RFC3339, in.FetchedAt)
	s.apply(ctx, raw, in.ETag, in.Pin, at.UTC().Truncate(time.Second))
	if cur := s.running(); cur == nil || cur.indexDigest != in.Digest {
		// Refused here: not asked for again, the next check of the hub decides.
		s.mu.Lock()
		s.refusedShared = in.Digest
		s.mu.Unlock()
		return errors.New("hub index of a member was refused by this node's checks, the running rules stay")
	}
	s.remember(raw, in.ETag, in.Pin)
	return nil
}

// SetOnReset names what tells the group that the rules were reset here.
func (s *Source) SetOnReset(f func(at time.Time)) {
	s.mu.Lock()
	s.onReset = f
	s.mu.Unlock()
}

// ResetOfGroup follows a reset made on another node of the group at the
// time at: a stored set downloaded before it is dropped and the image
// snapshot runs, as on the node that was reset; no index from before is
// taken from a member afterwards. A node whose set is newer, or that runs
// the snapshot already, only notes the time.
func (s *Source) ResetOfGroup(ctx context.Context, at time.Time) error {
	at = at.UTC().Truncate(time.Second)
	s.mu.Lock()
	if !at.After(s.resetAt) || at.After(s.now().Add(time.Minute)) {
		s.mu.Unlock()
		return nil
	}
	s.resetAt = at
	s.mu.Unlock()
	cur := s.running()
	if cur == nil || cur.source != crowdsec.SetStored {
		return nil
	}
	if mine, err := time.Parse(time.RFC3339, cur.fetchedAt); err == nil && mine.After(at) {
		return nil
	}
	return s.reset(ctx, false)
}
