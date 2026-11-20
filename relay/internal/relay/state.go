package relay

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/relay/upstream"
)

// Limits that keep a misbehaving upstream from growing the relay's memory.
const (
	maxLabs             = 256
	maxWithdrawalsPerUp = 64
	maxBundleIDsPerUp   = 16
	cacheEntries        = 64
	seenDigests         = 4096
)

// bundleEntry is the newest bundle of one channel from one upstream.
type bundleEntry struct {
	bundleID string
	version  uint64
	digest   string // sha256 of the envelope bytes
	env      []byte // envelope bytes (for inline events and the static file)
	inline   bool
	ref      *stream.Ref
}

type withdrawalEntry struct {
	bundleID string
	seq      uint64
	upTo     uint64
	digest   string
	env      []byte
}

type checkpointEntry struct {
	lab      string
	seq      uint64
	issuedAt time.Time
	digest   string
	env      []byte
}

type upstreamState struct {
	bundles     map[string]*bundleEntry // by bundle_id
	withdrawals []*withdrawalEntry
}

// State is what the relay knows. It is unverified by design: the relay only
// orders by the numbers inside payloads, and keeps state per upstream so that
// one upstream sending a bogus "newest" bundle cannot hide another's.
type State struct {
	mu          sync.Mutex
	ups         map[string]*upstreamState
	checkpoints map[string]*checkpointEntry // by lab
	cache       map[string][]byte           // url path -> envelope bytes
	cacheOrder  []string
	published   map[string]bool // digests already numbered
	pubOrder    []string
}

// NewState returns an empty state.
func NewState() *State {
	return &State{ups: map[string]*upstreamState{}, checkpoints: map[string]*checkpointEntry{}, cache: map[string][]byte{}, published: map[string]bool{}}
}

func (s *State) up(base string) *upstreamState {
	u := s.ups[base]
	if u == nil {
		u = &upstreamState{bundles: map[string]*bundleEntry{}}
		s.ups[base] = u
	}
	return u
}

// payloadOf decodes an envelope payload without verifying signatures.
func payloadOf(env []byte, out any) error {
	v, err := jsonx.ParseObject(env)
	if err != nil {
		return err
	}
	var e dsse.Envelope
	if err := jsonx.Decode(v, &e); err != nil {
		return err
	}
	p, err := e.DecodePayload()
	if err != nil {
		return err
	}
	pv, err := jsonx.ParseObject(p)
	if err != nil {
		return err
	}
	return jsonx.Decode(pv, out)
}

func (s *State) markPublished(d string) bool {
	if s.published[d] {
		return false
	}
	s.published[d] = true
	s.pubOrder = append(s.pubOrder, d)
	if len(s.pubOrder) > seenDigests {
		delete(s.published, s.pubOrder[0])
		s.pubOrder = s.pubOrder[1:]
	}
	return true
}

func (s *State) putCache(path string, b []byte) {
	if _, ok := s.cache[path]; !ok {
		s.cacheOrder = append(s.cacheOrder, path)
		if len(s.cacheOrder) > cacheEntries {
			delete(s.cache, s.cacheOrder[0])
			s.cacheOrder = s.cacheOrder[1:]
		}
	}
	s.cache[path] = b
}

// RefFor returns the reference an upstream announced for path (nil: none).
func (s *State) RefFor(path string) *stream.Ref {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.ups {
		for _, b := range u.bundles {
			if b.ref != nil && b.ref.URLPath == path {
				return b.ref
			}
		}
	}
	return nil
}

// Cached returns a bundle envelope by URL path.
func (s *State) Cached(path string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.cache[path]
	return b, ok
}

// PutCached stores a bundle envelope fetched on demand.
func (s *State) PutCached(path string, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putCache(path, b)
}

// Checkpoint records a checkpoint envelope; it returns true when it is newer
// than what the relay had for that lab (then it should be published).
func (s *State) Checkpoint(env []byte) (*checkpointEntry, bool) {
	var c msg.Checkpoint
	if err := payloadOf(env, &c); err != nil {
		return nil, false
	}
	at, err := msg.ParseTime(c.IssuedAt)
	if err != nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.checkpoints[c.Lab]
	if old != nil && c.Seq <= old.seq {
		return nil, false
	}
	if old == nil && len(s.checkpoints) >= maxLabs {
		return nil, false
	}
	e := &checkpointEntry{lab: c.Lab, seq: c.Seq, issuedAt: at, digest: upstream.SHA256(env), env: env}
	s.checkpoints[c.Lab] = e
	return e, true
}

// Bundle records a bundle (inline envelope or downloaded ref). It returns
// true when the envelope was not published by this relay before.
func (s *State) Bundle(base string, env []byte, inline bool, ref *stream.Ref) (*bundleEntry, bool) {
	var b msg.Bundle
	if err := payloadOf(env, &b); err != nil {
		return nil, false
	}
	d := upstream.SHA256(env)
	e := &bundleEntry{bundleID: b.BundleID, version: b.Version, digest: d, env: env, inline: inline, ref: ref}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.up(base)
	if old := u.bundles[b.BundleID]; old == nil || b.Version > old.version {
		if old == nil && len(u.bundles) >= maxBundleIDsPerUp {
			return nil, false
		}
		u.bundles[b.BundleID] = e
		// Withdrawals that no longer apply to this upstream's newest bundle.
		keep := u.withdrawals[:0]
		for _, w := range u.withdrawals {
			if w.bundleID != b.BundleID || w.upTo >= b.Version {
				keep = append(keep, w)
			}
		}
		u.withdrawals = keep
	}
	s.putCache(stream.BundleURLPath(b.BundleID, b.Version), env)
	return e, s.markPublished(d)
}

// Withdrawal records a withdrawal; true when new for this relay.
func (s *State) Withdrawal(base string, env []byte) (*withdrawalEntry, bool) {
	var w msg.Withdrawal
	if err := payloadOf(env, &w); err != nil {
		return nil, false
	}
	d := upstream.SHA256(env)
	e := &withdrawalEntry{bundleID: w.BundleID, seq: w.Seq, upTo: w.UpToVersion, digest: d, env: env}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.up(base)
	dup := false
	for _, x := range u.withdrawals {
		if x.digest == d {
			dup = true
		}
	}
	if !dup {
		if nb := u.bundles[w.BundleID]; nb == nil || w.UpToVersion >= nb.version {
			u.withdrawals = append(u.withdrawals, e)
			if len(u.withdrawals) > maxWithdrawalsPerUp {
				u.withdrawals = u.withdrawals[1:]
			}
		}
	}
	return e, s.markPublished(d)
}

// NewestCheckpoint returns the newest checkpoint envelope (by issued_at), or
// the one of a given lab.
func (s *State) NewestCheckpoint(lab string) json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if lab != "" {
		if c := s.checkpoints[lab]; c != nil {
			return c.env
		}
		return nil
	}
	var best *checkpointEntry
	for _, c := range s.checkpoints {
		if best == nil || c.issuedAt.After(best.issuedAt) || (c.issuedAt.Equal(best.issuedAt) && c.lab < best.lab) {
			best = c
		}
	}
	if best == nil {
		return nil
	}
	return best.env
}

// CheckpointAge returns the age of the newest checkpoint (0 if none).
func (s *State) CheckpointAge(now time.Time) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var newest time.Time
	for _, c := range s.checkpoints {
		if c.issuedAt.After(newest) {
			newest = c.issuedAt
		}
	}
	if newest.IsZero() {
		return 0, false
	}
	return now.Sub(newest), true
}

// Snapshot renders the full state in priority order: withdrawals that still
// apply, newest bundles, newest checkpoint per lab. Duplicates (the same
// envelope from several upstreams) are sent once.
func (s *State) Snapshot() []stream.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ws []*withdrawalEntry
	var bs []*bundleEntry
	seen := map[string]bool{}
	bases := make([]string, 0, len(s.ups))
	for b := range s.ups {
		bases = append(bases, b)
	}
	sort.Strings(bases)
	for _, base := range bases {
		u := s.ups[base]
		for _, w := range u.withdrawals {
			if !seen[w.digest] {
				seen[w.digest] = true
				ws = append(ws, w)
			}
		}
		for _, b := range u.bundles {
			if !seen[b.digest] {
				seen[b.digest] = true
				bs = append(bs, b)
			}
		}
	}
	sort.SliceStable(ws, func(i, j int) bool { return ws[i].seq < ws[j].seq })
	sort.SliceStable(bs, func(i, j int) bool { return bs[i].version < bs[j].version })
	var out []stream.Event
	for _, w := range ws {
		out = append(out, stream.Event{Type: stream.TypeWithdrawal, Envelope: w.env})
	}
	for _, b := range bs {
		out = append(out, bundleEvent(b))
	}
	labs := make([]string, 0, len(s.checkpoints))
	for l := range s.checkpoints {
		labs = append(labs, l)
	}
	sort.Strings(labs)
	for _, l := range labs {
		out = append(out, stream.Event{Type: stream.TypeCheckpoint, Envelope: s.checkpoints[l].env})
	}
	return out
}

func bundleEvent(b *bundleEntry) stream.Event {
	if b.inline {
		return stream.Event{Type: stream.TypeBundle, Envelope: b.env}
	}
	return stream.Event{Type: stream.TypeBundle, Ref: b.ref}
}

// Counts returns numbers for metrics and readiness.
func (s *State) Counts() (labs, bundles, withdrawals int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.ups {
		bundles += len(u.bundles)
		withdrawals += len(u.withdrawals)
	}
	return len(s.checkpoints), bundles, withdrawals
}
