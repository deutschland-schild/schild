package cluster

import (
	"crypto/ed25519"
	"sort"
	"time"
)

// Roster is who may sign in a group: its members by node id, built from the
// records of class members that won. A member is trusted like the operator
// (one group is one operator); what ends that for one node is its removal.
type Roster struct {
	Group   string
	members map[string]rosterEntry
}

type rosterEntry struct {
	member Member
	key    ed25519.PublicKey
	// removedAt is the clock of the tombstone; 0: a member.
	removedAt uint64
}

// NewRoster returns the empty roster of a group.
func NewRoster(group string) *Roster {
	return &Roster{Group: group, members: map[string]rosterEntry{}}
}

// Set takes the winning record of one member (a write or a tombstone). The
// caller checked it with Check.
func (ro *Roster) Set(r *Record) {
	m, err := DecodeMember(r)
	if err != nil {
		return
	}
	key, _ := m.Key()
	e := rosterEntry{member: *m, key: key}
	if r.Deleted {
		e.removedAt = r.HLC
	}
	ro.members[r.ID] = e
}

// Member returns an active member.
func (ro *Roster) Member(id string) (Member, bool) {
	e, ok := ro.members[id]
	return e.member, ok && e.removedAt == 0
}

// Known reports whether id is or was a member.
func (ro *Roster) Known(id string) bool { _, ok := ro.members[id]; return ok }

// ActiveKey reports whether pub is the key of an active member with one of
// the roles (any role when none is named), and returns its id.
func (ro *Roster) ActiveKey(pub ed25519.PublicKey, roles ...string) (string, bool) {
	id := NodeID(pub)
	e, ok := ro.members[id]
	if !ok || e.removedAt != 0 || !e.key.Equal(pub) {
		return "", false
	}
	for _, r := range roles {
		if e.member.Role == r {
			return id, true
		}
	}
	return id, len(roles) == 0
}

// Entry is one row of Members.
type Entry struct {
	ID      string
	Member  Member
	Removed bool
}

// Members lists every member the roster knows, removed ones too, by name.
func (ro *Roster) Members() []Entry {
	out := make([]Entry, 0, len(ro.members))
	for id, e := range ro.members {
		out = append(out, Entry{ID: id, Member: e.member, Removed: e.removedAt != 0})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Member.Name != out[j].Member.Name {
			return out[i].Member.Name < out[j].Member.Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Check decides whether a record is taken, in this order: version, group,
// shape, clock, origin, signature, the rules of its class. now is the
// receiver's wall clock.
//
// Who may sign: an active gateway. A removed member's records stand when
// their clock is before its removal, so that what it decided while it was a
// member reads the same on a node that joins later. The one record without
// a member behind it is the founder's own: its key hashes to the group id.
func (ro *Roster) Check(r *Record, now time.Time) error {
	if r.V != Version {
		return ErrVersion
	}
	if r.Group != ro.Group {
		return ErrGroup
	}
	if err := r.shape(); err != nil {
		return err
	}
	if HLCTime(r.HLC).After(now.Add(MaxClockAhead)) {
		return ErrClock
	}
	var key ed25519.PublicKey
	e, ok := ro.members[r.Origin]
	switch {
	case ok && e.member.Role != RoleGateway:
		return ErrOrigin
	case ok && e.removedAt != 0 && r.HLC >= e.removedAt:
		return ErrRemoved
	case ok:
		key = e.key
	default:
		// A node's record of itself: the founder's, or one admitted by the
		// group secret.
		m, err := DecodeMember(r)
		if err != nil || r.Class != ClassMembers || r.ID != r.Origin || r.Deleted {
			return ErrOrigin
		}
		k, _ := m.Key()
		if m.Role != RoleGateway || (GroupID(k) != ro.Group && !m.admitted(ro.Group)) {
			return ErrOrigin
		}
		key = k
	}
	if err := r.VerifySig(key); err != nil {
		return err
	}
	switch r.Class {
	case ClassMembers:
		// Write and tombstone both carry the member.
		if _, err := DecodeMember(r); err != nil {
			return err
		}
	case ClassBlocks:
		if r.Deleted {
			if _, err := DecodeLift(r); err != nil {
				return err
			}
		} else if _, err := DecodeBlock(r); err != nil {
			return err
		}
	}
	return nil
}
