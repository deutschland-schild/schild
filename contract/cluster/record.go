// Package cluster is the contract of a group of gateways that share their
// state from node to node (MVP-27, DECISIONS D103, contracts/cluster.md):
// the signed record every change travels in, the clock that orders two
// writes of the same thing, who may sign, and the join code.
//
// There is no store beside the gateways and no majority: every class merges
// without a leader, so two nodes are a group.
package cluster

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Version is the record version this implementation reads and writes. A
// record of another version stays unread and is passed on unchanged.
const Version = 1

// Record classes of this version.
const (
	ClassMembers = "members"
	ClassBlocks  = "blocks"
	// ClassSettings is what the dashboard and the agent API set.
	ClassSettings = "settings"
	// ClassAccess is who passes: allowlist, IP exceptions, rule decisions.
	ClassAccess = "access"
	// ClassLogins is who may sign in: users, sessions, agent tokens.
	ClassLogins = "logins"
	// ClassErasure is one erased address (Art. 17 GDPR).
	ClassErasure = "erasure"
)

// Things of the classes settings, access and logins: each is one value that
// is replaced as a whole. The names of settings are the keys the gateway
// stores them under.
var things = map[string][]string{
	ClassSettings: {"settings_overlay_v1", "behaviour_rate_limits_v1", "rules_state_by_v1", "crawler_policies_v1", "access_protections_v1",
		"human_check_v1", "rule_exceptions_v2", "agent_pseudonym_key_v1"},
	ClassAccess: {"allowlist", "ip_exceptions", "rule_decisions"},
	ClassLogins: {"users", "sessions", "agent_tokens"},
}

// Things returns the ids of a class of whole values.
func Things(class string) []string { return things[class] }

func knownThing(class, id string) bool {
	for _, t := range things[class] {
		if t == id {
			return true
		}
	}
	return false
}

// Limits of one record and of the clock.
const (
	// MaxData bounds the decoded data of one record: a whole value of the
	// classes settings, access and logins has to fit.
	MaxData = 256 << 10
	// MaxRecord bounds one record on the wire.
	MaxRecord = 512 << 10
	// MaxClockAhead: a record whose clock is further ahead of the receiver
	// is not taken (yet).
	MaxClockAhead = 60 * time.Second
	// MaxID bounds Record.ID.
	MaxID = 128
)

// Record is one change of one thing: the member with id n-…, the block of
// one client key. Data is the standard base64 of the class's JSON object;
// the signature covers the decoded bytes, so no re-encoding of JSON on the
// way can break or bend it.
type Record struct {
	V      int    `json:"v"`
	Group  string `json:"group"`
	Class  string `json:"class"`
	ID     string `json:"id"`
	Origin string `json:"origin"`
	// Seq counts the records of one origin, from 1. A peer asks for
	// "everything of origin X after N".
	Seq uint64 `json:"seq"`
	// HLC is the hybrid logical clock of the write (clock.go).
	HLC uint64 `json:"hlc"`
	// Deleted marks a tombstone: the thing is gone, and the record stays so
	// that an older write cannot bring it back.
	Deleted bool `json:"deleted,omitempty"`
	// Expires (RFC 3339, UTC, seconds) is when every node drops the record;
	// empty: never.
	Expires string `json:"expires,omitempty"`
	Data    string `json:"data"`
	Sig     string `json:"sig"`
}

// Reasons a record is not taken. ErrClock and ErrOrigin may pass with time
// (the receiver's clock catches up, the member record of the origin
// arrives); the others never do.
var (
	ErrVersion   = errors.New("cluster: unknown record version")
	ErrGroup     = errors.New("cluster: record of another group")
	ErrSchema    = errors.New("cluster: record does not fit its class")
	ErrOrigin    = errors.New("cluster: origin is no member")
	ErrRemoved   = errors.New("cluster: origin was removed before this record")
	ErrSignature = errors.New("cluster: signature does not verify")
	ErrClock     = errors.New("cluster: clock too far ahead")
)

const sigContext = "schild-cluster-record-v1"

// signingBytes is what a signature covers: the context and every field,
// each as "<decimal length> <bytes>" (the pre-authentication encoding of
// DSSE), so no two records share their bytes.
func (r *Record) signingBytes(data []byte) []byte {
	var b bytes.Buffer
	put := func(p []byte) {
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(' ')
		b.Write(p)
		b.WriteByte(' ')
	}
	del := "0"
	if r.Deleted {
		del = "1"
	}
	put([]byte(sigContext))
	put([]byte(strconv.Itoa(r.V)))
	put([]byte(r.Group))
	put([]byte(r.Class))
	put([]byte(r.ID))
	put([]byte(r.Origin))
	put([]byte(strconv.FormatUint(r.Seq, 10)))
	put([]byte(strconv.FormatUint(r.HLC, 10)))
	put([]byte(del))
	put([]byte(r.Expires))
	put(data)
	return b.Bytes()
}

// Payload returns the decoded data.
func (r *Record) Payload() ([]byte, error) {
	if r.Data == "" {
		return nil, nil
	}
	p, err := base64.StdEncoding.Strict().DecodeString(r.Data)
	if err != nil || len(p) > MaxData {
		return nil, ErrSchema
	}
	return p, nil
}

// Sign fills Data and Sig. data is the class's value (nil for a tombstone
// without one).
func (r *Record) Sign(key ed25519.PrivateKey, data any) error {
	var p []byte
	if data != nil {
		var err error
		if p, err = json.Marshal(data); err != nil {
			return err
		}
	}
	if len(p) > MaxData {
		return fmt.Errorf("%w: data over %d bytes", ErrSchema, MaxData)
	}
	r.Data = base64.StdEncoding.EncodeToString(p)
	if p == nil {
		r.Data = ""
	}
	r.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, r.signingBytes(p)))
	return nil
}

// VerifySig checks the signature against the public key of the origin.
func (r *Record) VerifySig(pub ed25519.PublicKey) error {
	p, err := r.Payload()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(r.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return ErrSignature
	}
	if !ed25519.Verify(pub, r.signingBytes(p), sig) {
		return ErrSignature
	}
	return nil
}

// shape checks what holds for a record of every class.
func (r *Record) shape() error {
	switch {
	case r.Group == "" || r.Origin == "" || r.ID == "" || len(r.ID) > MaxID:
		return ErrSchema
	case r.Seq == 0 || r.HLC == 0:
		return ErrSchema
	}
	switch r.Class {
	case ClassMembers, ClassBlocks, ClassErasure:
	case ClassSettings, ClassAccess, ClassLogins:
		if !knownThing(r.Class, r.ID) || r.Deleted {
			return ErrSchema
		}
	default:
		return ErrSchema
	}
	if r.Expires != "" {
		if _, err := time.Parse("2006-01-02T15:04:05Z", r.Expires); err != nil {
			return ErrSchema
		}
	}
	return nil
}

// ExpiresAt is Expires as a time; ok false: never.
func (r *Record) ExpiresAt() (time.Time, bool) {
	if r.Expires == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", r.Expires)
	return t, err == nil
}

// TimeText formats t as records carry times.
func TimeText(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// Wins reports whether a replaces b as the state of their (class, id): the
// later clock wins; at the same clock a tombstone beats a write (a lift by
// a person beats the block of a detector of the same moment), then the
// greater origin, then the greater sequence number.
func Wins(a, b *Record) bool {
	switch {
	case a.HLC != b.HLC:
		return a.HLC > b.HLC
	case a.Deleted != b.Deleted:
		return a.Deleted
	case a.Origin != b.Origin:
		return a.Origin > b.Origin
	}
	return a.Seq > b.Seq
}

func idOf(prefix, context string, pub ed25519.PublicKey) string {
	h := sha256.Sum256(append([]byte(context), pub...))
	return prefix + hex.EncodeToString(h[:16])
}

// NodeID is the id of the node with this public key.
func NodeID(pub ed25519.PublicKey) string { return idOf("n-", "schild-node:", pub) }

// GroupID is the id of the group this key founded. The founder's own member
// record is the one record that needs no member to sign it: its key hashes
// to the group id, so every trust in a group starts at its id.
func GroupID(founder ed25519.PublicKey) string { return idOf("g-", "schild-group:", founder) }
