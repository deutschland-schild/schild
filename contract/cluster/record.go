// Package cluster is the contract of a group of gateways that share their
// state from node to node (MVP-27, DECISIONS D105, contracts/cluster.md):
// the signed record every change travels in, the clock that orders two
// writes of the same thing, who may sign, and how the group secret admits
// a node.
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
	"strings"
	"time"
)

// Version is the record version this implementation reads and writes. A
// record of another version stays unread and is passed on unchanged.
const Version = 1

// Record classes of this version.
const (
	ClassMembers = "members"
	// ClassBlocks is the class of blocks before D109: one record per client.
	// A node reads it until the last such record is over and writes none.
	ClassBlocks = "blocks"
	// ClassIncidentBlocks is one block per record; its id is the incident.
	ClassIncidentBlocks = "incident_blocks"
	// ClassLifts is the end a person or an erasure put to the block of an
	// incident; its id is the incident.
	ClassLifts = "lifts"
	// ClassSettings is what the dashboard and the agent API set.
	ClassSettings = "settings"
	// ClassAccess is who passes: allowlist, IP exceptions, rule decisions.
	ClassAccess = "access"
	// ClassLogins is who may sign in: users, sessions, agent tokens.
	ClassLogins = "logins"
	// ClassErasure is one erased address (Art. 17 GDPR).
	ClassErasure = "erasure"
	// ClassCertificates is the storage of the embedded Caddy: certificates
	// with their keys, ACME accounts, challenge tokens, session ticket keys.
	ClassCertificates = "certificates"
	// ClassJobs is when a task that runs once for the group last ran.
	ClassJobs = "jobs"
)

// Things of the classes settings, access and logins. Each is a set of
// entries (a row of a list, one setting, the policy of one website), and
// every entry is a record of its own: two nodes that change different
// entries of one thing both keep their change. The names of settings are
// the keys the gateway stores them under.
var things = map[string][]string{
	ClassSettings: {"settings_overlay_v1", "behaviour_rate_limits_v1", "rules_state_by_v1", "crawler_policies_v1", "access_protections_v1",
		"human_check_v1", "rule_exceptions_v2", "agent_pseudonym_key_v1"},
	ClassAccess: {"allowlist", "ip_exceptions", "rule_decisions"},
	ClassLogins: {"users", "sessions", "agent_tokens"},
}

// Things returns the named things of a class.
func Things(class string) []string { return things[class] }

// Everything a gateway sets at runtime is shared (initiator, 2026-11-22):
// beside its named things the class settings takes every key of the
// gateway's key-value store as a thing, whatever feature wrote it, so a new
// setting holds on every node without a change here. A key is a lower-case
// name of at most 64 characters (SettingKey). The classes access and logins
// stay closed lists: their things are tables with a schema.
//
// PerNodeSettings are the keys that describe one node and never travel.
// A record that names one is refused, so no member can set them on another.
var PerNodeSettings = map[string]string{
	"installed_at_v1":         "when this node was installed: the start of its own learning phase and the name of its event store",
	"dashboard_setup_code_v1": "the pending first-run or reset code of this node, shown in its own log",
	"crowdsec_hub_status_v1":  "when this node last downloaded the hub index and what it answered",
	"crowdsec_hub_set_v1":     "the hub rules this node holds; the group hands the index on by its own messages (hub, hub_index)",
	"allow_version":           "a counter of this node's allowlist changes for its own caches",
	"jobs_local_v1":           "when a once-per-period task last ran on a single gateway; a node of a group keeps that in the shared jobs records, and sharing this key would double them",
}

// SettingKey reports whether s can be a thing of class settings: a named
// thing, or a key of the store that is not per node.
func SettingKey(s string) bool {
	if len(s) == 0 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	_, perNode := PerNodeSettings[s]
	return !perNode
}

// MaxEntryKey bounds the key of one entry.
const MaxEntryKey = 1024

// EntryID is the record id of one entry of a thing: the thing, a slash and
// the first 16 bytes, in hex, of SHA-256 over the entry's key. The key
// itself travels in the data.
func EntryID(thing, key string) string {
	h := sha256.Sum256([]byte(key))
	return thing + "/" + hex.EncodeToString(h[:16])
}

// ThingOf returns the thing a record id of the classes settings, access and
// logins names; ok false: the id is none of that class.
func ThingOf(class, id string) (thing string, ok bool) {
	i := strings.LastIndexByte(id, '/')
	if i < 0 || len(id)-i-1 != 32 {
		return "", false
	}
	for _, t := range things[class] {
		if t == id[:i] {
			return t, true
		}
	}
	if class == ClassSettings && SettingKey(id[:i]) {
		return id[:i], true
	}
	return "", false
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
	// MaxID bounds Record.ID; a storage path of a certificate is the longest.
	MaxID = 512
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
	case ClassMembers, ClassBlocks, ClassErasure, ClassCertificates, ClassJobs:
	case ClassIncidentBlocks, ClassLifts:
		if !incidentID(r.ID) {
			return ErrSchema
		}
	case ClassSettings, ClassAccess, ClassLogins:
		if _, ok := ThingOf(r.Class, r.ID); !ok {
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

// GroupID is the id of the group of this group key (admit.go): every trust
// in a group starts at its id, which only the holders of the group secret
// can sign for.
func GroupID(groupKey ed25519.PublicKey) string { return idOf("g-", "schild-group:", groupKey) }
