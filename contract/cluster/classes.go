package cluster

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"time"
)

// RoleGateway is the role of a member; this version has no other.
const RoleGateway = "gateway"

// Member is the data of a record of class members; its id is the node id.
// A tombstone keeps the data, so that records the node signed before it was
// removed can still be verified.
type Member struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	PublicKey string `json:"public_key"`
	// Address is host:port of the node's mesh listener, as the others reach it.
	Address string `json:"address"`
	Joined  string `json:"joined"`
	Version string `json:"version,omitempty"`
	// AdmitKey and Admit let a node into its group (admit.go): the public
	// key the group id is the hash of, and its signature over this node's
	// key. Both or none in the data; a member record that is no tombstone
	// carries them (Roster.Check).
	AdmitKey string `json:"admit_public_key,omitempty"`
	Admit    string `json:"admit,omitempty"`
}

// Key returns the public key.
func (m *Member) Key() (ed25519.PublicKey, bool) {
	p, err := base64.StdEncoding.Strict().DecodeString(m.PublicKey)
	return ed25519.PublicKey(p), err == nil && len(p) == ed25519.PublicKeySize
}

func (m *Member) valid() bool {
	if _, ok := m.Key(); !ok {
		return false
	}
	if m.Role != RoleGateway {
		return false
	}
	if m.Name == "" || len(m.Name) > 63 || strings.ContainsAny(m.Name, " \t\r\n/") {
		return false
	}
	if _, err := netip.ParseAddrPort(m.Address); err != nil {
		return false
	}
	if (m.AdmitKey == "") != (m.Admit == "") || len(m.AdmitKey) > 64 || len(m.Admit) > 128 {
		return false
	}
	_, err := time.Parse("2006-01-02T15:04:05Z", m.Joined)
	return err == nil
}

// MaxBlockS bounds how long a block of the group runs: the longest ladder
// step of the gateway (7 days, contract/events).
const MaxBlockS = 7 * 24 * 3600

// Block is the data of a record of class blocks; its id is Client. A lift
// is a tombstone whose data names the incident it ends.
type Block struct {
	// Client is the IPv4 address or the first address of the IPv6 /64.
	Client string `json:"client"`
	Bits   int    `json:"bits"`
	// Source as the gateway names it: behaviour:<scenario>, agent:<token id>
	// or dashboard.
	Source    string `json:"source"`
	Level     int    `json:"level"`
	Since     string `json:"since"`
	Until     string `json:"until"`
	DurationS int    `json:"duration_s"`
	Incident  string `json:"incident"`
	EventID   string `json:"event_id,omitempty"`
	NetClass  string `json:"net_class"`
	// Node is the name of the node that decided the block.
	Node string `json:"node"`
}

// Lift is the data of a tombstone of class blocks.
type Lift struct {
	Incident string `json:"incident"`
	Node     string `json:"node"`
}

func (b *Block) valid(id string) bool {
	a, err := netip.ParseAddr(b.Client)
	if err != nil || b.Client != id || a.String() != b.Client {
		return false
	}
	if (a.Is4() && b.Bits != 32) || (!a.Is4() && b.Bits != 64) {
		return false
	}
	since, err1 := time.Parse("2006-01-02T15:04:05Z", b.Since)
	until, err2 := time.Parse("2006-01-02T15:04:05Z", b.Until)
	if err1 != nil || err2 != nil || !until.After(since) || until.Sub(since) > MaxBlockS*time.Second+time.Minute {
		return false
	}
	if b.Source == "" || len(b.Source) > 96 || b.Level < 1 || b.Level > 16 || b.DurationS < 1 || b.DurationS > MaxBlockS {
		return false
	}
	return len(b.Incident) <= 64 && len(b.EventID) <= 64 && len(b.NetClass) <= 32 && len(b.Node) <= 63
}

// ScopeGateway is the scope of a block that holds for every website of the
// gateway, the only scope of this version.
const ScopeGateway = "gateway"

// IncidentBlock is the data of a record of class incident_blocks; its id
// is the incident number. One block is one record, written by the node
// that decided it; the record is never a tombstone. Two blocks of one
// client are two records.
type IncidentBlock struct {
	// Client is the IPv4 address or the first address of the IPv6 /64.
	Client string `json:"client"`
	Bits   int    `json:"bits"`
	// Scope is ScopeGateway.
	Scope string `json:"scope"`
	// Source as the gateway names it: behaviour:<scenario>, agent:<token id>
	// or dashboard.
	Source    string `json:"source"`
	Level     int    `json:"level"`
	Since     string `json:"since"`
	Until     string `json:"until"`
	DurationS int    `json:"duration_s"`
	EventID   string `json:"event_id,omitempty"`
	NetClass  string `json:"net_class"`
	// Node is the name of the node that decided the block.
	Node string `json:"node"`
}

// IncidentLift is the data of a record of class lifts; its id is the
// incident number of the block it ends. It carries no address.
type IncidentLift struct {
	// Node is the name of the node the lift was made on.
	Node string `json:"node"`
}

// incidentID says whether id is written like an incident number: 1 to 64
// characters of A to Z, 0 to 9 and the hyphen.
func incidentID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ValidScope says whether s is a scope of a block this version has.
func ValidScope(s string) bool { return s == ScopeGateway }

// DecodeIncidentBlock returns the block of a record of class
// incident_blocks.
func DecodeIncidentBlock(r *Record) (*IncidentBlock, error) {
	var b IncidentBlock
	if err := decodeData(r, &b); err != nil || r.Deleted || !incidentID(r.ID) || !ValidScope(b.Scope) {
		return nil, ErrSchema
	}
	// The rules of the fields both models share.
	old := Block{Client: b.Client, Bits: b.Bits, Source: b.Source, Level: b.Level, Since: b.Since, Until: b.Until, DurationS: b.DurationS,
		EventID: b.EventID, NetClass: b.NetClass, Node: b.Node}
	if !old.valid(b.Client) || r.Expires != b.Until {
		return nil, ErrSchema
	}
	return &b, nil
}

// DecodeIncidentLift returns the lift of a record of class lifts.
func DecodeIncidentLift(r *Record) (*IncidentLift, error) {
	var l IncidentLift
	if err := decodeData(r, &l); err != nil || r.Deleted || !incidentID(r.ID) || len(l.Node) > 63 || r.Expires == "" {
		return nil, ErrSchema
	}
	return &l, nil
}

// DecodeMember returns the member of a record of class members.
func DecodeMember(r *Record) (*Member, error) {
	var m Member
	if err := decodeData(r, &m); err != nil || !m.valid() {
		return nil, ErrSchema
	}
	key, _ := m.Key()
	if NodeID(key) != r.ID {
		return nil, ErrSchema
	}
	return &m, nil
}

// DecodeBlock returns the block of a record of class blocks that is no
// tombstone.
func DecodeBlock(r *Record) (*Block, error) {
	var b Block
	if err := decodeData(r, &b); err != nil || !b.valid(r.ID) {
		return nil, ErrSchema
	}
	// A block is dropped by every node when it ends.
	if r.Expires != b.Until {
		return nil, ErrSchema
	}
	return &b, nil
}

// DecodeLift returns the lift of a tombstone of class blocks.
func DecodeLift(r *Record) (*Lift, error) {
	var l Lift
	if err := decodeData(r, &l); err != nil || len(l.Incident) > 64 || len(l.Node) > 63 {
		return nil, ErrSchema
	}
	if _, err := netip.ParseAddr(r.ID); err != nil || r.Expires == "" {
		return nil, ErrSchema
	}
	return &l, nil
}

func decodeData(r *Record, v any) error {
	p, err := r.Payload()
	if err != nil || len(p) == 0 {
		return ErrSchema
	}
	d := json.NewDecoder(strings.NewReader(string(p)))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil || d.More() {
		return ErrSchema
	}
	return nil
}

// Value is the data of a record of the classes settings, access and logins:
// one entry of a thing. K is the entry's key, which the record id is the
// hash of; V its value as the gateway stores it. A tombstone has K and no
// V: the entry is gone.
type Value struct {
	K string `json:"key"`
	// V is the value in standard base64.
	V string `json:"value"`
	// Node is the name of the node the change was made on.
	Node string `json:"node"`
}

// Bytes returns the value.
func (v *Value) Bytes() ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(v.V)
}

// NewValue wraps one entry.
func NewValue(key string, b []byte, node string) *Value {
	return &Value{K: key, V: base64.StdEncoding.EncodeToString(b), Node: node}
}

// DecodeValue returns the entry of a record of class settings, access or
// logins. The record names its thing and the hash of the entry's key; a
// tombstone carries no value and says when it is dropped.
func DecodeValue(r *Record) (*Value, error) {
	var v Value
	if err := decodeData(r, &v); err != nil || len(v.Node) > 63 || len(v.K) > MaxEntryKey {
		return nil, ErrSchema
	}
	thing, ok := ThingOf(r.Class, r.ID)
	if !ok || EntryID(thing, v.K) != r.ID {
		return nil, ErrSchema
	}
	if r.Deleted {
		if v.V != "" || r.Expires == "" {
			return nil, ErrSchema
		}
		return &v, nil
	}
	if _, err := v.Bytes(); err != nil {
		return nil, ErrSchema
	}
	return &v, nil
}

// ErasureKeepS is how long the record of an erased address stays: longer
// than any node keeps the data it erases (requests 30 days), so a node that
// was away erases too. Then the record, and with it the address, is gone.
const ErasureKeepS = 31 * 24 * 3600

// Erasure is the data of a record of class erasure; its id is the address.
type Erasure struct {
	IP string `json:"ip"`
	// KeepIncidents: incidents of the address stay, without the address.
	KeepIncidents bool   `json:"keep_incidents"`
	Node          string `json:"node"`
}

// DecodeErasure returns the erasure of a record of class erasure.
func DecodeErasure(r *Record) (*Erasure, error) {
	var e Erasure
	if err := decodeData(r, &e); err != nil || len(e.Node) > 63 {
		return nil, ErrSchema
	}
	a, err := netip.ParseAddr(e.IP)
	if err != nil || a.String() != e.IP || e.IP != r.ID || r.Deleted || r.Expires == "" {
		return nil, ErrSchema
	}
	return &e, nil
}

// Files is the data of a record of class certificates. The id is a path of
// the Caddy storage. A certificate, its key and its metadata are files of
// one directory and travel as one record, so no node ever pairs the
// certificate of one order with the key of another; everything else is one
// file per record.
type Files struct {
	// Files maps a file name inside the directory id to its content in
	// standard base64; the name "" is the path id itself, as a file.
	Files map[string]string `json:"files"`
	Node  string            `json:"node"`
}

// CleanPath reports whether p is a storage path a record may name: relative,
// with no empty, "." or ".." element.
func CleanPath(p string) bool {
	if p == "" || len(p) > MaxID {
		return false
	}
	for _, el := range strings.Split(p, "/") {
		if el == "" || el == "." || el == ".." || strings.ContainsAny(el, "\\\x00") {
			return false
		}
	}
	return true
}

// DecodeFiles returns the files of a record of class certificates. A
// tombstone has none.
func DecodeFiles(r *Record) (*Files, error) {
	var f Files
	if err := decodeData(r, &f); err != nil || len(f.Node) > 63 || !CleanPath(r.ID) {
		return nil, ErrSchema
	}
	if r.Deleted {
		if len(f.Files) != 0 {
			return nil, ErrSchema
		}
		return &f, nil
	}
	if len(f.Files) == 0 || len(f.Files) > 16 {
		return nil, ErrSchema
	}
	for name, content := range f.Files {
		if name != "" && (strings.Contains(name, "/") || !CleanPath(name)) {
			return nil, ErrSchema
		}
		if name == "" && len(f.Files) != 1 {
			return nil, ErrSchema
		}
		if _, err := base64.StdEncoding.Strict().DecodeString(content); err != nil {
			return nil, ErrSchema
		}
	}
	return &f, nil
}

// Job is the data of a record of class jobs: when a task that runs once
// for the whole group (a rotation of keys, a notification) last started,
// and on which node. Its id is the task's name. Every node reads it to know
// whether the task is due; the node that keeps the group's locks writes it
// before it runs the task, so a task runs at most once per interval while
// the nodes reach each other.
type Job struct {
	At   string `json:"at"`
	Node string `json:"node"`
}

// JobName reports whether s names a job: 1 to 64 of a-z, 0-9, "_", "." and "-".
func JobName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// DecodeJob returns the job of a record of class jobs.
func DecodeJob(r *Record) (*Job, time.Time, error) {
	var j Job
	if err := decodeData(r, &j); err != nil || len(j.Node) > 63 || !JobName(r.ID) || r.Deleted {
		return nil, time.Time{}, ErrSchema
	}
	at, err := time.Parse("2006-01-02T15:04:05Z", j.At)
	if err != nil {
		return nil, time.Time{}, ErrSchema
	}
	return &j, at, nil
}
