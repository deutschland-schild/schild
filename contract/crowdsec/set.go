package crowdsec

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/schema"
)

// SetSchema names the set schema; SetSchemaVersion is its "schema" field;
// StoreKey is the key of the stored last good set in schild.db.
const (
	SetSchema        = "crowdsec-set"
	SetSchemaVersion = "schild.crowdsec_set/0.1"
	StoreKey         = "crowdsec_hub_set_v1"
	// MaxSetFileBytes of one stored set or image snapshot.
	MaxSetFileBytes = 8 << 20
)

// SetItem is one hub item of a Set.
type SetItem struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Digest      string `json:"digest"`
	Content     string `json:"content"`
	Description string `json:"description,omitempty"`
	FirstSeen   string `json:"first_seen"`
	ChangedAt   string `json:"changed_at"`
}

// Set is a checked rule set (crowdsec-set.schema.json): the image snapshot or
// the stored last good set. It holds hub items, not SecLang; a load runs
// Convert on every item.
type Set struct {
	Schema      string    `json:"schema"`
	IndexDigest string    `json:"index_sha256"`
	HubCommit   string    `json:"hub_commit,omitempty"`
	HubCommitAt string    `json:"hub_commit_at,omitempty"`
	FetchedAt   string    `json:"fetched_at"`
	NotSelected int       `json:"not_selected"`
	Rules       []SetItem `json:"rules"`
}

// Time returns the date that says how new the rules of a set are (never a
// file time): the commit time when known; else fetched_at for a set from the
// master branch, whose index was the head at that moment; else "": a set of a
// commit without a known commit time may be old however recently it came.
func (s *Set) Time() string {
	switch {
	case s.HubCommitAt != "":
		return s.HubCommitAt
	case s.HubCommit == "":
		return s.FetchedAt
	}
	return ""
}

// ParseSet checks size, strict JSON, schema and the semantic rules of a set:
// names sorted and unique, every digest fits its content, times in order. A
// set that fails is not used: the next one in the precedence loads.
func ParseSet(raw []byte) (*Set, error) {
	if len(raw) > MaxSetFileBytes {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxSetFileBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(SetSchema, v); err != nil {
		return nil, err
	}
	var s Set
	if err := jsonx.Decode(v, &s); err != nil {
		return nil, contract.Errf(contract.CodeSchema, "set: %v", err)
	}
	prev := ""
	for _, r := range s.Rules {
		if r.Name <= prev {
			return nil, contract.Errf(contract.CodeSchema, "rules not sorted at %s", r.Name)
		}
		prev = r.Name
		body, err := base64.StdEncoding.DecodeString(r.Content)
		if err != nil {
			return nil, contract.Errf(contract.CodeSchema, "%s: content: %v", r.Name, err)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != r.Digest {
			return nil, contract.Errf(contract.CodeSchema, "%s: digest does not fit the content", r.Name)
		}
		first, err1 := msg.ParseTime(r.FirstSeen)
		changed, err2 := msg.ParseTime(r.ChangedAt)
		if err1 != nil || err2 != nil || changed.Before(first) {
			return nil, contract.Errf(contract.CodeSchema, "%s: changed_at before first_seen", r.Name)
		}
	}
	return &s, nil
}
