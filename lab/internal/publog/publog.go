// Package publog is the lab's public append-only log (MVP-03): every
// proposal decision, bundle, withdrawal and state-changing checkpoint. The
// head {size, root} is the RFC 6962 Merkle tree hash over the leaf data of
// all entries (contracts v0.1, contracts/cosign.md, contract/logtree); the
// signed checkpoint carries it, so anyone holding a checkpoint can recompute
// the root from a log copy (the lab dashboard does it in the browser). The
// log never contains client data: entries are built from rule texts,
// digests and counts only, and Append refuses anything address-like.
package publog

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/deutschland-schild/schild/contract/logtree"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/lab/internal/store"
)

// Kinds of log entries.
const (
	KindProposal   = "proposal"
	KindBundle     = "bundle"
	KindWithdrawal = "withdrawal"
	KindCheckpoint = "checkpoint"
)

// Entry is one log entry (the dashboard's LogEntry plus its leaf hash).
type Entry struct {
	Index          uint64          `json:"index"`
	Time           string          `json:"time"`
	Kind           string          `json:"kind"`
	Ref            string          `json:"ref"`
	Digest         string          `json:"digest"`
	Summary        string          `json:"summary"`
	EnvelopeSHA256 *string         `json:"envelope_sha256"`
	Envelope       json.RawMessage `json:"envelope,omitempty"`
	LeafHash       string          `json:"leaf_hash"`
}

// Head is the size and root of the log.
type Head struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
}

// EmptyRoot is the root of the empty log (SHA-256 of the empty string).
var EmptyRoot = logtree.Format(logtree.EmptyRoot())

var (
	safeText  = regexp.MustCompile(`^[ -~]{0,280}$`)
	safeRef   = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	ipLike    = regexp.MustCompile(`[0-9]{1,3}[.\-_][0-9]{1,3}[.\-_][0-9]{1,3}[.\-_][0-9]{1,3}|[0-9a-fA-F]{1,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}`)
	digestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	errUnsafe = errors.New("publog: entry would carry free text or address-like data")
)

// TreeEntry returns the fields of e that enter its leaf.
func (e *Entry) TreeEntry() logtree.Entry {
	return logtree.Entry{Index: e.Index, Time: e.Time, Kind: e.Kind, Ref: e.Ref, Digest: e.Digest, Summary: e.Summary, EnvelopeSHA256: e.EnvelopeSHA256}
}

func leafOf(e *Entry) logtree.Hash { return logtree.LeafHash(logtree.LeafData(e.TreeEntry())) }

// frontierTx returns the stored tree frontier; logs written before v0.1
// (hash chain) are rebuilt from their entries once.
func frontierTx(tx *bolt.Tx) (*logtree.Frontier, error) {
	var f logtree.Frontier
	if ok, err := store.GetMeta(tx, "log_frontier", &f); err != nil {
		return nil, err
	} else if ok {
		return &f, nil
	}
	f = logtree.Frontier{}
	c := tx.Bucket(store.Log).Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var e Entry
		if err := json.Unmarshal(v, &e); err != nil {
			return nil, err
		}
		if e.Index != f.Size {
			return nil, fmt.Errorf("publog: entry %d out of order", e.Index)
		}
		if e.EnvelopeSHA256 == nil && len(e.Envelope) > 0 {
			d := msg.Digest(e.Envelope)
			e.EnvelopeSHA256 = &d
		}
		f.Append(leafOf(&e))
	}
	return &f, nil
}

// HeadTx returns the current head.
func HeadTx(tx *bolt.Tx) Head {
	f, err := frontierTx(tx)
	if err != nil {
		return Head{Root: EmptyRoot}
	}
	return Head{Size: f.Size, Root: logtree.Format(f.Root())}
}

// Append adds an entry inside tx.
func Append(tx *bolt.Tx, now time.Time, kind, ref, digest, summary string, envelope json.RawMessage) (*Entry, error) {
	switch kind {
	case KindProposal:
		if len(envelope) > 0 {
			return nil, errors.New("publog: proposals carry no envelope")
		}
	case KindBundle, KindWithdrawal, KindCheckpoint:
	default:
		return nil, fmt.Errorf("publog: unknown kind %q", kind)
	}
	if !safeText.MatchString(summary) || !safeRef.MatchString(ref) || ipLike.MatchString(summary) || !digestRe.MatchString(digest) {
		return nil, errUnsafe
	}
	f, err := frontierTx(tx)
	if err != nil {
		return nil, err
	}
	e := &Entry{Index: f.Size, Time: msg.FormatTime(now), Kind: kind, Ref: ref, Digest: digest, Summary: summary, Envelope: envelope}
	if len(envelope) > 0 {
		d := msg.Digest(envelope)
		e.EnvelopeSHA256 = &d
	}
	lh := leafOf(e)
	e.LeafHash = logtree.Format(lh)
	if err := store.PutJSON(tx, store.Log, store.U64(e.Index), e); err != nil {
		return nil, err
	}
	f.Append(lh)
	return e, store.PutMeta(tx, "log_frontier", f)
}

// Get returns entry i.
func Get(tx *bolt.Tx, i uint64) (*Entry, bool, error) {
	var e Entry
	ok, err := store.GetJSON(tx, store.Log, store.U64(i), &e)
	return &e, ok, err
}

// List returns up to limit entries with index < before (newest first),
// optionally of one kind.
func List(tx *bolt.Tx, kind string, before uint64, limit int) []*Entry {
	var out []*Entry
	c := tx.Bucket(store.Log).Cursor()
	var k, v []byte
	if before == 0 {
		k, v = c.Last()
	} else {
		k, v = c.Seek(store.U64(before))
		if k == nil {
			k, v = c.Last()
		} else {
			k, v = c.Prev()
		}
	}
	for ; k != nil && len(out) < limit; k, v = c.Prev() {
		var e Entry
		if json.Unmarshal(v, &e) != nil {
			continue
		}
		if store.FromU64(k) >= before && before != 0 {
			continue
		}
		if kind == "" || e.Kind == kind {
			out = append(out, &e)
		}
	}
	return out
}

// Range returns entries [from, from+limit) in ascending order (public feed).
func Range(tx *bolt.Tx, from uint64, limit int) []*Entry {
	var out []*Entry
	c := tx.Bucket(store.Log).Cursor()
	for k, v := c.Seek(store.U64(from)); k != nil && len(out) < limit; k, v = c.Next() {
		var e Entry
		if json.Unmarshal(v, &e) == nil {
			out = append(out, &e)
		}
	}
	return out
}

// Verify recomputes the RFC 6962 root of a complete log copy (entries
// 0..n-1 in order) and returns its head; it fails on gaps.
func Verify(entries []*Entry) (Head, error) {
	var f logtree.Frontier
	for i, e := range entries {
		if e.Index != uint64(i) {
			return Head{}, fmt.Errorf("publog: entry %d has index %d", i, e.Index)
		}
		f.Append(leafOf(e))
	}
	return Head{Size: f.Size, Root: logtree.Format(f.Root())}, nil
}
