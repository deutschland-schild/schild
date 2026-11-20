// Package store is the lab's state file (store.db, bbolt): received
// signals, pattern aggregates, proposals, bundles, withdrawals, the public
// log and dashboard accounts. The ingest queue lives in its own file
// (internal/queue), so nothing here can slow the ingest path.
package store

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bucket names.
var (
	Signals         = []byte("signals")         // recvMS|seq -> ReceivedSignal
	SignalIDs       = []byte("signal_ids")      // signal id -> signals key
	SignalByPattern = []byte("signal_by_pat")   // pattern id|signals key -> nil
	Patterns        = []byte("patterns")        // pattern id -> Pattern
	Units           = []byte("units")           // pattern id|bucket|issuer\x00request_sig -> nil
	Timeline        = []byte("timeline")        // pattern id|hour -> TimelineEntry
	PatternClients  = []byte("pattern_clients") // pattern id|keyid -> nil
	PatternReqSigs  = []byte("pattern_reqsigs") // pattern id|request_sig -> nil
	Feedback        = []byte("feedback")        // rule id|issuer -> count
	Proposals       = []byte("proposals")       // proposal id -> Proposal
	ReproRequests   = []byte("repro_requests")  // sha256 -> raw reproducing request (private)
	Bundles         = []byte("bundles")         // version -> BundleRecord
	Withdrawals     = []byte("withdrawals")     // seq -> WithdrawalRecord
	Log             = []byte("log")             // index -> log entry
	Meta            = []byte("meta")            // counters and heads
	Auth            = []byte("auth")            // dashboard users
	Settings        = []byte("settings")        // dashboard settings overlay
	all             = [][]byte{Signals, SignalIDs, SignalByPattern, Patterns, Units, Timeline, PatternClients, PatternReqSigs, Feedback, Proposals, ReproRequests, Bundles, Withdrawals, Log, Meta, Auth, Settings}
)

// DB is the store.
type DB struct{ *bolt.DB }

// Open opens or creates the store and its buckets.
func Open(path string) (*DB, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second, NoFreelistSync: true, FreelistType: bolt.FreelistMapType})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range all {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db}, nil
}

// U64 encodes v big-endian (sortable keys).
func U64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// FromU64 decodes a big-endian key.
func FromU64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// Key joins parts into one key.
func Key(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// GetJSON reads k from bucket b into v; false when absent.
func GetJSON(tx *bolt.Tx, b, k []byte, v any) (bool, error) {
	raw := tx.Bucket(b).Get(k)
	if raw == nil {
		return false, nil
	}
	return true, json.Unmarshal(raw, v)
}

// PutJSON writes v under k in bucket b.
func PutJSON(tx *bolt.Tx, b, k []byte, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Bucket(b).Put(k, raw)
}

// Counter reads a meta counter.
func Counter(tx *bolt.Tx, name string) uint64 {
	return FromU64(tx.Bucket(Meta).Get([]byte("ctr:" + name)))
}

// SetCounter writes a meta counter.
func SetCounter(tx *bolt.Tx, name string, v uint64) error {
	return tx.Bucket(Meta).Put([]byte("ctr:"+name), U64(v))
}

// NextCounter increments and returns a meta counter.
func NextCounter(tx *bolt.Tx, name string) (uint64, error) {
	v := Counter(tx, name) + 1
	return v, SetCounter(tx, name, v)
}

// GetMeta reads a JSON meta value.
func GetMeta(tx *bolt.Tx, name string, v any) (bool, error) {
	return GetJSON(tx, Meta, []byte("val:"+name), v)
}

// PutMeta writes a JSON meta value.
func PutMeta(tx *bolt.Tx, name string, v any) error {
	return PutJSON(tx, Meta, []byte("val:"+name), v)
}
