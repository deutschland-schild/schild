// Package cluster is the group of gateways of MVP-27 (DECISIONS D105,
// contracts/cluster.md): this node's key, its copy of the group's records in
// <data>/cluster/cluster.db, and the mesh that carries records from node to
// node.
//
// Guarantees:
//   - Nothing in the request path comes here. The gate reads its own memory;
//     this package hands it changes in the background.
//   - A peer that is away, slow or hostile costs the sync and nothing else:
//     every call has a deadline, every record is checked before it is
//     applied (contract/cluster.Roster.Check), and what fails is counted and
//     dropped.
//   - Without cluster.enabled nothing of this package runs: no file, no
//     listener, no connection.
package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // the driver "sqlite", as the store uses it

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// ErrNoGroup: the node was not set up with a group secret yet.
var ErrNoGroup = errors.New("cluster: this node belongs to no group (set cluster.secret_file and cluster.peers, then start schild)")

const (
	keyFile = "node.key"
	dbFile  = "cluster.db"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
-- One row per record this node holds: the winner of its (class, id), or a
-- record of a version it cannot read (state 2), kept to pass it on.
CREATE TABLE IF NOT EXISTS records (
  origin TEXT NOT NULL,
  seq INTEGER NOT NULL,
  class TEXT NOT NULL,
  id TEXT NOT NULL,
  hlc INTEGER NOT NULL,
  deleted INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL,
  state INTEGER NOT NULL,
  raw BLOB NOT NULL,
  PRIMARY KEY (origin, seq)
);
CREATE INDEX IF NOT EXISTS records_key ON records(class, id, state);
-- The latest clock value held, read with every write (publish).
CREATE INDEX IF NOT EXISTS records_hlc ON records(hlc);
-- The highest sequence number seen per origin.
CREATE TABLE IF NOT EXISTS vector (origin TEXT PRIMARY KEY, seq INTEGER NOT NULL);
-- What the running node last saw of each peer, for schild cluster status.
CREATE TABLE IF NOT EXISTS peers (node TEXT PRIMARY KEY, out_ok_ms INTEGER NOT NULL, in_ok_ms INTEGER NOT NULL, error TEXT NOT NULL, behind INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS counters (k TEXT PRIMARY KEY, n INTEGER NOT NULL);
-- What a value of the group replaced on this node at its first sync.
CREATE TABLE IF NOT EXISTS replaced (k TEXT NOT NULL, at_ms INTEGER NOT NULL, v BLOB NOT NULL);
`

// maxAnswer bounds the bytes of the records of one answer; one record over
// it still goes alone.
const maxAnswer = 4 << 20

const (
	stateWinner = 1
	stateUnread = 2
)

// state is what a command on the host and the running node share: the key,
// the database and the clock.
type state struct {
	dir   string
	db    *sql.DB
	key   ed25519.PrivateKey
	pub   ed25519.PublicKey
	id    string
	group string
	clock contract.Clock
	now   func() time.Time
	// wmu serialises writes of this process; SQLite serialises them between
	// the node and a command on the host.
	wmu sync.Mutex
}

func openState(dir string, create bool, now func() time.Time) (*state, error) {
	if now == nil {
		now = time.Now
	}
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	key, err := loadKey(filepath.Join(dir, keyFile), create)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, dbFile)
	if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		f.Close()
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(6) // one is kept by watchStore, one by the look of the roster (reload)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("cluster: %s: %w", path, err)
	}
	s := &state{dir: dir, db: db, key: key, pub: key.Public().(ed25519.PublicKey), now: now}
	s.id = contract.NodeID(s.pub)
	if g, err := s.meta("group"); err == nil {
		s.group = string(g)
	}
	return s, nil
}

// loadKey reads the node's key: 64 hex characters of an Ed25519 seed, in a
// file only its owner reads. It never leaves the node.
func loadKey(path string, create bool) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) && create {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoGroup
	}
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("cluster: %s is readable by others (mode %04o): chmod 600", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("cluster: %s is no node key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (s *state) close() { _ = s.db.Close() }

func (s *state) meta(k string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, k).Scan(&v)
	return v, err
}

func setMeta(tx *sql.Tx, k string, v []byte) error {
	_, err := tx.Exec(`INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}

func expiresMS(r *contract.Record) int64 {
	if t, ok := r.ExpiresAt(); ok {
		return t.UnixMilli()
	}
	return 0
}

// put makes rec the state of its (class, id) when it wins against the
// record held, and reports whether it did. The same record twice changes
// nothing.
func put(tx *sql.Tx, rec *contract.Record, raw []byte) (won bool, err error) {
	rows, err := tx.Query(`SELECT origin, seq, hlc, deleted FROM records WHERE class = ? AND id = ? AND state = ?`, rec.Class, rec.ID, stateWinner)
	if err != nil {
		return false, err
	}
	var held []contract.Record
	for rows.Next() {
		var h contract.Record
		if err := rows.Scan(&h.Origin, &h.Seq, &h.HLC, &h.Deleted); err != nil {
			rows.Close()
			return false, err
		}
		held = append(held, h)
	}
	rows.Close()
	for i := range held {
		if !contract.Wins(rec, &held[i]) {
			return false, nil
		}
	}
	if _, err := tx.Exec(`DELETE FROM records WHERE class = ? AND id = ? AND state = ?`, rec.Class, rec.ID, stateWinner); err != nil {
		return false, err
	}
	_, err = tx.Exec(`INSERT OR REPLACE INTO records(origin, seq, class, id, hlc, deleted, expires_ms, state, raw) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Origin, rec.Seq, rec.Class, rec.ID, int64(rec.HLC), rec.Deleted, expiresMS(rec), stateWinner, raw)
	return err == nil, err
}

func putUnread(tx *sql.Tx, rec *contract.Record, raw []byte) error {
	_, err := tx.Exec(`INSERT OR IGNORE INTO records(origin, seq, class, id, hlc, deleted, expires_ms, state, raw) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Origin, rec.Seq, rec.Class, rec.ID, int64(rec.HLC), rec.Deleted, expiresMS(rec), stateUnread, raw)
	return err
}

func raiseVector(tx *sql.Tx, origin string, seq uint64) error {
	_, err := tx.Exec(`INSERT INTO vector(origin, seq) VALUES(?, ?) ON CONFLICT(origin) DO UPDATE SET seq = max(seq, excluded.seq)`, origin, int64(seq))
	return err
}

func (s *state) vector() (map[string]uint64, error) {
	rows, err := s.db.Query(`SELECT origin, seq FROM vector`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]uint64{}
	for rows.Next() {
		var o string
		var n int64
		if err := rows.Scan(&o, &n); err != nil {
			return nil, err
		}
		out[o] = uint64(n)
	}
	return out, rows.Err()
}

// errLost: a record this node wrote did not win against the record held.
var errLost = errors.New("cluster: the write lost against a later record of the same thing")

// publish writes a record of this node: the next sequence number, a clock
// value later than everything held, signed, and applied here first. It
// fails when the record does not become the state of its (class, id),
// which the clock rules out unless the store holds a record from a clock
// far ahead.
func (s *state) publish(class, id string, data any, deleted bool, expires time.Time) (*contract.Record, error) {
	if s.group == "" {
		return nil, ErrNoGroup
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var seq int64
	if err := tx.QueryRow(`SELECT seq FROM vector WHERE origin = ?`, s.id).Scan(&seq); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	// The clock moves past every record held and every value this node
	// gave out: a command on the host (schild cluster remove) runs in a
	// process of its own, and a node that restarted forgot what it saw. A
	// write must be later than every record either of them holds, or a
	// record of a clock a little ahead beats it.
	var last, held int64
	if err := tx.QueryRow(`SELECT coalesce((SELECT CAST(v AS INTEGER) FROM meta WHERE k = 'hlc'), 0), coalesce((SELECT max(hlc) FROM records), 0)`).Scan(&last, &held); err != nil {
		return nil, err
	}
	s.clock.Observe(uint64(last))
	s.clock.Observe(uint64(held))
	rec := &contract.Record{V: contract.Version, Group: s.group, Class: class, ID: id, Origin: s.id, Seq: uint64(seq) + 1, HLC: s.clock.Next(s.now()), Deleted: deleted}
	if !expires.IsZero() {
		rec.Expires = contract.TimeText(expires)
	}
	if err := rec.Sign(s.key, data); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	won, err := put(tx, rec, raw)
	if err != nil {
		return nil, err
	}
	if !won {
		return nil, fmt.Errorf("%w (%s %s)", errLost, class, id)
	}
	if err := raiseVector(tx, s.id, rec.Seq); err != nil {
		return nil, err
	}
	if err := setMeta(tx, "hlc", []byte(fmt.Sprint(rec.HLC))); err != nil {
		return nil, err
	}
	return rec, tx.Commit()
}

// winners returns the records that are the state of a class.
func (s *state) winners(class string) ([]*contract.Record, [][]byte, error) {
	rows, err := s.db.Query(`SELECT raw FROM records WHERE class = ? AND state = ? ORDER BY hlc`, class, stateWinner)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var recs []*contract.Record
	var raws [][]byte
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, nil, err
		}
		var r contract.Record
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		recs = append(recs, &r)
		raws = append(raws, raw)
	}
	return recs, raws, rows.Err()
}

// roster builds who may sign from the member records held.
func (s *state) roster() (*contract.Roster, error) {
	recs, _, err := s.winners(contract.ClassMembers)
	if err != nil {
		return nil, err
	}
	ro := contract.NewRoster(s.group)
	for _, r := range recs {
		ro.Set(r)
	}
	return ro, nil
}

// afterOf returns the records a peer with this vector lacks, at most limit,
// and how far the answer covers each origin: the peer may set its vector
// there once it applied them. mine is the vector of this node (a running
// node keeps it while its store stands, Node.vectorNow).
func (s *state) afterOf(ctx context.Context, mine, peer map[string]uint64, limit int) (recs []json.RawMessage, covered map[string]uint64, more bool, err error) {
	covered = map[string]uint64{}
	size := 0
	for origin, seq := range mine {
		if seq <= peer[origin] {
			continue
		}
		if len(recs) >= limit || size >= maxAnswer {
			more = true
			continue
		}
		rows, err := s.db.QueryContext(ctx, `SELECT seq, raw FROM records WHERE origin = ? AND seq > ? ORDER BY seq LIMIT ?`,
			origin, int64(peer[origin]), limit-len(recs)+1)
		if err != nil {
			return nil, nil, false, err
		}
		last, cut := peer[origin], false
		for rows.Next() {
			var n int64
			var raw []byte
			if err := rows.Scan(&n, &raw); err != nil {
				rows.Close()
				return nil, nil, false, err
			}
			if len(recs) >= limit || (len(recs) > 0 && size+len(raw) > maxAnswer) {
				cut = true
				break
			}
			recs = append(recs, raw)
			size += len(raw)
			last = uint64(n)
		}
		rows.Close()
		switch {
		case !cut:
			covered[origin] = seq
		case last > peer[origin]:
			more = true
			covered[origin] = last
		default:
			more = true
		}
	}
	return recs, covered, more, nil
}

// expire drops records whose time is over.
func (s *state) expire(now time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM records WHERE expires_ms != 0 AND expires_ms < ?`, now.UnixMilli())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
