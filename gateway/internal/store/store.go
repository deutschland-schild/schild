// Package store keeps everything Schild stores locally in one SQLite file
// (modernc.org/sqlite, pure Go): local events with full visitor IP and
// location (E7), incidents, the allowlist, dashboard users and sessions,
// settings and hourly summaries without IPs. Nothing in here ever leaves the
// server.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// Store is the local database.
type Store struct {
	db   *sql.DB
	path string
	// written counts the bytes the event and incident writers handed to SQLite (D38 size cap, capacity.go).
	written atomic.Int64
	// capDeleted is when a size-cap pass last deleted rows that counters
	// may cover (unix ns; Overview.counters_24h.partial, D36 open items).
	capDeleted atomic.Int64
}

const baseSchema = `
CREATE TABLE events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  time_ms INTEGER NOT NULL,
  type TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  ip_key TEXT NOT NULL DEFAULT '',
  ip_truncated INTEGER NOT NULL DEFAULT 0,
  country TEXT NOT NULL DEFAULT '',
  asn INTEGER NOT NULL DEFAULT 0,
  method TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL DEFAULT 0,
  score INTEGER NOT NULL DEFAULT 0,
  outcome TEXT NOT NULL DEFAULT '',
  rules TEXT NOT NULL DEFAULT '',
  incident TEXT NOT NULL DEFAULT '',
  session TEXT NOT NULL DEFAULT '',
  ua TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  body BLOB NOT NULL,
  site TEXT NOT NULL DEFAULT '',
  cls INTEGER NOT NULL
);
CREATE INDEX events_time ON events(time_ms);
CREATE INDEX events_ip ON events(ip_key, seq);
CREATE INDEX events_incident ON events(incident) WHERE incident != '';
CREATE INDEX events_type ON events(type, seq);
CREATE INDEX events_outcome ON events(outcome, seq);
CREATE INDEX events_session ON events(session, seq) WHERE session != '';
CREATE INDEX events_country ON events(country, seq);
CREATE INDEX events_trunc ON events(ip_truncated, time_ms);
CREATE INDEX events_cap ON events(cls, time_ms, id);

CREATE TABLE incidents (
  incident TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  time_ms INTEGER NOT NULL,
  ip TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  sources TEXT NOT NULL DEFAULT '',
  unblocked_ms INTEGER NOT NULL DEFAULT 0,
  allowlist_entry TEXT NOT NULL DEFAULT '',
  site TEXT NOT NULL DEFAULT '',
  count INTEGER NOT NULL,
  first_ms INTEGER NOT NULL,
  last_ms INTEGER NOT NULL
);
CREATE INDEX incidents_ip ON incidents(ip);
CREATE INDEX incidents_time ON incidents(time_ms);

CREATE TABLE exceptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  sources TEXT NOT NULL,
  expires_ms INTEGER NOT NULL,
  incident TEXT NOT NULL DEFAULT ''
);

CREATE TABLE allowlist (
  id TEXT PRIMARY KEY,
  ip TEXT NOT NULL DEFAULT '',
  cidr TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL,
  level TEXT NOT NULL,
  expires TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  source TEXT NOT NULL
);

CREATE TABLE users (
  name TEXT PRIMARY KEY,
  hash TEXT NOT NULL,
  role TEXT NOT NULL,
  created_ms INTEGER NOT NULL
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user TEXT NOT NULL,
  csrf TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL
);

CREATE TABLE kv (
  k TEXT PRIMARY KEY,
  v BLOB NOT NULL
);

CREATE TABLE summaries (
  hour INTEGER NOT NULL,
  outcome TEXT NOT NULL,
  country TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (hour, outcome, country)
);
`

// schema is every table, index and trigger of the baseline of schild.db
// (migrate.go), created at once in a new file.
const schema = baseSchema + agentSchema + websitesSchema + alertsSchema + blocksSchema + decisionsSchema

// Open opens the database at path and creates it with the schema when the
// file is new or empty. It never converts an existing database: one of an
// older release is refused with ErrNeedsUpgrade (the gateway's start
// upgrades it, OpenMigrate), one of a pre-release build or of a newer
// release with an error that names the path. Commands next to a running
// gateway use Open, so a new binary never changes the schema under an old
// process.
func Open(path string) (*Store, error) { return openDB(path, false, nil) }

// OpenMigrate is Open for the gateway's start (`schild run`, which holds
// the gateway lock of the data directory): a database of an older release
// is copied to BackupPath and upgraded in one transaction (D75). log may be
// nil.
func OpenMigrate(path string, log *slog.Logger) (*Store, error) { return openDB(path, true, log) }

func openDB(path string, migrate bool, log *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := ensurePrivate(path); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=auto_vacuum(INCREMENTAL)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=journal_size_limit(67108864)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := initSchema(db, path, migrate, log); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, path: path}, nil
}

// ensurePrivate creates a missing database file with mode 0600 before
// SQLite opens it and narrows an existing file and its -wal and -shm files
// to 0600 (best effort, as before for the database file). SQLite creates
// the -wal and -shm files with the mode of the database file; a database
// file it created itself would be 0644 (minus umask), and the WAL holds the
// same visitor addresses as the database.
func ensurePrivate(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case err == nil:
		if err := f.Close(); err != nil {
			return err
		}
	case !errors.Is(err, os.ErrExist):
		return err
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		_ = os.Chmod(p, 0o600)
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for tests.
func (s *Store) DB() *sql.DB { return s.db }

// Path of the database file.
func (s *Store) Path() string { return s.path }

// SizeBytes returns the used bytes of the size cap (D38): the pages in
// use, (page_count - freelist_count) * page_size, plus schild.db-wal.
func (s *Store) SizeBytes() int64 {
	return s.pageBytes(context.Background()) + s.WALBytes()
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

// NewID returns a short random id with a prefix (allowlist entries).
func NewID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------- kv

// Get returns a kv value.
func (s *Store) Get(ctx context.Context, k string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, "SELECT v FROM kv WHERE k = ?", k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// Put stores a kv value.
func (s *Store) Put(ctx context.Context, k string, v []byte) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO kv(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", k, v)
	return err
}

// Delete removes a kv value; a value that is not there is no error.
func (s *Store) Delete(ctx context.Context, k string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM kv WHERE k = ?", k)
	return err
}

// ---------------------------------------------------------------- helpers

func joinList(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return "," + strings.Join(xs, ",") + ","
}

func splitList(s string) []string {
	s = strings.Trim(s, ",")
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
