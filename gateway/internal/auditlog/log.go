// Package auditlog is the audit log of a gateway (MVP-36, contracts/audit.md):
// who changed what, when, through which way, and what it was before.
//
// An entry is written into the outbox of schild.db in the transaction of its
// change (Tx, Write). The running gateway moves it to audit.db, a file of its
// own outside the size cap, and reads from there. A command on the host
// writes into the outbox alone (ForStore); the gateway moves its entries at
// the next start or move.
//
// The contract of an entry (what is recorded, what a viewer sees, what its
// age deletes) is contract/audit; nothing here decides it again.
package auditlog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// FileName of the log in the data directory.
const FileName = "audit.db"

// SizeHintBytes: from this size on the hint audit_size names the growth.
const SizeHintBytes = int64(1) << 30

// StuckAfter: entries that wait longer in the outbox make the hint
// audit_stuck.
const StuckAfter = time.Minute

const fileSchema = `
CREATE TABLE IF NOT EXISTS entries (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  t_ms INTEGER NOT NULL,
  time_ms INTEGER NOT NULL,
  class TEXT NOT NULL,
  action TEXT NOT NULL,
  way TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  session TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  subject_id TEXT NOT NULL DEFAULT '',
  website TEXT NOT NULL DEFAULT '',
  event TEXT NOT NULL DEFAULT '',
  incident TEXT NOT NULL DEFAULT '',
  own INTEGER NOT NULL DEFAULT 0,
  open INTEGER NOT NULL DEFAULT 0,
  body BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_time ON entries(time_ms, seq);
CREATE INDEX IF NOT EXISTS entries_keep ON entries(class, t_ms, id);
CREATE INDEX IF NOT EXISTS entries_action ON entries(action, time_ms);
CREATE INDEX IF NOT EXISTS entries_way ON entries(way, time_ms);
CREATE INDEX IF NOT EXISTS entries_website ON entries(website, time_ms) WHERE website != '';
CREATE INDEX IF NOT EXISTS entries_actor ON entries(actor, time_ms) WHERE actor != '';
CREATE INDEX IF NOT EXISTS entries_session ON entries(session, time_ms) WHERE session != '';
CREATE INDEX IF NOT EXISTS entries_subject ON entries(subject, subject_id, time_ms);
CREATE INDEX IF NOT EXISTS entries_event ON entries(event, time_ms) WHERE event != '';
CREATE INDEX IF NOT EXISTS entries_incident ON entries(incident, time_ms) WHERE incident != '';
CREATE INDEX IF NOT EXISTS entries_open ON entries(open) WHERE open = 1;
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
`

// Reasons of audit.start.
const (
	StartFirst      = "first"
	StartMissing    = "missing"
	StartUnreadable = "unreadable"
)

// Options of Open.
type Options struct {
	// Node is the node name of this gateway's entries: the CloudEvents
	// source of its events without schild://.
	Node string
	// KeepDays is audit.keep_days now; 0 is unlimited.
	KeepDays func() int64
	// Stream receives every entry of this node as one JSON line
	// (audit.stream); nil: no copy.
	Stream io.Writer
	Log    *slog.Logger
	Now    func() time.Time
}

// Log is the audit log of a node.
type Log struct {
	st   *store.Store
	db   *sql.DB // audit.db; nil for a command on the host
	path string
	opts Options
	node atomic.Pointer[string]

	// moveMu: one move at a time.
	moveMu sync.Mutex
	kick   chan struct{}
	// moveErr is the error of the last move, nil after a good one.
	moveErr atomic.Pointer[error]
	// streamFailed counts the lines the copy could not take.
	streamFailed atomic.Int64
	streamMu     sync.Mutex
	// differing counts entries of members that came with another content
	// under an id this node holds.
	differing atomic.Int64
	// skipped counts entries of members that did not pass the check.
	skipped atomic.Int64

	refused refused
	budget  budget
}

func dsn(path string, readOnly bool) string {
	d := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=journal_size_limit(67108864)&_txlock=immediate"
	if readOnly {
		d = "file:" + path + "?mode=ro&_pragma=busy_timeout(10000)"
	}
	return d
}

// ForStore returns the log of a command on the host: it writes into the
// outbox of st and reads nothing. node is the node name of the entries; the
// name the gateway stored at its last start wins.
func ForStore(ctx context.Context, st *store.Store, node string) *Log {
	l := &Log{st: st}
	if n, err := st.AuditState(ctx, nodeKey); err == nil && n != "" {
		node = n
	}
	if node == "" {
		node = "schild"
	}
	l.node.Store(&node)
	return l
}

const nodeKey = "node"

// Open opens audit.db at path for the running gateway and starts a new log
// when there is none (audit.start). An unreadable file is renamed, never
// deleted.
func Open(ctx context.Context, st *store.Store, path string, opts Options) (*Log, error) {
	l := &Log{st: st, path: path, opts: opts, kick: make(chan struct{}, 1)}
	l.refused.wake = make(chan struct{}, 1)
	node := opts.Node
	if node == "" {
		node = "schild"
	}
	l.node.Store(&node)
	if err := st.SetAuditState(ctx, nodeKey, node); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	reason := ""
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		reason = StartMissing
		if had, _ := st.AuditState(ctx, store.AuditHadFile); had == "" {
			reason = StartFirst
		}
	} else if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	db, name, err := openFile(path)
	if err != nil && reason == "" {
		// Unreadable: keep the file under another name and start anew.
		moved := path + ".unreadable-" + l.now().Format("20060102T150405Z")
		if rerr := os.Rename(path, moved); rerr != nil {
			return nil, fmt.Errorf("audit log: %s is unreadable (%v) and cannot be moved away: %w", path, err, rerr)
		}
		for _, ext := range []string{"-wal", "-shm"} {
			_ = os.Rename(path+ext, moved+ext)
		}
		if opts.Log != nil {
			opts.Log.Error("audit.db is unreadable: kept under another name, a new log starts", "path", path, "kept_as", moved, "err", err)
		}
		reason = StartUnreadable
		db, name, err = openFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	l.db = db
	switch reason {
	case StartFirst:
		// A command on the host may have written before the first start:
		// its name stays.
		if name, err = st.AuditLogName(ctx); err != nil {
			db.Close()
			return nil, fmt.Errorf("audit log: %w", err)
		}
	case StartMissing, StartUnreadable:
		if name, err = st.NewAuditLog(ctx); err == nil {
			err = st.ClearAuditConfig(ctx)
		}
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("audit log: %w", err)
		}
	default:
		have, err := st.AuditState(ctx, "log")
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("audit log: %w", err)
		}
		if name == "" {
			name = have
		}
		if name == "" {
			if name, err = st.AuditLogName(ctx); err != nil {
				db.Close()
				return nil, fmt.Errorf("audit log: %w", err)
			}
		} else if have != name {
			// Another schild.db than the one that wrote this file: go on
			// after the numbers the file holds.
			nums, err := l.highest(ctx, name)
			if err == nil {
				err = st.AdoptAuditLog(ctx, name, nums)
			}
			if err != nil {
				db.Close()
				return nil, fmt.Errorf("audit log: %w", err)
			}
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO meta(k, v) VALUES('log', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, name); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if err := st.SetAuditState(ctx, store.AuditHadFile, "1"); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if err := l.closeOpenRefused(ctx, true); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if reason != "" {
		if err := l.Write(ctx, Entry{Action: "audit.start", Operation: "system:start", Actor: System(), Subject: name,
			After: map[string]any{"reason": reason}}); err != nil {
			db.Close()
			return nil, fmt.Errorf("audit log: %w", err)
		}
	}
	if err := l.Move(ctx); err != nil && opts.Log != nil {
		opts.Log.Warn("audit log: entries wait in schild.db, audit.db could not be written", "err", err)
	}
	return l, nil
}

// openFile opens audit.db, creates its tables and returns the name of its
// log ("" in a new file).
func openFile(path string) (*sql.DB, string, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, "", err
	}
	if err := f.Close(); err != nil {
		return nil, "", err
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		_ = os.Chmod(p, 0o600)
	}
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, "", err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(fileSchema); err != nil {
		db.Close()
		return nil, "", err
	}
	var name string
	if err := db.QueryRow(`SELECT v FROM meta WHERE k = 'log'`).Scan(&name); err != nil && !errors.Is(err, sql.ErrNoRows) {
		db.Close()
		return nil, "", err
	}
	return db, name, nil
}

// OpenRead opens audit.db for a command on the host next to a running
// gateway: it reads the file and the outbox of st and writes into the
// outbox alone. Without a file it reads the outbox.
func OpenRead(ctx context.Context, st *store.Store, path, node string) (*Log, error) {
	l := ForStore(ctx, st, node)
	l.path = path
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return l, nil
		}
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return nil, err
	}
	l.db = db
	return l, nil
}

// Close closes audit.db.
func (l *Log) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	return l.db.Close()
}

func (l *Log) now() time.Time {
	if l.opts.Now != nil {
		return l.opts.Now().UTC()
	}
	return time.Now().UTC()
}

// Node is the node name of this log's entries.
func (l *Log) Node() string { return *l.node.Load() }

// Name is the name of the log this node writes.
func (l *Log) Name(ctx context.Context) string {
	n, _ := l.st.AuditLogName(ctx)
	return n
}

// keepDays is audit.keep_days, 0 for unlimited.
func (l *Log) keepDays() int64 {
	if l.opts.KeepDays == nil {
		return 365
	}
	return l.opts.KeepDays()
}

// highest returns the highest number of each letter the file holds of a
// log.
func (l *Log) highest(ctx context.Context, name string) (map[string]int64, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT id FROM entries WHERE id >= ? AND id < ?`, name+"-", name+".")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		_, letter, n := splitID(id)
		out[letter] = max(out[letter], n)
	}
	return out, rows.Err()
}

// splitID splits <log>-<letter>-<number>.
func splitID(id string) (log, letter string, n int64) {
	p := strings.SplitN(id, "-", 3)
	if len(p) != 3 {
		return "", "", 0
	}
	n, _ = strconv.ParseInt(p[2], 10, 64)
	return p[0], p[1], n
}

// SizeBytes is the size of audit.db with its WAL.
func (l *Log) SizeBytes() int64 {
	if l == nil || l.path == "" {
		return 0
	}
	var n int64
	for _, p := range []string{l.path, l.path + "-wal"} {
		if fi, err := os.Stat(p); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// Counters of the log, for the metrics and the status.
type Counters struct {
	// StreamFailed: lines the copy (audit.stream) could not take.
	StreamFailed int64
	// Differing: entries of members with another content under a known id.
	Differing int64
	// Skipped: entries of members that did not pass the check.
	Skipped int64
}

// Counters returns the counters of the log.
func (l *Log) Counters() Counters {
	if l == nil {
		return Counters{}
	}
	return Counters{StreamFailed: l.streamFailed.Load(), Differing: l.differing.Load(), Skipped: l.skipped.Load()}
}
