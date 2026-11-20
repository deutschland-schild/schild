package monitoring

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// ringStore is <storage.path>/metrics.db (DECISIONS D33): one WITHOUT ROWID
// table per ring, slot = (unix / step) mod slots, a write is INSERT OR
// REPLACE of one row, so the file stops growing once every slot was written.
// Its own file and write lock: never waits for or delays the event store.
type ringStore struct {
	db    *sql.DB
	path  string
	rings []cm.Ring
	// hide is the start (unix) of the 10 min bucket this process is
	// collecting (0: none). Its row is a minute checkpoint, a backup for a
	// hard stop, and reads skip it as they skipped the bucket in progress
	// before checkpoints existed.
	hide atomic.Int64
}

func tableOf(r cm.Resolution) string {
	switch r {
	case cm.Res10s:
		return "ring_10s"
	case cm.Res1m:
		return "ring_1m"
	}
	return "ring_10m"
}

func openRingStore(path string, rings []cm.Ring) (*ringStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := ensurePrivate(path); err != nil {
		return nil, err
	}
	// journal_size_limit: the WAL is truncated to 64 MiB after a checkpoint
	// (D38, storage.WALLimitBytes).
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=journal_size_limit(67108864)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	s := &ringStore{db: db, path: path, rings: rings}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS starts (t INTEGER PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS orderly_starts (t INTEGER PRIMARY KEY) WITHOUT ROWID;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("metrics.db: %w", err)
	}
	for _, r := range rings {
		if err := s.openRing(r); err != nil {
			db.Close()
			return nil, fmt.Errorf("metrics.db: %w", err)
		}
	}
	return s, nil
}

// ensurePrivate creates a missing metrics.db with mode 0600 before SQLite
// opens it (SQLite gives the -wal and -shm files the mode of the database
// file, 0644 minus umask when it creates the file itself) and narrows
// existing files to 0600 (best effort).
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

func (s *ringStore) close() error { return s.db.Close() }

// sizeBytes of metrics.db (main file plus WAL).
func (s *ringStore) sizeBytes() int64 {
	var n int64
	for _, p := range []string{s.path, s.path + "-wal"} {
		if st, err := os.Stat(p); err == nil {
			n += st.Size()
		}
	}
	return n
}

// oldest returns the start of the oldest stored bucket of a ring.
func (s *ringStore) oldest(r cm.Ring, now time.Time) *time.Time {
	var t sql.NullInt64
	_ = s.db.QueryRow(`SELECT MIN(t) FROM `+tableOf(r.Resolution)+` WHERE t >= ?`, r.Oldest(now).Unix()).Scan(&t)
	if !t.Valid {
		return nil
	}
	v := time.Unix(t.Int64, 0).UTC()
	return &v
}

// addStart records a process start (restart markers); at most 100 within
// 90 days are kept. orderly: the process before it stopped in an orderly
// way (or there was none), so the time in between is a restart gap
// (gap_kind restart), not lost data.
func (s *ringStore) addStart(t time.Time, orderly bool) {
	_, _ = s.db.Exec(`INSERT OR IGNORE INTO starts (t) VALUES (?)`, t.Unix())
	if orderly {
		_, _ = s.db.Exec(`INSERT OR IGNORE INTO orderly_starts (t) VALUES (?)`, t.Unix())
	}
	for _, tbl := range []string{"starts", "orderly_starts"} {
		_, _ = s.db.Exec(`DELETE FROM `+tbl+` WHERE t < ? OR t NOT IN (SELECT t FROM `+tbl+` ORDER BY t DESC LIMIT 100)`, t.Add(-90*24*time.Hour).Unix())
	}
}

// Run state (meta key run_state): "running" while a process runs, "clean"
// after an orderly shutdown wrote its buckets. A start that finds
// "running" follows a hard stop (SIGKILL, OOM, crash).
const (
	runStateKey     = "run_state"
	runStateRunning = "running"
	runStateClean   = "clean"
)

// swapRunState returns the stored run state and stores next.
func (s *ringStore) swapRunState(next string) string {
	var v string
	_ = s.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, runStateKey).Scan(&v)
	_, _ = s.db.Exec(`INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)`, runStateKey, next)
	return v
}

// unorderlyStarts reports whether a process start in [from, to] followed a
// hard stop; any reports whether there was a start at all.
func (s *ringStore) unorderlyStarts(from, to time.Time) (unorderly, any bool) {
	var n, bad int64
	_ = s.db.QueryRow(`SELECT COUNT(*), COUNT(*) - (SELECT COUNT(*) FROM orderly_starts WHERE t >= ? AND t <= ?) FROM starts WHERE t >= ? AND t <= ?`,
		from.Unix(), to.Unix(), from.Unix(), to.Unix()).Scan(&n, &bad)
	return bad > 0, n > 0
}

// startTimes lists the process starts in [from, to], oldest first.
func (s *ringStore) startTimes(from, to time.Time) []time.Time {
	q, err := s.db.Query(`SELECT t FROM starts WHERE t >= ? AND t <= ? ORDER BY t LIMIT 100`, from.Unix(), to.Unix())
	if err != nil {
		return nil
	}
	defer q.Close()
	var out []time.Time
	for q.Next() {
		var t int64
		if q.Scan(&t) == nil {
			out = append(out, time.Unix(t, 0).UTC())
		}
	}
	return out
}

// times returns the bucket starts of a ring in [from, to], oldest first
// (the t column only).
func (s *ringStore) times(r cm.Ring, from, to time.Time) []time.Time {
	var out []time.Time
	for _, sr := range r.SlotRanges(from, to) {
		q, err := s.db.Query(`SELECT t FROM `+tableOf(r.Resolution)+` WHERE slot BETWEEN ? AND ? AND t BETWEEN ? AND ?`, sr[0], sr[1], from.Unix(), to.Unix())
		if err != nil {
			return out
		}
		for q.Next() {
			var t int64
			if q.Scan(&t) == nil {
				out = append(out, time.Unix(t, 0).UTC())
			}
		}
		q.Close()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}
