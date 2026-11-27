package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// The audit log in schild.db (contracts/audit.md section 4, MVP-36). An
// entry is written into audit_outbox in the transaction of its change; the
// running gateway moves it to audit.db afterwards (internal/auditlog).
// audit_state holds the name of the log and the numbers of its entries,
// audit_config a keyed digest per key of the configuration, so config.apply
// names the keys that changed without holding a value.

const auditMigration = `
CREATE TABLE audit_outbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  time_ms INTEGER NOT NULL,
  class TEXT NOT NULL,
  body BLOB NOT NULL
);
CREATE TABLE audit_state (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE audit_config (
  source TEXT NOT NULL,
  k TEXT NOT NULL,
  digest TEXT NOT NULL,
  PRIMARY KEY (source, k)
);
`

// Keys of audit_state.
const (
	auditLogKey = "log"
	// AuditHadFile: this node had an audit.db once ("1").
	AuditHadFile = "had_file"
	// AuditConfigKey: the key of the digests in audit_config, hex.
	AuditConfigKey = "config_key"
)

// AuditRow is an entry in the outbox.
type AuditRow struct {
	Seq    int64
	ID     string
	TimeMS int64
	Class  string
	Body   []byte
}

func newLogName() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// AuditState returns a value of audit_state, "" when it is not there.
func (s *Store) AuditState(ctx context.Context, k string) (string, error) {
	var v string
	err := s.q(ctx).QueryRowContext(ctx, `SELECT v FROM audit_state WHERE k = ?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetAuditState stores a value of audit_state.
func (s *Store) SetAuditState(ctx context.Context, k, v string) error {
	_, err := s.q(ctx).ExecContext(ctx, `INSERT INTO audit_state(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}

// AuditLogName returns the name of the log of this node and draws one when
// there is none yet.
func (s *Store) AuditLogName(ctx context.Context) (string, error) {
	var name string
	err := s.InTx(ctx, func(ctx context.Context) error {
		v, err := s.AuditState(ctx, auditLogKey)
		if err != nil {
			return err
		}
		if v == "" {
			v = newLogName()
			if err := s.SetAuditState(ctx, auditLogKey, v); err != nil {
				return err
			}
		}
		name = v
		return nil
	})
	return name, err
}

// NewAuditLog starts a log under a new name: the numbers count from 1
// again. What waits in the outbox keeps its id.
func (s *Store) NewAuditLog(ctx context.Context) (string, error) {
	name := newLogName()
	err := s.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.q(ctx).ExecContext(ctx, `DELETE FROM audit_state WHERE k LIKE 'n\_%' ESCAPE '\'`); err != nil {
			return err
		}
		return s.SetAuditState(ctx, auditLogKey, name)
	})
	return name, err
}

// AdoptAuditLog continues the log of an audit.db this schild.db does not
// know (a new schild.db next to an old audit.db): its name, and the numbers
// after the highest ones the file holds.
func (s *Store) AdoptAuditLog(ctx context.Context, name string, numbers map[string]int64) error {
	return s.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.q(ctx).ExecContext(ctx, `DELETE FROM audit_state WHERE k LIKE 'n\_%' ESCAPE '\'`); err != nil {
			return err
		}
		for letter, n := range numbers {
			if err := s.SetAuditState(ctx, "n_"+letter, strconv.FormatInt(n, 10)); err != nil {
				return err
			}
		}
		return s.SetAuditState(ctx, auditLogKey, name)
	})
}

// NextAuditID draws the id of the next entry of a letter (k, a, r):
// <log>-<letter>-<number>, the number counted from 1 per log and letter.
// Called in the transaction that writes the entry, so a change that is
// rolled back leaves no hole.
func (s *Store) NextAuditID(ctx context.Context, letter string) (string, error) {
	var id string
	err := s.InTx(ctx, func(ctx context.Context) error {
		name, err := s.AuditLogName(ctx)
		if err != nil {
			return err
		}
		v, err := s.AuditState(ctx, "n_"+letter)
		if err != nil {
			return err
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		n++
		if err := s.SetAuditState(ctx, "n_"+letter, strconv.FormatInt(n, 10)); err != nil {
			return err
		}
		id = name + "-" + letter + "-" + strconv.FormatInt(n, 10)
		return nil
	})
	return id, err
}

// PutAudit writes an entry into the outbox.
func (s *Store) PutAudit(ctx context.Context, r AuditRow) error {
	_, err := s.q(ctx).ExecContext(ctx, `INSERT INTO audit_outbox(id, time_ms, class, body) VALUES(?, ?, ?, ?)`, r.ID, r.TimeMS, r.Class, r.Body)
	return err
}

// AuditOutbox returns the entries that wait for audit.db, oldest first.
func (s *Store) AuditOutbox(ctx context.Context, limit int) ([]AuditRow, error) {
	rows, err := s.q(ctx).QueryContext(ctx, `SELECT seq, id, time_ms, class, body FROM audit_outbox ORDER BY seq LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.Seq, &r.ID, &r.TimeMS, &r.Class, &r.Body); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AuditOutboxLen returns how many entries wait and the time of the oldest
// (0 without one).
func (s *Store) AuditOutboxLen(ctx context.Context) (n int, oldestMS int64, err error) {
	var oldest sql.NullInt64
	err = s.q(ctx).QueryRowContext(ctx, `SELECT COUNT(*), MIN(time_ms) FROM audit_outbox`).Scan(&n, &oldest)
	return n, oldest.Int64, err
}

// DeleteAuditOutbox removes entries that are in audit.db now, or too old to
// be kept.
func (s *Store) DeleteAuditOutbox(ctx context.Context, ids []string) error {
	for len(ids) > 0 {
		n := min(len(ids), 500)
		args := make([]any, n)
		for i, id := range ids[:n] {
			args[i] = id
		}
		marks := strings.TrimSuffix(strings.Repeat("?,", n), ",")
		if _, err := s.q(ctx).ExecContext(ctx, `DELETE FROM audit_outbox WHERE id IN (`+marks+`)`, args...); err != nil {
			return err
		}
		ids = ids[n:]
	}
	return nil
}

// AuditConfig returns the digests of the configuration of a source
// (schild_yaml, caddyfile) as they were when it was last applied.
func (s *Store) AuditConfig(ctx context.Context, source string) (map[string]string, error) {
	rows, err := s.q(ctx).QueryContext(ctx, `SELECT k, digest FROM audit_config WHERE source = ?`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, d string
		if err := rows.Scan(&k, &d); err != nil {
			return nil, err
		}
		out[k] = d
	}
	return out, rows.Err()
}

// SetAuditConfig replaces the digests of a source.
func (s *Store) SetAuditConfig(ctx context.Context, source string, digests map[string]string) error {
	return s.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.q(ctx).ExecContext(ctx, `DELETE FROM audit_config WHERE source = ?`, source); err != nil {
			return err
		}
		keys := make([]string, 0, len(digests))
		for k := range digests {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, err := s.q(ctx).ExecContext(ctx, `INSERT INTO audit_config(source, k, digest) VALUES(?, ?, ?)`, source, k, digests[k]); err != nil {
				return err
			}
		}
		return nil
	})
}

// ClearAuditConfig forgets the digests of every source: a new log draws a
// new key for them.
func (s *Store) ClearAuditConfig(ctx context.Context) error {
	_, err := s.q(ctx).ExecContext(ctx, `DELETE FROM audit_config`)
	return err
}
