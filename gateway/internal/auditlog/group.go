package auditlog

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/contract/jsonx"
)

// The audit log in a group (contracts/audit.md section 9): members ask for
// entries and hand on all they hold, also those of other nodes, so a node
// that joins later has the history of nodes that are gone.

// AskBatch is the most entries one answer carries.
const AskBatch = 500

// Epoch names this audit.db: a member that sees another one starts to ask
// from the beginning.
func (l *Log) Epoch(ctx context.Context) (string, error) {
	var v string
	err := l.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'epoch'`).Scan(&v)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	v = hex.EncodeToString(b[:])
	if _, err := l.db.ExecContext(ctx, `INSERT OR IGNORE INTO meta(k, v) VALUES('epoch', ?)`, v); err != nil {
		return "", err
	}
	err = l.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'epoch'`).Scan(&v)
	return v, err
}

// After returns the entries this node stored after the place `after`, in the
// order it stored them, at most AskBatch, and the place of the last one. A
// refused call that still counts is not handed on; it gets a later place
// when its minute is over.
func (l *Log) After(ctx context.Context, after int64) (rows []json.RawMessage, next int64, err error) {
	next = after
	if l == nil || l.db == nil {
		return nil, next, nil
	}
	_ = l.Move(ctx)
	rs, err := l.db.QueryContext(ctx, `SELECT seq, body FROM entries WHERE seq > ? AND open = 0 ORDER BY seq LIMIT ?`, after, AskBatch)
	if err != nil {
		return nil, next, err
	}
	defer rs.Close()
	size := 0
	for rs.Next() {
		var seq int64
		var body []byte
		if err := rs.Scan(&seq, &body); err != nil {
			return nil, after, err
		}
		// An answer of the mesh is bounded; an entry is at most 64 KiB.
		if size += len(body); size > 4<<20 && len(rows) > 0 {
			break
		}
		rows = append(rows, json.RawMessage(body))
		next = seq
	}
	return rows, next, rs.Err()
}

// Head is the place of the newest entry this node hands on, 0 without one.
// It moves when an entry is stored, whoever wrote it.
func (l *Log) Head(ctx context.Context) (int64, error) {
	if l == nil || l.db == nil {
		return 0, nil
	}
	var seq int64
	// Backwards from the end: the entries that still count are few.
	err := l.db.QueryRowContext(ctx, `SELECT seq FROM entries WHERE open = 0 ORDER BY seq DESC LIMIT 1`).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}

// OwnSince reports whether this node stored an entry of its own after the
// place `after`: news for the members. An entry a member handed over is none,
// every member that holds it says so itself.
func (l *Log) OwnSince(ctx context.Context, after int64) (bool, error) {
	if l == nil || l.db == nil {
		return false, nil
	}
	var one int
	err := l.db.QueryRowContext(ctx, `SELECT 1 FROM entries WHERE seq > ? AND own = 1 AND open = 0 LIMIT 1`, after).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Import stores entries a member handed over and returns how many were new.
// An entry is checked as the contract says for a member (audit.ParseEntry):
// an action a later build knows is taken, a value this build may not record
// is taken out. One that does not pass is counted and skipped, one that is
// too old here is skipped, an id this node holds is not stored again.
func (l *Log) Import(ctx context.Context, rows []json.RawMessage) (int, error) {
	if l == nil || l.db == nil || l.kick == nil || len(rows) == 0 {
		return 0, nil
	}
	now := l.now()
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	taken := 0
	for _, raw := range rows {
		e, res, err := audit.ParseEntry(raw, false)
		if err != nil {
			l.skipped.Add(1)
			continue
		}
		c := columns(e)
		if l.tooOld(c.class, c.timeMS, now) {
			continue
		}
		body := []byte(raw)
		if res.Stripped > 0 {
			if body, err = marshal(e); err != nil {
				l.skipped.Add(1)
				continue
			}
		}
		fresh, err := insert(ctx, tx, c, body, false, false, now)
		if err != nil {
			return 0, err
		}
		if fresh {
			taken++
			continue
		}
		var have []byte
		if err := tx.QueryRowContext(ctx, `SELECT body FROM entries WHERE id = ?`, c.id).Scan(&have); err == nil && !sameEntry(have, body) {
			l.differing.Add(1)
			if l.opts.Log != nil {
				l.opts.Log.Warn("audit log: a member handed over another content under an id this node holds; not taken", "id", c.id)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return taken, nil
}

// sameEntry compares two entries by what they say, not by their bytes.
func sameEntry(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	x, err1 := jsonx.ParseObject(a)
	y, err2 := jsonx.ParseObject(b)
	if err1 != nil || err2 != nil {
		return false
	}
	p, _ := json.Marshal(x)
	q, _ := json.Marshal(y)
	return bytes.Equal(p, q)
}
