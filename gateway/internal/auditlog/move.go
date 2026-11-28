package auditlog

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/contract/jsonx"
)

// cols are the columns of an entry in audit.db, taken from its body.
type cols struct {
	id, class, action, way, actor, session, subject, subjectID, website, event, incident string
	timeMS                                                                               int64
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func obj(m map[string]any, k string) map[string]any { o, _ := m[k].(map[string]any); return o }

func columns(e map[string]any) cols {
	c := cols{id: str(e, "id"), class: str(e, "class"), action: str(e, "action")}
	c.way, _, _ = strings.Cut(str(e, "operation"), ":")
	actor, subject, cause := obj(e, "actor"), obj(e, "subject"), obj(e, "cause")
	c.actor, c.session = str(actor, "id"), str(actor, "session")
	c.subject, c.subjectID = str(subject, "kind"), str(subject, "id")
	c.website = str(e, "website")
	c.event, c.incident = str(cause, "event"), str(cause, "incident")
	if c.incident == "" && c.subject == "block" {
		c.incident = c.subjectID
	}
	if t, err := time.Parse(timeFormat, str(e, "time")); err == nil {
		c.timeMS = t.UnixMilli()
	}
	return c
}

const insertEntry = `INSERT OR IGNORE INTO entries(id, t_ms, time_ms, class, action, way, actor, session, subject, subject_id, website, event, incident, own, open, body)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// insert stores an entry; false when the id is there already. The age of
// an entry counts from its time, at the latest from now.
func insert(ctx context.Context, x execer, c cols, body []byte, own, open bool, now time.Time) (bool, error) {
	r, err := x.ExecContext(ctx, insertEntry, c.id, min(c.timeMS, now.UnixMilli()), c.timeMS, c.class, c.action, c.way, c.actor, c.session,
		c.subject, c.subjectID, c.website, c.event, c.incident, own, open, body)
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n > 0, nil
}

// moveBatch entries leave the outbox in one transaction of audit.db.
const moveBatch = 200

// Move moves the entries of the outbox to audit.db and deletes them from
// the outbox afterwards. The id makes a second move harmless. A command on
// the host moves nothing.
func (l *Log) Move(ctx context.Context) error {
	if l == nil || l.db == nil || l.kick == nil {
		return nil
	}
	l.moveMu.Lock()
	defer l.moveMu.Unlock()
	err := l.move(ctx)
	if err != nil {
		l.moveErr.Store(&err)
	} else {
		l.moveErr.Store(nil)
	}
	return err
}

func (l *Log) move(ctx context.Context) error {
	for {
		rows, err := l.st.AuditOutbox(ctx, moveBatch)
		if err != nil || len(rows) == 0 {
			return err
		}
		now := l.now()
		tx, err := l.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var ids []string
		var lines [][]byte
		for _, r := range rows {
			ids = append(ids, r.ID)
			if l.tooOld(r.Class, r.TimeMS, now) {
				continue
			}
			e, err := jsonx.ParseObject(r.Body)
			if err != nil {
				// Written by this node and checked then; never expected.
				if l.opts.Log != nil {
					l.opts.Log.Error("audit log: an entry of the outbox is not readable and is dropped", "id", r.ID, "err", err)
				}
				continue
			}
			fresh, err := insert(ctx, tx, columns(e), r.Body, true, false, now)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			if fresh {
				lines = append(lines, r.Body)
				continue
			}
			// The id is there: moved before (a crash between copy and
			// delete), or another entry under the same id, which is lost.
			var have []byte
			if err := tx.QueryRowContext(ctx, `SELECT body FROM entries WHERE id = ?`, r.ID).Scan(&have); err == nil && !bytes.Equal(have, r.Body) {
				l.differing.Add(1)
				if l.opts.Log != nil {
					l.opts.Log.Error("audit log: the file holds another entry under the id of a new one; the new one is lost", "id", r.ID)
				}
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		l.copyOut(lines)
		if err := l.st.DeleteAuditOutbox(ctx, ids); err != nil {
			return err
		}
		if len(rows) < moveBatch {
			return nil
		}
	}
}

// copyOut writes entries to the copy (audit.stream), one JSON line each. A
// line that cannot be written is counted; it never holds a change back.
func (l *Log) copyOut(lines [][]byte) {
	if l.opts.Stream == nil || len(lines) == 0 {
		return
	}
	l.streamMu.Lock()
	defer l.streamMu.Unlock()
	for _, b := range lines {
		// One write per line, so two writers never mix their lines. The
		// entry is at most audit.MaxEntryBytes.
		line := append(bytes.Clone(b), '\n')
		if _, err := l.opts.Stream.Write(line); err != nil {
			l.streamFailed.Add(1)
		}
	}
}

// Run moves the outbox when an entry was written, tries again every ten
// seconds, and writes the counts of refused calls. It returns when ctx ends,
// after a last move.
func (l *Log) Run(ctx context.Context) {
	if l == nil || l.db == nil || l.kick == nil {
		return
	}
	t := time.NewTicker(refusedFlush)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			l.flushRefused(bg, true)
			_ = l.Move(bg)
			cancel()
			return
		case <-l.kick:
			if err := l.Move(ctx); err != nil && l.opts.Log != nil && ctx.Err() == nil {
				l.opts.Log.Warn("audit log: entries wait in schild.db, audit.db could not be written", "err", err)
			}
		case <-l.refused.wake:
			l.flushRefused(ctx, false)
		case <-t.C:
			l.flushRefused(ctx, false)
			_ = l.Move(ctx)
		}
	}
}

// Status of the log for the hints of the dashboard.
type Status struct {
	// Waiting entries in the outbox, and Stuck: they wait because audit.db
	// cannot be written (hint audit_stuck).
	Waiting int
	Stuck   bool
	// SizeBytes of audit.db; Large from SizeHintBytes on (hint audit_size).
	SizeBytes int64
	Large     bool
	// Entries30d and TopActor (a token id, a way) of the last 30 days,
	// filled when Large.
	Entries30d int64
	TopActor   string
}

// Status reads the state of the log.
func (l *Log) Status(ctx context.Context) Status {
	var s Status
	if l == nil {
		return s
	}
	n, oldest, err := l.st.AuditOutboxLen(ctx)
	if err == nil {
		s.Waiting = n
		s.Stuck = n > 0 && l.moveErr.Load() != nil && l.now().Sub(time.UnixMilli(oldest)) > StuckAfter
	}
	s.SizeBytes = l.SizeBytes()
	s.Large = s.SizeBytes >= SizeHintBytes
	if s.Large && l.db != nil {
		since := l.now().Add(-30 * 24 * time.Hour).UnixMilli()
		_ = l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entries WHERE time_ms >= ?`, since).Scan(&s.Entries30d)
		var actor, way string
		if err := l.db.QueryRowContext(ctx, `SELECT actor, way FROM entries WHERE time_ms >= ? GROUP BY actor, way ORDER BY COUNT(*) DESC LIMIT 1`, since).Scan(&actor, &way); err == nil {
			s.TopActor = actor
			if actor == "" {
				s.TopActor = way
			}
		}
	}
	return s
}

// tooOld reports whether an entry of a class and time is past what this
// node keeps (contracts/audit.md section 6, without the caps of rows).
func (l *Log) tooOld(class string, timeMS int64, now time.Time) bool {
	return len(audit.Delete([]audit.Row{{ID: "x", Class: class, T: timeMS}}, now.UnixMilli(), l.keepDays(), audit.MaxAccessRows)) > 0
}

// marshal is the JSON of an entry as this node stores one it did not write.
func marshal(e map[string]any) ([]byte, error) { return json.Marshal(e) }
