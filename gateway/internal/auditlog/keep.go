package auditlog

import (
	"context"

	"github.com/deutschland-schild/schild/contract/audit"
)

const dayMS = int64(24 * 3600 * 1000)

// Retain deletes what is past its age (contracts/audit.md section 6), in
// audit.db and in the outbox. It is audit.Delete in SQL: changes,
// credentials and privacy entries by audit.keep_days alone; sign-ins and
// refused calls after AccessDays or audit.keep_days if that is shorter, and
// the oldest beyond MaxAccessRows of each. Nothing else removes an entry.
// It returns how many entries it deleted.
func (l *Log) Retain(ctx context.Context) (int64, error) {
	if l == nil || l.db == nil || l.kick == nil {
		return 0, nil
	}
	now := l.now()
	keep := l.keepDays()
	access := int64(audit.AccessDays)
	if keep > 0 && keep < access {
		access = keep
	}
	var deleted int64
	count := func(r interface{ RowsAffected() (int64, error) }) {
		n, _ := r.RowsAffected()
		deleted += n
	}
	if keep > 0 {
		r, err := l.db.ExecContext(ctx, `DELETE FROM entries WHERE class IN ('change', 'credential', 'privacy') AND t_ms <= ?`, now.UnixMilli()-keep*dayMS)
		if err != nil {
			return deleted, err
		}
		count(r)
	}
	for _, class := range []string{audit.ClassAccess, audit.ClassRefused} {
		r, err := l.db.ExecContext(ctx, `DELETE FROM entries WHERE class = ? AND t_ms <= ? AND open = 0`, class, now.UnixMilli()-access*dayMS)
		if err != nil {
			return deleted, err
		}
		count(r)
		var n int64
		if err := l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entries WHERE class = ?`, class).Scan(&n); err != nil {
			return deleted, err
		}
		if over := n - audit.MaxAccessRows; over > 0 {
			r, err := l.db.ExecContext(ctx, `DELETE FROM entries WHERE seq IN (SELECT seq FROM entries WHERE class = ? AND open = 0 ORDER BY t_ms, id LIMIT ?)`, class, over)
			if err != nil {
				return deleted, err
			}
			count(r)
		}
	}
	// The outbox: what waits there and is too old never reaches the file.
	waiting, err := l.st.AuditOutbox(ctx, 100000)
	if err != nil {
		return deleted, err
	}
	var old []string
	for _, r := range waiting {
		if l.tooOld(r.Class, r.TimeMS, now) {
			old = append(old, r.ID)
		}
	}
	if len(old) > 0 {
		if err := l.st.DeleteAuditOutbox(ctx, old); err != nil {
			return deleted, err
		}
		deleted += int64(len(old))
	}
	if deleted > 0 {
		_, _ = l.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	return deleted, nil
}
