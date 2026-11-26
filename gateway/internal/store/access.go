package store

import (
	"context"
	"errors"
	"time"
)

// DashboardSetupKey keeps the SHA-256 of a pending one-time setup code from
// `schild dashboard reset-password` (MVP-09 addendum, D38), so the code
// printed on the host still works after a restart. The code itself is never
// stored.
const DashboardSetupKey = "dashboard_setup_code_v1"

// AccessReset is the result of ResetDashboardAccess.
type AccessReset struct {
	UsersRemoved  int
	SessionsEnded int // sessions that had not expired yet
}

// ResetDashboardAccess removes every dashboard user and session and stores
// setupHash as the pending setup code, in one transaction. audit, when set,
// builds the audit event from the counts; it is written in the same
// transaction (and gets its sequence number). Events, settings, blocks and
// everything else stay as they are.
func (s *Store) ResetDashboardAccess(ctx context.Context, setupHash []byte, now time.Time, audit func(AccessReset) (*EventRow, error)) (AccessReset, error) {
	var res AccessReset
	if len(setupHash) == 0 {
		return res, errors.New("store: reset without a setup code hash")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE expires_ms > ?", ms(now)).Scan(&res.SessionsEnded); err != nil {
		return res, err
	}
	r, err := tx.ExecContext(ctx, "DELETE FROM users")
	if err != nil {
		return res, err
	}
	n, _ := r.RowsAffected()
	res.UsersRemoved = int(n)
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return res, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO kv(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", DashboardSetupKey, setupHash); err != nil {
		return res, err
	}
	if audit != nil {
		row, err := audit(res)
		if err != nil {
			return res, err
		}
		written, err := insertEventsTx(ctx, tx, []*EventRow{row})
		if err != nil {
			return res, err
		}
		if err := tx.Commit(); err != nil {
			return res, err
		}
		s.written.Add(written)
		return res, nil
	}
	return res, tx.Commit()
}

// PendingSetupHash returns the hash stored by ResetDashboardAccess, nil when
// none is pending.
func (s *Store) PendingSetupHash(ctx context.Context) []byte {
	v, err := s.Get(ctx, DashboardSetupKey)
	if err != nil || len(v) == 0 {
		return nil
	}
	return v
}

// ClearPendingSetup removes the pending setup code hash (it works once).
func (s *Store) ClearPendingSetup(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM kv WHERE k = ?", DashboardSetupKey)
	return err
}

// ClearPendingSetupWithUsers removes the hash only while there are users: one
// statement, so it never takes the hash of a reset that just removed them.
func (s *Store) ClearPendingSetupWithUsers(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM kv WHERE k = ? AND EXISTS (SELECT 1 FROM users)", DashboardSetupKey)
	return err
}
