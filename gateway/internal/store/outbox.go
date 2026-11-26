package store

import (
	"context"
	"database/sql"
	"sync/atomic"
	"time"
)

// The lifts a node of a group still owes its group (contracts/cluster.md,
// class lifts; D109). A lift is noted here in the transaction of the change
// that made it, and the node writes it to the group from here until that
// succeeds, also after a restart. A row holds the incident number and the
// time, no address.

const outboxMigration = `
CREATE TABLE cluster_outbox (
  incident TEXT PRIMARY KEY,
  at_ms INTEGER NOT NULL
);
`

// Lift is one lift that waits for the group.
type Lift struct {
	Incident string
	At       time.Time
}

// outbox is the state of the lifts in memory: whether this gateway notes
// any (a single gateway has no group to tell and notes none), and how many
// wait, so a node with nothing to hand over reads nothing.
type outbox struct {
	on      atomic.Bool
	waiting atomic.Int64
}

// ShareLifts makes the store note lifts from now on: the gateway is a node
// of a group. It counts what waits from before the start.
func (s *Store) ShareLifts(ctx context.Context) error {
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cluster_outbox`).Scan(&n); err != nil {
		return err
	}
	s.outbox.waiting.Store(n)
	s.outbox.on.Store(true)
	return nil
}

// LiftsWaiting reports whether a lift waits for the group, without a look
// into the database.
func (s *Store) LiftsWaiting() bool { return s.outbox.waiting.Load() > 0 }

func (s *Store) noteLiftTx(ctx context.Context, tx *sql.Tx, incident string, at time.Time) (added int64, err error) {
	if !s.outbox.on.Load() || incident == "" {
		return 0, nil
	}
	r, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO cluster_outbox(incident, at_ms) VALUES(?, ?)`, incident, ms(at))
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

// NoteLifts notes the lift of each incident for the group and stores the
// incidents this node holds of them as unblocked, in one transaction: the
// release of an address, the lift of an agent. An incident the node does
// not hold is lifted all the same; the group knows a block by its number.
// A single gateway notes nothing and changes nothing here: the end of its
// blocks reaches its incidents as before (Sink.Ended of the engine).
func (s *Store) NoteLifts(ctx context.Context, at time.Time, incidents ...string) error {
	if len(incidents) == 0 || !s.outbox.on.Load() {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var added, changed int64
	for _, id := range incidents {
		r, err := tx.ExecContext(ctx, `UPDATE incidents SET status = 'unblocked', unblocked_ms = ? WHERE incident = ? AND status = 'blocked'`, ms(at), id)
		if err != nil {
			return err
		}
		n, _ := r.RowsAffected()
		changed += n
		if n, err = s.noteLiftTx(ctx, tx, id, at); err != nil {
			return err
		}
		added += n
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.outbox.waiting.Add(added)
	if changed > 0 {
		s.noteOwn(ctx)
	}
	return nil
}

// MarkUnblockedLift is MarkUnblocked for the unblock a person made, and
// notes the lift of the incident for the group in the same transaction.
func (s *Store) MarkUnblockedLift(ctx context.Context, id string, at time.Time, allowEntry string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE incidents SET status = 'unblocked', unblocked_ms = ?, allowlist_entry = ? WHERE incident = ? AND status = 'blocked'`,
		ms(at), allowEntry, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	added, err := s.noteLiftTx(ctx, tx, id, at)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.outbox.waiting.Add(added)
	s.noteOwn(ctx)
	return nil
}

// LiftNoted reports whether the lift of an incident waits for the group.
func (s *Store) LiftNoted(ctx context.Context, incident string) bool {
	if !s.LiftsWaiting() {
		return false
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM cluster_outbox WHERE incident = ?`, incident).Scan(&n)
	return err == nil
}

// WaitingLifts returns the lifts that wait, oldest first, at most limit.
func (s *Store) WaitingLifts(ctx context.Context, limit int) ([]Lift, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT incident, at_ms FROM cluster_outbox ORDER BY at_ms, incident LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Lift
	for rows.Next() {
		var l Lift
		var at int64
		if err := rows.Scan(&l.Incident, &at); err != nil {
			return nil, err
		}
		l.At = time.UnixMilli(at).UTC()
		out = append(out, l)
	}
	return out, rows.Err()
}

// LiftWritten removes a lift the group holds now.
func (s *Store) LiftWritten(ctx context.Context, incident string) error {
	r, err := s.db.ExecContext(ctx, `DELETE FROM cluster_outbox WHERE incident = ?`, incident)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	s.outbox.waiting.Add(-n)
	return nil
}
