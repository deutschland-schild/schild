package store

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"time"
)

// The lifts a node of a group still owes its group (contracts/cluster.md,
// class lifts; D109). A lift is noted here in the transaction of the change
// that made it, and the node writes it to the group from here until that
// succeeds, also after a restart. A row holds the incident number and the
// time, no address.
//
// Migration 2 also marks the kept blocks this node decided itself
// (kept_blocks.own): a node writes only its own decisions to its group, and
// a block it took from the group and keeps over a restart is none. A row of
// a build before the mark is not own.

const outboxMigration = `
CREATE TABLE cluster_outbox (
  incident TEXT PRIMARY KEY,
  at_ms INTEGER NOT NULL
);
ALTER TABLE kept_blocks ADD COLUMN own INTEGER NOT NULL DEFAULT 0;
`

// Lift is one lift that waits for the group.
type Lift struct {
	Incident string
	At       time.Time
}

// outbox is the state of the lifts in memory: whether this gateway notes
// any (a single gateway has no group to tell and notes none), and which
// incidents wait, so the node asks without a look into the database.
type outbox struct {
	on    atomic.Bool
	mu    sync.Mutex
	noted map[string]struct{}
	// loaded: noted holds what waited in the database before the start too.
	loaded bool
}

// ShareLifts makes the store note lifts from now on: the gateway is a node
// of a group. It cannot fail, so no lift of a node is lost because this
// call was. What waited before the start is read with it, and when that
// read fails, again with every later look until it succeeds (loadLifts).
func (s *Store) ShareLifts() {
	s.outbox.on.Store(true)
	_ = s.loadLifts(context.Background())
}

// loadLifts reads the lifts that waited before the start, once.
func (s *Store) loadLifts(ctx context.Context) error {
	s.outbox.mu.Lock()
	defer s.outbox.mu.Unlock()
	if s.outbox.noted == nil {
		s.outbox.noted = map[string]struct{}{}
	}
	if s.outbox.loaded {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT incident FROM cluster_outbox`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		s.outbox.noted[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.outbox.loaded = true
	return nil
}

// LiftsWaiting reports whether a lift waits for the group, without a look
// into the database. Until the lifts from before the start are read it says
// yes: the look that follows reads them.
func (s *Store) LiftsWaiting() bool {
	if !s.outbox.on.Load() {
		return false
	}
	s.outbox.mu.Lock()
	defer s.outbox.mu.Unlock()
	return !s.outbox.loaded || len(s.outbox.noted) > 0
}

// LiftNoted reports whether the lift of an incident waits for the group,
// without a look into the database once the lifts from before the start
// are read.
func (s *Store) LiftNoted(incident string) bool {
	if !s.outbox.on.Load() {
		return false
	}
	_ = s.loadLifts(context.Background())
	s.outbox.mu.Lock()
	defer s.outbox.mu.Unlock()
	_, ok := s.outbox.noted[incident]
	return ok
}

// noteLiftTx notes a lift in tx; the caller hands the incident to noted
// when tx is committed.
func (s *Store) noteLiftTx(ctx context.Context, tx *sql.Tx, incident string, at time.Time) (bool, error) {
	if !s.outbox.on.Load() || incident == "" {
		return false, nil
	}
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO cluster_outbox(incident, at_ms) VALUES(?, ?)`, incident, ms(at))
	return err == nil, err
}

func (s *Store) liftsNoted(incidents []string) {
	s.outbox.mu.Lock()
	if s.outbox.noted == nil {
		s.outbox.noted = map[string]struct{}{}
	}
	for _, id := range incidents {
		s.outbox.noted[id] = struct{}{}
	}
	s.outbox.mu.Unlock()
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
	var noted []string
	var changed int64
	for _, id := range incidents {
		r, err := tx.ExecContext(ctx, `UPDATE incidents SET status = 'unblocked', unblocked_ms = ? WHERE incident = ? AND status = 'blocked'`, ms(at), id)
		if err != nil {
			return err
		}
		n, _ := r.RowsAffected()
		changed += n
		ok, err := s.noteLiftTx(ctx, tx, id, at)
		if err != nil {
			return err
		}
		if ok {
			noted = append(noted, id)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.liftsNoted(noted)
	if changed > 0 {
		s.noteOwn(ctx)
	}
	return nil
}

// MarkUnblockedLift records the unblock a person made, as MarkUnblocked
// does, and notes the lift of the incident for the group in the same
// transaction. An incident that the end of its block marked unblocked
// already (the allowlist entry of the same request ended the block first,
// Sink.Ended of the engine) takes the reference to that entry instead, as
// SetUnblockRefs does, and its lift is noted too. ErrNotFound: neither.
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
	marked, _ := r.RowsAffected()
	if marked == 0 {
		if allowEntry == "" {
			return ErrNotFound
		}
		r, err = tx.ExecContext(ctx, `UPDATE incidents SET allowlist_entry = ? WHERE incident = ? AND status = 'unblocked' AND allowlist_entry = ''`, allowEntry, id)
		if err != nil {
			return err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return ErrNotFound
		}
	}
	noted, err := s.noteLiftTx(ctx, tx, id, at)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if noted {
		s.liftsNoted([]string{id})
	}
	if marked > 0 {
		s.noteOwn(ctx)
	}
	return nil
}

// WaitingLifts returns the lifts that wait, oldest first, at most limit.
func (s *Store) WaitingLifts(ctx context.Context, limit int) ([]Lift, error) {
	if err := s.loadLifts(ctx); err != nil {
		return nil, err
	}
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

// LiftWritten removes a lift the group holds now, or one that can never be
// written.
func (s *Store) LiftWritten(ctx context.Context, incident string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM cluster_outbox WHERE incident = ?`, incident); err != nil {
		return err
	}
	s.outbox.mu.Lock()
	delete(s.outbox.noted, incident)
	s.outbox.mu.Unlock()
	return nil
}
