package store

import (
	"context"
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
// Migration 2 also marks who decided a kept block (kept_blocks.own): 1 this
// gateway, 0 another node of its group (the block was taken from the
// group). A node writes only its own decisions to its group. A row a build
// before the mark kept does not say (-1) and counts as this gateway's own.

const outboxMigration = `
CREATE TABLE cluster_outbox (
  incident TEXT PRIMARY KEY,
  at_ms INTEGER NOT NULL
);
ALTER TABLE kept_blocks ADD COLUMN own INTEGER NOT NULL DEFAULT -1;
`

// Lift is one lift that waits for the group.
type Lift struct {
	Incident string
	At       time.Time
}

// outbox is the state of the lifts in memory: whether this gateway notes
// any (a single gateway has no group to tell and notes none), and which
// incidents wait, so the node asks without a look into the database.
//
// Two locks, and one order. wmu is taken by whoever changes the table
// cluster_outbox, before its transaction begins and until the change is in
// memory: the paths that note a lift, the removal of a written one, the
// first read. The database opens a write transaction with the write lock
// (_txlock=immediate), so the order is always wmu, then the database, then
// mu; nobody holds the database's write lock and waits for wmu. mu guards
// the map alone and is never held across a statement, so LiftNoted and
// LiftsWaiting, which the request path and the round call, never wait
// behind the database. Nothing here takes a lock of another package.
type outbox struct {
	on  atomic.Bool
	wmu sync.Mutex
	mu  sync.Mutex
	// noted, under mu: the incidents whose lift waits.
	noted map[string]struct{}
	// loaded, under mu: noted holds what waited before the start too.
	loaded bool
}

// ShareLifts makes the store note lifts from now on: the gateway is a node
// of a group. It cannot fail, so no lift of a node is lost because this
// call was. What waited before the start is read with it, and when that
// read fails, again with every later look of the round until it succeeds
// (WaitingLifts).
func (s *Store) ShareLifts() {
	s.outbox.on.Store(true)
	_ = s.loadLifts(context.Background())
}

// loadLifts reads the lifts that waited before the start, once.
func (s *Store) loadLifts(ctx context.Context) error {
	s.outbox.wmu.Lock()
	defer s.outbox.wmu.Unlock()
	s.outbox.mu.Lock()
	loaded := s.outbox.loaded
	s.outbox.mu.Unlock()
	if loaded {
		return nil
	}
	rows, err := s.q(ctx).QueryContext(ctx, `SELECT incident FROM cluster_outbox`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.outbox.mu.Lock()
	s.remember(ids)
	s.outbox.loaded = true
	s.outbox.mu.Unlock()
	return nil
}

// remember puts incidents into noted. Called with mu held.
func (s *Store) remember(incidents []string) {
	if s.outbox.noted == nil {
		s.outbox.noted = map[string]struct{}{}
	}
	for _, id := range incidents {
		s.outbox.noted[id] = struct{}{}
	}
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

// LiftNoted reports whether the lift of an incident waits for the group. It
// reads memory alone and waits for no statement: the request path asks when
// a new block draws its number.
func (s *Store) LiftNoted(incident string) bool {
	if !s.outbox.on.Load() {
		return false
	}
	s.outbox.mu.Lock()
	defer s.outbox.mu.Unlock()
	_, ok := s.outbox.noted[incident]
	return ok
}

// noteLiftTx notes a lift in tx. The caller took outbox.wmu before it began
// tx, and commits with commitNoted.
func (s *Store) noteLiftTx(ctx context.Context, tx *txn, incident string, at time.Time) (bool, error) {
	if !s.outbox.on.Load() || incident == "" {
		return false, nil
	}
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO cluster_outbox(incident, at_ms) VALUES(?, ?)`, incident, ms(at))
	return err == nil, err
}

// outboxCommitted, in tests, runs after a transaction that notes lifts is
// committed and before the lifts are in memory.
var outboxCommitted func(s *Store)

// commitNoted commits tx and puts the lifts it noted into memory. The
// caller holds outbox.wmu since before tx began, so this is one step for
// LiftWritten: a lift that is written to the group and removed right after
// the commit would otherwise stay in memory, and the node would look into
// the database for it with every round until its restart.
func (s *Store) commitNoted(tx *txn, incidents []string) error {
	if err := tx.Commit(); err != nil {
		return err
	}
	noted := func() {
		if outboxCommitted != nil {
			outboxCommitted(s)
		}
		s.outbox.mu.Lock()
		s.remember(incidents)
		s.outbox.mu.Unlock()
	}
	if tx.nested() {
		// A savepoint of InTx, which holds outbox.wmu until its commit.
		tx.st.after = append(tx.st.after, noted)
		return nil
	}
	noted()
	return nil
}

// lockLifts takes outbox.wmu for a path that notes a lift and returns the
// unlock. In a transaction of InTx the lock is held already.
func (s *Store) lockLifts(ctx context.Context) func() {
	if txOf(ctx) != nil {
		return func() {}
	}
	s.outbox.wmu.Lock()
	return s.outbox.wmu.Unlock
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
	defer s.lockLifts(ctx)()
	tx, err := s.begin(ctx)
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
	if err := s.commitNoted(tx, noted); err != nil {
		return err
	}
	if changed > 0 {
		s.noteOwn(ctx)
	}
	return nil
}

// Unblock is the unblock of an incident a person made.
type Unblock struct {
	Incident string
	At       time.Time
	// AllowEntry is the allowlist entry made with the unblock ("" none).
	AllowEntry string
	// Live: the block of the incident runs, on this node or in the group,
	// although the incident reads unblocked (an allowlist entry ended it
	// for a while). Then the unblock holds whatever the row says.
	Live bool
	// Lift: the incident has a block, so its lift is noted for the group.
	// The incident of a single refused request has none, and no lift.
	Lift bool
	// Others are the incidents of the other blocks the node holds for the
	// same client: a person who releases means the client, so each of them
	// is lifted with this one and stored as unblocked.
	Others []string
}

// MarkUnblockedLift records the unblock a person made, as MarkUnblocked
// does, and notes the lifts for the group in the same transaction. An
// incident that the end of its block marked unblocked already (the
// allowlist entry of the same request ended the block first, Sink.Ended of
// the engine) takes the reference to that entry instead, as SetUnblockRefs
// does. ErrNotFound: the incident is not blocked, takes no reference and
// is not live. The reference to the allowlist entry is for the incident
// that was clicked alone.
func (s *Store) MarkUnblockedLift(ctx context.Context, u Unblock) error {
	defer s.lockLifts(ctx)()
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE incidents SET status = 'unblocked', unblocked_ms = ?, allowlist_entry = ? WHERE incident = ? AND status = 'blocked'`,
		ms(u.At), u.AllowEntry, u.Incident)
	if err != nil {
		return err
	}
	marked, _ := r.RowsAffected()
	if marked == 0 {
		var refs int64
		if u.AllowEntry != "" {
			r, err = tx.ExecContext(ctx, `UPDATE incidents SET allowlist_entry = ? WHERE incident = ? AND status = 'unblocked' AND allowlist_entry = ''`, u.AllowEntry, u.Incident)
			if err != nil {
				return err
			}
			refs, _ = r.RowsAffected()
		}
		if refs == 0 && !u.Live {
			return ErrNotFound
		}
	}
	var noted []string
	if u.Lift {
		for i, incident := range append([]string{u.Incident}, u.Others...) {
			if i > 0 && incident != u.Incident {
				r, err := tx.ExecContext(ctx, `UPDATE incidents SET status = 'unblocked', unblocked_ms = ? WHERE incident = ? AND status = 'blocked'`, ms(u.At), incident)
				if err != nil {
					return err
				}
				n, _ := r.RowsAffected()
				marked += n
			}
			ok, err := s.noteLiftTx(ctx, tx, incident, u.At)
			if err != nil {
				return err
			}
			if ok {
				noted = append(noted, incident)
			}
		}
	}
	if err := s.commitNoted(tx, noted); err != nil {
		return err
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
	rows, err := s.q(ctx).QueryContext(ctx, `SELECT incident, at_ms FROM cluster_outbox ORDER BY at_ms, incident LIMIT ?`, limit)
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
	s.outbox.wmu.Lock()
	defer s.outbox.wmu.Unlock()
	if _, err := s.q(ctx).ExecContext(ctx, `DELETE FROM cluster_outbox WHERE incident = ?`, incident); err != nil {
		return err
	}
	s.outbox.mu.Lock()
	delete(s.outbox.noted, incident)
	s.outbox.mu.Unlock()
	return nil
}
