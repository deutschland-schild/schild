package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
)

// A change and its audit entry are one transaction of schild.db
// (contracts/audit.md section 4). InTx opens it and hands it on in the
// context: every method of the store that gets this context works in the
// transaction, and a method that opens a transaction of its own gets a
// savepoint in it instead.
//
// Locks. InTx takes outbox.wmu before the transaction begins, as every path
// that notes a lift does (outbox.go), so the order stays wmu, then the
// database. Inside f only the store is called: code that takes a lock of
// another package belongs around InTx, never into it, or a writer that
// holds that lock and waits for the database would wait for f.

type txKey struct{}

// txState is the transaction a context carries.
type txState struct {
	tx *sql.Tx
	// sp numbers the savepoints.
	sp int
	// after run once the transaction is committed, in order.
	after []func()
	// done: committed or rolled back; the context is used no more.
	done bool
}

func txOf(ctx context.Context) *txState {
	st, _ := ctx.Value(txKey{}).(*txState)
	if st == nil || st.done {
		return nil
	}
	return st
}

// InTx runs f in one write transaction of schild.db. An error of f rolls
// everything back. A call inside another InTx joins it.
func (s *Store) InTx(ctx context.Context, f func(ctx context.Context) error) error {
	if txOf(ctx) != nil {
		return f(ctx)
	}
	s.outbox.wmu.Lock()
	defer s.outbox.wmu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	st := &txState{tx: tx}
	defer func() {
		if !st.done {
			st.done = true
			_ = tx.Rollback()
		}
	}()
	if err := f(context.WithValue(ctx, txKey{}, st)); err != nil {
		return err
	}
	st.done = true
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, g := range st.after {
		g()
	}
	return nil
}

// AfterCommit runs g once the transaction of ctx is committed, at once
// without one. For what follows a change in memory.
func AfterCommit(ctx context.Context, g func()) {
	if st := txOf(ctx); st != nil {
		st.after = append(st.after, g)
		return
	}
	g()
}

// InTransaction reports whether ctx carries a transaction of InTx.
func InTransaction(ctx context.Context) bool { return txOf(ctx) != nil }

// querier is what a statement runs on: the database or a transaction.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// q is the transaction of ctx, or the database.
func (s *Store) q(ctx context.Context) querier {
	if st := txOf(ctx); st != nil {
		return st.tx
	}
	return s.db
}

// Querier is q for the packages that keep tables of their own in schild.db
// (hosts): db is the handle they hold.
func Querier(ctx context.Context, db *sql.DB) interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
} {
	if st := txOf(ctx); st != nil {
		return st.tx
	}
	return db
}

// txn is a transaction of a method of the store: its own, or a savepoint in
// the transaction of the context.
type txn struct {
	*sql.Tx
	st     *txState
	sp     string
	closed bool
}

// begin opens a transaction, or a savepoint in the one of ctx.
func (s *Store) begin(ctx context.Context) (*txn, error) { return beginOn(ctx, s.db) }

func beginOn(ctx context.Context, db *sql.DB) (*txn, error) {
	if st := txOf(ctx); st != nil {
		st.sp++
		sp := "sp" + strconv.Itoa(st.sp)
		if _, err := st.tx.ExecContext(ctx, "SAVEPOINT "+sp); err != nil {
			return nil, err
		}
		return &txn{Tx: st.tx, st: st, sp: sp}, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &txn{Tx: tx}, nil
}

// Txn is begin for the packages that keep tables of their own in schild.db.
type Txn = txn

// Begin opens a transaction on db, or a savepoint in the one of ctx.
func Begin(ctx context.Context, db *sql.DB) (*Txn, error) { return beginOn(ctx, db) }

// nested reports whether t is a savepoint.
func (t *txn) nested() bool { return t.sp != "" }

// Commit commits the transaction or releases the savepoint.
func (t *txn) Commit() error {
	if !t.nested() {
		return t.Tx.Commit()
	}
	if t.closed {
		return sql.ErrTxDone
	}
	t.closed = true
	_, err := t.Tx.Exec("RELEASE " + t.sp)
	return err
}

// Rollback rolls the transaction back, or what happened since the
// savepoint. After Commit it does nothing.
func (t *txn) Rollback() error {
	if !t.nested() {
		return t.Tx.Rollback()
	}
	if t.closed || t.st.done {
		return nil
	}
	t.closed = true
	if _, err := t.Tx.Exec("ROLLBACK TO " + t.sp); err != nil {
		return err
	}
	_, err := t.Tx.Exec("RELEASE " + t.sp)
	return err
}

// Change is one write of a value the store keeps under a key: a kv value
// (Key is its key) or a rule decision (Key is RuleDecisionKey).
type Change struct {
	Key string
	// Old and New are the value before and after; nil: not there.
	Old, New []byte
}

type hookKey struct{}

// ChangeHook is told a change in the transaction that makes it. Its error
// rolls the change back.
type ChangeHook func(ctx context.Context, c Change) error

// OnChange returns a context whose writes of kv values and rule decisions
// tell hook, each in the transaction of the write: what the hook writes with
// the context it gets (an audit entry) is committed with the change or not
// at all. The code between the caller and the store needs no change and
// holds its own locks as before: the transaction is around the one write.
func OnChange(ctx context.Context, hook ChangeHook) context.Context {
	return context.WithValue(ctx, hookKey{}, hook)
}

func hookOf(ctx context.Context) ChangeHook {
	h, _ := ctx.Value(hookKey{}).(ChangeHook)
	return h
}

// changed runs a write of a kv value and the hook of ctx in one
// transaction.
func (s *Store) changed(ctx context.Context, k string, v []byte, write func(context.Context) error) error {
	hook := hookOf(ctx)
	return s.InTx(ctx, func(ctx context.Context) error {
		old, err := s.Get(ctx, k)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err := write(ctx); err != nil {
			return err
		}
		return hook(ctx, Change{Key: k, Old: old, New: v})
	})
}
