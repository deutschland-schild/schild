package store

import (
	"context"
	"database/sql"
	"sync"
)

// Watcher says whether anything was committed to the database since it
// last looked: by this process or by a command on the host that writes
// into the same file (schild token, schild dashboard reset-password). A
// loop that would otherwise read its values again and again asks it first.
//
// SQLite counts, per connection, the commits of every other connection
// (PRAGMA data_version), so the watcher keeps one connection of the pool
// for itself and never writes through it. A look is one read of the file's
// change counter, no query of a table. It may say yes once too often (a
// connection the pool opens sets its pragmas), never once too rarely.
type Watcher struct {
	db   *sql.DB
	mu   sync.Mutex
	conn *sql.Conn
	last int64
	seen bool
}

// Watch returns a watcher of this database. Close it when done.
func (s *Store) Watch() *Watcher { return &Watcher{db: s.db} }

// Changed reports whether something was committed since the last call. The
// first call says yes, and so does a call that could not look: a caller
// then does what it did without a watcher.
func (w *Watcher) Changed(ctx context.Context) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn == nil {
		c, err := w.db.Conn(ctx)
		if err != nil {
			return true
		}
		w.conn, w.seen = c, false
	}
	var v int64
	if err := w.conn.QueryRowContext(ctx, "PRAGMA data_version").Scan(&v); err != nil {
		// A connection that broke is replaced with the next look.
		_ = w.conn.Close()
		w.conn = nil
		return true
	}
	if w.seen && v == w.last {
		return false
	}
	w.last, w.seen = v, true
	return true
}

// Close gives the connection back.
func (w *Watcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
}
