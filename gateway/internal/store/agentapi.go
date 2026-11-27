package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"time"
)

// v0.4 (MVP-21, D33): tokens and call log of the read-only agent API, the
// gateway-local pseudonym key, and the bounded time-range reads it serves.

const agentSchema = `
CREATE TABLE agent_tokens (
  id TEXT PRIMARY KEY,
  hash TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL,
  revoked_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE agent_calls (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  token_id TEXT NOT NULL,
  time_ms INTEGER NOT NULL,
  op TEXT NOT NULL,
  status INTEGER NOT NULL,
  rows INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  n INTEGER NOT NULL
);
CREATE INDEX agent_calls_time ON agent_calls(time_ms);
`

// AgentCallsMax bounds the call log on its own: it is a ring of the newest
// rows, whatever log_days says. Refused calls are one row per token and
// minute, so a flood of 429s cannot fill it, and the size cap of the
// retention trims the call log before it deletes a single event (MVP-21
// measurement: 240 000 refused calls wrote 240 000 rows and the size cap
// then deleted every event).
const AgentCallsMax = 50000

// AgentToken is a stored token (the token itself is never stored).
type AgentToken struct {
	ID        string
	Hash      string
	Scope     string
	Label     string
	Created   time.Time
	Expires   time.Time
	RevokedAt time.Time
}

// Active reports whether the token may be used at now.
func (t *AgentToken) Active(now time.Time) bool {
	return t.RevokedAt.IsZero() && now.Before(t.Expires)
}

// AddAgentToken stores a new token.
func (s *Store) AddAgentToken(ctx context.Context, t AgentToken) error {
	_, err := s.q(ctx).ExecContext(ctx, `INSERT INTO agent_tokens(id, hash, scope, label, created_ms, expires_ms) VALUES(?, ?, ?, ?, ?, ?)`,
		t.ID, t.Hash, t.Scope, t.Label, ms(t.Created), ms(t.Expires))
	return err
}

func scanToken(sc interface{ Scan(...any) error }) (*AgentToken, error) {
	var t AgentToken
	var c, e, r int64
	if err := sc.Scan(&t.ID, &t.Hash, &t.Scope, &t.Label, &c, &e, &r); err != nil {
		return nil, err
	}
	t.Created, t.Expires = fromMS(c), fromMS(e)
	if r != 0 {
		t.RevokedAt = fromMS(r)
	}
	return &t, nil
}

const tokenCols = "id, hash, scope, label, created_ms, expires_ms, revoked_ms"

// AgentTokenByHash finds a token by the SHA-256 of its secret.
func (s *Store) AgentTokenByHash(ctx context.Context, hash string) (*AgentToken, error) {
	t, err := scanToken(s.q(ctx).QueryRowContext(ctx, `SELECT `+tokenCols+` FROM agent_tokens WHERE hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// ListAgentTokens returns every token, newest first.
func (s *Store) ListAgentTokens(ctx context.Context) ([]AgentToken, error) {
	rows, err := s.q(ctx).QueryContext(ctx, `SELECT `+tokenCols+` FROM agent_tokens ORDER BY created_ms DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// RevokeAgentToken revokes a token by id (ErrNotFound if unknown or already revoked).
func (s *Store) RevokeAgentToken(ctx context.Context, id string, at time.Time) error {
	res, err := s.q(ctx).ExecContext(ctx, `UPDATE agent_tokens SET revoked_ms = ? WHERE id = ? AND revoked_ms = 0`, ms(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AgentCall is one entry of the call log. Count > 1 aggregates refused
// calls of one token in one minute (Time is the minute).
type AgentCall struct {
	TokenID string
	Time    time.Time
	Op      string
	Status  int
	Rows    int
	Bytes   int64
	Count   int
}

// LogAgentCalls appends calls to the call log and keeps only the newest
// AgentCallsMax rows.
func (s *Store) LogAgentCalls(ctx context.Context, calls []AgentCall) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, c := range calls {
		if _, err := tx.ExecContext(ctx, `INSERT INTO agent_calls(token_id, time_ms, op, status, rows, bytes, n) VALUES(?, ?, ?, ?, ?, ?, ?)`,
			c.TokenID, ms(c.Time), c.Op, c.Status, c.Rows, c.Bytes, max(1, c.Count)); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_calls WHERE seq <= (SELECT MAX(seq) FROM agent_calls) - ?`, AgentCallsMax); err != nil {
		return err
	}
	return tx.Commit()
}

// ListAgentCalls returns the newest calls (all tokens when tokenID is "").
func (s *Store) ListAgentCalls(ctx context.Context, tokenID string, limit int) ([]AgentCall, error) {
	q := `SELECT token_id, time_ms, op, status, rows, bytes, n FROM agent_calls`
	args := []any{}
	if tokenID != "" {
		q += ` WHERE token_id = ?`
		args = append(args, tokenID)
	}
	q += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.q(ctx).QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentCall
	for rows.Next() {
		var c AgentCall
		var t int64
		if err := rows.Scan(&c.TokenID, &t, &c.Op, &c.Status, &c.Rows, &c.Bytes, &c.Count); err != nil {
			return nil, err
		}
		c.Time = fromMS(t)
		out = append(out, c)
	}
	return out, rows.Err()
}

// PruneAgentCalls deletes call log entries older than before.
func (s *Store) PruneAgentCalls(ctx context.Context, before time.Time) error {
	_, err := s.q(ctx).ExecContext(ctx, `DELETE FROM agent_calls WHERE time_ms < ?`, ms(before))
	return err
}

const pseudonymKey = "agent_pseudonym_key_v1"

// PseudonymKey returns the gateway-local key of client pseudonyms, creating
// it on first use. It never leaves the gateway.
func (s *Store) PseudonymKey(ctx context.Context) ([]byte, error) {
	if v, err := s.Get(ctx, pseudonymKey); err == nil && len(v) == 32 {
		return v, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if _, err := s.q(ctx).ExecContext(ctx, `INSERT OR IGNORE INTO kv(k, v) VALUES(?, ?)`, pseudonymKey, k); err != nil {
		return nil, err
	}
	return s.Get(ctx, pseudonymKey)
}

// EventsInRange reads events with time in [from, to) newest first, starting
// after the cursor position (beforeMS, beforeSeq; 0 = from the top), at most
// max rows (an index range on events(time_ms), no scan).
func (s *Store) EventsInRange(ctx context.Context, from, to time.Time, site string, beforeMS, beforeSeq int64, max int) ([]*EventRow, error) {
	q := `SELECT ` + eventCols + ` FROM events WHERE time_ms >= ? AND time_ms < ?`
	args := []any{ms(from), ms(to)}
	if site != "" {
		q += ` AND site = ?`
		args = append(args, site)
	}
	if beforeMS > 0 {
		q += ` AND (time_ms < ? OR (time_ms = ? AND seq < ?))`
		args = append(args, beforeMS, beforeMS, beforeSeq)
	}
	q += ` ORDER BY time_ms DESC, seq DESC LIMIT ?`
	args = append(args, max)
	rows, err := s.q(ctx).QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EventRow
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// IncidentsInRange reads incidents with time in [from, to) newest first
// after the cursor (beforeMS, beforeID), at most max rows.
func (s *Store) IncidentsInRange(ctx context.Context, from, to time.Time, f IncidentFilter, beforeMS int64, beforeID string, max int) ([]*Incident, error) {
	q := `SELECT incident FROM incidents WHERE time_ms >= ? AND time_ms < ?`
	args := []any{ms(from), ms(to)}
	if f.Site != "" {
		q += ` AND site = ?`
		args = append(args, f.Site)
	}
	if f.Status != "" {
		q += ` AND status = ?`
		args = append(args, f.Status)
	}
	if beforeMS > 0 {
		q += ` AND (time_ms < ? OR (time_ms = ? AND incident < ?))`
		args = append(args, beforeMS, beforeMS, beforeID)
	}
	q += ` ORDER BY time_ms DESC, incident DESC LIMIT ?`
	args = append(args, max)
	rows, err := s.q(ctx).QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := make([]*Incident, 0, len(ids))
	for _, id := range ids {
		in, err := s.GetIncident(ctx, id)
		if err != nil {
			continue
		}
		out = append(out, in)
	}
	return out, nil
}
