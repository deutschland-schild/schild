package hosts

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/ratelog"
)

// schema of the gateway's host state. It lives in the same SQLite file as
// the rest of schild (store.Store.DB()) in tables of its own. Nothing in
// these tables is ever sent anywhere.
const schema = `
CREATE TABLE IF NOT EXISTS host_agents (
  id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  keyid TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL UNIQUE,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL,
  source TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  confirmed_ms INTEGER NOT NULL DEFAULT 0,
  revoked_ms INTEGER NOT NULL DEFAULT 0,
  note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS host_enrolments (
  code_hash TEXT PRIMARY KEY,
  label TEXT NOT NULL DEFAULT '',
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL,
  used_ms INTEGER NOT NULL DEFAULT 0,
  agent_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS host_reports (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id TEXT NOT NULL,
  report_id TEXT NOT NULL UNIQUE,
  started_ms INTEGER NOT NULL,
  received_ms INTEGER NOT NULL,
  critical INTEGER NOT NULL, high INTEGER NOT NULL, medium INTEGER NOT NULL, low INTEGER NOT NULL, info INTEGER NOT NULL,
  unreadable INTEGER NOT NULL,
  body BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS host_reports_host ON host_reports(host_id, started_ms);
CREATE TABLE IF NOT EXISTS host_rejects (
  host_id TEXT PRIMARY KEY,
  at_ms INTEGER NOT NULL,
  code TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS agent_nonces (
  nonce TEXT PRIMARY KEY,
  digest TEXT NOT NULL,
  expires_ms INTEGER NOT NULL
);
`

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func tsp(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := ts(t)
	return &s
}

// agentRow is one row of host_agents.
type agentRow struct {
	ID, Hostname, Label, KeyID, PublicKey, Fingerprint, Status, Source, Note string
	Created, Confirmed, Revoked                                              time.Time
}

const agentCols = "id, hostname, label, keyid, public_key, fingerprint, status, source, created_ms, confirmed_ms, revoked_ms, note"

func scanAgent(sc interface{ Scan(...any) error }) (*agentRow, error) {
	var a agentRow
	var c, cf, rv int64
	if err := sc.Scan(&a.ID, &a.Hostname, &a.Label, &a.KeyID, &a.PublicKey, &a.Fingerprint, &a.Status, &a.Source, &c, &cf, &rv, &a.Note); err != nil {
		return nil, err
	}
	a.Created, a.Confirmed, a.Revoked = fromMS(c), fromMS(cf), fromMS(rv)
	return &a, nil
}

var errNotFound = errors.New("hosts: not found")

func (g *Gateway) agents(ctx context.Context) ([]*agentRow, error) {
	rows, err := g.db.QueryContext(ctx, "SELECT "+agentCols+" FROM host_agents ORDER BY hostname, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*agentRow
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (g *Gateway) agent(ctx context.Context, where string, arg any) (*agentRow, error) {
	a, err := scanAgent(g.db.QueryRowContext(ctx, "SELECT "+agentCols+" FROM host_agents WHERE "+where+" = ?", arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return a, err
}

// reportRow is one kept report without the body.
type reportRow struct {
	ReportID          string
	Started, Received time.Time
	Counts            SeverityCounts
	Unreadable        int64
}

func (g *Gateway) history(ctx context.Context, hostID string, limit int) ([]reportRow, error) {
	rows, err := g.db.QueryContext(ctx, `SELECT report_id, started_ms, received_ms, critical, high, medium, low, info, unreadable
		FROM host_reports WHERE host_id = ? ORDER BY started_ms DESC, seq DESC LIMIT ?`, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reportRow
	for rows.Next() {
		var r reportRow
		var s, rc int64
		if err := rows.Scan(&r.ReportID, &s, &rc, &r.Counts.Critical, &r.Counts.High, &r.Counts.Medium, &r.Counts.Low, &r.Counts.Info, &r.Unreadable); err != nil {
			return nil, err
		}
		r.Started, r.Received = fromMS(s), fromMS(rc)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (g *Gateway) newestBody(ctx context.Context, hostID string) ([]byte, error) {
	var b []byte
	err := g.db.QueryRowContext(ctx, "SELECT body FROM host_reports WHERE host_id = ? ORDER BY started_ms DESC, seq DESC LIMIT 1", hostID).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return b, err
}

// prune keeps the newest keep reports of a host.
func (g *Gateway) prune(ctx context.Context, hostID string, keep int) error {
	_, err := g.db.ExecContext(ctx, `DELETE FROM host_reports WHERE host_id = ? AND seq NOT IN
		(SELECT seq FROM host_reports WHERE host_id = ? ORDER BY started_ms DESC, seq DESC LIMIT ?)`, hostID, hostID, keep)
	return err
}

func (g *Gateway) lastRejected(ctx context.Context, hostID string) (*Rejected, error) {
	var at int64
	var r Rejected
	err := g.db.QueryRowContext(ctx, "SELECT at_ms, code, detail FROM host_rejects WHERE host_id = ?", hostID).Scan(&at, &r.Code, &r.Detail)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.At = ts(fromMS(at))
	return &r, nil
}

func (g *Gateway) recordReject(ctx context.Context, hostID, code, detail string) {
	if len(detail) > 300 {
		detail = detail[:300]
	}
	_, err := g.db.ExecContext(ctx, `INSERT INTO host_rejects(host_id, at_ms, code, detail) VALUES(?, ?, ?, ?)
		ON CONFLICT(host_id) DO UPDATE SET at_ms = excluded.at_ms, code = excluded.code, detail = excluded.detail`, hostID, ms(g.now()), code, detail)
	if err != nil {
		ratelog.Warn(g.log, "record rejected agent delivery", "err", err)
	}
}

// expireNonces drops nonces outside the replay window.
func (g *Gateway) expireNonces(ctx context.Context) {
	if _, err := g.db.ExecContext(ctx, "DELETE FROM agent_nonces WHERE expires_ms < ?", ms(g.now())); err != nil {
		ratelog.Warn(g.log, "expire agent nonces", "err", err)
	}
}

func (g *Gateway) nonceDigest(ctx context.Context, nonce string) (string, bool) {
	var d string
	err := g.db.QueryRowContext(ctx, "SELECT digest FROM agent_nonces WHERE nonce = ?", nonce).Scan(&d)
	return d, err == nil
}
