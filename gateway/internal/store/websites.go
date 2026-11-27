package store

import (
	"context"
	"database/sql"
	"time"
)

// v0.5 (D36): the website of every event and incident (the site columns
// in baseSchema, indexes on (site, seq) for the event lists, (site, time)
// for the alert feed and (site, time) for incidents), the configuration
// change log of the chart annotations and the reads behind "betrifft 3 von
// 4 Websites".

const websitesSchema = `
CREATE INDEX events_site ON events(site, seq);
CREATE INDEX events_site_time ON events(site, time_ms);
CREATE INDEX incidents_site ON incidents(site, time_ms);
CREATE INDEX events_ip_site ON events(ip_key, site, time_ms);
CREATE TABLE config_changes (
  time_ms INTEGER NOT NULL,
  mode_from TEXT NOT NULL DEFAULT '',
  mode_to TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL
);
CREATE INDEX config_changes_time ON config_changes(time_ms);
`

// IncidentFilter narrows IncidentsInRange.
type IncidentFilter struct {
	Site   string
	Status string // blocked | unblocked
}

// CountIncidents counts incidents with time in [from, to) (of one website).
func (s *Store) CountIncidents(ctx context.Context, from, to time.Time, site string) (int64, error) {
	q := `SELECT COUNT(*) FROM incidents WHERE time_ms >= ? AND time_ms < ?`
	args := []any{ms(from), ms(to)}
	if site != "" {
		q += ` AND site = ?`
		args = append(args, site)
	}
	var n int64
	err := s.q(ctx).QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

// SitesOfIP lists the websites the address's events touched in [from, to)
// (index events_ip_site), at most max distinct ids, and how many there are.
func (s *Store) SitesOfIP(ctx context.Context, ip string, from, to time.Time, max int) ([]string, int, error) {
	k := ipKey(ip)
	if k == "" {
		return nil, 0, nil
	}
	// Skip-scan over the distinct websites of the address (index
	// events_ip_site), then one seek per website for an event in the range
	// (D36 fix round 2, re-measurement B 3.3 c: DISTINCT over every event
	// of a busy address made listIncidents take 300-400 ms at 1M events).
	rows, err := s.q(ctx).QueryContext(ctx, `WITH RECURSIVE s(site) AS (
  SELECT (SELECT site FROM events INDEXED BY events_ip_site WHERE ip_key = ?1 AND site > '' ORDER BY site LIMIT 1)
  UNION ALL
  SELECT (SELECT site FROM events INDEXED BY events_ip_site WHERE ip_key = ?1 AND site > s.site ORDER BY site LIMIT 1) FROM s WHERE s.site IS NOT NULL
)
SELECT site FROM s WHERE site IS NOT NULL AND EXISTS (
  SELECT 1 FROM events INDEXED BY events_ip_site WHERE ip_key = ?1 AND site = s.site AND time_ms >= ?2 AND time_ms < ?3)`, k, ms(from), ms(to))
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []string
	n := 0
	for rows.Next() {
		var site string
		if err := rows.Scan(&site); err != nil {
			return nil, 0, err
		}
		n++
		if len(out) < max {
			out = append(out, site)
		}
	}
	return out, n, rows.Err()
}

// ConfigChange is one entry of the configuration change log.
type ConfigChange struct {
	Time     time.Time
	ModeFrom string
	ModeTo   string
	SHA256   string
}

// AddConfigChange appends to the change log (kept at most 1000 entries).
func (s *Store) AddConfigChange(ctx context.Context, c ConfigChange) error {
	if _, err := s.q(ctx).ExecContext(ctx, `INSERT INTO config_changes(time_ms, mode_from, mode_to, sha256) VALUES(?, ?, ?, ?)`, ms(c.Time), c.ModeFrom, c.ModeTo, c.SHA256); err != nil {
		return err
	}
	_, err := s.q(ctx).ExecContext(ctx, `DELETE FROM config_changes WHERE rowid NOT IN (SELECT rowid FROM config_changes ORDER BY time_ms DESC LIMIT 1000)`)
	return err
}

// LastConfigChange returns the newest entry (ErrNotFound for none).
func (s *Store) LastConfigChange(ctx context.Context) (*ConfigChange, error) {
	var c ConfigChange
	var t int64
	err := s.q(ctx).QueryRowContext(ctx, `SELECT time_ms, mode_from, mode_to, sha256 FROM config_changes ORDER BY time_ms DESC LIMIT 1`).Scan(&t, &c.ModeFrom, &c.ModeTo, &c.SHA256)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.Time = fromMS(t)
	return &c, nil
}

// ConfigChanges lists the entries with time in [from, to), oldest first.
func (s *Store) ConfigChanges(ctx context.Context, from, to time.Time, max int) ([]ConfigChange, error) {
	rows, err := s.q(ctx).QueryContext(ctx, `SELECT time_ms, mode_from, mode_to, sha256 FROM config_changes WHERE time_ms >= ? AND time_ms < ? ORDER BY time_ms LIMIT ?`, ms(from), ms(to), max)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConfigChange
	for rows.Next() {
		var c ConfigChange
		var t int64
		if err := rows.Scan(&t, &c.ModeFrom, &c.ModeTo, &c.SHA256); err != nil {
			return nil, err
		}
		c.Time = fromMS(t)
		out = append(out, c)
	}
	return out, rows.Err()
}

// IncidentsBetween lists incidents with time in [from, to), oldest first,
// at most max (annotations; index incidents_time or incidents_site).
func (s *Store) IncidentsBetween(ctx context.Context, from, to time.Time, site string, max int) ([]*Incident, error) {
	q := `SELECT ` + incidentCols + ` FROM incidents WHERE time_ms >= ? AND time_ms < ?`
	args := []any{ms(from), ms(to)}
	if site != "" {
		q += ` AND site = ?`
		args = append(args, site)
	}
	q += ` ORDER BY time_ms LIMIT ?`
	args = append(args, max)
	rows, err := s.q(ctx).QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Incident
	for rows.Next() {
		in, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// IncidentBin is one bin of N incidents of one website: Start and End
// are the bin bounds (End clipped to the range), Last is the time of the
// newest incident and Incident its number (the only one when N is 1).
type IncidentBin struct {
	Start, End, Last time.Time
	N                int64
	Incident         string
}

// IncidentBins counts the incidents of a website in [from, to) in bins of
// bin length, oldest first (index incidents(site, time_ms)); bins without
// incidents are left out.
func (s *Store) IncidentBins(ctx context.Context, site string, from, to time.Time, bin time.Duration) ([]IncidentBin, error) {
	b := max(bin.Milliseconds(), 1)
	// One max() aggregate: SQLite takes the bare column incident from the
	// row holding the maximum, so Incident is the newest of the bin.
	rows, err := s.q(ctx).QueryContext(ctx, `SELECT (time_ms - ?) / ? AS b, COUNT(*), MAX(time_ms), incident FROM incidents
WHERE site = ? AND time_ms >= ? AND time_ms < ? GROUP BY b ORDER BY b`, ms(from), b, site, ms(from), ms(to))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IncidentBin
	for rows.Next() {
		var k, last int64
		var x IncidentBin
		if err := rows.Scan(&k, &x.N, &last, &x.Incident); err != nil {
			return nil, err
		}
		x.Start = fromMS(ms(from) + k*b)
		x.End = fromMS(min(ms(from)+(k+1)*b, ms(to)))
		x.Last = fromMS(last)
		out = append(out, x)
	}
	return out, rows.Err()
}

// AgentCallsInRange lists agent API calls with time in [from, to), newest
// first, after the cursor (beforeSeq; 0 = from the top), optionally of one
// token (index agent_calls_time).
func (s *Store) AgentCallsInRange(ctx context.Context, from, to time.Time, token string, beforeSeq int64, max int) ([]AgentCall, []int64, error) {
	q := `SELECT seq, token_id, time_ms, op, status, rows, bytes FROM agent_calls WHERE time_ms >= ? AND time_ms < ?`
	args := []any{ms(from), ms(to)}
	if token != "" {
		q += ` AND token_id = ?`
		args = append(args, token)
	}
	if beforeSeq > 0 {
		q += ` AND seq < ?`
		args = append(args, beforeSeq)
	}
	q += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, max)
	rows, err := s.q(ctx).QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []AgentCall
	var seqs []int64
	for rows.Next() {
		var c AgentCall
		var seq, t int64
		if err := rows.Scan(&seq, &c.TokenID, &t, &c.Op, &c.Status, &c.Rows, &c.Bytes); err != nil {
			return nil, nil, err
		}
		c.Time = fromMS(t)
		out = append(out, c)
		seqs = append(seqs, seq)
	}
	return out, seqs, rows.Err()
}

// LastAgentUse returns the newest call time per token.
func (s *Store) LastAgentUse(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.q(ctx).QueryContext(ctx, `SELECT token_id, MAX(time_ms) FROM agent_calls GROUP BY token_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var t int64
		if err := rows.Scan(&id, &t); err != nil {
			return nil, err
		}
		out[id] = fromMS(t)
	}
	return out, rows.Err()
}
