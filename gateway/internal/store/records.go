package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"
)

// ---------------------------------------------------------------- incidents

// Incident is a blocked request with its incident number.
type Incident struct {
	Incident       string
	EventID        string
	Time           time.Time
	IP             string
	Status         string // blocked | unblocked
	Reason         string
	Sources        []string
	UnblockedAt    time.Time
	AllowlistEntry string
	// Site is the website of the incident's request (v0.5, D36); Host is
	// its Host header, only used to resolve Site before the insert.
	Site string
	Host string
	// Count, FirstSeen and LastSeen describe an aggregated incident (v0.5,
	// D38): WAF and request-limit blocks of one client, rule key and UTC
	// minute share one row. Count 0 on insert means 1; zero times mean Time.
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// incidentCols are the columns scanIncident reads.
const incidentCols = `incident, event_id, time_ms, ip, status, reason, sources, unblocked_ms, allowlist_entry, site, count, first_ms, last_ms`

type scanner interface{ Scan(dest ...any) error }

func scanIncident(sc scanner) (*Incident, error) {
	var in Incident
	var t, u, first, last int64
	var src string
	if err := sc.Scan(&in.Incident, &in.EventID, &t, &in.IP, &in.Status, &in.Reason, &src, &u, &in.AllowlistEntry, &in.Site,
		&in.Count, &first, &last); err != nil {
		return nil, err
	}
	in.Time, in.UnblockedAt, in.Sources = fromMS(t), fromMS(u), splitList(src)
	in.FirstSeen, in.LastSeen = fromMS(first), fromMS(last)
	return &in, nil
}

// InsertIncident stores a new incident.
func (s *Store) InsertIncident(ctx context.Context, in *Incident) error {
	n, first, last := in.Count, in.FirstSeen, in.LastSeen
	if n < 1 {
		n = 1
	}
	if first.IsZero() {
		first = in.Time
	}
	if last.IsZero() {
		last = in.Time
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO incidents(incident, event_id, time_ms, ip, status, reason, sources, site, count, first_ms, last_ms)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, in.Incident, in.EventID, ms(in.Time), in.IP, in.Status, in.Reason, joinList(in.Sources), in.Site,
		n, ms(first), ms(last))
	if err == nil {
		s.written.Add(incidentBytes(in))
	}
	return err
}

// IncidentHits are further requests of an aggregated incident (D38): Count
// requests between FirstMS and LastMS (unix ms).
type IncidentHits struct {
	Incident string
	Count    int64
	FirstMS  int64
	LastMS   int64
}

// incidentHitBytes is what one aggregated hit counts for the size cap:
// three integer columns rewritten.
const incidentHitBytes = 24

// AddIncidentHits adds the hits to their incidents in one transaction (the
// gate batches them, so a flood costs one write per flush, not one per
// request). It returns the hits whose incident row does not exist (yet):
// the caller may retry them after the pending inserts.
func (s *Store) AddIncidentHits(ctx context.Context, hits []IncidentHits) (missing []IncidentHits, err error) {
	if len(hits) == 0 {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	st, err := tx.PrepareContext(ctx, `UPDATE incidents SET count = count + ?,
		first_ms = CASE WHEN first_ms = 0 OR ? < first_ms THEN ? ELSE first_ms END,
		last_ms = CASE WHEN ? > last_ms THEN ? ELSE last_ms END WHERE incident = ?`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	for _, h := range hits {
		r, err2 := st.ExecContext(ctx, h.Count, h.FirstMS, h.FirstMS, h.LastMS, h.LastMS, h.Incident)
		if err2 != nil {
			err = err2
			return nil, err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			missing = append(missing, h)
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	// An update rewrites the row in place; it still costs WAL and page
	// churn, so it counts towards the next size-cap pass (D38).
	s.written.Add(int64(len(hits)-len(missing)) * incidentHitBytes)
	return missing, nil
}

// GetIncident loads an incident.
func (s *Store) GetIncident(ctx context.Context, id string) (*Incident, error) {
	in, err := scanIncident(s.db.QueryRowContext(ctx, `SELECT `+incidentCols+` FROM incidents WHERE incident = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return in, nil
}

// MarkUnblocked records the unblock decision.
func (s *Store) MarkUnblocked(ctx context.Context, id string, at time.Time, allowEntry string) error {
	r, err := s.db.ExecContext(ctx, `UPDATE incidents SET status = 'unblocked', unblocked_ms = ?, allowlist_entry = ? WHERE incident = ? AND status = 'blocked'`,
		ms(at), allowEntry, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUnblockRefs adds the allowlist entry of an operator unblock to an
// incident that the block's early end already marked unblocked (Sink.Ended
// of the behaviour engine, D36 fix round 2). Only an empty reference is
// filled; ErrNotFound when it was not empty.
func (s *Store) SetUnblockRefs(ctx context.Context, id, allowEntry string) error {
	r, err := s.db.ExecContext(ctx, `UPDATE incidents SET allowlist_entry = ? WHERE incident = ? AND status = 'unblocked' AND allowlist_entry = ''`,
		allowEntry, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Exception lets one client past the sources that blocked an incident.
type Exception struct {
	IP       string
	Sources  []string
	Expires  time.Time
	Incident string
}

// AddException stores an exception.
func (s *Store) AddException(ctx context.Context, e Exception) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO exceptions(ip, sources, expires_ms, incident) VALUES(?,?,?,?)", e.IP, joinList(e.Sources), ms(e.Expires), e.Incident)
	return err
}

// ActiveExceptions returns all unexpired exceptions.
func (s *Store) ActiveExceptions(ctx context.Context, now time.Time) ([]Exception, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT ip, sources, expires_ms, incident FROM exceptions WHERE expires_ms > ?", ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Exception
	for rows.Next() {
		var e Exception
		var src string
		var exp int64
		if err := rows.Scan(&e.IP, &src, &exp, &e.Incident); err != nil {
			return nil, err
		}
		e.Sources, e.Expires = splitList(src), fromMS(exp)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- allowlist

// AllowEntry is one allowlist entry (local only, never sent).
type AllowEntry struct {
	ID        string
	IP        string
	CIDR      string
	Host      string
	Label     string
	Level     string // no_block | bypass_waf
	Expires   string // "never" or timestamp
	CreatedAt time.Time
	Source    string // config | dashboard | cli
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func bumpAllowVersion(ctx context.Context, x execer) error {
	_, err := x.ExecContext(ctx, `INSERT INTO kv(k, v) VALUES('allow_version', '1')
		ON CONFLICT(k) DO UPDATE SET v = CAST(CAST(v AS INTEGER) + 1 AS TEXT)`)
	return err
}

// AllowVersion changes whenever the allowlist changes (also from the CLI in
// another process), so the proxy can reload it cheaply.
func (s *Store) AllowVersion(ctx context.Context) int64 {
	var v string
	if err := s.db.QueryRowContext(ctx, "SELECT CAST(v AS TEXT) FROM kv WHERE k = 'allow_version'").Scan(&v); err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

// ListAllow returns all stored entries, oldest first.
func (s *Store) ListAllow(ctx context.Context) ([]AllowEntry, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, ip, cidr, host, label, level, expires, created_ms, source FROM allowlist ORDER BY created_ms, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AllowEntry
	for rows.Next() {
		var e AllowEntry
		var c int64
		if err := rows.Scan(&e.ID, &e.IP, &e.CIDR, &e.Host, &e.Label, &e.Level, &e.Expires, &c, &e.Source); err != nil {
			return nil, err
		}
		e.CreatedAt = fromMS(c)
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddAllow stores an entry.
func (s *Store) AddAllow(ctx context.Context, e *AllowEntry) error {
	if e.ID == "" {
		e.ID = NewID("al_")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO allowlist(id, ip, cidr, host, label, level, expires, created_ms, source) VALUES(?,?,?,?,?,?,?,?,?)",
		e.ID, e.IP, e.CIDR, e.Host, e.Label, e.Level, e.Expires, ms(e.CreatedAt), e.Source); err != nil {
		return err
	}
	if err := bumpAllowVersion(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteAllow removes an entry (not config entries).
func (s *Store) DeleteAllow(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, "DELETE FROM allowlist WHERE id = ? AND source != 'config'", id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := bumpAllowVersion(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------------------------------------------------------------- users and sessions

// User is a dashboard user.
type User struct {
	Name string
	Hash string
	Role string
}

// GetUser loads a user.
func (s *Store) GetUser(ctx context.Context, name string) (*User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, "SELECT name, hash, role FROM users WHERE name = ?", name).Scan(&u.Name, &u.Hash, &u.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

// HasUsers reports whether any password is set.
func (s *Store) HasUsers(ctx context.Context) bool {
	var n int
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n)
	return n > 0
}

// CreateFirstUser inserts the first admin only if no user exists yet.
func (s *Store) CreateFirstUser(ctx context.Context, u User) error {
	r, err := s.db.ExecContext(ctx, "INSERT INTO users(name, hash, role, created_ms) SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)",
		u.Name, u.Hash, u.Role, ms(time.Now()))
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return errors.New("store: a user exists already")
	}
	return nil
}

// SetPassword replaces a user's hash and ends all of their sessions.
func (s *Store) SetPassword(ctx context.Context, name, hash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE users SET hash = ? WHERE name = ?", hash, name); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE user = ?", name); err != nil {
		return err
	}
	return tx.Commit()
}

// Session is a dashboard session.
type Session struct {
	TokenHash string
	User      string
	CSRF      string
	Created   time.Time
	Expires   time.Time
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, se Session) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO sessions(token_hash, user, csrf, created_ms, expires_ms) VALUES(?,?,?,?,?)",
		se.TokenHash, se.User, se.CSRF, ms(se.Created), ms(se.Expires))
	return err
}

// GetSession loads an unexpired session.
func (s *Store) GetSession(ctx context.Context, tokenHash string, now time.Time) (*Session, error) {
	var se Session
	var c, e int64
	err := s.db.QueryRowContext(ctx, "SELECT token_hash, user, csrf, created_ms, expires_ms FROM sessions WHERE token_hash = ? AND expires_ms > ?",
		tokenHash, ms(now)).Scan(&se.TokenHash, &se.User, &se.CSRF, &c, &e)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	se.Created, se.Expires = fromMS(c), fromMS(e)
	return &se, nil
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash = ?", tokenHash)
	return err
}

// ---------------------------------------------------------------- summaries

// SummaryKey is one hourly counter cell (no IP).
type SummaryKey struct {
	Hour    int64 // unix hour
	Outcome string
	Country string
}

// AddSummaries adds counts.
func (s *Store) AddSummaries(ctx context.Context, counts map[SummaryKey]int) error {
	if len(counts) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, n := range counts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO summaries(hour, outcome, country, count) VALUES(?,?,?,?)
			ON CONFLICT(hour, outcome, country) DO UPDATE SET count = count + excluded.count`, k.Hour, k.Outcome, k.Country, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SummaryTotals sums counts per outcome since a time.
func (s *Store) SummaryTotals(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT outcome, SUM(count) FROM summaries WHERE hour >= ? GROUP BY outcome", since.Unix()/3600)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var o string
		var n int
		if err := rows.Scan(&o, &n); err != nil {
			return nil, err
		}
		out[o] = n
	}
	return out, rows.Err()
}
