package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/clientip"
)

// EventRow is one local event with its indexed columns and the full
// CloudEvent JSON in Body.
type EventRow struct {
	Seq      int64
	ID       string
	Time     time.Time
	Type     string
	IP       string
	Country  string
	ASN      uint32
	Method   string
	Host     string
	Path     string
	Status   int
	Score    int
	Outcome  string
	Rules    []string
	Incident string
	Session  string
	UA       string
	Summary  string
	Body     []byte
	// Site is the website the request Host resolves to (v0.5, D36).
	Site string
	// Sampled is the request event's sampled flag (value class of the
	// size cap, D38); not read back.
	Sampled bool
}

const eventCols = "seq, id, time_ms, type, ip, country, asn, method, host, path, status, score, outcome, rules, incident, session, ua, summary, body, site"

func scanEvent(sc interface{ Scan(...any) error }) (*EventRow, error) {
	var e EventRow
	var t int64
	var rules string
	if err := sc.Scan(&e.Seq, &e.ID, &t, &e.Type, &e.IP, &e.Country, &e.ASN, &e.Method, &e.Host, &e.Path, &e.Status, &e.Score,
		&e.Outcome, &rules, &e.Incident, &e.Session, &e.UA, &e.Summary, &e.Body, &e.Site); err != nil {
		return nil, err
	}
	e.Time = fromMS(t)
	e.Rules = splitList(rules)
	return &e, nil
}

func ipKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return clientip.Key(a)
}

// InsertEvents writes a batch in one transaction and returns the sequence
// numbers assigned to the rows.
func (s *Store) InsertEvents(ctx context.Context, rows []*EventRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	written, err := insertEventsTx(ctx, tx, rows)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Bytes handed to SQLite count towards the next size-cap pass (D38).
	s.written.Add(written)
	s.noteOwn(ctx)
	return nil
}

// insertEventsTx writes rows inside tx, sets their sequence numbers and
// returns the bytes written (payload and index keys) for the size cap.
func insertEventsTx(ctx context.Context, tx *sql.Tx, rows []*EventRow) (int64, error) {
	st, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO events(id, time_ms, type, ip, ip_key, country, asn, method, host, path, status, score, outcome, rules, incident, session, ua, summary, body, site, cls)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	var rs *sql.Stmt // event_rules of alert events (alerts.go)
	var written int64
	for _, e := range rows {
		res, err := st.ExecContext(ctx, e.ID, ms(e.Time), e.Type, e.IP, ipKey(e.IP), e.Country, e.ASN, e.Method, e.Host, e.Path, e.Status, e.Score,
			e.Outcome, joinList(e.Rules), e.Incident, e.Session, e.UA, e.Summary, e.Body, e.Site, EventClass(e))
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			written += eventBytes(e)
		}
		if id, err := res.LastInsertId(); err == nil {
			e.Seq = id
		}
		if n, _ := res.RowsAffected(); n == 1 && len(e.Rules) > 0 && isAlert(e) {
			if rs == nil {
				if rs, err = tx.PrepareContext(ctx, `INSERT OR IGNORE INTO event_rules(rule, site, time_ms, seq) VALUES(?, ?, ?, ?)`); err != nil {
					return 0, err
				}
				defer rs.Close()
			}
			for _, r := range e.Rules {
				if _, err := rs.ExecContext(ctx, r, e.Site, ms(e.Time), e.Seq); err != nil {
					return 0, err
				}
			}
		}
	}
	return written, nil
}

// EventFilter selects events. Zero values do not filter.
type EventFilter struct {
	From, To time.Time
	Type     string
	Types    []string // any of these types (MVP-17 hit lists)
	// SummaryPrefix filters on the summary column (e.g. "behaviour login_bruteforce ").
	SummaryPrefix string
	IP            string // exact address or CIDR
	Country       string
	ASN           *uint32
	Path          string // prefix
	Rule          string
	Outcome       string
	Session       string
	Q             string
	// Site is a website id (v0.5, D36); index events(site, seq).
	Site string
	// Outcomes: any of these outcomes.
	Outcomes []string
	// D36 amendment (2026-10-29), listEvents: NetClass is the client's net
	// class in the event body; Method an HTTP method, with OtherMethods set
	// every method outside that list instead (OTHER); Match a filter SQL
	// cannot express (ua_class), applied to the rows read (ListEvents).
	NetClass     string
	Method       string
	OtherMethods []string
	Match        func(*EventRow) bool
}

// MatchScanMax bounds the rows ListEvents reads for one page when the
// filter has a Match: a page may then hold fewer rows than asked, with a
// cursor to continue.
const MatchScanMax = 20000

// where renders the filter as SQL text from constant fragments and "?"
// placeholders; every filter value is a bound argument, never SQL text.
func (f EventFilter) where() (string, []any, error) {
	var w []string
	var args []any
	if !f.From.IsZero() {
		w, args = append(w, "time_ms >= ?"), append(args, ms(f.From))
	}
	if !f.To.IsZero() {
		w, args = append(w, "time_ms <= ?"), append(args, ms(f.To))
	}
	if f.Type != "" {
		w, args = append(w, "type = ?"), append(args, f.Type)
	}
	if len(f.Types) > 0 {
		w = append(w, "type IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.Types)), ",")+")")
		for _, t := range f.Types {
			args = append(args, t)
		}
	}
	if f.SummaryPrefix != "" {
		w, args = append(w, `summary LIKE ? ESCAPE '\'`), append(args, escapeLike(f.SummaryPrefix)+"%")
	}
	if f.IP != "" {
		if strings.Contains(f.IP, "/") {
			p, err := netip.ParsePrefix(f.IP)
			if err != nil {
				return "", nil, fmt.Errorf("ip: %w", err)
			}
			lo, hi := clientip.Range(p)
			w, args = append(w, "ip_key BETWEEN ? AND ?"), append(args, lo, hi)
		} else {
			a, err := netip.ParseAddr(f.IP)
			if err != nil {
				return "", nil, fmt.Errorf("ip: %w", err)
			}
			w, args = append(w, "ip_key = ?"), append(args, clientip.Key(a.Unmap()))
		}
	}
	if f.Country != "" {
		w, args = append(w, "country = ?"), append(args, f.Country)
	}
	if f.ASN != nil {
		w, args = append(w, "asn = ?"), append(args, *f.ASN)
	}
	if f.Path != "" {
		w, args = append(w, `path LIKE ? ESCAPE '\'`), append(args, escapeLike(f.Path)+"%")
	}
	if f.Rule != "" {
		w, args = append(w, `rules LIKE ? ESCAPE '\'`), append(args, "%,"+escapeLike(f.Rule)+",%")
	}
	if f.Outcome != "" {
		w, args = append(w, "outcome = ?"), append(args, f.Outcome)
	}
	if f.Session != "" {
		w, args = append(w, "session = ?"), append(args, f.Session)
	}
	if f.Site != "" {
		w, args = append(w, "site = ?"), append(args, f.Site)
	}
	if f.NetClass != "" {
		w, args = append(w, "json_extract(CAST(body AS TEXT), '$.data.client.geo.net_class') = ?"), append(args, f.NetClass)
	}
	if len(f.OtherMethods) > 0 {
		w = append(w, "method != '' AND method NOT IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.OtherMethods)), ",")+")")
		for _, m := range f.OtherMethods {
			args = append(args, m)
		}
	} else if f.Method != "" {
		w, args = append(w, "method = ?"), append(args, f.Method)
	}
	if len(f.Outcomes) > 0 {
		w = append(w, "outcome IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.Outcomes)), ",")+")")
		for _, o := range f.Outcomes {
			args = append(args, o)
		}
	}
	if f.Q != "" {
		q := "%" + escapeLike(f.Q) + "%"
		w, args = append(w, `(path LIKE ? ESCAPE '\' OR ua LIKE ? ESCAPE '\' OR incident LIKE ? ESCAPE '\' OR summary LIKE ? ESCAPE '\')`), append(args, q, q, q, q)
	}
	return strings.Join(w, " AND "), args, nil
}

// ParseCursor decodes a list cursor ("" = start).
func ParseCursor(c string) (int64, error) {
	if c == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(strings.TrimPrefix(c, "c"), 10, 64)
	if err != nil || n <= 0 || !strings.HasPrefix(c, "c") {
		return 0, errors.New("invalid cursor")
	}
	return n, nil
}

// FormatCursor encodes a list cursor.
func FormatCursor(seq int64) string { return "c" + strconv.FormatInt(seq, 10) }

// ListEvents returns events newest first. cursor is the seq to continue
// below (exclusive); 0 starts at the newest. next is 0 at the end.
func (s *Store) ListEvents(ctx context.Context, f EventFilter, cursor int64, limit int) ([]*EventRow, int64, error) {
	if f.Match != nil {
		return s.listMatching(ctx, f, cursor, limit)
	}
	where, args, err := f.where()
	if err != nil {
		return nil, 0, err
	}
	if cursor > 0 {
		if where != "" {
			where += " AND "
		}
		where += "seq < ?"
		args = append(args, cursor)
	}
	q := "SELECT " + eventCols + " FROM events"
	if where != "" {
		q += " WHERE " + where
	}
	q += " ORDER BY seq DESC LIMIT ?"
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*EventRow
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	var next int64
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].Seq
	}
	return out, next, rows.Err()
}

// listMatching reads pages of the SQL filter newest first and keeps the
// rows f.Match accepts, until limit rows or MatchScanMax rows read; next
// then continues below the last row read.
func (s *Store) listMatching(ctx context.Context, f EventFilter, cursor int64, limit int) ([]*EventRow, int64, error) {
	match := f.Match
	f.Match = nil
	const batch = 500
	var out []*EventRow
	scanned := 0
	for {
		rows, next, err := s.ListEvents(ctx, f, cursor, batch)
		if err != nil {
			return nil, 0, err
		}
		for i, e := range rows {
			scanned++
			if !match(e) {
				continue
			}
			out = append(out, e)
			if len(out) == limit {
				if i == len(rows)-1 && next == 0 {
					return out, 0, nil
				}
				return out, e.Seq, nil
			}
		}
		if next == 0 {
			return out, 0, nil
		}
		cursor = next
		if scanned >= MatchScanMax {
			return out, cursor, nil
		}
	}
}

// EventsAfter returns events with seq > after, oldest first (SSE replay).
func (s *Store) EventsAfter(ctx context.Context, f EventFilter, after int64, limit int) ([]*EventRow, error) {
	where, args, err := f.where()
	if err != nil {
		return nil, err
	}
	if where != "" {
		where += " AND "
	}
	where += "seq > ?"
	args = append(args, after, limit)
	rows, err := s.db.QueryContext(ctx, "SELECT "+eventCols+" FROM events WHERE "+where+" ORDER BY seq ASC LIMIT ?", args...)
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

// GetEvent returns one event by id.
func (s *Store) GetEvent(ctx context.Context, id string) (*EventRow, error) {
	e, err := scanEvent(s.db.QueryRowContext(ctx, "SELECT "+eventCols+" FROM events WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// EventAddress is the stored address of one event.
type EventAddress struct {
	EventID string
	IP      string
}

// RecentAddresses returns the addresses of the newest limit events that still
// hold one in full, newest first (D42: a pseudonym names an address only by
// comparison, it cannot be reversed).
func (s *Store) RecentAddresses(ctx context.Context, limit int) ([]EventAddress, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, ip FROM events WHERE ip != '' AND ip_truncated = 0 ORDER BY seq DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventAddress
	for rows.Next() {
		var a EventAddress
		if err := rows.Scan(&a.EventID, &a.IP); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// MaxSeq returns the newest event sequence number.
func (s *Store) MaxSeq(ctx context.Context) int64 {
	var n sql.NullInt64
	_ = s.db.QueryRowContext(ctx, "SELECT MAX(seq) FROM events").Scan(&n)
	return n.Int64
}

// Related returns other events of the same session or IP within window.
func (s *Store) Related(ctx context.Context, e *EventRow, window time.Duration, limit int) ([]*EventRow, error) {
	if e.IP == "" && e.Session == "" {
		return nil, nil
	}
	q := "SELECT " + eventCols + " FROM events WHERE id != ? AND time_ms BETWEEN ? AND ? AND (ip_key = ?"
	args := []any{e.ID, ms(e.Time.Add(-window)), ms(e.Time.Add(window)), ipKey(e.IP)}
	if e.Session != "" {
		q += " OR session = ?"
		args = append(args, e.Session)
	}
	q += ") ORDER BY seq DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EventRow
	for rows.Next() {
		r, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountEvents counts events matching f.
func (s *Store) CountEvents(ctx context.Context, f EventFilter) (int, error) {
	where, args, err := f.where()
	if err != nil {
		return 0, err
	}
	q := "SELECT COUNT(*) FROM events"
	if where != "" {
		q += " WHERE " + where
	}
	var n int
	err = s.db.QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

// EventsByIP returns all events of one address, oldest first (privacy export).
func (s *Store) EventsByIP(ctx context.Context, ip string, limit int) ([]*EventRow, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+eventCols+" FROM events WHERE ip_key = ? ORDER BY seq ASC LIMIT ?", ipKey(ip), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EventRow
	for rows.Next() {
		r, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EventsByIncident returns the events of one incident, oldest first (D51).
func (s *Store) EventsByIncident(ctx context.Context, incident string, limit int) ([]*EventRow, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+eventCols+" FROM events WHERE incident = ? ORDER BY seq ASC LIMIT ?", incident, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EventRow
	for rows.Next() {
		r, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// IPSummary is what is stored about one address.
type IPSummary struct {
	Events      int
	Sessions    int
	Incidents   []string
	FirstSeen   time.Time
	LastSeen    time.Time
	Untruncated time.Time // oldest event that still holds the full address
}

// SummarizeIP returns counts for the privacy view.
func (s *Store) SummarizeIP(ctx context.Context, ip string) (*IPSummary, error) {
	k := ipKey(ip)
	if k == "" {
		return nil, errors.New("invalid ip")
	}
	var sum IPSummary
	var first, last, oldest sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT NULLIF(session, '')), MIN(time_ms), MAX(time_ms),
		MIN(CASE WHEN ip_truncated = 0 THEN time_ms END) FROM events WHERE ip_key = ?`, k).Scan(&sum.Events, &sum.Sessions, &first, &last, &oldest)
	if err != nil {
		return nil, err
	}
	sum.FirstSeen, sum.LastSeen, sum.Untruncated = fromMS(first.Int64), fromMS(last.Int64), fromMS(oldest.Int64)
	rows, err := s.db.QueryContext(ctx, "SELECT incident FROM incidents WHERE ip = ? ORDER BY time_ms", ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sum.Incidents = []string{}
	for rows.Next() {
		var inc string
		if err := rows.Scan(&inc); err != nil {
			return nil, err
		}
		sum.Incidents = append(sum.Incidents, inc)
	}
	return &sum, rows.Err()
}

// DeleteResult counts what a privacy deletion removed.
type DeleteResult struct {
	Events, Sessions, Allowlist int
}

// DeleteIP deletes everything stored about one address. With keepIncidents
// the blocked events and incidents stay, with the address truncated.
func (s *Store) DeleteIP(ctx context.Context, ip string, keepIncidents bool, truncate func(body []byte, ip string) []byte) (*DeleteResult, error) {
	k := ipKey(ip)
	if k == "" {
		return nil, errors.New("invalid ip")
	}
	a, _ := netip.ParseAddr(ip)
	short := clientip.Truncate(a).String()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res := &DeleteResult{}
	_ = tx.QueryRowContext(ctx, "SELECT COUNT(DISTINCT NULLIF(session, '')) FROM events WHERE ip_key = ?", k).Scan(&res.Sessions)
	cond := "ip_key = ?"
	if keepIncidents {
		cond += " AND incident = ''"
	}
	r, err := tx.ExecContext(ctx, "DELETE FROM events WHERE "+cond, k)
	if err != nil {
		return nil, err
	}
	n, _ := r.RowsAffected()
	res.Events = int(n)
	if keepIncidents {
		rows, err := tx.QueryContext(ctx, "SELECT seq, body FROM events WHERE ip_key = ?", k)
		if err != nil {
			return nil, err
		}
		type upd struct {
			seq  int64
			body []byte
		}
		var ups []upd
		for rows.Next() {
			var u upd
			if err := rows.Scan(&u.seq, &u.body); err != nil {
				rows.Close()
				return nil, err
			}
			u.body = truncate(u.body, short)
			ups = append(ups, u)
		}
		rows.Close()
		for _, u := range ups {
			if _, err := tx.ExecContext(ctx, "UPDATE events SET ip = ?, ip_key = ?, ip_truncated = 1, session = '', body = ? WHERE seq = ?", short, ipKey(short), u.body, u.seq); err != nil {
				return nil, err
			}
		}
		if _, err := tx.ExecContext(ctx, "UPDATE incidents SET ip = ? WHERE ip = ?", short, ip); err != nil {
			return nil, err
		}
	} else {
		if _, err := tx.ExecContext(ctx, "DELETE FROM incidents WHERE ip = ?", ip); err != nil {
			return nil, err
		}
	}
	// Art. 17 always wins over a kept block (D29 amendment).
	if err := deleteBlockTx(ctx, tx, ip); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM exceptions WHERE ip = ?", ip); err != nil {
		return nil, err
	}
	r, err = tx.ExecContext(ctx, "DELETE FROM allowlist WHERE ip = ? AND source != 'config'", ip)
	if err != nil {
		return nil, err
	}
	n, _ = r.RowsAffected()
	res.Allowlist = int(n)
	if err := bumpAllowVersion(ctx, tx); err != nil {
		return nil, err
	}
	return res, tx.Commit()
}

// RequestLite is the part of a stored request event a rate-limit dry run
// needs (MVP-17).
type RequestLite struct {
	Time                   time.Time
	IP, Method, Host, Path string
}

// RequestsSince returns stored request events since from, oldest first, at
// most limit rows; pathPrefix narrows by the literal start of a route.
func (s *Store) RequestsSince(ctx context.Context, from time.Time, pathPrefix string, limit int) ([]RequestLite, error) {
	q := `SELECT time_ms, ip, method, host, path FROM events WHERE time_ms >= ? AND type IN (?, ?)`
	args := []any{ms(from), "schild.request.evaluated.v1", "schild.request.blocked.v1"}
	if pathPrefix != "" {
		q += ` AND path LIKE ? ESCAPE '\'`
		args = append(args, escapeLike(pathPrefix)+"%")
	}
	q += ` ORDER BY seq ASC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RequestLite
	for rows.Next() {
		var r RequestLite
		var t int64
		if err := rows.Scan(&t, &r.IP, &r.Method, &r.Host, &r.Path); err != nil {
			return nil, err
		}
		r.Time = fromMS(t)
		out = append(out, r)
	}
	return out, rows.Err()
}
