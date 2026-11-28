package store

import (
	"context"
	"strings"
	"time"
)

// Indexes behind "Letzte Alarme" (listAlerts) and the wave annotations
// (D36 fix round 1, finding B.4.4 c): with a million events a filter that
// rarely matches walked the (site, time) index of every event of the
// website and filtered the event type afterwards (up to 978 ms). Every
// supported filter now has an index that holds the alert events only:
// partial indexes on events for site, country, ASN, path and net class,
// and event_rules (rule, site, time) for the rule filter, kept by a
// trigger on delete. The alert condition is written as literals so
// SQLite can use the partial indexes.

const alertCond = `(type IN ('schild.request.blocked.v1', 'schild.behaviour.triggered.v1', 'schild.ratelimit.exceeded.v1') OR (type = 'schild.request.evaluated.v1' AND outcome = 'would_block'))`

const netClassExpr = `json_extract(CAST(body AS TEXT), '$.data.client.geo.net_class')`

const waveCond = `type IN ('schild.distributed.detected.v1', 'schild.distributed.ended.v1')`

const alertsSchema = `
CREATE INDEX events_alert ON events(site, time_ms) WHERE ` + alertCond + `;
CREATE INDEX events_alert_country ON events(site, country, time_ms) WHERE ` + alertCond + `;
CREATE INDEX events_alert_asn ON events(site, asn, time_ms) WHERE ` + alertCond + `;
CREATE INDEX events_alert_path ON events(site, path, time_ms) WHERE ` + alertCond + `;
CREATE INDEX events_alert_net ON events(site, ` + netClassExpr + `, time_ms) WHERE ` + alertCond + `;
CREATE INDEX events_wave ON events(site, time_ms) WHERE ` + waveCond + `;
CREATE TABLE event_rules (
  rule TEXT NOT NULL,
  site TEXT NOT NULL,
  time_ms INTEGER NOT NULL,
  seq INTEGER NOT NULL,
  PRIMARY KEY (rule, site, time_ms, seq)
) WITHOUT ROWID;
CREATE INDEX event_rules_seq ON event_rules(seq);
CREATE TRIGGER event_rules_delete AFTER DELETE ON events WHEN old.rules != '' BEGIN
  DELETE FROM event_rules WHERE seq = old.seq;
END;
`

// isAlert mirrors alertCond for the rows InsertEvents writes.
func isAlert(e *EventRow) bool {
	switch e.Type {
	case "schild.request.blocked.v1", "schild.behaviour.triggered.v1", "schild.ratelimit.exceeded.v1":
		return true
	case "schild.request.evaluated.v1":
		return e.Outcome == "would_block"
	}
	return false
}

// AlertFilter selects the detection events of "Letzte Alarme" (D36). At
// most one of Path, Country, ASN, Rule and NetClass is set (the API takes
// one filter); each has its own index.
type AlertFilter struct {
	Site     string
	From, To time.Time
	Path     string // prefix
	Country  string
	ASN      *uint32
	Rule     string
	NetClass string
}

// AlertEvents returns the newest detection events of one website: WAF
// blocks and would-blocks, behaviour hits and rate-limit records, newest
// first, at most max. Every filter reads an index of the alert events in
// time order (no scan of other events, no LIKE over the rows).
func (s *Store) AlertEvents(ctx context.Context, f AlertFilter, max int) ([]*EventRow, error) {
	q, args := alertQuery(f, max)
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

func alertQuery(f AlertFilter, max int) (string, []any) {
	var q string
	var args []any
	timeCond := func(col string) string {
		var w []string
		if !f.From.IsZero() {
			w, args = append(w, col+" >= ?"), append(args, ms(f.From))
		}
		if !f.To.IsZero() {
			w, args = append(w, col+" <= ?"), append(args, ms(f.To))
		}
		if len(w) == 0 {
			return ""
		}
		return " AND " + strings.Join(w, " AND ")
	}
	if f.Rule != "" {
		args = append(args, f.Rule, f.Site)
		cond := timeCond("r.time_ms")
		q = `SELECT ` + prefixCols("e.") + ` FROM event_rules r JOIN events e ON e.seq = r.seq WHERE r.rule = ? AND r.site = ?` + cond +
			` ORDER BY r.time_ms DESC, r.seq DESC LIMIT ?`
	} else {
		w := []string{"site = ?"}
		args = append(args, f.Site)
		// Without statistics SQLite prefers the (site, time) index and
		// filters afterwards; INDEXED BY names the index of the filter.
		index := "events_alert"
		switch {
		case f.Country != "":
			w, args, index = append(w, "country = ?"), append(args, f.Country), "events_alert_country"
		case f.ASN != nil:
			w, args, index = append(w, "asn = ?"), append(args, *f.ASN), "events_alert_asn"
		case f.NetClass != "":
			w, args, index = append(w, netClassExpr+" = ?"), append(args, f.NetClass), "events_alert_net"
		case f.Path != "":
			// A range on the path (the index), not LIKE.
			w, args, index = append(w, "path >= ? AND path < ?"), append(args, f.Path, f.Path+"\xff"), "events_alert_path"
		}
		// The newest seqs first from the index alone, then the rows: a
		// frequent path prefix matches many paths, so its rows are sorted
		// by time; sorting the index entries and reading only the rows of
		// the page keeps that cheap (D36 fix round 2, re-measurement B
		// 3.3 c: path:/search p95 1045 ms, every matching body was read).
		q = `SELECT ` + eventCols + ` FROM events WHERE seq IN (SELECT seq FROM events INDEXED BY ` + index + ` WHERE ` + strings.Join(w, " AND ") + timeCond("time_ms") + ` AND ` + alertCond +
			` ORDER BY time_ms DESC, seq DESC LIMIT ?) ORDER BY time_ms DESC, seq DESC`
	}
	args = append(args, max)
	return q, args
}

// WaveEvents returns the wave events (distributed.detected and .ended) of
// one website in [from, to] (ms), oldest first, at most max (partial
// index events_wave).
func (s *Store) WaveEvents(ctx context.Context, site string, from, to int64, max int) ([]*EventRow, error) {
	rows, err := s.q(ctx).QueryContext(ctx, `SELECT `+eventCols+` FROM events WHERE site = ? AND time_ms >= ? AND time_ms <= ? AND `+waveCond+
		` ORDER BY time_ms, seq LIMIT ?`, site, from, to, max)
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

func prefixCols(p string) string {
	cols := strings.Split(eventCols, ", ")
	for i := range cols {
		cols[i] = p + cols[i]
	}
	return strings.Join(cols, ", ")
}
