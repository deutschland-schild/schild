package store

import (
	"bytes"
	"context"
	"encoding/json"
)

// What a group of gateways reads and writes of events and incidents
// (MVP-27, D103): every node keeps the events of every node, so each
// dashboard shows the group, also what a node wrote that is gone.

// sourceOf reads the CloudEvents source of a stored event.
func sourceOf(body []byte) string {
	var e struct {
		Source string `json:"source"`
	}
	if !bytes.Contains(body, []byte(`"source"`)) || json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Source
}

// EventsOfSource returns events after a sequence number that this node
// wrote itself (their CloudEvents source is source), in the order of their
// sequence numbers, and the last sequence number it looked at: the cursor
// of the next call. It looks at scan rows at most and returns limit rows at
// most, so a call next to traffic is short.
func (s *Store) EventsOfSource(ctx context.Context, source string, after int64, scan, limit int) (rows []*EventRow, next int64, err error) {
	rs, err := s.db.QueryContext(ctx, "SELECT "+eventCols+", cls FROM events WHERE seq > ? ORDER BY seq LIMIT ?", after, scan)
	if err != nil {
		return nil, after, err
	}
	defer rs.Close()
	next = after
	for rs.Next() {
		var e EventRow
		var asn int64
		var t int64
		var rules string
		var cls int
		if err := rs.Scan(&e.Seq, &e.ID, &t, &e.Type, &e.IP, &e.Country, &asn, &e.Method, &e.Host, &e.Path, &e.Status, &e.Score, &e.Outcome, &rules,
			&e.Incident, &e.Session, &e.UA, &e.Summary, &e.Body, &e.Site, &cls); err != nil {
			return nil, after, err
		}
		if len(rows) >= limit {
			break
		}
		next = e.Seq
		if sourceOf(e.Body) != source {
			continue
		}
		e.Time, e.ASN, e.Rules = fromMS(t), uint32(asn), splitList(rules)
		// The value class of the size cap travels as the sampled flag.
		probe := EventRow{Type: e.Type, Outcome: e.Outcome, Sampled: true}
		if with := EventClass(&probe); with == cls {
			probe.Sampled = false
			e.Sampled = EventClass(&probe) != cls
		}
		rows = append(rows, &e)
	}
	return rows, next, rs.Err()
}

// IncidentsOfSource returns incidents that changed at or after sinceMS and
// whose event this node wrote itself, at most limit, oldest change first.
func (s *Store) IncidentsOfSource(ctx context.Context, source string, sinceMS int64, limit int) ([]*Incident, error) {
	rs, err := s.db.QueryContext(ctx, `SELECT i.incident, i.event_id, i.time_ms, i.ip, i.status, i.reason, i.sources, i.unblocked_ms, i.site, i.count, i.first_ms, i.last_ms, e.body
		FROM incidents i JOIN events e ON e.id = i.event_id
		WHERE max(i.last_ms, i.unblocked_ms, i.time_ms) >= ? ORDER BY max(i.last_ms, i.unblocked_ms, i.time_ms) LIMIT ?`, sinceMS, limit*4)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []*Incident
	for rs.Next() {
		var in Incident
		var t, unblocked, first, last int64
		var sources string
		var body []byte
		if err := rs.Scan(&in.Incident, &in.EventID, &t, &in.IP, &in.Status, &in.Reason, &sources, &unblocked, &in.Site, &in.Count, &first, &last, &body); err != nil {
			return nil, err
		}
		if sourceOf(body) != source || len(out) >= limit {
			continue
		}
		in.Time, in.Sources, in.FirstSeen, in.LastSeen = fromMS(t), splitList(sources), fromMS(first), fromMS(last)
		in.UnblockedAt = fromMS(unblocked)
		out = append(out, &in)
	}
	return out, rs.Err()
}

// MergeIncident stores an incident another node of the group wrote, or
// takes over what changed of one this node holds already: a higher count, a
// later last request, and that it was unblocked.
func (s *Store) MergeIncident(ctx context.Context, in *Incident) error {
	if err := s.InsertIncident(ctx, in); err != nil {
		return err
	}
	var unblocked int64
	if !in.UnblockedAt.IsZero() {
		unblocked = ms(in.UnblockedAt)
	}
	// A row a node made from a block's record (it knew no more than the
	// address and the source) takes what the incident says.
	if _, err := s.db.ExecContext(ctx, `UPDATE incidents SET reason = ?, site = ?,
		event_id = CASE WHEN event_id = '' THEN ? ELSE event_id END,
		sources = CASE WHEN ? != '' THEN ? ELSE sources END,
		time_ms = ?, first_ms = min(first_ms, ?)
		WHERE incident = ? AND reason = '' AND site = '' AND ? != ''`,
		in.Reason, in.Site, in.EventID, joinList(in.Sources), joinList(in.Sources), ms(in.Time), ms(in.Time), in.Incident, in.Reason+in.Site); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE incidents SET count = max(count, ?), last_ms = max(last_ms, ?),
		status = CASE WHEN ? != 0 AND unblocked_ms = 0 THEN ? ELSE status END,
		unblocked_ms = CASE WHEN unblocked_ms = 0 THEN ? ELSE unblocked_ms END
		WHERE incident = ?`, max(in.Count, 1), ms(in.LastSeen), unblocked, in.Status, unblocked, in.Incident)
	return err
}

// A group of gateways pulls events and incidents from a member only when
// the member wrote some of its own (MVP-27). OwnGen is the sign for it: a
// number that grows with every write of an event or an incident that did
// not come from another node. It says that something changed, not what; it
// starts at 0 with every start.

type foreignKey struct{}

// Foreign marks ctx for writes of rows another node of the group wrote:
// they do not count in OwnGen, or every node would ask every other again
// for what it just took from one of them.
func Foreign(ctx context.Context) context.Context {
	return context.WithValue(ctx, foreignKey{}, true)
}

func (s *Store) noteOwn(ctx context.Context) {
	if ctx.Value(foreignKey{}) == nil {
		s.ownGen.Add(1)
	}
}

// OwnGen returns the number described above.
func (s *Store) OwnGen() int64 { return s.ownGen.Load() }
