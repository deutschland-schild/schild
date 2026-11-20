package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/storage"
)

// Size cap of schild.db (contracts v0.5, D38, storage-bounds.md section 1).
//
// Every event row carries its value class (column cls, the position of
// storage.ClassOfEvent in storage.DeletionOrder), so a pass walks the
// oldest rows of a class in contract order through the index events_cap
// (cls, time_ms, id) without reading bodies or sorting. The writers of events and incidents count the bytes they
// hand to SQLite (row payload and index keys, estimated per row), so the
// caller can run a pass as soon as a tenth of the cap was written
// (storage.CheckDue, CapScheduler).
//
// A pass follows storage.CapPass: used = (page_count - freelist_count) *
// page_size + the WAL left after the starting checkpoint; nothing happens
// while used <= cap; above the cap it deletes down to 95 % of the cap, the
// older half of agent_calls first, then per class the oldest rows (write
// time, then id) except the newest storage.FloorRows. The pass measures
// used bytes after every delete batch (capBatch rows) and stops at the low
// water mark. Rows of different classes share pages: deleting one class
// out of mixed pages frees pages only once they run nearly empty (SQLite
// merges pages under a third full), so a pass may delete more rows than
// their own size; it never deletes past the floors.

// capBatch is the number of rows one delete transaction removes at most.
const capBatch = 256

// The overheads approximate what SQLite stores per row beyond the column
// bytes counted by the writer estimates: record headers, integer columns,
// rowids in the table and in every index.
const (
	eventOverhead    = 160
	incidentOverhead = 64
)

// Value class codes stored in events.cls: the index in
// storage.DeletionOrder.
var classCode = func() map[string]int {
	m := map[string]int{}
	for i, c := range storage.DeletionOrder {
		m[c] = i
	}
	return m
}()

// EventClass returns the class code of an event row. Behaviour and
// rate-limit events store their action in the outcome column.
func EventClass(e *EventRow) int {
	return classCode[storage.ClassOfEvent(e.Type, e.Outcome, e.Outcome, e.Sampled)]
}

// eventBytes estimates what one event row costs in schild.db: its column
// bytes and the keys of its indexes.
func eventBytes(e *EventRow) int64 {
	ik := int64(len(ipKey(e.IP)))
	rules := int64(len(joinList(e.Rules)))
	n := int64(len(e.ID)+len(e.Type)+len(e.IP)+len(e.Country)+len(e.Method)+len(e.Host)+len(e.Path)+len(e.Outcome)+
		len(e.Incident)+len(e.Session)+len(e.UA)+len(e.Summary)+len(e.Body)+len(e.Site)) + ik + rules
	// Index keys: id, type, outcome, country, session, incident, ip_key
	// twice, site three times.
	n += int64(len(e.ID)+len(e.Type)+len(e.Outcome)+len(e.Country)+len(e.Session)+len(e.Incident)+3*len(e.Site)) + 2*ik
	return n + eventOverhead
}

func incidentBytes(in *Incident) int64 {
	return int64(2*len(in.Incident)+len(in.EventID)+2*len(in.IP)+len(in.Status)+len(in.Reason)+len(joinList(in.Sources))+2*len(in.Site)) + incidentOverhead
}

// Written returns the bytes the event and incident writers handed
// to SQLite since the store was opened (estimate, see eventBytes).
func (s *Store) Written() int64 { return s.written.Load() }

// WALBytes is the size of schild.db-wal (0 when there is none).
func (s *Store) WALBytes() int64 {
	if st, err := os.Stat(s.path + "-wal"); err == nil {
		return st.Size()
	}
	return 0
}

// pageBytes is (page_count - freelist_count) * page_size.
func (s *Store) pageBytes(ctx context.Context) int64 {
	var pages, size, free int64
	_ = s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages)
	_ = s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size)
	_ = s.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free)
	return (pages - free) * size
}

// Checkpoint runs PRAGMA wal_checkpoint(TRUNCATE). A checkpoint that cannot
// finish (a reader holds an old snapshot) is not an error.
func (s *Store) Checkpoint(ctx context.Context) {
	_, _ = s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
}

// CapResult of one size-cap pass.
type CapResult struct {
	CapBytes    int64
	UsedBefore  int64
	UsedAfter   int64
	WALBytes    int64
	Calls       int            // agent_calls rows deleted
	Deleted     map[string]int // rows deleted per value class
	Unreachable bool
}

// LastCapDeleted returns when a size-cap pass last deleted events or
// incidents (zero: never since start).
func (s *Store) LastCapDeleted() time.Time {
	if n := s.capDeleted.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// Total is the number of rows deleted (call log and every class).
func (r *CapResult) Total() int {
	n := r.Calls
	for _, v := range r.Deleted {
		n += v
	}
	return n
}

// capKey orders rows of a class: write time, then id in byte order.
type capKey struct {
	t  int64
	id string
}

func (a capKey) less(b capKey) bool { return a.t < b.t || (a.t == b.t && a.id < b.id) }

type capRow struct {
	capKey
	src int
}

// capSource is one table a value class lives in. table, idCol and where
// are SQL text and only ever constants of capSources; values go in args.
type capSource struct {
	table, idCol, where string
	args                []any
	// del deletes rows by id inside tx (nil: DELETE FROM table WHERE idCol IN ...).
	del func(ctx context.Context, tx *sql.Tx, ids []string) error
}

func (c capSource) newest(ctx context.Context, db *sql.DB, n int) ([]capKey, error) {
	q := fmt.Sprintf(`SELECT time_ms, %s FROM %s WHERE %s ORDER BY time_ms DESC, %s DESC LIMIT ?`, c.idCol, c.table, c.where, c.idCol)
	rows, err := db.QueryContext(ctx, q, append(append([]any{}, c.args...), n)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []capKey
	for rows.Next() {
		var k capKey
		if err := rows.Scan(&k.t, &k.id); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (c capSource) oldest(ctx context.Context, db *sql.DB, below capKey, n, src int) ([]capRow, error) {
	q := fmt.Sprintf(`SELECT time_ms, %s FROM %s WHERE %s AND (time_ms, %s) < (?, ?) ORDER BY time_ms, %s LIMIT ?`,
		c.idCol, c.table, c.where, c.idCol, c.idCol)
	rows, err := db.QueryContext(ctx, q, append(append([]any{}, c.args...), below.t, below.id, n)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []capRow
	for rows.Next() {
		r := capRow{src: src}
		if err := rows.Scan(&r.t, &r.id); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (c capSource) delete(ctx context.Context, tx *sql.Tx, ids []string) error {
	if c.del != nil {
		return c.del(ctx, tx, ids)
	}
	return deleteIn(ctx, tx, c.table, c.idCol, ids)
}

// deleteIn deletes rows by id; table and col are constants of the callers,
// the ids are bound as "?" arguments.
func deleteIn(ctx context.Context, tx *sql.Tx, table, col string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE %s IN (%s)`, table, col, strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")), args...)
	return err
}

func eventSource(class string) capSource {
	return capSource{table: "events", idCol: "id", where: "cls = ?", args: []any{classCode[class]}}
}

// capSources lists the tables of a value class.
func capSources(class string) []capSource {
	switch class {
	case storage.ClassIncident:
		return []capSource{{table: "incidents", idCol: "incident", where: "1 = 1"}}
	}
	return []capSource{eventSource(class)}
}

// capPass is one pass over a store (see the top of this file).
type capPass struct {
	s       *Store
	ctx     context.Context
	res     *CapResult
	target  int64
	wal     int64
	measure int64 // last measured used bytes
}

// over reports whether the pass must go on deleting.
func (p *capPass) over() bool { return p.measure > p.target }

func (p *capPass) remeasure() { p.measure = p.s.pageBytes(p.ctx) + p.wal }

// SizeCap runs one size-cap pass with a cap of maxSizeMB MiB. The WAL is
// checkpointed (TRUNCATE) before and after the pass.
func (s *Store) SizeCap(ctx context.Context, maxSizeMB int) (*CapResult, error) {
	res := &CapResult{CapBytes: int64(maxSizeMB) * storage.MiB, Deleted: map[string]int{}}
	s.Checkpoint(ctx)
	defer s.Checkpoint(ctx)
	p := &capPass{s: s, ctx: ctx, res: res, wal: s.WALBytes()}
	res.WALBytes = p.wal
	p.remeasure()
	res.UsedBefore, res.UsedAfter = p.measure, p.measure
	if maxSizeMB <= 0 || res.UsedBefore <= res.CapBytes {
		return res, nil
	}
	p.target = res.CapBytes * storage.LowWaterPerMil / 1000
	if err := p.trimCalls(); err != nil {
		return res, err
	}
	for _, c := range storage.DeletionOrder {
		if !p.over() {
			break
		}
		n, err := p.trimClass(capSources(c))
		res.Deleted[c] += n
		if err != nil {
			return res, err
		}
	}
	for _, n := range res.Deleted {
		if n > 0 {
			s.capDeleted.Store(time.Now().UnixNano())
			break
		}
	}
	_, _ = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum")
	p.remeasure()
	res.UsedAfter = p.measure
	res.Unreachable = p.measure > res.CapBytes
	return res, nil
}

// trimCalls deletes the oldest agent_calls rows, at most the older half.
func (p *capPass) trimCalls() error {
	var total int
	if err := p.s.db.QueryRowContext(p.ctx, `SELECT COUNT(*) FROM agent_calls`).Scan(&total); err != nil {
		return err
	}
	left := total / 2
	for left > 0 && p.over() {
		rows, err := p.s.db.QueryContext(p.ctx, `SELECT seq FROM agent_calls ORDER BY time_ms, seq LIMIT ?`, min(left, 4*capBatch))
		if err != nil {
			return err
		}
		var ids []any
		var marks []string
		for rows.Next() {
			var seq int64
			if err := rows.Scan(&seq); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, seq)
			marks = append(marks, "?")
		}
		rows.Close()
		if len(ids) == 0 {
			return nil
		}
		// marks are "?" placeholders only.
		if _, err := p.s.db.ExecContext(p.ctx, `DELETE FROM agent_calls WHERE seq IN (`+strings.Join(marks, ",")+`)`, ids...); err != nil {
			return err
		}
		p.res.Calls += len(ids)
		left -= len(ids)
		p.remeasure()
	}
	return nil
}

// trimClass deletes the oldest rows of one class (across its tables)
// except the newest FloorRows while the pass is over the low water mark.
func (p *capPass) trimClass(srcs []capSource) (int, error) {
	// The floor: the FloorRows-th newest row of the class; only older rows
	// may go.
	var newest []capKey
	for _, c := range srcs {
		ks, err := c.newest(p.ctx, p.s.db, storage.FloorRows)
		if err != nil {
			return 0, err
		}
		newest = append(newest, ks...)
	}
	if len(newest) < storage.FloorRows {
		return 0, nil
	}
	sort.Slice(newest, func(i, j int) bool { return newest[j].less(newest[i]) })
	floor := newest[storage.FloorRows-1]
	deleted := 0
	for p.over() {
		var cand []capRow
		// limit: rows of a source past its last fetched row (when the batch
		// was full) may be older than rows of another source, so only rows
		// up to the smallest such last row are taken.
		limit, bounded := capKey{}, false
		for i, c := range srcs {
			rs, err := c.oldest(p.ctx, p.s.db, floor, capBatch, i)
			if err != nil {
				return deleted, err
			}
			if len(rs) == capBatch {
				if last := rs[len(rs)-1].capKey; !bounded || last.less(limit) {
					limit, bounded = last, true
				}
			}
			cand = append(cand, rs...)
		}
		if len(cand) == 0 {
			return deleted, nil
		}
		sort.Slice(cand, func(i, j int) bool { return cand[i].less(cand[j].capKey) })
		ids := make([][]string, len(srcs))
		n := 0
		for _, r := range cand {
			if bounded && limit.less(r.capKey) {
				break
			}
			ids[r.src] = append(ids[r.src], r.id)
			n++
		}
		if n == 0 {
			return deleted, nil
		}
		tx, err := p.s.db.BeginTx(p.ctx, nil)
		if err != nil {
			return deleted, err
		}
		for i, c := range srcs {
			if err := c.delete(p.ctx, tx, ids[i]); err != nil {
				_ = tx.Rollback()
				return deleted, err
			}
		}
		if err := tx.Commit(); err != nil {
			return deleted, err
		}
		deleted += n
		p.remeasure()
	}
	return deleted, nil
}

// CapScheduler decides when a size-cap pass is due (storage.CheckDue): at
// the first call, every storage.CheckIntervalS seconds, and as soon as the
// writers wrote a tenth of the cap since the last pass.
type CapScheduler struct {
	s        *Store
	last     time.Time
	lastSeen int64
	started  bool
}

// NewCapScheduler returns a scheduler for s.
func NewCapScheduler(s *Store) *CapScheduler { return &CapScheduler{s: s} }

// Due reports whether a pass is due at now.
func (c *CapScheduler) Due(now time.Time, maxSizeMB int) bool {
	if !c.started {
		return true
	}
	return storage.CheckDue(int64(maxSizeMB), c.s.Written()-c.lastSeen, int64(now.Sub(c.last)/time.Second))
}

// Full reports whether the timer part is due (first call or
// storage.CheckIntervalS since the last pass): the caller then runs the
// whole retention, not only the size cap.
func (c *CapScheduler) Full(now time.Time) bool {
	return !c.started || int64(now.Sub(c.last)/time.Second) >= storage.CheckIntervalS
}

// Ran notes a pass that started at now (call it before the pass, so bytes
// written during the pass count towards the next one).
func (c *CapScheduler) Ran(now time.Time) {
	c.started, c.last, c.lastSeen = true, now, c.s.Written()
}
