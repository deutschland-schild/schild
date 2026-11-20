// Package groundtruth is the authoritative record of what every request in a
// test-lab run really was. The label stripper writes one row per request keyed
// by the X-Request-Id it assigned; the evaluator reads the rows and joins them
// to the schild client's local events. The store is a single pure-Go SQLite
// file (modernc.org/sqlite, CGO_ENABLED=0) so it survives container restarts
// and can be copied into results/runs/<run_id>/ as an artifact.
package groundtruth

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/deutschland-schild/schild/testlab/internal/label"

	_ "modernc.org/sqlite"
)

// Record is one ground-truth row.
type Record struct {
	RequestID   string      `json:"request_id"`
	RecordedAt  string      `json:"recorded_at"`
	Class       label.Class `json:"class"`
	Scenario    string      `json:"scenario"`
	Source      string      `json:"source"`
	Technique   string      `json:"technique,omitempty"`
	ExpectBlock bool        `json:"expect_block"`
	Canary      string      `json:"canary,omitempty"`
	Seq         int         `json:"seq"`
	// Observed request shape, recorded by the stripper for debugging and for
	// the egress checker (host/path never leave the server, but the checker
	// needs them to recompute request shapes locally).
	Host   string `json:"host"`
	Method string `json:"method"`
	Path   string `json:"path"`
	SrcIP  string `json:"src_ip"`
	// Labelled is false when a request arrived without a valid label; such a
	// request is a finding (a generator that forgot the label, or injection).
	Labelled bool `json:"labelled"`
}

// Store is a SQLite-backed ground-truth database.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS ground_truth (
	request_id   TEXT PRIMARY KEY,
	recorded_at  TEXT NOT NULL,
	class        TEXT NOT NULL,
	scenario     TEXT NOT NULL DEFAULT '',
	source       TEXT NOT NULL DEFAULT '',
	technique    TEXT NOT NULL DEFAULT '',
	expect_block INTEGER NOT NULL DEFAULT 0,
	canary       TEXT NOT NULL DEFAULT '',
	seq          INTEGER NOT NULL DEFAULT 0,
	host         TEXT NOT NULL DEFAULT '',
	method       TEXT NOT NULL DEFAULT '',
	path         TEXT NOT NULL DEFAULT '',
	src_ip       TEXT NOT NULL DEFAULT '',
	labelled     INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS gt_class ON ground_truth(class);
`

// Open opens (and if needed creates) the ground-truth database at path.
// Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// One writer at a time keeps modernc.org/sqlite happy under concurrency.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Put inserts or replaces a record. RecordedAt defaults to now (UTC) if empty.
func (s *Store) Put(r Record) error {
	if r.RequestID == "" {
		return fmt.Errorf("groundtruth: empty request_id")
	}
	if r.RecordedAt == "" {
		r.RecordedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	_, err := s.db.Exec(`
		INSERT INTO ground_truth
			(request_id, recorded_at, class, scenario, source, technique,
			 expect_block, canary, seq, host, method, path, src_ip, labelled)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(request_id) DO UPDATE SET
			recorded_at=excluded.recorded_at, class=excluded.class,
			scenario=excluded.scenario, source=excluded.source,
			technique=excluded.technique, expect_block=excluded.expect_block,
			canary=excluded.canary, seq=excluded.seq, host=excluded.host,
			method=excluded.method, path=excluded.path, src_ip=excluded.src_ip,
			labelled=excluded.labelled`,
		r.RequestID, r.RecordedAt, string(r.Class), r.Scenario, r.Source,
		r.Technique, b2i(r.ExpectBlock), r.Canary, r.Seq, r.Host, r.Method,
		r.Path, r.SrcIP, b2i(r.Labelled))
	return err
}

// FromLabel builds a record from a parsed label and request metadata.
func FromLabel(requestID string, l label.Label, host, method, path, srcIP string) Record {
	return Record{
		RequestID: requestID, Class: l.Class, Scenario: l.Scenario,
		Source: l.Source, Technique: l.Technique, ExpectBlock: l.ExpectBlock,
		Canary: l.Canary, Seq: l.Seq, Host: host, Method: method, Path: path,
		SrcIP: srcIP, Labelled: true,
	}
}

// Get returns the record for a request id.
func (s *Store) Get(requestID string) (Record, bool, error) {
	row := s.db.QueryRow(`SELECT request_id, recorded_at, class, scenario,
		source, technique, expect_block, canary, seq, host, method, path,
		src_ip, labelled FROM ground_truth WHERE request_id=?`, requestID)
	r, err := scan(row)
	if err == sql.ErrNoRows {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return r, true, nil
}

// All returns every record ordered by seq then request_id.
func (s *Store) All() ([]Record, error) {
	rows, err := s.db.Query(`SELECT request_id, recorded_at, class, scenario,
		source, technique, expect_block, canary, seq, host, method, path,
		src_ip, labelled FROM ground_truth ORDER BY seq, request_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Count returns the number of records.
func (s *Store) Count() (int, error) {
	var n int
	return n, s.db.QueryRow(`SELECT COUNT(*) FROM ground_truth`).Scan(&n)
}

type scanner interface {
	Scan(dest ...any) error
}

func scan(sc scanner) (Record, error) {
	var r Record
	var expect, labelled int
	var class string
	err := sc.Scan(&r.RequestID, &r.RecordedAt, &class, &r.Scenario, &r.Source,
		&r.Technique, &expect, &r.Canary, &r.Seq, &r.Host, &r.Method, &r.Path,
		&r.SrcIP, &labelled)
	r.Class = label.Class(class)
	r.ExpectBlock = expect != 0
	r.Labelled = labelled != 0
	return r, err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
