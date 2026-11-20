package monitoring

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/storage"
)

// D38: a size-cap pass that cannot reach the cap raises
// store_cap_unreachable (warning, value = used bytes, threshold = the cap);
// it clears with the condition.
func TestHintStoreCapUnreachable(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)
	var unreachable atomic.Bool
	unreachable.Store(true)
	m, err := New(Config{StoragePath: t.TempDir(), Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
		Sampler: SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: now, Version: "test"},
		Internals: func(bool) Internals {
			return Internals{EventQueueCapacity: 8192, EvalSlotsMax: 16, StoreBytes: 120 << 20, StoreMaxBytes: 100 << 20, StoreCapUnreachable: unreachable.Load()}
		},
	}, now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	find := func(at time.Time) *cm.HealthHint {
		for _, h := range m.ServerHints(at) {
			if h.Code == cm.HintStoreCapUnreachable {
				return &h
			}
		}
		return nil
	}
	m.Sample(now)
	m.Tick(now.Add(10 * time.Second)) // hints are evaluated every 10 s
	h := find(now.Add(10 * time.Second))
	if h == nil || h.Level != "warning" || h.Value == nil || *h.Value != 120<<20 || h.Threshold == nil || *h.Threshold != 100<<20 || h.Site != "" {
		t.Fatalf("%+v", h)
	}
	unreachable.Store(false)
	at := now
	for s := 0; s < 400; s += 10 {
		at = now.Add(time.Duration(s+20) * time.Second)
		m.Sample(at)
		m.Tick(at)
	}
	if h := find(at); h != nil {
		t.Fatalf("hint still active: %+v", h)
	}
}

// D38: metrics.db limits its WAL to 64 MiB.
func TestMetricsJournalSizeLimit(t *testing.T) {
	s, err := openRingStore(filepath.Join(t.TempDir(), "metrics.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	var n int64
	if err := s.db.QueryRow("PRAGMA journal_size_limit").Scan(&n); err != nil || n != storage.WALLimitBytes {
		t.Fatalf("journal_size_limit %d %v", n, err)
	}
}

// metrics.db and its -wal and -shm files are readable by the owner only,
// also when the file is new (SQLite gives -wal and -shm the database's mode).
func TestMetricsFilesPrivate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "metrics.db")
	s, err := openRingStore(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if _, err := s.db.Exec(`INSERT OR REPLACE INTO meta(k, v) VALUES('x', 'y')`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p, p + "-wal", p + "-shm"} {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := st.Mode().Perm(); m != 0o600 {
			t.Errorf("%s: mode %o, want 600", filepath.Base(f), m)
		}
	}
}

// A meta row that cannot be read is an error, not a changed layout: the
// ring's history stays (a changed layout drops the ring's tables).
func TestOpenRingReadErrorKeepsHistory(t *testing.T) {
	p := filepath.Join(t.TempDir(), "metrics.db")
	rings := RingsFor(config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14})
	s, err := openRingStore(p, rings)
	if err != nil {
		t.Fatal(err)
	}
	tbl := tableOf(rings[0].Resolution)
	if _, err := s.db.Exec(`INSERT INTO ` + tbl + ` (slot, t, core) VALUES (1, 1, x'00')`); err != nil {
		t.Fatal(err)
	}
	// A meta value that does not scan into a string stands in for a read
	// error (busy, I/O).
	if _, err := s.db.Exec(`DROP TABLE meta; CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID; INSERT INTO meta (k, v) VALUES (?, NULL)`, tbl); err != nil {
		t.Fatal(err)
	}
	s.close()
	if s2, err := openRingStore(p, rings); err == nil {
		s2.close()
		t.Fatal("open succeeded on an unreadable meta row")
	}
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ring rows %d, %v", n, err)
	}
}
