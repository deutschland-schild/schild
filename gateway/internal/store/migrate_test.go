package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withMigrations replaces the migration list for one test.
func withMigrations(t *testing.T, ms ...migration) {
	t.Helper()
	old := migrations
	migrations = ms
	t.Cleanup(func() { migrations = old })
}

// baselineDB writes a database as the first release creates it, without
// any later migration, and returns its path. With legacy set it has no
// schema_migrations table, like the builds before the migration runner.
func baselineDB(t *testing.T, legacy bool) string {
	t.Helper()
	old := migrations
	migrations = nil
	defer func() { migrations = old }()
	path := filepath.Join(t.TempDir(), "schild.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Put(ctx, "settings_overlay_v1", []byte(`{"mode":"autoblock"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirstUser(ctx, User{Name: "admin", Hash: "hash", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertEvents(ctx, []*EventRow{ev(1, "203.0.113.42", time.Now())}); err != nil {
		t.Fatal(err)
	}
	if legacy {
		if _, err := s.DB().Exec(`DROP TABLE schema_migrations`); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func userVersion(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

var testMigrations = []migration{
	{2, "kv_note", `ALTER TABLE kv ADD COLUMN note TEXT NOT NULL DEFAULT ''`},
	{3, "upgrade_marks", `CREATE TABLE upgrade_marks (id INTEGER PRIMARY KEY, mark TEXT NOT NULL); INSERT INTO upgrade_marks(mark) SELECT k FROM kv;`},
}

// The production list is in order and starts right after the baseline.
func TestMigrationListInOrder(t *testing.T) {
	if err := checkMigrations(); err != nil {
		t.Fatal(err)
	}
	withMigrations(t, migration{3, "gap", "SELECT 1"})
	if err := checkMigrations(); err == nil {
		t.Fatal("a list with a gap passed")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "schild.db")); err == nil {
		t.Fatal("opened with a broken migration list")
	}
}

// A database of the baseline (with and without the history table) is
// upgraded at the gateway's start: backup first, every migration in order,
// the data stays.
func TestMigrateFromBaseline(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			path := baselineDB(t, legacy)
			withMigrations(t, testMigrations...)
			s, err := OpenMigrate(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx := context.Background()
			if v := userVersion(t, path); v != 3 {
				t.Fatalf("user_version %d, want 3", v)
			}
			var versions string
			rows, err := s.DB().Query(`SELECT version, name FROM schema_migrations ORDER BY version`)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var v int
				var n string
				_ = rows.Scan(&v, &n)
				versions += fmt.Sprintf("%d:%s ", v, n)
			}
			rows.Close()
			if versions != "1:baseline 2:kv_note 3:upgrade_marks " {
				t.Fatalf("history %q", versions)
			}
			// Data of the old version is still there and the migrations saw it.
			if raw, err := s.Get(ctx, "settings_overlay_v1"); err != nil || string(raw) != `{"mode":"autoblock"}` {
				t.Fatalf("settings after the upgrade: %q %v", raw, err)
			}
			if !s.HasUsers(ctx) {
				t.Fatal("dashboard user lost")
			}
			var events, marks int
			_ = s.DB().QueryRow(`SELECT COUNT(*) FROM events`).Scan(&events)
			_ = s.DB().QueryRow(`SELECT COUNT(*) FROM upgrade_marks`).Scan(&marks)
			if events != 1 || marks == 0 {
				t.Fatalf("events %d, marks %d", events, marks)
			}
			// The backup is the database before the upgrade, private.
			bak := BackupPath(path, 1)
			fi, err := os.Stat(bak)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("backup mode %o, want 600", fi.Mode().Perm())
			}
			if v := userVersion(t, bak); v != 1 {
				t.Fatalf("backup has schema version %d, want 1", v)
			}
			bdb, _ := sql.Open("sqlite", "file:"+bak)
			defer bdb.Close()
			var n int
			if err := bdb.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil || n != 1 {
				t.Fatalf("backup users %d (%v)", n, err)
			}
			if err := bdb.QueryRow(`SELECT COUNT(*) FROM upgrade_marks`).Scan(&n); err == nil {
				t.Fatal("backup already has the new table")
			}
			// Opening again changes nothing and writes no further backup.
			s2, err := OpenMigrate(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			s2.Close()
			if m, _ := filepath.Glob(path + ".backup*"); len(m) != 1 {
				t.Fatalf("backups %v", m)
			}
		})
	}
}

// A new file gets the baseline and every migration, without a backup.
func TestMigrateNewFile(t *testing.T) {
	withMigrations(t, testMigrations...)
	path := filepath.Join(t.TempDir(), "schild.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v := userVersion(t, path); v != 3 {
		t.Fatalf("user_version %d", v)
	}
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("history rows %d (%v)", n, err)
	}
	if m, _ := filepath.Glob(path + ".backup*"); len(m) != 0 {
		t.Fatalf("backup of a new file: %v", m)
	}
}

// Commands next to a running gateway never upgrade: Open refuses an older
// database with ErrNeedsUpgrade and leaves it alone.
func TestOpenDoesNotMigrate(t *testing.T) {
	path := baselineDB(t, true)
	withMigrations(t, testMigrations...)
	s, err := Open(path)
	if err == nil {
		s.Close()
		t.Fatal("Open upgraded or accepted an older database")
	}
	if !errors.Is(err, ErrNeedsUpgrade) || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "schild run") {
		t.Fatalf("error %v", err)
	}
	if v := userVersion(t, path); v != 1 {
		t.Fatalf("user_version %d after the refusal", v)
	}
	if m, _ := filepath.Glob(path + ".backup*"); len(m) != 0 {
		t.Fatalf("backup written by Open: %v", m)
	}
}

// A failing migration rolls everything back, also the steps before it; the
// backup stays and the old build still opens the database.
func TestMigrateFailureRollsBack(t *testing.T) {
	path := baselineDB(t, true)
	withMigrations(t, testMigrations[0], migration{3, "broken", `CREATE TABLE half (id INTEGER); INSERT INTO no_such_table VALUES(1);`})
	s, err := OpenMigrate(path, nil)
	if err == nil {
		s.Close()
		t.Fatal("opened after a failed migration")
	}
	for _, want := range []string{"schema version 3", "broken", "unchanged", BackupPath(path, 1)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if v := userVersion(t, path); v != 1 {
		t.Fatalf("user_version %d after the rollback", v)
	}
	db, _ := sql.Open("sqlite", "file:"+path)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('half', 'schema_migrations')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d tables of the failed upgrade stayed (%v)", n, err)
	}
	if err := db.QueryRow(`SELECT note FROM kv LIMIT 1`).Scan(new(string)); err == nil {
		t.Fatal("column of the first migration stayed")
	}
	db.Close()
	if _, err := os.Stat(BackupPath(path, 1)); err != nil {
		t.Fatal(err)
	}
	withMigrations(t)
	s, err = Open(path)
	if err != nil {
		t.Fatalf("the old build no longer opens the database: %v", err)
	}
	s.Close()
}

// A database of a newer release is refused and not touched, by both ways
// of opening.
func TestNewerDatabaseRefused(t *testing.T) {
	withMigrations(t, testMigrations...)
	path := filepath.Join(t.TempDir(), "schild.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	withMigrations(t, testMigrations[0])
	for _, migrate := range []bool{false, true} {
		s, err := openDB(path, migrate, nil)
		if err == nil {
			s.Close()
			t.Fatalf("migrate %v: a newer database opened", migrate)
		}
		if errors.Is(err, ErrNeedsUpgrade) || !strings.Contains(err.Error(), "newer schild") || !strings.Contains(err.Error(), path) ||
			!strings.Contains(err.Error(), "schema version 3") {
			t.Fatalf("migrate %v: %v", migrate, err)
		}
		if v := userVersion(t, path); v != 3 {
			t.Fatalf("user_version %d", v)
		}
	}
	if m, _ := filepath.Glob(path + ".backup*"); len(m) != 0 {
		t.Fatalf("backup of a refused database: %v", m)
	}
}

// Without a backup there is no upgrade.
func TestMigrateNeedsBackup(t *testing.T) {
	path := baselineDB(t, true)
	withMigrations(t, testMigrations...)
	// A directory in the place of the backup makes the rename fail.
	if err := os.MkdirAll(filepath.Join(BackupPath(path, 1), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenMigrate(path, nil)
	if err == nil {
		s.Close()
		t.Fatal("upgraded without a backup")
	}
	if !strings.Contains(err.Error(), "no backup") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("error %v", err)
	}
	if v := userVersion(t, path); v != 1 {
		t.Fatalf("user_version %d", v)
	}
	if _, err := os.Stat(BackupPath(path, 1) + ".tmp"); err == nil {
		t.Fatal("partial backup left behind")
	}
}

// One backup generation: the copy of an earlier upgrade goes with the next.
func TestMigrateKeepsOneBackup(t *testing.T) {
	path := baselineDB(t, true)
	withMigrations(t, testMigrations[0])
	s, err := OpenMigrate(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	withMigrations(t, testMigrations...)
	if s, err = OpenMigrate(path, nil); err != nil {
		t.Fatal(err)
	}
	s.Close()
	m, _ := filepath.Glob(path + ".backup*")
	if len(m) != 1 || m[0] != BackupPath(path, 2) {
		t.Fatalf("backups %v, want only %s", m, BackupPath(path, 2))
	}
}
