package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Schema versions of schild.db (D75).
//
// baselineVersion is the schema of the first public release
// (0.1.0-alpha.1): baseSchema and the other *Schema constants, created at
// once in a new file. Every later change is a migration in migrations, with
// the next version number. PRAGMA user_version holds the version of a file;
// the table schema_migrations is its history.
//
// Rules for a migration: forward only, never edited after a release, plain
// SQL that works on the data of every earlier version. The *Schema constants
// stay the baseline; a new file gets the baseline and then every migration,
// so there is one path to the newest schema.
const baselineVersion = 1

// migration is one step from version-1 to version.
type migration struct {
	version int
	name    string
	sql     string
}

// migrations are the steps after the baseline, in order and without gaps:
// the first has version baselineVersion+1. Tests replace the list.
var migrations = []migration{
	{version: 2, name: "cluster_outbox", sql: outboxMigration},
}

const migrationsSchema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_ms INTEGER NOT NULL
);
`

// ErrNeedsUpgrade is returned by Open for a database of an older release:
// only the gateway's start (OpenMigrate) converts it.
var ErrNeedsUpgrade = errors.New("store: database needs an upgrade")

// latestVersion is the schema version this build works with.
func latestVersion() int {
	if n := len(migrations); n > 0 {
		return migrations[n-1].version
	}
	return baselineVersion
}

// checkMigrations refuses a list with gaps or a wrong start (a programming
// error, found by the first test that opens a store).
func checkMigrations() error {
	for i, m := range migrations {
		if m.version != baselineVersion+1+i || m.name == "" || strings.TrimSpace(m.sql) == "" {
			return fmt.Errorf("store: migration %d (%q) is out of order or empty", m.version, m.name)
		}
	}
	return nil
}

// BackupPath is where the copy of the database of schema version from is
// kept before it is upgraded.
func BackupPath(path string, from int) string {
	return fmt.Sprintf("%s.backup-v%d", path, from)
}

// schemaState reads the schema version and whether the file has tables.
func schemaState(q interface {
	QueryRow(string, ...any) *sql.Row
}) (version int, empty bool, err error) {
	var tables int
	if err := q.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return 0, false, fmt.Errorf("store: schema version: %w", err)
	}
	if err := q.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&tables); err != nil {
		return 0, false, fmt.Errorf("store: schema: %w", err)
	}
	return version, tables == 0, nil
}

// refuse returns the error for a database this build must not touch: one of
// a pre-release build (before the baseline) or one of a newer release. nil
// when the version is between the baseline and the newest.
func refuse(path string, version int, empty bool) error {
	latest := latestVersion()
	switch {
	case version == 0 && empty:
		return nil
	case version < baselineVersion:
		return fmt.Errorf("store: %s comes from a pre-release build of schild (schema version %d, older than the first release) and cannot be upgraded: "+
			"stop schild, move the file away (with its -wal and -shm files) and start again to create a new database", path, version)
	case version > latest:
		return fmt.Errorf("store: %s has schema version %d, this build of schild knows versions up to %d: the database was last used by a newer schild. "+
			"Nothing was changed. Start that newer version again, or stop schild and put back the backup it made before its upgrade (%s, as %s without -wal and -shm files)",
			path, version, latest, BackupPath(path, latest), filepath.Base(path))
	}
	return nil
}

// initSchema brings the file to the newest schema. A new or empty file gets
// the baseline and every migration. An older database is upgraded only with
// migrate set (the gateway's start); otherwise the error wraps
// ErrNeedsUpgrade and nothing is written.
func initSchema(db *sql.DB, path string, migrate bool, log *slog.Logger) error {
	if err := checkMigrations(); err != nil {
		return err
	}
	version, empty, err := schemaState(db)
	if err != nil {
		return err
	}
	if err := refuse(path, version, empty); err != nil {
		return err
	}
	latest := latestVersion()
	if version == latest {
		return nil
	}
	if !empty {
		if !migrate {
			return fmt.Errorf("%w: %s has schema version %d, this build of schild needs %d. Restart schild: `schild run` upgrades the database at start and keeps a backup copy next to it",
				ErrNeedsUpgrade, path, version, latest)
		}
		// The copy is made before the write transaction. One gateway per data
		// directory (control.Lock) keeps other writers away in between; the
		// transaction below checks the version again anyway.
		if err := backup(db, path, version); err != nil {
			return err
		}
		if log != nil {
			log.Info("upgrading schild.db: backup written", "path", path, "from_version", version, "to_version", latest, "backup", BackupPath(path, version))
		}
	}
	applied, err := upgrade(db, path, version, empty)
	if err != nil {
		if !empty {
			return fmt.Errorf("%w. The database is unchanged (still schema version %d); a copy is at %s", err, version, BackupPath(path, version))
		}
		return err
	}
	if !empty && applied > 0 {
		dropOldBackups(path, version)
		if log != nil {
			log.Info("schild.db upgraded", "path", path, "from_version", version, "to_version", latest, "migrations", applied,
				"backup", BackupPath(path, version), "note", "delete the backup once the new version runs well")
		}
	}
	return nil
}

// upgrade runs in one write transaction: the baseline in an empty file,
// then every migration above the file's version. Any error rolls all of it
// back. Two processes opening a new file at once create it once: the second
// one finds the newest version inside its transaction.
func upgrade(db *sql.DB, path string, expect int, expectEmpty bool) (applied int, err error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	version, empty, err := schemaState(tx)
	if err != nil {
		return 0, err
	}
	if err := refuse(path, version, empty); err != nil {
		return 0, err
	}
	if version == latestVersion() {
		return 0, nil // another process was faster
	}
	if version != expect || empty != expectEmpty {
		return 0, fmt.Errorf("store: %s changed while schild prepared its upgrade (schema version %d, was %d); start schild again", path, version, expect)
	}
	now := time.Now().UnixMilli()
	if empty {
		if _, err := tx.Exec(schema); err != nil {
			return 0, fmt.Errorf("store: schema: %w", err)
		}
		version = baselineVersion
	}
	// An older file of the baseline has no history table yet.
	if _, err := tx.Exec(migrationsSchema); err != nil {
		return 0, fmt.Errorf("store: schema history: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO schema_migrations(version, name, applied_ms) VALUES(?, 'baseline', ?)`, baselineVersion, now); err != nil {
		return 0, fmt.Errorf("store: schema history: %w", err)
	}
	for _, m := range migrations {
		if m.version <= version {
			continue
		}
		if _, err := tx.Exec(m.sql); err != nil {
			return 0, fmt.Errorf("store: upgrade of %s to schema version %d (%s) failed: %w", path, m.version, m.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, name, applied_ms) VALUES(?, ?, ?)`, m.version, m.name, now); err != nil {
			return 0, fmt.Errorf("store: upgrade of %s to schema version %d (%s) failed: %w", path, m.version, m.name, err)
		}
		version = m.version
		applied++
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, version)); err != nil {
		return 0, fmt.Errorf("store: schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: upgrade of %s: %w", path, err)
	}
	return applied, nil
}

// backup writes a consistent copy of the database (WAL included) to
// BackupPath, mode 0600, with VACUUM INTO. A copy left by an earlier attempt
// is replaced: the database is still at that version. Without the copy
// there is no upgrade.
func backup(db *sql.DB, path string, version int) error {
	dst := BackupPath(path, version)
	tmp := dst + ".tmp"
	fail := func(err error) error {
		_ = os.Remove(tmp)
		return fmt.Errorf("store: no backup of %s before the upgrade from schema version %d, so nothing was changed: %w "+
			"(the copy needs about as much free space as the database; free space or lower retention.max_size_mb with the old version, then start again)", path, version, err)
	}
	_ = os.Remove(tmp)
	// VACUUM INTO wants a missing or empty file; creating it first gives it
	// the mode of the database, which holds visitor addresses.
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		return fail(err)
	}
	if _, err := db.ExecContext(context.Background(), `VACUUM INTO ?`, tmp); err != nil {
		return fail(err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fail(err)
	}
	return nil
}

// dropOldBackups keeps one backup generation: after a successful upgrade
// from version keep, the copies of earlier upgrades go.
func dropOldBackups(path string, keep int) {
	old, _ := filepath.Glob(path + ".backup-v*")
	for _, p := range old {
		if p != BackupPath(path, keep) {
			_ = os.Remove(p)
		}
	}
}
