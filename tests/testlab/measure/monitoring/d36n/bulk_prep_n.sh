#!/bin/sh
# D36 re-measurement (TEST ONLY): build the bulk store for the latency
# measurement from a COPY of the stopped main instance's data dir.
#
# usage: bulk_prep_n.sh <main data dir> <bulk dir>
#
# 1. copies schild.db (+ wal) of the stopped main instance into <bulk dir>/data
# 2. drops event_rules (table, index, trigger) so the gateway's own
#    migration (store/alerts.go migrateAlerts, the path of a database of an
#    earlier build) backfills it for the bulk events on the next start;
#    bulk_d36.sql writes events with plain SQL, which bypasses the
#    event_rules insert of InsertEvents
# 3. runs bulk_d36.sql (1,000,000 events, 50,000 incidents)
# The caller then starts schild on <bulk dir> (startup time = migration).
set -eu
SRC=$1
DST=$2
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$DST/data"
cp "$SRC/schild.db" "$DST/data/schild.db"
[ -f "$SRC/schild.db-wal" ] && cp "$SRC/schild.db-wal" "$DST/data/schild.db-wal" || true
sqlite3 "$DST/data/schild.db" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
sqlite3 "$DST/data/schild.db" "DROP TRIGGER IF EXISTS event_rules_delete; DROP INDEX IF EXISTS event_rules_seq; DROP TABLE IF EXISTS event_rules;"
NOW=$(python3 -c 'import time; print(int(time.time()*1000))')
{ echo "CREATE TEMP TABLE t_now(v); INSERT INTO t_now VALUES($NOW);"; cat "$HERE/bulk_d36.sql"; } | sqlite3 "$DST/data/schild.db"
sqlite3 "$DST/data/schild.db" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
ls -l "$DST/data"
