# Storage bounds (contracts v0.5, D38)

What the gateway guarantees about the disk it uses, and what operators and agents see when a bound is reached. Decided by the initiator on 2026-10-29 from the audit `tests/results/storage-bounds-audit-2026-10-29.md` (all eight fixes approved), recorded in [DECISIONS](DECISIONS.md) D38. Go: `contract/storage`; vectors `storage-bounds` (input [storage-bounds.schema.json](storage-bounds.schema.json)), cross-checked by `tools/crosscheck.py`. Every rule is integer arithmetic so both implementations agree byte for byte.

## 1. Size cap of schild.db

`retention.max_size_mb` (10 to 100 000, default 100) bounds `schild.db`. **Used bytes** = (page_count − freelist_count) × page_size of `schild.db` + the size of `schild.db-wal`.

- **When a pass runs** (`storage.CheckDue`, op `check_due`): at start, at least every 600 s, and as soon as the event and incident writers wrote `max_size_mb × 1 MiB / 10` bytes since the last pass (whichever comes first). The writers count the bytes they hand to SQLite (row payload and index keys); the timer alone is not enough (a flood wrote 89 MB in 3 minutes during D36).
- **Guarantee:** between two passes `schild.db` exceeds the cap by at most one check step (10 %) plus one write batch. Measured by the gateway builder: a flood that writes 3 × the cap within 10 minutes ends at most 10 % above the cap.
- **WAL:** `PRAGMA journal_size_limit = 67108864` (64 MiB, `storage.WALLimitBytes`) on `schild.db` and `metrics.db`. Every pass starts and ends with `PRAGMA wal_checkpoint(TRUNCATE)`; the WAL left after the first checkpoint counts against the cap.
- **What a pass deletes** (`storage.CapPass`, op `cap_pass`): nothing while used ≤ cap. Above the cap it deletes until used ≤ 95 % of the cap (`LowWaterPerMil`), in this order:
  1. the agent API call log (`agent_calls`), oldest first, at most its older half per pass (it was wiped before);
  2. then by value class, each oldest first (write time, then id in byte order), never the newest `FloorRows` (100) rows of a class:

| # | Class | Rows |
| --- | --- | --- |
| 1 | `sampled` | request events with `sampled: true` (unremarkable requests, requests stopped by a running block) |
| 2 | `logged` | other request events with outcome `passed` or `logged`, `session.flagged`, `environment.anomaly` |
| 3 | `would_block` | request events with outcome `would_block`; `behaviour.triggered` and `ratelimit.exceeded` with action `observe` |
| 4 | `blocked` | request events with outcome `blocked` or `challenged`; enforced `behaviour.triggered` and `ratelimit.exceeded` |
| 5 | `incident` | rows of `incidents` (aggregated, section 3) |
| 6 | `record` | waves (`distributed.*`), rule changes (`rule.*`), `request.unblocked`, `environment.changed`, `advisory.assessed`, `dashboard.access_reset` and every later event type |

  The mapping is `storage.ClassOfEvent`. Nothing else is deleted by the cap: summaries, settings, users, sessions, exceptions, allowlist, `config_changes` (1000 rows) and `kept_blocks` count as used bytes but have their own bounds (section 4).
- **When the cap cannot be reached:** when every class is at its floor and used is still above the cap, the pass stops there (`unreachable`) instead of deleting everything. The gateway raises the hint **`store_cap_unreachable`** (level warning, value = used bytes, threshold = the cap) and logs one warning per hour at most. Age retention (`events_days`) still applies to every row.
- **Hints:** `store_near_cap` (unchanged: used ≥ 90 % of the cap), `store_cap_unreachable` and `storage_budget` (section 2) are about schild's own store: they mark only the server, never its websites (`websites.ServerOnlyHintCodes`, vectors `website-status`).

## 2. Disk budget

`storage.Budget` (op `disk_budget`): the sum of every bound schild keeps on `storage.path`:

budget = cap + cap / 10 (overshoot) + 2 × 64 MiB (both WAL limits) + `monitoring.MetricsBoundBytes` (0 with monitoring off) + `monitoring.requests.max_size_mb` × 1 MiB (0 with the request ring off) + `waf.body.max_in_flight_bytes` (D41, section 8)

Compared with the file system of `storage.path` (statfs: total = f_blocks × f_frsize, available = f_bavail × f_frsize) and what the bounded files use now (used = `schild.db`, `metrics.db`, both WALs, the request ring segments):

- **error** when budget > total: `schild preflight` and `schild run` refuse to start, contract code `config`, pointer `/retention/max_size_mb` (the audit's example: `max_size_mb: 100000` on a 20 GB disk; for a small disk also lower `waf.body.max_in_flight_bytes`).
- **hint `storage_budget`** (notice, object = `storage.path`) when available − max(0, budget − used) < reserve, reserve = max(1 GiB, min(5 % of total, 20 GiB)) (`storage.Reserve`; the 20 GiB cap since 2026-10-29, so a large disk does not get a reserve of 5 %, e.g. 102 GiB on 2 TiB): filling the caps would eat the space everything else needs. Checked at start and once an hour. The dashboard settings page shows budget, used and available.
- **ok** otherwise.

Caddy access logs and host logs are not in the budget; the host check covers them (section 6).

## 3. Incident aggregation

A flood of WAF blocks used to write one incident row per request. From v0.5 (`storage.Aggregate`, op `incident_aggregate`):

- **Key:** client key of the behaviour engine (IPv4 address, IPv6 /64), rule key, UTC minute (`t − t mod 60 000`). Rule key: `limit:<code>` for a request-limit block, else the sorted, de-duplicated rule ids that caused the block joined with `,` (`storage.RuleKey`).
- **Numbers on the block page:** the first blocked request of a key draws a fresh incident number and creates the row (count 1, first and last seen = its time). Every later request of the same key shows **the same number** on its block page, and its event carries it; the row's `count` grows and `last_seen` (and, for requests within the minute arriving out of order, `first_seen`) widen. A number a visitor reports therefore always finds its incident (`GET /incidents/{number}` returns the aggregate: `count`, `first_seen`, `last_seen`; `request` is the first request).
- **Closing:** a request of a later minute than any before closes every open aggregate. A request of an earlier (closed) minute gets its own incident.
- **Bound:** at most `MaxOpenAggregates` (65 536) open keys in memory. With every slot taken a new key gets a single-request incident: never dropped, only not aggregated.
- Behaviour and rate-limit blocks keep one incident per block (they were never per request).

## 4. Other bounded tables (no vectors)

- `kept_blocks`: every pass deletes rows with `until` in the past; a long block evicted from memory is also deleted from the table (`Unpersist`).
- `review` and allowlist rows past their expiry are deleted by every pass.
- `agent_calls`: trimmed to its newer half at the cap (section 1), never wiped.
- Ended behaviour blocks are evicted before running ones when a behaviour table is full.

## 5. Process logs

Every warning a request or event can trigger (`incident queue full`, `kept behaviour block queue full`, `panic recovered`, `write events`) is rate-limited per message: the first occurrence is logged, then at most one line per minute with the number suppressed since the last line (`"… (n suppressed)"`). Documented behaviour, no contract type. The Kamal runbook and `docker-compose.example.yml` set `logging: {options: {max-size: 10m, max-file: "5"}}`.

## 6. Caddy logs and the host

- `schild ingress validate` warns for every Caddyfile log `output file <path>` with `roll_disabled`: code **`log_roll_disabled`** (`storage.WarnLogRollDisabled`), message key `ingress.warn.log_roll_disabled`, printed as `log_roll_disabled: output file <path> uses roll_disabled; the embedded Caddy does not reopen it, so the logrotate rule needs copytruncate (schild check: logs.logrotate_config)`. A warning, never an error.
- The host check (MVP-11 addendum "Log-Hygiene", area `logs`, [host-check.md](host-check.md)) reports unbounded Docker logs, the journal size, missing, stale or broken logrotate and large unrotated files, with `fix_config` snippets from gateway templates.

## 7. disk_fill_projection (MVP-21 hint)

`storage.Projection` (op `disk_projection`), per mount, from the existing 10-minute ring of `server.disk_used` (no new sampling):

- daily minimum of each of the last 7 complete UTC days; a day counts with at least 36 of its 144 points;
- fewer than 4 counted days: no hint;
- steady growth: at least two thirds of the steps between consecutive counted days rise (a one-off copy is one step: no hint);
- rate = Theil-Sen slope: the lower median of the slopes (bytes per day) of every pair of counted days;
- rate ≤ 0: no hint; else days_left = floor((total − used now) / rate);
- **hint** when days_left < 14: level warning under 3 days, else notice; object = mount, value = days_left. Like `disk_full_soon` it reaches every website on the server.

Text (de): „{mount} ist in etwa {tage} Tagen voll, wenn es so weitergeht wie in den letzten 7 Tagen (+{rate} pro Tag). Unter „Server“ siehst du große Logdateien.“

## 8. Temp space of bodies (D41)

- Bodies that do not fit in memory spool to `<storage.path>/tmp` (`bodylimit.TempDir`), mode 0700, so they count against the file system of the budget. The gateway sets `TMPDIR` to it: Coraza ignores `SecTmpDir`.
- `waf.body.max_in_flight_bytes` bounds this space ([body-limits.md](body-limits.md) section 2) and is the term `body_spool_bytes` of `disk_budget`. Absent in the op: not counted, so earlier vectors stay.
- **At start, before the first request,** the gateway removes the files `body*` and `crzmp*` (`bodylimit.TempFilePrefixes`) from that directory: an earlier process may have ended without closing its transactions. The content is visitor data, so nothing else may keep it.
- A body is stored here only during its request (D14 as amended by D41). No event, incident or log holds its content.
