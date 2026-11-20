-- TEST ONLY (D36 measurement): 1,000,000 synthetic events and 50,000
-- synthetic incidents in a COPY of schild.db of the measurement instance
-- (gateway stopped). Events are copies of the replayed events with new ids,
-- shifted times (500,000 over the last 24 h, 500,000 over the 6 days before)
-- and the site of the template (so every website keeps its own mix of
-- request, detection and rate-limit events); inserted oldest first, so seq
-- order is time order as in a real store (retention deletes by seq).
-- Run the instance with storage.retention.max_size_mb large enough. Incidents: copies with site
-- spread over the five websites, one every 12 s over 7 days.
-- The caller creates TEMP TABLE t_now(v) with the current Unix ms.
PRAGMA journal_mode=WAL;
PRAGMA synchronous=OFF;
CREATE TEMP TABLE tpl AS SELECT row_number() OVER (ORDER BY seq) - 1 AS k, * FROM events;
CREATE TEMP TABLE ntpl AS SELECT count(*) AS n FROM tpl;
BEGIN;
WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM c WHERE i < 999999)
INSERT INTO events(id, time_ms, type, ip, ip_key, ip_truncated, country, asn, method, host, path, status, score, outcome, rules, incident, session, ua, signal_id, summary, body, site)
SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))), 2) || '-' ||
       substr('89ab', 1 + abs(random()) % 4, 1) || substr(lower(hex(randomblob(2))), 2) || '-' || lower(hex(randomblob(6))),
       CASE WHEN (999999 - c.i) < 500000 THEN (SELECT v FROM t_now) - 5000 - (999999 - c.i) * 172
            ELSE (SELECT v FROM t_now) - 86400000 - 5000 - ((999999 - c.i) - 500000) * 1036 END,
       t.type, t.ip, t.ip_key, t.ip_truncated, t.country, t.asn, t.method, t.host, t.path, t.status, t.score, t.outcome, t.rules, t.incident, t.session, t.ua, t.signal_id, t.summary, t.body, t.site
FROM c JOIN tpl t ON t.k = c.i % (SELECT n FROM ntpl);
COMMIT;
CREATE TEMP TABLE itpl AS SELECT row_number() OVER (ORDER BY time_ms) - 1 AS k, * FROM incidents;
BEGIN;
WITH RECURSIVE c0(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM c0 WHERE i < 49999),
c(i, v) AS (SELECT i, (i * 2654435761 + 977) % 1099511627776 FROM c0)
INSERT OR IGNORE INTO incidents(incident, event_id, time_ms, ip, status, network_rule, reason, sources, unblocked_ms, allowlist_entry, feedback_id, site)
SELECT substr('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 1 + ((c.v >> 0) & 31), 1) || substr('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 1 + ((c.v >> 5) & 31), 1) || substr('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 1 + ((c.v >> 10) & 31), 1) || substr('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 1 + ((c.v >> 15) & 31), 1) || '-' || substr('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 1 + ((c.v >> 20) & 31), 1) || substr('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 1 + ((c.v >> 25) & 31), 1) || substr('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 1 + ((c.v >> 30) & 31), 1) || substr('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 1 + ((c.v >> 35) & 31), 1),
       t.event_id, (SELECT v FROM t_now) - 5000 - c.i * 12000, t.ip, t.status, t.network_rule, t.reason, t.sources, t.unblocked_ms, t.allowlist_entry, t.feedback_id,
       CASE c.i % 5 WHEN 0 THEN 'shop.test' WHEN 1 THEN 'blog.test' WHEN 2 THEN 'app.test' WHEN 3 THEN 'slow.test' ELSE 'down.test' END
FROM c JOIN itpl t ON t.k = c.i % (SELECT count(*) FROM itpl);
COMMIT;
SELECT 'events', count(*), min(time_ms), max(time_ms) FROM events;
SELECT 'events per site', site, count(*) FROM events GROUP BY site;
SELECT 'events per type', type, count(*) FROM events GROUP BY type;
SELECT 'incidents', count(*) FROM incidents;
