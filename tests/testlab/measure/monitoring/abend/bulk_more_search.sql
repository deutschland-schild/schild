-- TEST ONLY (D36 evening re-measurement, item 7): 25,000 more alert events on
-- shop.test with path /search... (copies of existing ones, new ids, times
-- spread over the last 7 days) so the frequent path prefix matches about as
-- many alert rows as in the previous bulk store (31,879). Run on the stopped
-- bulk copy after bulk_prep_n.sh; the caller creates TEMP TABLE t_now(v).
CREATE TEMP TABLE stpl AS SELECT row_number() OVER (ORDER BY seq) - 1 AS k, * FROM events
 WHERE site = 'shop.test' AND path >= '/search' AND path < '/search' || char(255)
   AND (type IN ('schild.request.blocked.v1', 'schild.behaviour.triggered.v1', 'schild.ratelimit.exceeded.v1') OR (type = 'schild.request.evaluated.v1' AND outcome = 'would_block'));
BEGIN;
WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM c WHERE i < 24999)
INSERT INTO events(id, time_ms, type, ip, ip_key, ip_truncated, country, asn, method, host, path, status, score, outcome, rules, incident, session, ua, signal_id, summary, body, site)
SELECT lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))), 2) || '-a' || substr(lower(hex(randomblob(2))), 2) || '-' || lower(hex(randomblob(6))),
       (SELECT v FROM t_now) - 7 * 86400000 + c.i * 24000, t.type, t.ip, t.ip_key, t.ip_truncated, t.country, t.asn, t.method, t.host, t.path, t.status, t.score, t.outcome, t.rules, t.incident, t.session, t.ua, t.signal_id, t.summary, t.body, t.site
FROM c JOIN stpl t ON t.k = c.i % (SELECT count(*) FROM stpl);
COMMIT;
SELECT 'shop alerts / with /search', count(*), sum(path >= '/search' and path < '/search'||char(255)) FROM events WHERE site='shop.test'
 AND (type IN ('schild.request.blocked.v1', 'schild.behaviour.triggered.v1', 'schild.ratelimit.exceeded.v1') OR (type = 'schild.request.evaluated.v1' AND outcome = 'would_block'));
