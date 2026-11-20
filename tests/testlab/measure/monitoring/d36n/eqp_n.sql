-- D36 re-measurement (TEST ONLY): EXPLAIN QUERY PLAN of the website reads on
-- the bulk store, the same SQL shapes as client/internal/store (alerts.go
-- alertQuery, WaveEvents, websites.go IncidentBins/IncidentsBetween,
-- events.go ListEvents with site). Literal values instead of parameters.
-- usage: sqlite3 -readonly schild.db < eqp_n.sql
.headers off
.print '== listAlerts no filter (events_alert)'
EXPLAIN QUERY PLAN SELECT * FROM events INDEXED BY events_alert WHERE site = 'shop.test' AND time_ms >= 0 AND time_ms <= 9999999999999 AND (type IN ('schild.request.blocked.v1', 'schild.behaviour.triggered.v1', 'schild.ratelimit.exceeded.v1') OR (type = 'schild.request.evaluated.v1' AND outcome = 'would_block')) ORDER BY time_ms DESC, seq DESC LIMIT 500;
.print '== listAlerts country'
EXPLAIN QUERY PLAN SELECT * FROM events INDEXED BY events_alert_country WHERE site = 'shop.test' AND country = 'ZZ' AND time_ms >= 0 AND time_ms <= 9999999999999 AND (type IN ('schild.request.blocked.v1', 'schild.behaviour.triggered.v1', 'schild.ratelimit.exceeded.v1') OR (type = 'schild.request.evaluated.v1' AND outcome = 'would_block')) ORDER BY time_ms DESC, seq DESC LIMIT 500;
.print '== listAlerts asn'
EXPLAIN QUERY PLAN SELECT * FROM events INDEXED BY events_alert_asn WHERE site = 'shop.test' AND asn = 1 AND time_ms >= 0 AND time_ms <= 9999999999999 AND (type IN ('schild.request.blocked.v1', 'schild.behaviour.triggered.v1', 'schild.ratelimit.exceeded.v1') OR (type = 'schild.request.evaluated.v1' AND outcome = 'would_block')) ORDER BY time_ms DESC, seq DESC LIMIT 500;
.print '== listAlerts path (range)'
EXPLAIN QUERY PLAN SELECT * FROM events INDEXED BY events_alert_path WHERE site = 'shop.test' AND path >= '/nothing' AND path < '/nothing' || char(255) AND time_ms >= 0 AND time_ms <= 9999999999999 AND (type IN ('schild.request.blocked.v1', 'schild.behaviour.triggered.v1', 'schild.ratelimit.exceeded.v1') OR (type = 'schild.request.evaluated.v1' AND outcome = 'would_block')) ORDER BY time_ms DESC, seq DESC LIMIT 500;
.print '== listAlerts net_class'
EXPLAIN QUERY PLAN SELECT * FROM events INDEXED BY events_alert_net WHERE site = 'shop.test' AND json_extract(CAST(body AS TEXT), '$.data.client.geo.net_class') = 'tor' AND time_ms >= 0 AND time_ms <= 9999999999999 AND (type IN ('schild.request.blocked.v1', 'schild.behaviour.triggered.v1', 'schild.ratelimit.exceeded.v1') OR (type = 'schild.request.evaluated.v1' AND outcome = 'would_block')) ORDER BY time_ms DESC, seq DESC LIMIT 500;
.print '== listAlerts rule (event_rules)'
EXPLAIN QUERY PLAN SELECT e.* FROM event_rules r JOIN events e ON e.seq = r.seq WHERE r.rule = '999999' AND r.site = 'shop.test' AND r.time_ms >= 0 AND r.time_ms <= 9999999999999 ORDER BY r.time_ms DESC, r.seq DESC LIMIT 500;
.print '== listAnnotations waves'
EXPLAIN QUERY PLAN SELECT * FROM events WHERE site = 'shop.test' AND time_ms >= 0 AND time_ms <= 9999999999999 AND type IN ('schild.distributed.detected.v1', 'schild.distributed.ended.v1') ORDER BY time_ms, seq LIMIT 200;
.print '== listAnnotations incident bins'
EXPLAIN QUERY PLAN SELECT (time_ms - 0) / 10000 AS b, COUNT(*), MIN(time_ms), MAX(time_ms), MIN(incident) FROM incidents WHERE site = 'shop.test' AND time_ms >= 0 AND time_ms < 9999999999999 GROUP BY b ORDER BY b;
.print '== listIncidents site (IncidentsBetween shape)'
EXPLAIN QUERY PLAN SELECT * FROM incidents WHERE time_ms >= 0 AND time_ms < 9999999999999 AND site = 'blog.test' ORDER BY time_ms LIMIT 100;
.print '== listEvents site'
EXPLAIN QUERY PLAN SELECT * FROM events WHERE site = 'down.test' ORDER BY seq DESC LIMIT 100;
.print '== listEvents site + rule (LIKE)'
EXPLAIN QUERY PLAN SELECT * FROM events WHERE site = 'shop.test' AND rules LIKE '%,999999,%' ESCAPE '\' ORDER BY seq DESC LIMIT 100;
.print '== counts'
SELECT 'events', COUNT(*) FROM events;
SELECT 'event_rules', COUNT(*) FROM event_rules;
SELECT 'alert events shop', COUNT(*) FROM events INDEXED BY events_alert WHERE site = 'shop.test' AND (type IN ('schild.request.blocked.v1', 'schild.behaviour.triggered.v1', 'schild.ratelimit.exceeded.v1') OR (type = 'schild.request.evaluated.v1' AND outcome = 'would_block'));
SELECT 'incidents', COUNT(*) FROM incidents;
