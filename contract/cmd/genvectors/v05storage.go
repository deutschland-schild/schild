//go:build !release

package main

import (
	"fmt"
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/storage"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D38 (initiator, 2026-10-29): storage bounds. When the schild.db size cap
// runs, what it deletes first, when it stops and raises a hint, the disk
// budget, incident aggregation and the MVP-21 hint disk_fill_projection.
// Appended after D37.

const (
	kib = int64(1 << 10)
	mib = int64(1 << 20)
	gib = int64(1 << 30)
)

func genStorageBounds(g *gen) {
	const c = "storage-bounds"
	ctx := vectors.Context{}
	type M = map[string]any
	ok := func(name, desc string, m M) {
		res, err := storage.RunVector(mustJSON(m))
		if err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, res)
	}
	bad := func(name, desc string, m M) {
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(m), m)
	}
	t0 := int64(1793016000000) // 2026-10-26T12:00:00Z
	ev := func(id, typ string, t, b int64, kv ...any) M {
		m := M{"id": id, "kind": "event", "type": typ, "t": t, "bytes": b}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	req := func(id, outcome string, t, b int64, sampled bool) M {
		typ := "schild.request.evaluated.v1"
		if outcome == "blocked" {
			typ = "schild.request.blocked.v1"
		}
		m := ev(id, typ, t, b, "outcome", outcome)
		if sampled {
			m["sampled"] = true
		}
		return m
	}
	row := func(id, kind string, t, b int64) M { return M{"id": id, "kind": kind, "t": t, "bytes": b} }
	capPass := func(maxMB, base, wal int64, floor int, rows ...M) M {
		rs := []any{}
		for _, r := range rows {
			rs = append(rs, r)
		}
		return M{"op": "cap_pass", "max_size_mb": maxMB, "base_bytes": base, "wal_bytes": wal, "floor_rows": floor, "rows": rs}
	}

	// When a pass runs.
	due := func(mb, written, elapsed int64) M {
		return M{"op": "check_due", "max_size_mb": mb, "written_bytes": written, "elapsed_s": elapsed}
	}
	ok("due-by-bytes", "D38: a pass runs as soon as the writers wrote a tenth of the cap (10 MiB of 100 MB), long before the 10-minute timer.", due(100, 10*mib, 30))
	ok("not-due", "D38: one byte below a tenth of the cap and one second before 10 minutes: no pass yet.", due(100, 10*mib-1, 599))
	ok("due-by-time", "D38: nothing written, but 10 minutes passed: the timer runs the pass (age retention and the WAL checkpoint).", due(100, 0, 600))
	ok("due-large-cap", "D38: with the largest cap (100000 MB) the byte step is 10000 MiB; 9 GiB written within 2 minutes is not due yet.", due(100000, 9*gib, 120))

	// What a pass deletes.
	rows := []M{ev("rule-change", "schild.rule.repository_updated.v1", t0, 1*kib), ev("rule-switch", "schild.rule.repository_switched.v1", t0+1, 1*kib)}
	for i := 0; i < 12; i++ {
		rows = append(rows, req(fmt.Sprintf("passed-%02d", i), "passed", t0+1000+int64(i), 1*mib, true))
	}
	ok("under-cap", "D38: used bytes at or below the cap: the pass deletes nothing.", capPass(100, 2*mib, 1*mib, 1, rows...))
	ok("flood-of-passed-keeps-rule-change", "D38: a flood of sampled passed requests over a 10 MB cap: the pass deletes the oldest samples down to 95 % of the cap; the older rule changes stay (the earlier oldest-first pass deleted them first).", capPass(10, 1*mib, 0, 1, rows...))
	ok("value-order", "D38: deletion by value, not by age: sampled requests, then logged, then would_block, then blocked, then incidents, then records last, each class oldest first. The blocked request is the oldest row and still goes after every cheaper class.",
		capPass(10, 0, 0, 0,
			req("blocked-old", "blocked", t0, 2*mib, false),
			ev("wave", "schild.distributed.detected.v1", t0+1, 2*mib, "action", "observe"),
			row("incident-1", "incident", t0+2, 2*mib),
			ev("rule-change", "schild.rule.repository_updated.v1", t0+3, 2*mib),
			req("would-1", "would_block", t0+4, 2*mib, false),
			req("logged-1", "logged", t0+5, 2*mib, false),
			req("sampled-1", "passed", t0+6, 2*mib, true),
			req("blocked-new", "blocked", t0+7, 2*mib, false)))
	inc := []M{req("logged-a", "logged", t0, 100*kib, false), req("logged-b", "passed", t0+1, 100*kib, false), req("logged-c", "logged", t0+2, 100*kib, false)}
	for i := 0; i < 15; i++ {
		inc = append(inc, row(fmt.Sprintf("incident-%02d", i), "incident", t0+10+int64(i), 1*mib))
	}
	ok("incident-flood-keeps-events", "D38: incidents count against the cap. A flood of incidents never leaves 0 events: the newest floor_rows events of a class stay; the oldest incidents go once the cheaper classes are at their floor. A passed request that is not a sample is logged class.", capPass(10, 0, 0, 2, inc...))
	rec := []M{}
	for i := 0; i < 8; i++ {
		rec = append(rec, ev(fmt.Sprintf("rule-%d", i), "schild.rule.repository_updated.v1", t0+int64(i), 5*mib/2))
	}
	ok("cap-unreachable", "D38: when the rows above the floor are gone and used is still over the cap, the pass stops (unreachable: hint store_cap_unreachable, one rate-limited warning) instead of deleting everything.", capPass(10, 0, 0, 5, rec...))
	calls := []M{}
	for i := 0; i < 10; i++ {
		calls = append(calls, row(fmt.Sprintf("call-%02d", i), "agent_call", t0+int64(i), 512*kib))
	}
	for i := 0; i < 6; i++ {
		calls = append(calls, req(fmt.Sprintf("sample-%d", i), "passed", t0-100+int64(i), 1*mib, true))
	}
	ok("agent-calls-trimmed", "D38: the agent API call log is trimmed (oldest first, at most its older half per pass) before any event goes, instead of being wiped.", capPass(10, 0, 0, 0, calls...))
	calls2 := append([]M(nil), calls...)
	for i := 0; i < 4; i++ {
		calls2 = append(calls2, req(fmt.Sprintf("logged-%d", i), "logged", t0-200+int64(i), 1*mib, false))
	}
	ok("agent-calls-half-then-events", "D38: the call log loses at most half per pass (5 of 10); then the samples go, then logged requests.", capPass(10, 0, 0, 0, calls2...))
	ok("wal-counts", "D38: the WAL left after the starting checkpoint counts against the cap (journal_size_limit bounds it at 64 MiB).",
		capPass(10, 6*mib, 3*mib, 0, req("s-1", "passed", t0, 1*mib, true), req("s-2", "passed", t0+1, 1*mib, true), req("l-1", "logged", t0+2, 1*mib, false)))
	ok("behaviour-observe-before-enforced", "D38: a behaviour or rate-limit event that only observed (action observe) is would_block class and goes before an enforced one; a flagged session is logged class.",
		capPass(10, 0, 0, 0,
			ev("ratelimit-block", "schild.ratelimit.exceeded.v1", t0, 4*mib, "action", "block"),
			ev("behaviour-observe", "schild.behaviour.triggered.v1", t0+1, 4*mib, "action", "observe"),
			ev("session", "schild.session.flagged.v1", t0+2, 4*mib),
			ev("reset", "schild.dashboard.access_reset.v1", t0+3, 4*mib)))
	ok("same-time-by-id", "D38: rows of one class written in the same millisecond go in id order (byte order).",
		capPass(10, 0, 0, 0, req("b", "passed", t0, 4*mib, true), req("a", "passed", t0, 4*mib, true), req("c", "passed", t0, 4*mib, true)))
	ok("blocked-sample-is-sample", "D38: a request stopped by a running block is recorded as a sample and goes with the samples, before a would_block request.",
		capPass(10, 0, 0, 0, req("would", "would_block", t0, 6*mib, false), req("stopped", "blocked", t0+1, 6*mib, true)))

	// Disk budget.
	budget := func(mb, metrics, reqMB, total, avail, used int64) M {
		return M{"op": "disk_budget", "max_size_mb": mb, "metrics_bound_bytes": metrics, "requests_max_size_mb": reqMB,
			"fs_total_bytes": total, "fs_avail_bytes": avail, "schild_used_bytes": used}
	}
	ok("budget-default-fits", "D38: defaults (100 MB cap, metrics.db bound 79 MiB without websites, request ring 512 MB) on a 40 GiB disk with 30 GiB free: ok.", budget(100, 79*mib, 512, 40*gib, 30*gib, 50*mib))
	ok("budget-hint", "D38: a 10 GB cap on a 20 GiB disk with 9 GiB free: growing to the caps would leave less than the 1 GiB reserve: hint storage_budget.", budget(10000, 79*mib, 512, 20*gib, 9*gib, 1*gib))
	ok("budget-error", "D38: max_size_mb 100000 on a 20 GiB disk: the caps alone exceed the file system; preflight refuses to start (config, /retention/max_size_mb).", budget(100000, 79*mib, 512, 20*gib, 15*gib, 0))
	ok("budget-reserve-percent", "D38: on a 100 GiB file system the reserve is 5 % (5 GiB), not 1 GiB.", budget(20000, 374*mib, 4096, 100*gib, 30*gib, 2*gib))
	ok("budget-already-used", "D38: files that already use their caps need nothing more: the free space only has to cover the rest.", budget(1000, 79*mib, 0, 10*gib, 2*gib, 1300*mib))

	// Incident aggregation.
	breq := func(client string, rules []string, limit string, t int64, draw string) M {
		m := M{"client": client, "t": t, "draw": draw}
		if limit != "" {
			m["limit"] = limit
		} else {
			rs := []any{}
			for _, r := range rules {
				rs = append(rs, r)
			}
			m["rules"] = rs
		}
		return m
	}
	agg := func(maxOpen int, rs ...M) M {
		a := []any{}
		for _, r := range rs {
			a = append(a, r)
		}
		return M{"op": "incident_aggregate", "max_open": maxOpen, "requests": a}
	}
	sqli := []string{"942100"}
	draws := []string{"K7QM-4XWD", "A2BC-3DEF", "H4JK-5LMN", "P6QR-7STU", "V8WX-9YZA", "B2CD-3EFG", "J4KL-5MNP", "Q6RS-7TUV", "W8XY-9ZAB", "C2DE-3FGH"}
	ok("aggregate-flood", "D38: five blocked requests of one client for one rule within a minute are one incident (count 5, first and last seen); every block page shows its number K7QM-4XWD.",
		agg(65536, breq("c1", sqli, "", t0+1000, draws[0]), breq("c1", sqli, "", t0+2000, draws[1]), breq("c1", sqli, "", t0+3000, draws[2]), breq("c1", sqli, "", t0+59000, draws[3]), breq("c1", sqli, "", t0+59999, draws[4])))
	ok("aggregate-per-client-and-rule", "D38: another client or another rule key is another incident.",
		agg(65536, breq("c1", sqli, "", t0, draws[0]), breq("c2", sqli, "", t0+1, draws[1]), breq("c1", []string{"941100"}, "", t0+2, draws[2]), breq("c2", sqli, "", t0+3, draws[3])))
	ok("aggregate-minute-boundary", "D38: the next UTC minute starts a new incident and closes the open ones.",
		agg(65536, breq("c1", sqli, "", t0+59999, draws[0]), breq("c1", sqli, "", t0+60000, draws[1]), breq("c1", sqli, "", t0+60001, draws[2])))
	ok("aggregate-rule-set-order", "D38: the rule key is the sorted set of rule ids: order and repeats do not matter.",
		agg(65536, breq("c1", []string{"942100", "941100"}, "", t0, draws[0]), breq("c1", []string{"941100", "942100", "941100"}, "", t0+5, draws[1])))
	ok("aggregate-limit", "D38: a request-limit block has the rule key limit:<code>, apart from WAF rules.",
		agg(65536, breq("c1", nil, "body_size", t0, draws[0]), breq("c1", nil, "body_size", t0+10, draws[1]), breq("c1", sqli, "", t0+20, draws[2])))
	ok("aggregate-open-cap", "D38: with every open slot taken, a new key gets a single-request incident (never dropped, only not aggregated); the open one keeps aggregating.",
		agg(1, breq("c1", sqli, "", t0, draws[0]), breq("c2", sqli, "", t0+1, draws[1]), breq("c2", sqli, "", t0+2, draws[2]), breq("c1", sqli, "", t0+3, draws[3])))
	ok("aggregate-late-request", "D38: a request of an earlier minute arriving after a newer one gets its own incident (its minute is closed).",
		agg(65536, breq("c1", sqli, "", t0+60000, draws[0]), breq("c1", sqli, "", t0+59000, draws[1]), breq("c1", sqli, "", t0+60500, draws[2])))

	// disk_fill_projection.
	proj := func(total, used int64, mins []int64, samples []int) M {
		ds := []any{}
		for i := range mins {
			ds = append(ds, M{"min_used_bytes": mins[i], "samples": samples[i]})
		}
		return M{"op": "disk_projection", "total_bytes": total, "used_bytes": used, "days": ds}
	}
	full := []int{144, 144, 144, 144, 144, 144, 144}
	ok("projection-steady", "D38 (MVP-21): steady growth of 2 GiB a day, 20 GiB left: full in about 10 days, hint notice.",
		proj(100*gib, 80*gib, []int64{66 * gib, 68 * gib, 70 * gib, 72 * gib, 74 * gib, 76 * gib, 78 * gib}, full))
	ok("projection-warning", "D38 (MVP-21): 5 GiB a day with 12 GiB left: 2 days, hint warning.",
		proj(100*gib, 88*gib, []int64{55 * gib, 60 * gib, 65 * gib, 70 * gib, 75 * gib, 80 * gib, 85 * gib}, full))
	ok("projection-sawtooth", "D38 (MVP-21): backups and log rotation make a daily sawtooth; the daily minima stay flat: no hint.",
		proj(100*gib, 90*gib, []int64{60 * gib, 60*gib + 10*mib, 60 * gib, 60*gib + 5*mib, 60 * gib, 60*gib + 20*mib, 60 * gib}, full))
	ok("projection-one-off-copy", "D38 (MVP-21): a one-off copy of 30 GiB on day 4 is one rising step, not steady growth: no hint.",
		proj(100*gib, 92*gib, []int64{60 * gib, 60 * gib, 60 * gib, 90 * gib, 90 * gib, 90 * gib, 90 * gib}, full))
	ok("projection-restart-gaps", "D38 (MVP-21): days with fewer than 36 samples (restart gaps) do not count; four counted days of growth are enough.",
		proj(100*gib, 90*gib, []int64{70 * gib, 1 * gib, 74 * gib, 76 * gib, 0, 80 * gib, 82 * gib}, []int{144, 10, 144, 100, 0, 36, 144}))
	ok("projection-too-few-days", "D38 (MVP-21): fewer than four counted days: no hint.",
		proj(100*gib, 99*gib, []int64{70 * gib, 75 * gib, 80 * gib, 85 * gib, 90 * gib, 95 * gib, 98 * gib}, []int{144, 35, 144, 20, 0, 0, 144}))
	ok("projection-slow", "D38 (MVP-21): 1 GiB a day with 40 GiB left: 40 days, no hint.",
		proj(100*gib, 60*gib, []int64{53 * gib, 54 * gib, 55 * gib, 56 * gib, 57 * gib, 58 * gib, 59 * gib}, full))
	ok("projection-shrinking", "D38 (MVP-21): usage falls: no hint.",
		proj(100*gib, 95*gib, []int64{99 * gib, 98 * gib, 97 * gib, 96 * gib, 95 * gib, 94 * gib, 93 * gib}, full))
	// Reserve cap (initiator, 2026-10-29): reserve = max(1 GiB, min(5 %, 20 GiB)).
	ok("budget-reserve-capped", "2026-10-29: on a 2 TiB file system 5 % would be 102.4 GiB; the reserve is capped at 20 GiB, so 60 GiB free is ok.", budget(20000, 374*mib, 4096, 2048*gib, 60*gib, 2*gib))
	ok("budget-reserve-capped-hint", "2026-10-29: on a 2 TiB file system with 40 GiB free and about 26 GiB still to grow, less than the 20 GiB reserve would stay: hint storage_budget.", budget(20000, 374*mib, 4096, 2048*gib, 40*gib, 0))
	ok("budget-reserve-at-cap", "2026-10-29: at exactly 400 GiB, 5 % equals the 20 GiB cap; 22 GiB free minus about 1.8 GiB of growth stays above it: ok.", budget(1000, 79*mib, 512, 400*gib, 22*gib, 0))
	ok("budget-reserve-small-disk", "2026-10-29: on a 10 GiB file system 5 % is 0.5 GiB; the 1 GiB floor applies, and 1.5 GiB free minus about 0.8 GiB of growth is below it: hint.", budget(100, 79*mib, 512, 10*gib, 1500*mib, 0))

	// Invalid inputs.
	bad("unknown-op", "D38: op is one of check_due, cap_pass, disk_budget, incident_aggregate, disk_projection.", M{"op": "vacuum", "max_size_mb": 100})
	bad("check-due-missing-elapsed", "D38: check_due needs elapsed_s.", M{"op": "check_due", "max_size_mb": 100, "written_bytes": 0})
	bad("cap-below-minimum", "D38: max_size_mb is at least 10 as in schild.yaml.", due(9, 0, 0))
	m := capPass(10, 0, 0, 0, req("dup", "passed", t0, 1, true), req("dup", "logged", t0+1, 1, false))
	g.add(c, "cap-duplicate-row-id", false, contract.CodeSchema, "D38: row ids are unique.", ctx, mustJSON(m), m)
	r := row("i-1", "incident", t0, 1)
	r["type"] = "schild.request.blocked.v1"
	bad("cap-incident-with-type", "D38: only event rows carry type, outcome, action and sampled.", capPass(10, 0, 0, 0, r))
	bad("cap-event-without-type", "D38: an event row names its type.", capPass(10, 0, 0, 0, row("e-1", "event", t0, 1)))
	bad("cap-unknown-outcome", "D38: outcomes are those of events.schema.json.", capPass(10, 0, 0, 0, req("e-1", "denied", t0, 1, false)))
	bad("budget-ring-too-large", "D38: requests_max_size_mb is at most 4096 as in schild.yaml (0 = ring off).", budget(100, 0, 5000, 20*gib, 10*gib, 0))
	both := breq("c1", sqli, "", t0, draws[0])
	both["limit"] = "body_size"
	bad("aggregate-rules-and-limit", "D38: a block has rules or a limit code, not both.", agg(1, both))
	m = agg(16, breq("c1", sqli, "", t0, draws[0]), breq("c2", sqli, "", t0+1, draws[0]))
	g.add(c, "aggregate-duplicate-draw", false, contract.CodeSchema, "D38: drawn incident numbers are unique.", ctx, mustJSON(m), m)
	bad("aggregate-bad-number", "D38: incident numbers use the IncidentNumber alphabet (no O, I, 0, 1).", agg(16, breq("c1", sqli, "", t0, "K7QM-4XW0")))
	bad("projection-six-days", "D38 (MVP-21): exactly the last 7 complete days.", proj(100*gib, 80*gib, []int64{1, 2, 3, 4, 5, 6}, full[:6]))
	bad("projection-too-many-samples", "D38 (MVP-21): a day has at most 144 ten-minute points.", proj(100*gib, 80*gib, []int64{1, 2, 3, 4, 5, 6, 7}, []int{145, 144, 144, 144, 144, 144, 144}))
	x := due(100, 0, 0)
	x["force"] = true
	bad("extra-field", "D38: no unknown fields.", x)
	dup := strings.Replace(string(mustJSON(due(100, 0, 0))), `"op":`, `"op":"cap_pass","op":`, 1)
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "Duplicate key.", ctx, []byte(dup), nil)
}
