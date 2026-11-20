//go:build !release

package main

import (
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D41 (body limits) and D42 (agent block writes), 2026-10-30. Appended last so
// earlier vectors keep their numbers.

func genD41D42(g *gen) {
	genBodyLimits(g)
	genAgentBlock(g)
	genWaitingPageBodyBusy(g)
	genStorageBudgetBody(g)
	genSiteConfigD41D42(g)
	genEventsD42(g)
	genHubWriteD42(g)
}

type m = map[string]any

func genBodyLimits(g *gen) {
	const c = "body-limits"
	ctx := vectors.Context{}
	ok := func(name, desc string, in, res m) { g.addResult(c, name, true, "", desc, ctx, mustJSON(in), in, res) }
	bad := func(code contract.Code, name, desc string, in any) {
		g.add(c, name, false, code, desc, ctx, mustJSON(in), in)
	}
	lim := m{"max_per_client": 8, "max_per_network": 32, "max_in_flight": 1024, "max_in_flight_bytes": int64(4) << 30}
	st := func(cl, nw, fl int, by int64) m {
		return m{"client": cl, "network": nw, "in_flight": fl, "in_flight_bytes": by}
	}
	adm := func(s m, nc string, known bool, draw int64) m {
		return m{"op": "admit", "limits": lim, "state": s, "net_class": nc, "client_known": known, "jitter_draw": draw}
	}
	in := m{"admitted": true, "code": nil, "status": nil, "scope": nil, "class": nil, "fail_closed": nil, "retry_after": nil}
	r429 := func(scope string, retry int) m {
		return m{"admitted": false, "code": "body_client_share", "status": 429, "scope": scope, "class": "rejected_limit", "fail_closed": nil, "retry_after": retry}
	}
	r503 := func(code, scope string) m {
		return m{"admitted": false, "code": code, "status": 503, "scope": scope, "class": "fail_closed", "fail_closed": "body_busy", "retry_after": nil}
	}
	ok("admit-idle", "D41: nothing runs: admitted.", adm(st(0, 0, 0, 0), "residential", true, 0), in)
	ok("admit-last-client-place", "D41: 7 of 8 bodies run: the eighth is admitted.", adm(st(7, 7, 7, 0), "residential", true, 0), in)
	ok("client-over-share", "D41, E5: the ninth body of a client: 429, Retry-After 5 + draw mod 4.", adm(st(8, 8, 8, 0), "residential", true, 2), r429("client", 7))
	ok("client-retry-bounds", "D41: Retry-After stays within 5 to 8.", adm(st(8, 8, 8, 0), "hosting", true, 7), r429("client", 8))
	ok("network-over-share", "D41: 32 bodies in the /24 or /48: the next client there gets 429, scope network.", adm(st(0, 32, 40, 0), "business", true, 0), r429("network", 5))
	ok("cgnat-factor-client", "D41: cgnat counts four times: 31 of 32 run, admitted.", adm(st(31, 31, 31, 0), "cgnat", true, 0), in)
	ok("cgnat-over-share", "D41, E5: cgnat over its share: 503 with the waiting page, never 429 (D29).", adm(st(32, 32, 32, 0), "cgnat", true, 0), r503("body_client_share", "client"))
	ok("mobile-factor-network", "D41: mobile counts four times in the network too: 127 of 128 run, admitted.", adm(st(0, 127, 127, 0), "mobile", true, 0), in)
	ok("mobile-network-over-share", "D41, E5: mobile network over its share: 503.", adm(st(0, 128, 128, 0), "mobile", true, 0), r503("body_client_share", "network"))
	ok("tor-plain-limit", "D41, E5: tor keeps the plain limit, but gets 503, never 429.", adm(st(8, 8, 8, 0), "tor", true, 0), r503("body_client_share", "client"))
	ok("gateway-count-full", "D41: max_in_flight reached: 503 body_busy for a client within its share.", adm(st(0, 0, 1024, 0), "residential", true, 0), r503("body_busy", "gateway"))
	ok("gateway-bytes-full", "D41: the held bytes reached max_in_flight_bytes: 503 body_busy.", adm(st(0, 0, 3, int64(4)<<30), "residential", true, 0), r503("body_busy", "gateway"))
	ok("gateway-bytes-just-under", "D41: one byte under max_in_flight_bytes: admitted. Declared lengths are not reserved.", adm(st(0, 0, 3, int64(4)<<30-1), "residential", true, 0), in)
	ok("client-before-gateway", "D41: a client over its share gets its own answer, also while the gateway is full.", adm(st(8, 8, 1024, int64(4)<<30), "residential", true, 1), r429("client", 6))
	ok("unknown-client-skips-share", "D41: without a valid client address only the gateway-wide limits apply.", adm(st(99, 99, 99, 0), "unknown", false, 0), in)
	ok("unknown-client-gateway", "D41: without a valid client address the gateway-wide limits still apply.", adm(st(0, 0, 1024, 0), "unknown", false, 0), r503("body_busy", "gateway"))

	fl := func(mem int64, conf int) m {
		x := m{"op": "in_flight", "memory_bytes": mem}
		if conf != 0 {
			x["configured"] = conf
		}
		return x
	}
	const gib = int64(1) << 30
	ok("in-flight-2gib", "D41, E6: 512 per GiB: 1024 at 2 GiB.", fl(2*gib, 0), m{"max_in_flight": 1024})
	ok("in-flight-half-gib", "D41: 512 MiB give 256.", fl(gib/2, 0), m{"max_in_flight": 256})
	ok("in-flight-floor", "D41: at least 64.", fl(32<<20, 0), m{"max_in_flight": 64})
	ok("in-flight-ceiling", "D41: at most 65536.", fl(1024*gib, 0), m{"max_in_flight": 65536})
	ok("in-flight-unknown-memory", "D41: unknown memory: 1024.", fl(0, 0), m{"max_in_flight": 1024})
	ok("in-flight-configured", "D41: a configured value wins.", fl(2*gib, 77), m{"max_in_flight": 77})

	sz := func(ct string, n, raw, body int64) m {
		x := m{"op": "size", "bytes": n, "raw_limit_bytes": raw, "body_limit_bytes": body}
		if ct != "" {
			x["content_type"] = ct
		}
		return x
	}
	const rawL, whole, live = int64(131072), int64(13107200), int64(33554432)
	res := func(cl string, limit int64, code any, held int64) m {
		var status any
		if code != nil {
			status = 413
		}
		return m{"class": cl, "limit_bytes": limit, "code": code, "status": status, "held_bytes": held}
	}
	ok("raw-at-limit", "D41, E7: a raw body of exactly 128 KiB passes the size limit.", sz("application/octet-stream", rawL, rawL, whole), res("raw", rawL, nil, rawL))
	ok("raw-over-limit", "D41, E7: one byte more: 413 raw_body_too_large.", sz("application/octet-stream", rawL+1, rawL, whole), res("raw", rawL, "raw_body_too_large", rawL+1))
	ok("raw-no-content-type", "D41: no Content-Type counts as raw.", sz("", rawL+1, rawL, whole), res("raw", rawL, "raw_body_too_large", rawL+1))
	ok("raw-image-no-exemption", "D41, E8: a binary media type gets the raw limit like any other: no exemption by type.", sz("image/jpeg", rawL+1, rawL, live), res("raw", rawL, "raw_body_too_large", rawL+1))
	ok("raw-over-whole-limit", "D41: over request_body_limit_bytes the existing code wins.", sz("application/pdf", whole+1, rawL, whole), res("raw", rawL, "body_too_large", whole+1))
	ok("raw-limit-above-body-limit", "D41: a low request_body_limit_bytes stays the limit: min of both.", sz("application/octet-stream", 70000, rawL, 65536), res("raw", 65536, "body_too_large", 70000))
	ok("raw-limit-raised", "D41: the operator's way for an application with raw uploads until routes exist.", sz("application/zip", 5<<20, 10<<20, live), res("raw", 10<<20, nil, 5<<20))
	ok("json-not-raw", "D41: JSON is text: the raw limit does not apply.", sz("application/json; charset=utf-8", 1<<20, rawL, whole), res("text", whole, nil, 1<<20))
	ok("json-suffix", "D41: +json is text.", sz("application/vnd.api+json", 1<<20, rawL, whole), res("text", whole, nil, 1<<20))
	ok("xml-suffix-upper", "D41: compared without case.", sz("Application/SOAP+XML", 1<<20, rawL, whole), res("text", whole, nil, 1<<20))
	ok("form", "D41: a urlencoded form is text.", sz("application/x-www-form-urlencoded", 200000, rawL, whole), res("text", whole, nil, 200000))
	ok("text-plain", "D41: text/* is text.", sz("text/plain", 200000, rawL, whole), res("text", whole, nil, 200000))
	ok("multipart-counts-twice", "D41: a multipart body counts twice against max_in_flight_bytes.", sz("multipart/form-data; boundary=x", 12<<20, rawL, whole), res("multipart", whole, nil, 24<<20))

	rate := func(end int64, a ...[2]int64) m {
		l := []any{}
		for _, x := range a {
			l = append(l, m{"t_ms": x[0], "bytes": x[1]})
		}
		return m{"op": "rate", "arrivals": l, "end_ms": end}
	}
	first := func(i int) *int { return &i }
	rr := func(w []int64, f *int) m {
		l := []any{}
		for _, x := range w {
			l = append(l, x)
		}
		var fb any
		if f != nil {
			fb = *f
		}
		return m{"windows": l, "below_min": f != nil, "first_below": fb}
	}
	ok("rate-short-body", "D41, E2: a body under one window gives no sample.", rate(29999, [2]int64{0, 1 << 20}), rr(nil, nil))
	ok("rate-exact-minimum", "D41, E2: 1 KiB/s over a window is not below the minimum.", rate(30000, [2]int64{100, 30720}), rr([]int64{1024}, nil))
	ok("rate-just-below", "D41, E2: one byte less is below it.", rate(30000, [2]int64{100, 30719}), rr([]int64{1023}, first(0)))
	ok("rate-stall", "D41, E2: a stall gives a window of 0.", rate(60000, [2]int64{10, 1 << 20}), rr([]int64{34952, 0}, first(1)))
	ok("rate-head-buys-nothing", "D41, E2: fixed windows: bytes at the start do not cover a later slow window.", rate(90000, [2]int64{0, 128 << 10}, [2]int64{31000, 10}, [2]int64{61000, 10}), rr([]int64{4369, 0, 0}, first(1)))
	ok("rate-partial-tail-ignored", "D41, E2: the partial window at the end gives no sample.", rate(45000, [2]int64{0, 60000}, [2]int64{44000, 1}), rr([]int64{2000}, nil))
	ok("rate-1mbit", "D41, E2: 12 MB at 1 Mbit/s stays far above the minimum.", rate(90000, [2]int64{1000, 3750000}, [2]int64{31000, 3750000}, [2]int64{61000, 3750000}), rr([]int64{125000, 125000, 125000}, nil))
	ok("rate-first-below-only", "D41, E2: the first slow window counts, a body once.", rate(90000, [2]int64{0, 1000}, [2]int64{31000, 1000}, [2]int64{61000, 1 << 20}), rr([]int64{33, 33, 34952}, first(0)))
	ok("rate-open-body", "D41, E2: an open body is measured up to now, so a running body shows before it ends.", rate(60000), rr([]int64{0, 0}, first(0)))

	bad(contract.CodeSchema, "unknown-op", "D41: unknown op.", m{"op": "evict"})
	bad(contract.CodeSchema, "admit-no-state", "D41: state is required.", m{"op": "admit", "limits": lim, "net_class": "residential", "client_known": true, "jitter_draw": 0})
	bad(contract.CodeSchema, "admit-bad-class", "D41: a net class of the shared list.", adm(st(0, 0, 0, 0), "datacentre", true, 0))
	bad(contract.CodeSchema, "admit-zero-limit", "D41: limits are at least 1.", m{"op": "admit", "limits": m{"max_per_client": 0, "max_per_network": 32, "max_in_flight": 1024, "max_in_flight_bytes": 1}, "state": st(0, 0, 0, 0), "net_class": "residential", "client_known": true, "jitter_draw": 0})
	bad(contract.CodeSchema, "admit-negative-count", "D41: counts are not negative.", adm(st(-1, 0, 0, 0), "residential", true, 0))
	bad(contract.CodeSchema, "admit-extra-field", "D41: no client address in a decision input.", func() m { x := adm(st(0, 0, 0, 0), "residential", true, 0); x["ip"] = "203.0.113.7"; return x }())
	bad(contract.CodeSchema, "in-flight-no-memory", "D41: memory_bytes is required.", m{"op": "in_flight"})
	bad(contract.CodeSchema, "in-flight-zero-configured", "D41: a configured value is at least 1.", m{"op": "in_flight", "memory_bytes": gib, "configured": 0})
	bad(contract.CodeSchema, "size-low-raw-limit", "D41: raw_limit_bytes is at least 1 KiB.", sz("image/png", 1, 10, whole))
	bad(contract.CodeSchema, "size-high-body-limit", "D41: body_limit_bytes as in schild.yaml.", sz("image/png", 1, rawL, int64(1)<<40))
	bad(contract.CodeSchema, "rate-no-end", "D41: end_ms is required.", m{"op": "rate", "arrivals": []any{}})
	bad(contract.CodeSchema, "rate-negative-time", "D41: times start at 0.", rate(10, [2]int64{-1, 1}))
	g.add(c, "not-json", false, contract.CodeMalformed, "D41: not JSON.", ctx, []byte("{"), nil)
	bad(contract.CodeOversize, "oversize", "D41: at most 64 KiB.", m{"op": "size", "content_type": strings.Repeat("a", 70000)})
}

func genAgentBlock(g *gen) {
	const c = "agent-block"
	ctx := vectors.Context{}
	ok := func(name, desc string, in, res m) { g.addResult(c, name, true, "", desc, ctx, mustJSON(in), in, res) }
	bad := func(code contract.Code, name, desc string, in any) {
		g.add(c, name, false, code, desc, ctx, mustJSON(in), in)
	}
	bud := func(used int, running int) m {
		return m{"writes_per_hour": 30, "writes_used": used, "oldest_write_age_s": 1000, "max_blocks": 500, "running": running}
	}
	target := func(over m) m {
		t := m{"exists": true, "address": "203.0.113.7", "attribution": "tcp_peer", "net_class": "residential"}
		for k, v := range over {
			t[k] = v
		}
		return t
	}
	cr := func(mode string, d int, t m, b m) m {
		return m{"op": "create", "scope": "blocks:write", "mode": mode, "duration_s": d, "reason": "credential stuffing from this client", "target": t, "budget": b}
	}
	v := func(over m) m {
		r := m{"allowed": false, "status": 0, "code": nil, "effect": nil, "changed": false, "limited_by": nil, "max_duration_s": nil, "persisted": false, "counts_budget": false, "retry_after": nil}
		for k, x := range over {
			r[k] = x
		}
		return r
	}
	no := func(status int, code string) m { return v(m{"status": status, "code": code}) }
	done := v(m{"allowed": true, "status": 200, "effect": "block", "changed": true, "counts_budget": true})

	ok("create-autoblock", "D42: a block of one client within the cap.", cr("autoblock", 3600, target(nil), bud(0, 0)), done)
	g.retire(c, true) // create-review (D89: mode review is gone; an invalid vector of genD89)
	ok("create-minimum", "D42: the shortest block is 60 s.", cr("autoblock", 60, target(nil), bud(0, 0)), done)
	ok("create-observe", "D42: while the gateway observes nothing is blocked: would_block is recorded, the write counts.", cr("observe", 3600, target(nil), bud(0, 0)), v(m{"allowed": true, "status": 200, "effect": "would_block", "limited_by": "gateway_observe", "counts_budget": true}))
	ok("create-cap-default", "D42: 24 h is the cap of every class but hosting.", cr("autoblock", 86400, target(nil), bud(0, 0)), done)
	ok("create-over-cap-default", "D42: above the cap: refused and the cap named, never shortened silently.", cr("autoblock", 86401, target(nil), bud(0, 0)), v(m{"status": 400, "code": "duration_over_cap", "max_duration_s": 86400}))
	ok("create-hosting-7d", "D42: hosting up to 7 days, kept over a restart.", cr("autoblock", 604800, target(m{"net_class": "hosting"}), bud(0, 0)), v(m{"allowed": true, "status": 200, "effect": "block", "changed": true, "persisted": true, "counts_budget": true}))
	ok("create-hosting-over-cap", "D42: hosting above 7 days.", cr("autoblock", 604801, target(m{"net_class": "hosting"}), bud(0, 0)), v(m{"status": 400, "code": "duration_over_cap", "max_duration_s": 604800}))
	ok("create-vpn-cap", "D42: vpn stays at 24 h, as in the D29 amendment.", cr("autoblock", 90000, target(m{"net_class": "vpn"}), bud(0, 0)), v(m{"status": 400, "code": "duration_over_cap", "max_duration_s": 86400}))
	ok("create-unknown-class", "D42: an unknown net class may be blocked, with the 24 h cap.", cr("autoblock", 3600, target(m{"net_class": "unknown"}), bud(0, 0)), done)
	for _, nc := range []string{"cgnat", "mobile", "tor"} {
		ok("create-shared-"+nc, "D42: "+nc+" is never blocked, also not by an agent (D29).", cr("autoblock", 3600, target(m{"net_class": nc}), bud(0, 0)), no(409, "shared_address"))
	}
	ok("create-shared-observe", "D42: the same refusal while observing, so would_block means what block would do.", cr("observe", 3600, target(m{"net_class": "mobile"}), bud(0, 0)), no(409, "shared_address"))
	ok("create-allowlisted", "D42: an own address is never blocked.", cr("autoblock", 3600, target(m{"own": true}), bud(0, 0)), no(409, "own_address"))
	for _, x := range [][2]string{{"rfc1918", "192.168.1.20"}, {"ten", "10.66.1.2"}, {"cgn-range", "100.64.0.9"}, {"loopback", "127.0.0.1"}, {"link-local", "169.254.1.1"}, {"multicast", "224.0.0.1"}, {"reserved", "240.0.0.1"}, {"zero", "0.1.2.3"}, {"ula", "fd00::1"}, {"ipv6-loopback", "::1"}, {"ipv6-link-local", "fe80::1"}, {"mapped-private", "::ffff:10.0.0.1"}} {
		ok("create-private-"+x[0], "D42: a private or special range is never blocked.", cr("autoblock", 3600, target(m{"address": x[1]}), bud(0, 0)), no(409, "private_address"))
	}
	ok("create-ipv6-public", "D42: a public IPv6 client.", cr("autoblock", 3600, target(m{"address": "2001:db8:1:2::17"}), bud(0, 0)), done)
	ok("create-mapped-public", "D42: a mapped IPv4 is judged as IPv4.", cr("autoblock", 3600, target(m{"address": "::ffff:198.51.100.7"}), bud(0, 0)), done)
	ok("create-trusted-proxy-attribution", "D42: attributed by a trusted proxy.", cr("autoblock", 3600, target(m{"attribution": "trusted_proxy"}), bud(0, 0)), done)
	ok("create-bad-attribution", "D42: an address from any other source could name a victim.", cr("autoblock", 3600, target(m{"attribution": "untrusted_header"}), bud(0, 0)), no(409, "unreliable_attribution"))
	ok("create-no-target", "D42: nothing of that name, also for a visitor pseudonym: those have no address behind them.", cr("autoblock", 3600, m{"exists": false}, bud(0, 0)), no(404, "not_found"))
	ok("create-target-gone", "D42: the full address is no longer stored, or the evidence is older than 7 days.", cr("autoblock", 3600, m{"exists": true, "gone": true}, bud(0, 0)), no(409, "target_gone"))
	ok("create-released", "D42: the operator released this client: an agent does not overrule that.", cr("autoblock", 3600, target(m{"released": true}), bud(0, 0)), no(409, "released"))
	ok("create-already-running", "D42: a running block stands; its end does not move and no write counts.", cr("autoblock", 3600, target(m{"running": true}), bud(30, 0)), v(m{"allowed": true, "status": 200, "effect": "block"}))
	ok("create-budget-used", "D42: the token's writes of the hour are used up; Retry-After from the oldest write.", cr("autoblock", 3600, target(nil), bud(30, 0)), v(m{"status": 429, "code": "block_budget", "retry_after": 2600}))
	ok("create-budget-observe", "D42: the budget counts while observing too.", cr("observe", 3600, target(nil), bud(30, 0)), v(m{"status": 429, "code": "block_budget", "retry_after": 2600}))
	ok("create-budget-last", "D42: the last write of the hour.", cr("autoblock", 3600, target(nil), bud(29, 0)), done)
	ok("create-gateway-cap", "D42: max_agent_blocks run: refused for every token.", cr("autoblock", 3600, target(nil), bud(0, 500)), v(m{"status": 429, "code": "block_cap", "retry_after": 3600}))
	ok("create-cap-observe", "D42: nothing runs while observing, so the cap does not apply.", cr("observe", 3600, target(nil), bud(0, 500)), v(m{"allowed": true, "status": 200, "effect": "would_block", "limited_by": "gateway_observe", "counts_budget": true}))
	for _, s := range []string{"agent:read", "rules:write", "export:read"} {
		x := cr("autoblock", 3600, target(nil), bud(0, 0))
		x["scope"] = s
		ok("create-scope-"+strings.ReplaceAll(s, ":", "-"), "D42: only blocks:write may set a block.", x, no(403, "scope_required"))
	}
	blank := cr("autoblock", 3600, target(nil), bud(0, 0))
	blank["reason"] = "   "
	ok("create-blank-reason", "D42: a reason is required.", blank, no(400, "invalid"))
	ok("create-too-short", "D42: under 60 s.", cr("autoblock", 59, target(nil), bud(0, 0)), no(400, "invalid"))

	lift := func(status string, running bool, b m) m {
		return m{"op": "lift", "scope": "blocks:write", "reason": "false positive after review", "status": status, "running": running, "budget": b}
	}
	ok("lift-running", "D42: ends the block; no exception, no allowlist entry, no feedback.", lift("blocked", true, bud(0, 0)), v(m{"allowed": true, "status": 200, "changed": true, "counts_budget": true}))
	ok("lift-already-unblocked", "D42: idempotent: nothing changes, no write counts.", lift("unblocked", false, bud(30, 0)), v(m{"allowed": true, "status": 200}))
	ok("lift-no-timed-block", "D42: a single request the WAF refused or a network rule has nothing to lift.", lift("blocked", false, bud(0, 0)), no(409, "no_running_block"))
	ok("lift-missing", "D42: no such incident.", lift("missing", false, bud(0, 0)), no(404, "not_found"))
	ok("lift-budget", "D42: lifting uses the same budget.", lift("blocked", true, bud(30, 0)), v(m{"status": 429, "code": "block_budget", "retry_after": 2600}))
	rd := lift("blocked", true, bud(0, 0))
	rd["scope"] = "agent:read"
	ok("lift-scope", "D42: only blocks:write may lift.", rd, no(403, "scope_required"))
	nr := lift("blocked", true, bud(0, 0))
	nr["reason"] = ""
	ok("lift-no-reason", "D42: a reason is required.", nr, no(400, "invalid"))
	wave := m{"writes_per_hour": 600, "writes_used": 599, "oldest_write_age_s": 40, "max_blocks": 2000, "running": 1999}
	ok("create-wave-defaults", "D42: the defaults leave room for a wave: 599 writes within a minute, the last place of 2000.", cr("autoblock", 3600, target(nil), wave), done)

	bad(contract.CodeSchema, "unknown-op", "D42: only create and lift.", m{"op": "extend"})
	bad(contract.CodeSchema, "unknown-scope", "D42: known scopes only.", func() m { x := cr("autoblock", 60, target(nil), bud(0, 0)); x["scope"] = "agent:act"; return x }())
	bad(contract.CodeSchema, "unknown-mode", "D42: gateway modes only.", cr("off", 60, target(nil), bud(0, 0)))
	bad(contract.CodeSchema, "no-reason-field", "D42: reason is required.", func() m { x := cr("autoblock", 60, target(nil), bud(0, 0)); delete(x, "reason"); return x }())
	bad(contract.CodeSchema, "long-reason", "D42: at most 300 characters.", func() m {
		x := cr("autoblock", 60, target(nil), bud(0, 0))
		x["reason"] = strings.Repeat("x", 301)
		return x
	}())
	bad(contract.CodeSchema, "no-duration", "D42: duration_s is required.", func() m { x := cr("autoblock", 60, target(nil), bud(0, 0)); delete(x, "duration_s"); return x }())
	bad(contract.CodeSchema, "no-budget", "D42: budget is required.", func() m { x := cr("autoblock", 60, target(nil), bud(0, 0)); delete(x, "budget"); return x }())
	bad(contract.CodeSchema, "target-no-exists", "D42: exists is required.", cr("autoblock", 60, m{"address": "203.0.113.7"}, bud(0, 0)))
	bad(contract.CodeSchema, "target-extra", "D42: the target has no free fields.", cr("autoblock", 60, target(m{"prefix": "/24"}), bud(0, 0)))
	bad(contract.CodeSchema, "bad-net-class", "D42: a known net class.", cr("autoblock", 60, target(m{"net_class": "datacentre"}), bud(0, 0)))
	bad(contract.CodeSchema, "lift-bad-status", "D42: incident status.", lift("gone", false, bud(0, 0)))
	bad(contract.CodeSchema, "budget-zero-rate", "D42: at least one write per hour.", cr("autoblock", 60, target(nil), m{"writes_per_hour": 0, "writes_used": 0, "oldest_write_age_s": 0, "max_blocks": 1, "running": 0}))
	g.add(c, "not-json", false, contract.CodeMalformed, "D42: not JSON.", ctx, []byte("{"), nil)
	bad(contract.CodeOversize, "oversize", "D42: at most 64 KiB.", m{"op": "create", "reason": strings.Repeat("a", 70000)})
	bad(contract.CodeSchema, "create-review", "D89: mode review is gone; observe is the test profile, autoblock every other gateway.", cr("review", 900, target(nil), bud(0, 0)))
}

func genWaitingPageBodyBusy(g *gen) {
	const c = "waiting-page"
	ctx := vectors.Context{}
	h := m{"accept": chromeAccept, "sec_fetch_dest": "document", "sec_fetch_mode": "navigate"}
	in := func(method string, hh m, draw int64) m {
		return m{"fail_closed": "body_busy", "enabled": true, "method": method, "headers": hh, "host": "musterverein.example", "website": "musterverein.example", "jitter_draw": draw}
	}
	res := m{"answer": "waiting_page", "variant": "form", "language": "de", "retry_after": 5, "refresh": nil, "body": true, "site_name": "musterverein.example", "marker": true, "problem_code": nil}
	x := in("POST", h, 0)
	g.addResult(c, "body-busy-form-navigation", true, "", "D41, E5: a form upload refused by the body limits gets the waiting page in the form variant.", ctx, mustJSON(x), x, res)
	x = in("PUT", m{"accept": "application/json"}, 3)
	prob := m{"answer": "problem", "variant": nil, "language": nil, "retry_after": 8, "refresh": nil, "body": true, "site_name": nil, "marker": true, "problem_code": "waiting"}
	g.addResult(c, "body-busy-api", true, "", "D41: an API upload gets 503 problem details with code waiting.", ctx, mustJSON(x), x, prob)
	x = in("POST", h, 0)
	x["enabled"] = false
	un := m{"answer": "unchanged", "variant": nil, "language": nil, "retry_after": nil, "refresh": nil, "body": nil, "site_name": nil, "marker": false, "problem_code": nil}
	g.addResult(c, "body-busy-disabled", true, "", "D41: waiting_page.enabled false: the plain 503.", ctx, mustJSON(x), x, un)
}

func genStorageBudgetBody(g *gen) {
	const c = "storage-bounds"
	ctx := vectors.Context{}
	const gib = int64(1) << 30
	in := func(name, desc string, total, avail int64, verdict string) {
		x := m{"op": "disk_budget", "max_size_mb": 100, "metrics_bound_bytes": 0, "requests_max_size_mb": 0, "body_spool_bytes": 4 * gib, "fs_total_bytes": total, "fs_avail_bytes": avail, "schild_used_bytes": 0}
		const b = 104857600 + 10485760 + 134217728 + 4*gib
		res := m{"budget_bytes": b, "need_bytes": b, "reserve_bytes": max(gib, min(total*50/1000, 20*gib)), "verdict": verdict}
		g.addResult(c, name, true, "", desc, ctx, mustJSON(x), x, res)
	}
	in("disk-budget-body-spool", "D41, E11: the temp space of bodies counts in the budget.", 100*gib, 90*gib, "ok")
	in("disk-budget-body-spool-hint", "D41: the temp space can bring the budget under the reserve.", 100*gib, 8*gib, "hint")
	in("disk-budget-body-spool-error", "D41: a disk smaller than the budget refuses the start; lower waf.body.max_in_flight_bytes.", 4*gib, 3*gib, "error")
}

func genSiteConfigD41D42(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, key string, v m) {
		x := siteConfig()
		x[key] = v
		g.add(c, name, valid, code, desc, ctx, mustJSON(x), x)
	}
	body := func(b m) m { return m{"body": b} }
	add(true, "", "waf-body-defaults", "D41: an empty waf.body keeps the defaults.", "waf", body(m{}))
	add(true, "", "waf-body-all", "D41: every key set.", "waf", body(m{"max_per_client": 4, "max_per_network": 16, "max_in_flight": 512, "max_in_flight_bytes": 1 << 31}))
	add(true, "", "waf-raw-limit", "D41: the raw limit can be raised.", "waf", m{"raw_body_limit_bytes": 1 << 20})
	add(true, "", "waf-raw-above-body-limit", "D41: not a contradiction: the lower limit applies.", "waf", m{"raw_body_limit_bytes": 1 << 20, "request_body_limit_bytes": 65536})
	add(true, "", "waf-body-live", "D41: the first live config with 32 MiB bodies fits the default byte limit.", "waf", m{"request_body_limit_bytes": 33554432})
	add(false, contract.CodeConfig, "waf-body-client-over-network", "D41: the limits nest.", "waf", body(m{"max_per_client": 40}))
	add(false, contract.CodeConfig, "waf-body-network-over-gateway", "D41: the limits nest.", "waf", body(m{"max_in_flight": 16}))
	add(false, contract.CodeConfig, "waf-body-bytes-below-one-body", "D41: one multipart body of the largest size must fit, counted twice.", "waf", m{"request_body_limit_bytes": 33554432, "body": m{"max_in_flight_bytes": 33554432}})
	add(false, contract.CodeSchema, "waf-body-zero-client", "D41: at least 1.", "waf", body(m{"max_per_client": 0}))
	add(false, contract.CodeSchema, "waf-body-zero-gateway", "D41: at least 1; absent means derived, 0 means nothing.", "waf", body(m{"max_in_flight": 0}))
	add(false, contract.CodeSchema, "waf-body-unknown-key", "D41: the rate keys are not part of this version.", "waf", body(m{"min_rate_bytes_per_s": 1024}))
	add(false, contract.CodeSchema, "waf-upload-routes-not-yet", "D41: upload routes are not part of this version.", "waf", m{"upload_routes": []any{}})
	add(false, contract.CodeSchema, "waf-raw-too-low", "D41: at least 1 KiB.", "waf", m{"raw_body_limit_bytes": 10})
	add(true, "", "agent-block-limits", "D42: the block limits of the agent API.", "agent_api", m{"enabled": true, "block_writes_per_hour": 10, "max_agent_blocks": 50})
	add(false, contract.CodeSchema, "agent-block-writes-zero", "D42: at least 1.", "agent_api", m{"block_writes_per_hour": 0})
	add(false, contract.CodeSchema, "agent-block-writes-high", "D42: at most 36000.", "agent_api", m{"block_writes_per_hour": 36001})
	add(false, contract.CodeSchema, "agent-max-blocks-high", "D42: at most 4096.", "agent_api", m{"max_agent_blocks": 4097})
}

func genEventsD42(g *gen) {
	const c = "events"
	ctx := vectors.Context{}
	client := m{"ip": "203.0.113.7", "attribution": "tcp_peer", "allowlisted": false, "geo": m{"country": "DE", "asn": 64496, "net_class": "hosting"}}
	const evidence = "6f1c2b7e-1d4a-4c8e-9b2f-6a5d4e3c2b16"
	set := func(over m, drop ...string) m {
		d := m{"effect": "block", "client": client, "key_bits": 32, "duration_s": 3600, "until": "2026-10-26T13:00:00Z", "incident": "K7QM-4XWD", "target_kind": "event",
			"evidence_event_id": evidence, "token_id": "tok_000000000001", "token_label": "Local agent", "reason": "scanner, 40 probes in a minute"}
		for k, v := range over {
			d[k] = v
		}
		for _, k := range drop {
			delete(d, k)
		}
		return d
	}
	add := func(valid bool, code contract.Code, name, desc, typ string, d m) {
		e := cloudEvent(typ, name, d)
		g.add(c, name, valid, code, desc, ctx, mustJSON(e), e)
	}
	lifted := m{"incident": "K7QM-4XWD", "source": "agent:tok_000000000001", "token_id": "tok_000000000001", "token_label": "Local agent", "reason": "false positive"}
	add(true, "", "block-set", "D42: an agent set a block.", "schild.block.set.v1", set(nil))
	add(true, "", "block-set-long", "D42: 7 days for a data-centre address, kept in schild.db. No ladder step.", "schild.block.set.v1", set(m{"duration_s": 500000, "persisted": true}))
	add(true, "", "block-set-would-block", "D42: the gateway observes: a record, no incident and no end.", "schild.block.set.v1", set(m{"effect": "would_block"}, "until", "incident"))
	add(true, "", "block-lifted", "D42: an agent ended a block.", "schild.block.lifted.v1", lifted)
	add(false, contract.CodeSchema, "block-set-no-token", "D42: every write names its token.", "schild.block.set.v1", set(nil, "token_id"))
	add(false, contract.CodeSchema, "block-set-no-label", "D42: every write names its label.", "schild.block.set.v1", set(nil, "token_label"))
	add(false, contract.CodeSchema, "block-set-no-reason", "D42: a reason is required.", "schild.block.set.v1", set(nil, "reason"))
	add(false, contract.CodeSchema, "block-set-no-incident", "D42: a real block has an incident.", "schild.block.set.v1", set(nil, "incident"))
	add(false, contract.CodeSchema, "block-set-would-block-incident", "D42: would_block has no incident.", "schild.block.set.v1", set(m{"effect": "would_block"}, "until"))
	add(false, contract.CodeSchema, "block-set-over-cap", "D42: at most 7 days.", "schild.block.set.v1", set(m{"duration_s": 604801}))
	add(false, contract.CodeSchema, "block-set-short", "D42: at least 60 s.", "schild.block.set.v1", set(m{"duration_s": 59}))
	add(false, contract.CodeSchema, "block-set-target-address", "D42: an agent never names an address.", "schild.block.set.v1", set(m{"target_kind": "address"}))
	add(false, contract.CodeSchema, "block-lifted-no-reason", "D42: a reason is required.", "schild.block.lifted.v1", m{"incident": "K7QM-4XWD", "source": "agent:tok_000000000001", "token_id": "tok_000000000001", "token_label": "Local agent"})
	add(false, contract.CodeSchema, "block-lifted-exception", "D42: lifting creates no exception, so it has no such field.", "schild.block.lifted.v1", func() m {
		x := m{"allowlist_entry": "a1"}
		for k, v := range lifted {
			x[k] = v
		}
		return x
	}())
}

func genHubWriteD42(g *gen) {
	const c = "crowdsec-hub"
	ctx := vectors.Context{}
	_ = ctx
	g.retire(c, true) // agent-write-blocks-token: the scope checks of the rule writes are rule-effect vectors (D73)
}
