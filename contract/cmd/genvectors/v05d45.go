//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D45 (2026-10-30): requests waiting for the backend, memory pressure, a stalled
// body. Appended last so earlier vectors keep their numbers.

func genD45(g *gen) {
	genBodyLimitsD45(g)
	genSiteConfigD45(g)
}

func genBodyLimitsD45(g *gen) {
	const c = "body-limits"
	ctx := vectors.Context{}
	ok := func(name, desc string, in, res m) { g.addResult(c, name, true, "", desc, ctx, mustJSON(in), in, res) }
	bad := func(code contract.Code, name, desc string, in any) {
		g.add(c, name, false, code, desc, ctx, mustJSON(in), in)
	}
	const mib, gib = int64(1) << 20, int64(1) << 30
	lim := m{"max_waiting_per_client": 1024, "max_waiting_per_network": 4096, "max_waiting": 8192}
	adm := func(cl, nw, gw int, nc string, known bool, draw int64) m {
		return m{"op": "request_admit", "request_limits": lim, "request_state": m{"client_waiting": cl, "network_waiting": nw, "waiting": gw},
			"net_class": nc, "client_known": known, "jitter_draw": draw}
	}
	pressed := func(level int) m {
		x := adm(0, 0, 0, "residential", true, 0)
		x["request_state"].(m)["pressure"] = level
		return x
	}
	in := m{"admitted": true, "code": nil, "status": nil, "scope": nil, "class": nil, "fail_closed": nil, "retry_after": nil}
	r429 := func(scope string, retry int) m {
		return m{"admitted": false, "code": "request_waiting_share", "status": 429, "scope": scope, "class": "rejected_limit", "fail_closed": nil, "retry_after": retry}
	}
	r503 := func(code, scope string) m {
		return m{"admitted": false, "code": code, "status": 503, "scope": scope, "class": "fail_closed", "fail_closed": "body_busy", "retry_after": nil}
	}
	ok("request-client-just-under", "D45: one under the share: admitted.", adm(1023, 1023, 1023, "residential", true, 0), in)
	ok("request-page-of-assets", "D45: a page with 100 assets over HTTP/2, ten at once behind one address: admitted.", adm(1000, 1000, 2000, "business", true, 0), in)
	ok("request-client-share", "D45: a client at its share: 429 with Retry-After.", adm(1024, 1024, 1024, "residential", true, 1), r429("client", 6))
	ok("request-network-share", "D45: a network at its share: 429, scope network.", adm(10, 4096, 4096, "business", true, 3), r429("network", 8))
	ok("request-gateway-full", "D45: the gateway at max_waiting: 503 request_busy for a client within its share.", adm(0, 0, 8192, "residential", true, 0), r503("request_busy", "gateway"))
	ok("request-client-before-gateway", "D45: a client over its share gets its own answer on a full gateway.", adm(1024, 1024, 8192, "residential", true, 2), r429("client", 7))
	ok("request-cgnat-factor", "D45: cgnat counts four times: 4095 of 4096, admitted.", adm(4095, 4095, 4095, "cgnat", true, 0), in)
	ok("request-mobile-factor", "D45: mobile too.", adm(4095, 4095, 4095, "mobile", true, 0), in)
	ok("request-cgnat-share", "D45: cgnat at its share: 503 with the waiting page, never 429 (D29).", adm(4096, 4096, 4096, "cgnat", true, 0), r503("request_waiting_share", "client"))
	ok("request-mobile-network-share", "D45: a mobile network at its share: 503.", adm(0, 16384, 7000, "mobile", true, 0), r503("request_waiting_share", "network"))
	ok("request-tor-share", "D45: tor keeps the plain share, but gets 503, never 429.", adm(1024, 1024, 1024, "tor", true, 0), r503("request_waiting_share", "client"))
	ok("request-unknown-client", "D45: without a valid client address only the gateway-wide limit applies.", adm(9000, 9000, 8191, "unknown", false, 0), in)
	ok("request-pressure-bodies", "D45: the first level of pressure stops bodies, requests go on.", pressed(1), in)
	ok("request-pressure-requests", "D45: the second level stops requests too.", pressed(2), r503("request_busy", "gateway"))

	body := func(level int) m {
		return m{"op": "admit", "limits": m{"max_per_client": 8, "max_per_network": 32, "max_in_flight": 1024, "max_in_flight_bytes": 4 * gib},
			"state": m{"client": 0, "network": 0, "in_flight": 0, "in_flight_bytes": 0, "pressure": level}, "net_class": "residential", "client_known": true, "jitter_draw": 0}
	}
	ok("body-no-pressure", "D45: level 0 changes nothing.", body(0), in)
	ok("body-pressure", "D45: a body meets the first level: 503 body_busy.", body(1), r503("body_busy", "gateway"))

	large := func(n int, isLarge bool) m {
		return m{"op": "admit", "limits": m{"max_per_client": 8, "max_per_network": 32, "max_in_flight": 1024, "max_in_flight_bytes": 4 * gib, "max_large_in_flight": 256},
			"state": m{"client": 0, "network": 0, "in_flight": n, "in_flight_bytes": 0, "large_in_flight": n, "large": isLarge}, "net_class": "residential", "client_known": true, "jitter_draw": 0}
	}
	ok("large-under-limit", "D45: one under the limit of large bodies: admitted.", large(255, true), in)
	ok("large-at-limit", "D45: a large body at the limit: 503 body_busy.", large(256, true), r503("body_busy", "gateway"))
	ok("large-small-goes-on", "D45: a small body does not meet that limit.", large(256, false), in)
	li := func(mem int64, conf int) m {
		x := m{"op": "large_in_flight", "memory_bytes": mem}
		if conf != 0 {
			x["configured"] = conf
		}
		return x
	}
	ok("large-limit-2gib", "D45: 128 per GiB: 256 at 2 GiB.", li(2*gib, 0), m{"max_large_in_flight": 256})
	ok("large-limit-floor", "D45: at least 16.", li(64*mib, 0), m{"max_large_in_flight": 16})
	ok("large-limit-ceiling", "D45: at most 16384.", li(1024*gib, 0), m{"max_large_in_flight": 16384})
	ok("large-limit-unknown-memory", "D45: unknown memory: 256.", li(0, 0), m{"max_large_in_flight": 256})
	ok("large-limit-configured", "D45: a configured value wins.", li(2*gib, 500), m{"max_large_in_flight": 500})

	lm := func(mem int64, conf int) m {
		x := m{"op": "request_limit", "memory_bytes": mem}
		if conf != 0 {
			x["configured"] = conf
		}
		return x
	}
	ok("request-limit-2gib", "D45, D60: a quarter of the memory at 128 KiB: 4096 at 2 GiB.", lm(2*gib, 0), m{"max_waiting": 4096})
	ok("request-limit-512mib", "D45, D60: 1024 at 512 MiB.", lm(512*mib, 0), m{"max_waiting": 1024})
	ok("request-limit-floor", "D45: at least 256.", lm(16*mib, 0), m{"max_waiting": 256})
	ok("request-limit-ceiling", "D45: at most 1048576.", lm(1024*gib, 0), m{"max_waiting": 1048576})
	ok("request-limit-unknown-memory", "D45, D60: unknown memory: 4096.", lm(0, 0), m{"max_waiting": 4096})
	ok("request-limit-configured", "D45: a configured value wins.", lm(2*gib, 500), m{"max_waiting": 500})

	pr := func(mem, held int64) m { return m{"op": "pressure", "memory_bytes": mem, "held_bytes": held} }
	lvl := func(n int) m { return m{"pressure": n} }
	unit := 2 * gib / 100
	ok("pressure-none", "D45: under 70 %: no level.", pr(2*gib, 70*unit-1), lvl(0))
	ok("pressure-bodies", "D45: 70 %: bodies stop.", pr(2*gib, 70*unit), lvl(1))
	ok("pressure-under-requests", "D45: just under 85 %: still the first level.", pr(2*gib, 85*unit-1), lvl(1))
	ok("pressure-requests", "D45: 85 %: requests stop.", pr(2*gib, 85*unit), lvl(2))
	ok("pressure-no-limit", "D45: no known memory limit: no level.", pr(0, 8*gib), lvl(0))

	re := func(end string) m { return m{"op": "read_end", "end": end} }
	ok("read-end-left", "D41: the client left: no incident.", re("client_left"), m{"code": "client_gone", "incident": false})
	ok("read-end-timeout", "D45: read_body or read_body_idle ended the read: like a client that left, in every mode (E10).", re("timeout"), m{"code": "client_gone", "incident": false})
	ok("read-end-error", "D41: any other failed read stays body_read_error.", re("error"), m{"code": "body_read_error", "incident": true})

	bad(contract.CodeSchema, "request-admit-no-state", "D45: request_state is required.", m{"op": "request_admit", "request_limits": lim, "net_class": "unknown", "client_known": false, "jitter_draw": 0})
	bad(contract.CodeSchema, "request-limit-no-memory", "D45: memory_bytes is required.", m{"op": "request_limit"})
	bad(contract.CodeSchema, "pressure-bad-level", "D45: three levels.", func() m {
		x := adm(0, 0, 0, "unknown", false, 0)
		x["request_state"].(m)["pressure"] = 3
		return x
	}())
	bad(contract.CodeSchema, "read-end-unknown", "D45: three ends.", re("stalled"))
	bad(contract.CodeSchema, "large-limit-no-memory", "D45: memory_bytes is required.", m{"op": "large_in_flight"})
}

func genSiteConfigD45(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, q m) {
		x := siteConfig()
		x["waf"] = m{"requests": q}
		g.add(c, name, valid, code, desc, ctx, mustJSON(x), x)
	}
	add(true, "", "waf-requests-all", "D45: every key set.", m{"max_waiting_per_client": 512, "max_waiting_per_network": 2048, "max_waiting": 4096})
	add(true, "", "waf-requests-client-at-network", "D45: equal limits nest.", m{"max_waiting_per_client": 4096})
	add(false, contract.CodeConfig, "waf-requests-client-over-network", "D45: the limits nest.", m{"max_waiting_per_client": 8192})
	add(false, contract.CodeConfig, "waf-requests-network-over-gateway", "D45: the limits nest.", m{"max_waiting": 2048})
	add(false, contract.CodeSchema, "waf-requests-zero", "D45: at least 1.", m{"max_waiting_per_client": 0})
}
