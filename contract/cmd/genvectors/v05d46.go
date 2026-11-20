//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D46 (2026-10-31): open connections, what counts as held memory, a stall is not
// blocked. Appended last so earlier vectors keep their numbers.

func genD46(g *gen) {
	genBodyLimitsD46(g)
	genSiteConfigD46(g)
}

func genBodyLimitsD46(g *gen) {
	const c = "body-limits"
	ctx := vectors.Context{}
	ok := func(name, desc string, in, res m) { g.addResult(c, name, true, "", desc, ctx, mustJSON(in), in, res) }
	bad := func(code contract.Code, name, desc string, in any) {
		g.add(c, name, false, code, desc, ctx, mustJSON(in), in)
	}
	const mib, gib = int64(1) << 20, int64(1) << 30
	lim := m{"max_per_client": 2048, "max_per_network": 8192, "max_open": 16384}
	adm := func(cl, nw, open int, nc string, known, proxy bool, idle ...string) m {
		st := m{"client": cl, "network": nw, "open": open}
		for _, k := range idle {
			st[k] = true
		}
		return m{"op": "conn_admit", "conn_limits": lim, "conn_state": st, "net_class": nc, "peer_known": known, "proxy": proxy}
	}
	in := m{"admitted": true, "evict": nil, "refused": nil}
	evict := func(scope string) m { return m{"admitted": true, "evict": scope, "refused": nil} }
	refused := func(scope string) m { return m{"admitted": false, "evict": nil, "refused": scope} }

	ok("conn-client-just-under", "D46: one under the limit of a client: admitted.", adm(2047, 2047, 2047, "residential", true, false), in)
	ok("conn-office-browsers", "D46: 200 browsers behind one address on HTTP/1.1, six connections each, 200 WebSockets: admitted.", adm(1400, 1400, 3000, "business", true, false), in)
	ok("conn-client-full", "D46: a client at its limit, all connections busy: closed at once.", adm(2048, 2048, 2048, "residential", true, false), refused("client"))
	ok("conn-client-evicts", "D46: a client at its limit with an idle connection: that one gives way.", adm(2048, 2048, 2048, "residential", true, false, "client_idle"), evict("client"))
	ok("conn-client-other-idle", "D46: an idle connection of another scope does not help a full client.", adm(2048, 2048, 2048, "residential", true, false, "network_idle", "open_idle"), refused("client"))
	ok("conn-network-full", "D46: a network at its limit: closed at once.", adm(0, 8192, 8192, "business", true, false), refused("network"))
	ok("conn-network-evicts", "D46: a full network takes the place of its oldest idle connection.", adm(0, 8192, 8192, "business", true, false, "network_idle"), evict("network"))
	ok("conn-gateway-full", "D46: the gateway at max_open: closed at once.", adm(0, 0, 16384, "residential", true, false), refused("gateway"))
	ok("conn-gateway-evicts", "D46: a new visitor on a gateway full of idle connections gets in.", adm(0, 0, 16384, "residential", true, false, "open_idle"), evict("gateway"))
	ok("conn-client-before-gateway", "D46: the client limit is checked first: its own connection gives way, not a stranger's.", adm(2048, 2048, 16384, "residential", true, false, "client_idle", "open_idle"), evict("client"))
	ok("conn-cgnat-factor", "D46: cgnat counts four times: 8191 of 8192, admitted.", adm(8191, 8191, 8191, "cgnat", true, false), in)
	ok("conn-mobile-factor", "D46: mobile too, for the network as well.", adm(8191, 32767, 9000, "mobile", true, false), in)
	ok("conn-cgnat-full", "D46: cgnat at four times the limit: closed at once.", adm(8192, 8192, 8192, "cgnat", true, false), refused("client"))
	ok("conn-tor-plain", "D46: tor keeps the plain limit.", adm(2048, 2048, 2048, "tor", true, false), refused("client"))
	ok("conn-proxy-many", "D46: a trusted proxy is no client: thousands of connections from one address.", adm(9000, 9000, 9000, "residential", true, true), in)
	ok("conn-proxy-gateway", "D46: the gateway limit holds for a proxy too.", adm(16384, 16384, 16384, "residential", true, true), refused("gateway"))
	ok("conn-unknown-peer", "D46: without a peer address only the gateway limit applies.", adm(9000, 9000, 9000, "unknown", false, false), in)

	lm := func(mem int64, conf int) m {
		x := m{"op": "conn_limit", "memory_bytes": mem}
		if conf != 0 {
			x["configured"] = conf
		}
		return x
	}
	ok("conn-limit-2gib", "D46, D60: a quarter of the memory at 64 KiB: 8192 at 2 GiB.", lm(2*gib, 0), m{"max_open": 8192})
	ok("conn-limit-512mib", "D46, D60: 2048 at 512 MiB.", lm(512*mib, 0), m{"max_open": 2048})
	ok("conn-limit-floor", "D46: at least 1024.", lm(16*mib, 0), m{"max_open": 1024})
	ok("conn-limit-ceiling", "D46: at most 1048576.", lm(1024*gib, 0), m{"max_open": 1048576})
	ok("conn-limit-unknown-memory", "D46, D60: unknown memory: 8192.", lm(0, 0), m{"max_open": 8192})
	ok("conn-limit-configured", "D46: a configured value wins.", lm(2*gib, 500), m{"max_open": 500})

	held := func(s m) m { return m{"op": "held", "stat": s} }
	res := func(h, o int64) m { return m{"held_bytes": h, "outside_bytes": o} }
	ok("held-d45-part", "D46: what D45 counted still counts.", held(m{"anon": 100 * mib, "sock": 20 * mib, "file_dirty": 3 * mib, "file_writeback": 4 * mib}), res(127*mib, 27*mib))
	ok("held-slab", "D46: the slab counts, reclaimable part included: open sockets pin it.", held(m{"anon": 1800 * mib, "slab": 160 * mib}), res(1960*mib, 160*mib))
	ok("held-kernel", "D46: stacks of the kernel, page tables and tmpfs cannot go either.", held(m{"kernel_stack": mib, "pagetables": 2 * mib, "shmem": 4 * mib}), res(7*mib, 7*mib))
	ok("held-nothing", "D46: an empty stat.", held(m{}), res(0, 0))

	ro := func(end string) m { return m{"op": "read_outcome", "end": end} }
	ok("read-outcome-left", "D46: a client that left is not blocked.", ro("client_left"), m{"outcome": "client_gone"})
	ok("read-outcome-timeout", "D46: a stalled body is not blocked, in any mode. Takes back that part of D45.", ro("timeout"), m{"outcome": "client_gone"})
	ok("read-outcome-error", "D46: any other failed read stays blocked.", ro("error"), m{"outcome": "blocked"})

	bad(contract.CodeSchema, "conn-admit-no-state", "D46: conn_state is required.", m{"op": "conn_admit", "conn_limits": lim, "net_class": "unknown", "peer_known": false, "proxy": false})
	bad(contract.CodeSchema, "conn-admit-no-proxy", "D46: proxy is required: a default of false would refuse on a proxy's address.", m{"op": "conn_admit", "conn_limits": lim, "conn_state": m{"client": 0, "network": 0, "open": 0}, "net_class": "unknown", "peer_known": false})
	bad(contract.CodeSchema, "conn-limit-no-memory", "D46: memory_bytes is required.", m{"op": "conn_limit"})
	bad(contract.CodeSchema, "held-unknown-line", "D46: a line of memory.stat that does not count is no input: page cache stays out.", held(m{"file": mib}))
	bad(contract.CodeSchema, "read-outcome-unknown", "D46: three ends.", ro("stalled"))
}

func genSiteConfigD46(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, q m) {
		x := siteConfig()
		x["waf"] = m{"connections": q}
		g.add(c, name, valid, code, desc, ctx, mustJSON(x), x)
	}
	add(true, "", "waf-connections-all", "D46: every key set.", m{"max_per_client": 1024, "max_per_network": 4096, "max_open": 8192})
	add(true, "", "waf-connections-client-at-network", "D46: equal limits nest.", m{"max_per_client": 8192})
	add(false, contract.CodeConfig, "waf-connections-client-over-network", "D46: the limits nest.", m{"max_per_client": 16384})
	add(false, contract.CodeConfig, "waf-connections-network-over-gateway", "D46: the limits nest.", m{"max_open": 4096})
	add(false, contract.CodeSchema, "waf-connections-zero", "D46: at least 1.", m{"max_per_client": 0})
}
