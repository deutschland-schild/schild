//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D44 (2026-10-30): bodies waiting for the backend, and the multipart class.
// Appended last so earlier vectors keep their numbers.

func genD44(g *gen) {
	genBodyLimitsD44(g)
	genSiteConfigD44(g)
}

func genBodyLimitsD44(g *gen) {
	const c = "body-limits"
	ctx := vectors.Context{}
	ok := func(name, desc string, in, res m) { g.addResult(c, name, true, "", desc, ctx, mustJSON(in), in, res) }
	bad := func(code contract.Code, name, desc string, in any) {
		g.add(c, name, false, code, desc, ctx, mustJSON(in), in)
	}
	const mib, gib = int64(1) << 20, int64(1) << 30
	lim := m{"max_per_client": 8, "max_per_network": 32, "max_in_flight": 1024, "max_in_flight_bytes": 4 * gib,
		"max_waiting_bytes_per_client": 64 * mib, "max_waiting_bytes_per_network": 256 * mib, "max_waiting_bytes": 512 * mib}
	adm := func(cl, nw, gw int64, nc string, known bool, draw int64) m {
		s := m{"client": 0, "network": 0, "in_flight": 0, "in_flight_bytes": 0, "client_waiting_bytes": cl, "network_waiting_bytes": nw, "waiting_bytes": gw}
		return m{"op": "admit", "limits": lim, "state": s, "net_class": nc, "client_known": known, "jitter_draw": draw}
	}
	in := m{"admitted": true, "code": nil, "status": nil, "scope": nil, "class": nil, "fail_closed": nil, "retry_after": nil}
	r429 := func(scope string, retry int) m {
		return m{"admitted": false, "code": "body_waiting_share", "status": 429, "scope": scope, "class": "rejected_limit", "fail_closed": nil, "retry_after": retry}
	}
	r503 := func(code, scope string) m {
		return m{"admitted": false, "code": code, "status": 503, "scope": scope, "class": "fail_closed", "fail_closed": "body_busy", "retry_after": nil}
	}
	ok("waiting-client-just-under", "D44: one byte under the share: admitted.", adm(64*mib-1, 64*mib-1, 64*mib-1, "residential", true, 0), in)
	ok("waiting-client-share", "D44: a client at its share of waiting bytes: 429 body_waiting_share, whatever it sends now.", adm(64*mib, 64*mib, 64*mib, "residential", true, 1), r429("client", 6))
	ok("waiting-network-share", "D44: a network at its share: 429, scope network.", adm(0, 256*mib, 256*mib, "business", true, 3), r429("network", 8))
	ok("waiting-gateway-full", "D44: the gateway at max_waiting_bytes: 503 body_busy for a client within its share.", adm(0, 0, 512*mib, "residential", true, 0), r503("body_busy", "gateway"))
	ok("waiting-cgnat-factor", "D44: cgnat counts four times: 255 MiB of 256 MiB, admitted.", adm(255*mib, 255*mib, 255*mib, "cgnat", true, 0), in)
	ok("waiting-cgnat-share", "D44: cgnat at its share: 503 with the waiting page, never 429 (D29).", adm(256*mib, 256*mib, 256*mib, "cgnat", true, 0), r503("body_waiting_share", "client"))
	ok("waiting-tor-share", "D44: tor keeps the plain share, but gets 503, never 429.", adm(64*mib, 64*mib, 64*mib, "tor", true, 0), r503("body_waiting_share", "client"))
	ok("waiting-unknown-client", "D44: without a valid client address only the gateway-wide limit applies.", adm(900*mib, 900*mib, 511*mib, "unknown", false, 0), in)

	w := func(n int64) m { return m{"op": "waiting", "bytes": n} }
	wr := func(mem bool, b int64) m { return m{"in_memory": mem, "waiting_bytes": b} }
	const kib = int64(1) << 10
	ok("waiting-empty", "D44: a request waiting costs its overhead without a byte of body.", w(0), wr(true, 128*kib))
	ok("waiting-small", "D44: a small body waits in memory and counts on top.", w(1000), wr(true, 128*kib+1000))
	ok("waiting-at-memory-limit", "D44: 128 KiB still wait in memory.", w(128*kib), wr(true, 256*kib))
	ok("waiting-over-memory-limit", "D44: one byte more waits in a temp file; D45: it still counts what the send queue of the backend holds.", w(128*kib+1), wr(false, 256*kib+1))
	ok("waiting-megabyte", "D44: 1 MiB, the size of the OOM, waits on disk; D45: 384 KiB of it count, the send queue of the backend's socket.", w(mib), wr(false, 512*kib))

	wl := func(mem, conf int64) m {
		x := m{"op": "waiting_limit", "memory_bytes": mem}
		if conf != 0 {
			x["configured_bytes"] = conf
		}
		return x
	}
	ok("waiting-limit-2gib", "D44: a quarter of the memory: 512 MiB at 2 GiB.", wl(2*gib, 0), m{"max_waiting_bytes": 512 * mib})
	ok("waiting-limit-floor", "D44: at least 32 MiB.", wl(64*mib, 0), m{"max_waiting_bytes": 32 * mib})
	ok("waiting-limit-ceiling", "D44: at most 16 GiB.", wl(256*gib, 0), m{"max_waiting_bytes": 16 * gib})
	ok("waiting-limit-unknown-memory", "D44: unknown memory: 256 MiB.", wl(0, 0), m{"max_waiting_bytes": 256 * mib})
	ok("waiting-limit-configured", "D44: a configured value wins.", wl(2*gib, 100*mib), m{"max_waiting_bytes": 100 * mib})

	sz := func(ct string, n int64) m {
		return m{"op": "size", "content_type": ct, "bytes": n, "raw_limit_bytes": 131072, "body_limit_bytes": 33554432}
	}
	res := func(cl string, limit int64, code any, held int64) m {
		var status any
		if code != nil {
			status = 413
		}
		return m{"class": cl, "limit_bytes": limit, "code": code, "status": status, "held_bytes": held}
	}
	const rawL, live = int64(131072), int64(33554432)
	form := res("multipart", live, nil, 2*mib)
	over := res("raw", rawL, "raw_body_too_large", mib)
	ok("multipart-form-case", "D44: compared without case, as Coraza and mime do.", sz("Multipart/Form-Data; boundary=x", mib), form)
	ok("multipart-form-space-before-semicolon", "D44: space before the parameters.", sz("multipart/form-data ; boundary=x", mib), form)
	ok("multipart-form-unicode-space", "D44: Coraza trims Unicode space, so the class does too.", sz(" multipart/form-data; boundary=x", mib), form)
	ok("multipart-form-dotted-i", "D44: Go lowers U+0130 to i, in Coraza as here.", sz("MULTİPART/FORM-DATA; boundary=x", mib), form)
	ok("multipart-form-no-boundary", "D44: the class reads the media type; a missing boundary is refused with 400 after reading.", sz("multipart/form-data", mib), form)
	ok("multipart-mixed-raw", "D44: Coraza has no multipart parser for this subtype: raw, with the raw limit.", sz("multipart/mixed; boundary=x", mib), over)
	ok("multipart-related-raw", "D44: every other subtype too.", sz("multipart/related; boundary=x", mib), over)
	ok("multipart-suffix-raw", "D44: a +json suffix does not make a multipart type text.", sz("multipart/x+json; boundary=x", mib), over)
	ok("multipart-prefix-raw", "D44: Coraza's test is a prefix, this one is exact: a longer subtype stays raw, stricter than Coraza.", sz("multipart/form-data-x; boundary=x", mib), over)
	ok("multipart-comma-raw", "D44: a comma is no parameter separator: Coraza refuses this one, here it is raw.", sz("multipart/form-data, text/plain; boundary=x", mib), over)
	ok("multipart-mixed-under-raw", "D44: under the raw limit such a body is read, and counts as text in the estimate.", sz("multipart/mixed; boundary=x", 4096), res("raw", rawL, nil, 4096))
	two := func(a, b string) m {
		return m{"op": "size", "content_types": []any{a, b}, "bytes": mib, "raw_limit_bytes": rawL, "body_limit_bytes": live}
	}
	ok("content-type-twice-multipart-first", "D44: rules read every value, the parser the first: a header sent twice names no parser, raw.", two("multipart/form-data; boundary=x", "application/json"), over)
	ok("content-type-twice-multipart-second", "D44: Coraza's parser reads the first value only: raw as well.", two("text/plain", "multipart/form-data; boundary=x"), over)
	ok("content-type-twice-same", "D44: also for two equal values.", two("multipart/form-data; boundary=x", "multipart/form-data; boundary=x"), over)

	bad(contract.CodeSchema, "waiting-no-bytes", "D44: bytes is required.", m{"op": "waiting"})
	bad(contract.CodeSchema, "waiting-limit-no-memory", "D44: memory_bytes is required.", m{"op": "waiting_limit"})
	bad(contract.CodeSchema, "waiting-limit-low-configured", "D44: a configured value is at least 1 MiB.", wl(gib, 1024))
	bad(contract.CodeSchema, "content-types-one-value", "D44: content_types is for a header sent more than once.", m{"op": "size", "content_types": []any{"text/plain"}, "bytes": 1, "raw_limit_bytes": rawL, "body_limit_bytes": live})
}

func genSiteConfigD44(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, b m) {
		x := siteConfig()
		x["waf"] = m{"body": b}
		g.add(c, name, valid, code, desc, ctx, mustJSON(x), x)
	}
	const mib = 1 << 20
	add(true, "", "waf-waiting-all", "D44: every key set.", m{"max_waiting_bytes_per_client": 32 * mib, "max_waiting_bytes_per_network": 128 * mib, "max_waiting_bytes": 256 * mib})
	add(true, "", "waf-waiting-client-at-network", "D44: equal limits nest.", m{"max_waiting_bytes_per_client": 256 * mib})
	add(false, contract.CodeConfig, "waf-waiting-client-over-network", "D44: the limits nest.", m{"max_waiting_bytes_per_client": 512 * mib})
	add(false, contract.CodeConfig, "waf-waiting-network-over-gateway", "D44: the limits nest.", m{"max_waiting_bytes": 128 * mib})
	add(false, contract.CodeSchema, "waf-waiting-too-low", "D44: at least 1 MiB.", m{"max_waiting_bytes_per_client": 1024})
}
