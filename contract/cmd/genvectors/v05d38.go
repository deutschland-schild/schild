//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D36 open items and D38 (initiator, 2026-10-29): would_block_reason on
// request events, the audit event of `schild dashboard reset-password`,
// and the website status rule "schild's own store marks only the server".

func genEventsV05D38(g *gen) {
	const c = "events"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, e map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(e), e)
	}
	wb := func(name, reason string) map[string]any {
		d := reqData("req-wb-" + name)
		d["would_block_reason"] = reason
		return cloudEvent("schild.request.evaluated.v1", "wb-"+name, d)
	}
	add(true, "", "would-block-gateway-observe", "D36 open items: a would_block request names why it was passed: the gateway runs in observe (\"Erkannt, aber durchgelassen: Beobachten-Modus\").", wb("gateway", "gateway_observe"))
	g.retire(c, true) // would-block-rule-probation (D72: no network rules)
	d := reqData("req-wb-shared")
	d["mode"], d["would_block_reason"] = "autoblock", "shared_address"
	add(true, "", "would-block-shared-address", "D36 open items: in mode autoblock a shared address (cgnat, mobile, tor) is never blocked by address.", cloudEvent("schild.request.evaluated.v1", "wb-shared", d))
	add(true, "", "dashboard-access-reset", "D38 (MVP-09 addendum): audit record of schild dashboard reset-password on the host: who (host CLI, host account), how many users and sessions; no password, hash, setup code or session id.",
		cloudEvent("schild.dashboard.access_reset.v1", "reset", map[string]any{"via": "host_cli", "users_removed": 1, "sessions_ended": 3, "host_user": "deploy"}))
	add(true, "", "dashboard-access-reset-control-path", "D38: the CLI told the running gateway through its local control path; host account unknown.",
		cloudEvent("schild.dashboard.access_reset.v1", "reset-cp", map[string]any{"via": "control_path", "users_removed": 1, "sessions_ended": 0}))

	d = reqData("req-wb-blocked")
	d["outcome"], d["mode"], d["status"], d["would_block_reason"] = "blocked", "autoblock", 403, "gateway_observe"
	add(false, contract.CodeSchema, "would-block-reason-on-blocked", "D36 open items: would_block_reason only with outcome would_block.", cloudEvent("schild.request.blocked.v1", "wb-blocked", d))
	add(false, contract.CodeSchema, "would-block-reason-unknown", "D36 open items: the reasons are a fixed enum.", wb("unknown", "operator_said_so"))
	add(false, contract.CodeSchema, "access-reset-with-password", "D38: the audit record never carries a password or setup code (closed object).",
		cloudEvent("schild.dashboard.access_reset.v1", "reset-pw", map[string]any{"via": "host_cli", "users_removed": 1, "sessions_ended": 3, "setup_code": "ABCD-EFGH"}))
	add(false, contract.CodeSchema, "access-reset-unknown-via", "D38: via is host_cli or control_path (there is no API for it).",
		cloudEvent("schild.dashboard.access_reset.v1", "reset-api", map[string]any{"via": "dashboard_api", "users_removed": 1, "sessions_ended": 3}))
}

func genWebsiteStatusD38(g *gen) {
	const c = "website-status"
	ctx := vectors.Context{}
	traffic := map[string]any{"requests": 12000, "forwarded": 11900, "fail_closed": 0, "upstream_errors": 3, "upstream_timeouts": 0, "status_5xx": 4}
	in := func(hints ...map[string]any) map[string]any {
		hs := []any{}
		for _, h := range hints {
			hs = append(hs, h)
		}
		return map[string]any{"protection": "protected", "tracked": true, "monitoring": true, "traffic": traffic,
			"servers": []any{map[string]any{"node": "web-1", "state": "ok", "baseline_protection": "active", "hints": hs}}}
	}
	hint := func(code, level, object string) map[string]any {
		h := map[string]any{"code": code, "level": level}
		if object != "" {
			h["object"] = object
		}
		return h
	}
	ok := func(name, desc string, m, r map[string]any) {
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, r)
	}
	okRes := map[string]any{"status": "ok", "reasons": []any{}}
	ok("store-near-cap-server-only", "D36 open items (2026-10-29): store_near_cap is about schild's own event store and marks only the server; the website stays ok.",
		in(hint("store_near_cap", "notice", "")), okRes)
	ok("store-cap-unreachable-server-only", "D38: store_cap_unreachable marks only the server.", in(hint("store_cap_unreachable", "warning", "")), okRes)
	ok("storage-budget-server-only", "D38: storage_budget marks only the server.", in(hint("storage_budget", "notice", "/var/lib/schild")), okRes)
	ok("disk-fill-projection-reaches-websites", "D38: disk_fill_projection (a full disk stops the apps) reaches every website on the server like disk_full_soon.",
		in(hint("disk_fill_projection", "notice", "/var/lib/docker")),
		map[string]any{"status": "attention", "reasons": []any{map[string]any{"code": "server_hint", "node": "web-1", "hint": "disk_fill_projection", "object": "/var/lib/docker"}}})
	ok("store-near-cap-with-other-hint", "D36 open items: next to store_near_cap another server hint still marks the website, alone.",
		in(hint("store_near_cap", "notice", ""), hint("memory_low", "notice", "")),
		map[string]any{"status": "attention", "reasons": []any{map[string]any{"code": "server_hint", "node": "web-1", "hint": "memory_low"}}})
}
