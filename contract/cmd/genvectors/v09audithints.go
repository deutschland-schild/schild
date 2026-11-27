//go:build !release

package main

import "github.com/deutschland-schild/schild/contract/vectors"

// D108 (MVP-36): audit_stuck and audit_size are about the audit log of
// schild and mark only the server (audit.md section 10).
func genWebsiteStatusAudit(g *gen) {
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
	ok := func(name, desc string, m, r map[string]any) {
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, r)
	}
	okRes := map[string]any{"status": "ok", "reasons": []any{}}
	ok("audit-stuck-server-only", "D108: audit_stuck (entries wait in the outbox because audit.db cannot be written) marks only the server; the website stays ok.",
		in(map[string]any{"code": "audit_stuck", "level": "warning"}), okRes)
	ok("audit-size-server-only", "D108: audit_size (audit.db is 1 GiB or larger; object = the actor with the most entries) marks only the server.",
		in(map[string]any{"code": "audit_size", "level": "notice", "object": "tok_0123456789ab"}), okRes)
	ok("audit-hints-with-other-hint", "D108: next to the hints of the audit log another server hint still marks the website, alone.",
		in(map[string]any{"code": "audit_stuck", "level": "warning"}, map[string]any{"code": "audit_size", "level": "notice", "object": "dashboard"}, map[string]any{"code": "disk_full_soon", "level": "notice", "object": "/"}),
		map[string]any{"status": "attention", "reasons": []any{map[string]any{"code": "server_hint", "node": "web-1", "hint": "disk_full_soon", "object": "/"}}})
}
