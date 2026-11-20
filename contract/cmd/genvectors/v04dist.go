//go:build !release

package main

import (
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// v0.4 (MVP-18): distributed attacks. Appended after the MVP-17 vectors so
// every earlier vector keeps its number.

func genSiteConfigV04Distributed(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, dist map[string]any) {
		m := siteConfig()
		m["behaviour"] = map[string]any{"distributed": dist}
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	add(true, "", "distributed-defaults", "v0.4 MVP-18: empty section, every detector observes, 14 days learning.", map[string]any{})
	add(true, "", "distributed-full", "v0.4 MVP-18: detectors, responses, marked routes and a JA4 header of a trusted TLS terminator.", map[string]any{
		"learning_days": 30, "routes": []string{"/checkout/**", "/api/login"},
		"detectors": map[string]any{
			"route_wave":          map[string]any{"mode": "respond", "thresholds": map[string]any{"count": 30, "window_s": 60, "factor": 5}},
			"account_wave":        map[string]any{"mode": "respond", "thresholds": map[string]any{"count": 10, "window_s": 600}},
			"shape_wave":          map[string]any{"mode": "observe"},
			"fingerprint_cluster": map[string]any{"mode": "respond", "thresholds": map[string]any{"count": 20, "window_s": 300}},
			"inconsistency":       map[string]any{"mode": "off"},
		},
		"responses":   map[string]any{"route_tighten": map[string]any{"minutes": 20, "max_minutes": 60, "limit_per_minute": 10}, "account_slowdown": map[string]any{"start_s": 5, "max_s": 300}},
		"fingerprint": map[string]any{"ja4_header": "X-JA4"},
	})
	add(true, "", "distributed-short-response", "v0.4 MVP-18: a 1 minute response within the default maximum.", map[string]any{"responses": map[string]any{"route_tighten": map[string]any{"minutes": 1}}})
	add(false, contract.CodeSchema, "distributed-learning-short", "v0.4 MVP-18: at least 14 days of learning before responding.", map[string]any{"learning_days": 7})
	add(false, contract.CodeSchema, "distributed-slowdown-over-cap", "v0.4 MVP-18: account wait capped at 5 minutes, never a lockout.", map[string]any{"responses": map[string]any{"account_slowdown": map[string]any{"max_s": 301}}})
	add(false, contract.CodeSchema, "distributed-tighten-over-cap", "v0.4 MVP-18: route_tighten at most 2 hours.", map[string]any{"responses": map[string]any{"route_tighten": map[string]any{"minutes": 121}}})
	add(false, contract.CodeConfig, "distributed-minutes-above-max", "v0.4 MVP-18: minutes may not exceed max_minutes.", map[string]any{"responses": map[string]any{"route_tighten": map[string]any{"minutes": 90, "max_minutes": 60}}})
	add(false, contract.CodeConfig, "distributed-start-above-max", "v0.4 MVP-18: start_s may not exceed max_s.", map[string]any{"responses": map[string]any{"account_slowdown": map[string]any{"start_s": 30, "max_s": 10}}})
	add(false, contract.CodeSchema, "distributed-wave-hint-on", "D72: wave_hint is an unknown key (there are no signals).", map[string]any{"wave_hint": map[string]any{"enabled": true}})
	add(false, contract.CodeSchema, "distributed-address-ban", "v0.4 MVP-18: no response bans addresses.", map[string]any{"responses": map[string]any{"ip_ban": map[string]any{"minutes": 10}}})
	add(false, contract.CodeSchema, "distributed-block-mode", "v0.4 MVP-18: detectors observe or respond, they never block senders.", map[string]any{"detectors": map[string]any{"route_wave": map[string]any{"mode": "block"}}})
	add(false, contract.CodeSchema, "distributed-unknown-detector", "v0.4 MVP-18: fixed detectors only.", map[string]any{"detectors": map[string]any{"proxy_list": map[string]any{"mode": "observe"}}})
	add(false, contract.CodeSchema, "distributed-ja4-plus", "v0.4 MVP-18: one header name, not a JA4+ variant list.", map[string]any{"fingerprint": map[string]any{"ja4_header": "X-JA4H,X-JA4S"}})
}

func genEventsV04Distributed(g *gen) {
	const c = "events"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, typ string, data map[string]any) {
		e := cloudEvent(typ, name, data)
		g.add(c, name, valid, code, desc, ctx, mustJSON(e), e)
	}
	det := func() map[string]any {
		return map[string]any{"wave_id": uuid("wave-1"), "detector": "fingerprint_cluster", "host": "verein.example", "route": "/wp-login.php", "senders": 380, "count": 380, "threshold": 20,
			"window_s": 300, "fingerprint": "3f9a0c11b2d4", "fingerprint_kind": "headers", "user_agents": 41, "response": "route_tighten", "mode": "respond", "action": "respond", "until": ts(20 * time.Minute)}
	}
	add(true, "", "distributed-detected", "v0.4 MVP-18: login wave from 380 addresses with one fingerprint; the route is tightened for 20 minutes.", "schild.distributed.detected.v1", det())
	d := det()
	d["detector"], d["action"], d["reason"], d["baseline"] = "route_wave", "observe", "learning", 2.5
	for _, k := range []string{"until", "fingerprint", "fingerprint_kind", "user_agents"} {
		delete(d, k)
	}
	add(true, "", "distributed-learning", "v0.4 MVP-18: fresh install, still learning: shown as would have responded.", "schild.distributed.detected.v1", d)
	add(true, "", "distributed-shape", "v0.4 MVP-18: one malicious request shape from many senders, blocked for any sender (here: gateway observes).", "schild.distributed.detected.v1",
		map[string]any{"wave_id": uuid("wave-2"), "detector": "shape_wave", "route": "/wp-json/gallery/v1/upload", "senders": 120, "count": 120, "threshold": 20, "window_s": 60,
			"request_sig": "sha256:" + strings.Repeat("ab", 32), "waf_rules": []int{933100, 949110}, "response": "shape_block", "mode": "respond", "action": "observe", "reason": "gateway_observe"})
	add(true, "", "distributed-ended", "v0.4 MVP-18: the operator ended a response early.", "schild.distributed.ended.v1",
		map[string]any{"wave_id": uuid("wave-1"), "detector": "fingerprint_cluster", "host": "verein.example", "route": "/wp-login.php", "reason": "operator", "duration_s": 540, "stopped": 1830})
	add(true, "", "distributed-expired", "v0.4 MVP-18: a response expired by itself.", "schild.distributed.ended.v1",
		map[string]any{"wave_id": uuid("wave-3"), "detector": "account_wave", "route": "/user/login", "reason": "expired", "duration_s": 1200, "stopped": 0})

	d = det()
	d["client"] = reqData("x")["client"]
	add(false, contract.CodeSchema, "distributed-with-client", "v0.4 MVP-18: wave events are address-free.", "schild.distributed.detected.v1", d)
	d = det()
	d["user_name"] = "admin"
	add(false, contract.CodeSchema, "distributed-user-name", "v0.4 MVP-18: no user names, not even hashed.", "schild.distributed.detected.v1", d)
	d = det()
	d["accounts"] = []string{"a1b2"}
	add(false, contract.CodeSchema, "distributed-account-ids", "v0.4 MVP-18: no account identifiers.", "schild.distributed.detected.v1", d)
	d = det()
	delete(d, "until")
	add(false, contract.CodeSchema, "distributed-respond-without-until", "v0.4 MVP-18: every response is time-boxed.", "schild.distributed.detected.v1", d)
	d = det()
	d["response"] = "ip_ban"
	add(false, contract.CodeSchema, "distributed-ip-ban", "v0.4 MVP-18: no address ban.", "schild.distributed.detected.v1", d)
	d = det()
	d["fingerprint"] = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	add(false, contract.CodeSchema, "distributed-raw-ja4", "v0.4 MVP-18: only the local fingerprint id, never the raw JA4.", "schild.distributed.detected.v1", d)
	d = det()
	d["detector"] = "proxy_list"
	add(false, contract.CodeSchema, "distributed-unknown-detector", "v0.4 MVP-18: fixed detectors only.", "schild.distributed.detected.v1", d)
	add(false, contract.CodeSchema, "distributed-ended-too-long", "v0.4 MVP-18: a response lasts at most 2 hours.", "schild.distributed.ended.v1",
		map[string]any{"wave_id": uuid("wave-4"), "detector": "route_wave", "route": "/login", "reason": "expired", "duration_s": 7201, "stopped": 0})
	add(false, contract.CodeSchema, "distributed-ended-unknown-reason", "v0.4 MVP-18: expired or ended by the operator.", "schild.distributed.ended.v1",
		map[string]any{"wave_id": uuid("wave-5"), "detector": "route_wave", "route": "/login", "reason": "crash", "duration_s": 10, "stopped": 0})
	add(false, contract.CodeSchema, "distributed-ended-with-ip", "v0.4 MVP-18: no address in wave records.", "schild.distributed.ended.v1",
		map[string]any{"wave_id": uuid("wave-6"), "detector": "route_wave", "route": "/login", "reason": "expired", "duration_s": 10, "stopped": 0, "ip": "203.0.113.7"})
}
