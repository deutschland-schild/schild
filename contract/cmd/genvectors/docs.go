//go:build !release

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/seclang"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// Documentation addresses only: RFC 5737 (IPv4) and RFC 3849 (IPv6).
func reqData(id string) map[string]any {
	return map[string]any{
		"request_id": id,
		"client": map[string]any{
			"ip": "203.0.113.42", "port": 51234, "attribution": "tcp_peer",
			"geo": map[string]any{"country": "NL", "city": "Amsterdam", "asn": 64500, "as_org": "Example Hosting B.V.", "net_class": "hosting"},
		},
		"method": "POST", "host": "shop.example", "path": "/wp-login.php", "protocol": "h2", "status": 200,
		"user_agent": "python-requests/2.31.0",
		"rules":      []any{map[string]any{"id": 930120, "repository": "crs", "msg": "OS File Access Attempt", "severity": "critical", "match_shape": map[string]any{"location": "ARGS:log", "content_type": "application/x-www-form-urlencoded", "len_bucket": "16-64"}}},
		"score":      72, "outcome": "would_block", "mode": "observe", "duration_ms": 3.2, "waf_ms": 0.8,
	}
}

func cloudEvent(typ, name string, data map[string]any) map[string]any {
	return map[string]any{
		"specversion": "1.0", "id": uuid("event-" + name), "source": "schild://web-1", "type": typ,
		"time": "2026-10-26T11:59:58.123Z", "datacontenttype": "application/json", "data": data,
	}
}

func genEvents(g *gen) {
	const c = "events"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, e map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(e), e)
	}
	e := cloudEvent("schild.request.evaluated.v1", "eval", reqData("req-7f3a9c21"))
	add(true, "", "request-evaluated", "Local event with full visitor IP and location (E7).", e)
	d := reqData("req-7f3a9c22")
	d["client"].(map[string]any)["ip"] = "2001:db8::17"
	d["outcome"], d["mode"], d["status"], d["incident"] = "blocked", "autoblock", 403, "K7QM-4XWD"
	e = cloudEvent("schild.request.blocked.v1", "blocked", d)
	add(true, "", "request-blocked-ipv6", "Blocked request with incident number, IPv6 documentation address.", e)
	e = cloudEvent("schild.request.unblocked.v1", "unblocked", map[string]any{"incident": "K7QM-4XWD", "request_id": "req-7f3a9c22", "by": "operator", "false_positive": true, "allowlist_entry": "Office"})
	add(true, "", "request-unblocked", "Operator unblocked an incident and marked it as false positive.", e)
	// D72: signal.sent and the network rule events are gone.
	g.retire(c, true) // signal-sent
	g.retire(c, true) // rule-suspended
	e = cloudEvent("schild.environment.changed.v1", "env", map[string]any{"kind": "plugin", "name": "gallery", "from_version": "2.4.0", "to_version": "2.4.1"})
	add(true, "", "environment-changed", "Plugin update; never leaves the server.", e)
	e = cloudEvent("schild.session.flagged.v1", "session", map[string]any{"session_id": "s_k3j9x2m1p0", "client": reqData("x")["client"], "reason": "rate", "requests": 480, "window_s": 60, "threshold": 300})
	add(true, "", "session-flagged", "Session over the rate threshold.", e)
	e = cloudEvent("schild.advisory.assessed.v1", "adv", map[string]any{"advisory_id": "CVE-2026-12345", "result": "mitigated", "components": []string{"wp-plugin/gallery 2.4.0"}})
	add(true, "", "advisory-assessed", "Advisory matched against the environment.", e)

	d = reqData("req-1")
	d["outcome"] = "blocked"
	e = cloudEvent("schild.request.blocked.v1", "noincident", d)
	add(false, contract.CodeSchema, "blocked-without-incident", "Every block has an incident number.", e)
	e = cloudEvent("schild.request.forwarded.v1", "unknown", reqData("req-2"))
	add(false, contract.CodeSchema, "unknown-type", "Unknown event type.", e)
	d = reqData("req-3")
	d["client"].(map[string]any)["ip"] = "999.0.113.1"
	e = cloudEvent("schild.request.evaluated.v1", "badip", d)
	add(false, contract.CodeSchema, "bad-ip", "Invalid IPv4 address.", e)
	sp := toMap(baseSignal("leak"))
	sp["ip"] = "203.0.113.42"
	e = cloudEvent("schild.signal.sent.v1", "leak", map[string]any{"kind": "signal", "lab": "lab-a", "envelope_sha256": "sha256:" + strings.Repeat("0f", 32), "result": "accepted", "payload": sp})
	add(false, contract.CodeSchema, "signal-sent-with-ip", "D72: the gateway sends no signals; schild.signal.sent.v1 is an unknown type.", e)
	e = cloudEvent("schild.request.evaluated.v1", "spec", reqData("req-4"))
	e["specversion"] = "0.3"
	add(false, contract.CodeSchema, "specversion", "CloudEvents 1.0 only.", e)
	d = reqData("req-5")
	d["body"] = "user=alice&password=hunter2"
	e = cloudEvent("schild.request.evaluated.v1", "body", d)
	add(false, contract.CodeSchema, "request-body", "Request bodies are never stored.", e)
	e = cloudEvent("schild.rule.dropped.v1", "dropped", map[string]any{"rule_id": "schild-2026-0412", "bundle_version": 42})
	add(false, contract.CodeSchema, "dropped-without-reason", "D72: the gateway has no network rules; schild.rule.dropped.v1 is an unknown type.", e)
	e = cloudEvent("schild.request.evaluated.v1", "time", reqData("req-6"))
	e["time"] = "26.10.2026 12:00"
	add(false, contract.CodeSchema, "time-format", "RFC 3339 UTC only.", e)
	d = reqData("req-7")
	d["outcome"] = "allowed"
	e = cloudEvent("schild.request.evaluated.v1", "outcome", d)
	add(false, contract.CodeSchema, "unknown-outcome", "Unknown outcome.", e)
	e = cloudEvent("schild.rule.suspended.v1", "noshare", map[string]any{"rule_id": "schild-2026-0412", "bundle_version": 42, "reason": "local_brake"})
	add(false, contract.CodeSchema, "suspended-without-share", "D72: the gateway has no network rules; schild.rule.suspended.v1 is an unknown type.", e)
	g.add(c, "malformed", false, contract.CodeMalformed, "Broken JSON.", ctx, []byte(`{"specversion":"1.0"`), nil)
	g.add(c, "oversize", false, contract.CodeOversize, "Event larger than 64 KiB.", ctx, []byte(string(mustJSON(cloudEvent("schild.request.evaluated.v1", "big", reqData("req-8"))))+strings.Repeat(" ", 64*1024)), nil)
}

func labEntry(name, endpoint string) map[string]any {
	k := testkeys.Get(name)
	return map[string]any{
		"id": k.Lab, "endpoint": endpoint, "operator": k.Operator, "weight": 1,
		"keys": []any{map[string]any{"keyid": k.KeyID, "public_key": k.Public, "purposes": k.Purposes}},
	}
}

func siteConfig() map[string]any {
	return map[string]any{
		"config_version": 0,
		"mode":           "observe",
		"node_name":      "web-1",
		"upstream":       map[string]any{"url": "http://app:80"},
	}
}

func genSiteConfig(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	m := siteConfig()
	add(true, "", "minimal", "Minimal production config (defaults apply).", m)
	m = siteConfig()
	m["profile"] = "production"
	m["mode"] = "review"
	m["listen"] = map[string]any{"proxy": ":8080", "dashboard": "127.0.0.1:8788", "metrics": "127.0.0.1:9101"}
	m["ingress"] = map[string]any{"trusted_proxies": []string{"127.0.0.1/32", "::1/128"}, "client_ip_headers": []string{"X-Forwarded-For"}}
	m["rules"] = map[string]any{"crs": map[string]any{"state": "block", "paranoia_level": 1, "inbound_anomaly_threshold": 5}}
	m["waf"] = map[string]any{"request_body_limit_bytes": 13107200, "eval_timeout_ms": 1000}
	m["geo"] = map[string]any{"db_path": "/var/lib/schild/geo/geo.mmdb"}
	m["storage"] = map[string]any{"path": "/var/lib/schild"}
	m["retention"] = map[string]any{"raw_ip_days": 7, "events_days": 14, "max_size_mb": 100, "summaries_days": 90}
	m["dashboard"] = map[string]any{"enabled": true, "session_ttl_minutes": 720}
	add(true, "", "full", "Every section set explicitly.", m)
	m = siteConfig()
	m["profile"] = "test"
	add(true, "", "test-profile", "Test profile: test lab only, observe mode only.", m)
	m = siteConfig()
	m["allowlist"] = []any{
		map[string]any{"ip": "203.0.113.42", "label": "Office", "level": "no_block", "expires": "never"},
		map[string]any{"cidr": "198.51.100.0/24", "label": "Agency", "level": "no_block", "expires": "2026-11-30T00:00:00Z"},
		map[string]any{"host": "home.example.net", "label": "Home office", "level": "bypass_waf", "expires": "2026-11-02T00:00:00Z"},
		map[string]any{"ip": "2001:db8::1", "label": "Admin IPv6", "level": "no_block", "expires": "never"},
	}
	add(true, "", "allowlist", "Own IPs, ranges and DynDNS names.", m)
	m = siteConfig()
	m["mode"] = "autoblock"
	add(true, "", "raised-floor", "Mode autoblock. D72: the floor of independent operators is gone with the network.", m)

	for _, f := range []struct {
		name string
		code contract.Code
		mut  func(map[string]any)
		desc string
	}{
		{"floor-one", contract.CodeSchema, func(m map[string]any) { m["min_independent_operators"] = 1 }, "D72: min_independent_operators is an unknown key."},
		{"floor-zero", contract.CodeSchema, func(m map[string]any) { m["min_independent_operators"] = 0 }, "D72: min_independent_operators is an unknown key."},
		{"test-profile-autoblock", "", nil, "D89: the mode is ignored, the test profile observes on its own; a valid vector of genD89."},
		{"test-profile-in-production", contract.CodeSchema, func(m map[string]any) {
			m["test_profile"] = map[string]any{"simulated_operators": []any{map[string]any{"lab": "lab-a", "operator": "sim-1"}}}
		}, "D72: test_profile is an unknown key."},
		{"one-relay", contract.CodeSchema, func(m map[string]any) { m["relays"] = []any{map[string]any{"url": "https://relay-1.schild.test:7480"}} }, "D72: relays is an unknown key."},
		{"unknown-key", contract.CodeSchema, func(m map[string]any) { m["autoupdate"] = true }, "Unknown key."},
		{"quic-0rtt", contract.CodeSchema, func(m map[string]any) { m["ingress"] = map[string]any{"quic_0rtt": true} }, "quic_0rtt is an unknown key (removed in v0.6, it had only one legal value)."},
		{"process-partial", contract.CodeSchema, func(m map[string]any) {
			m["waf"] = map[string]any{"request_body_limit_action": "process_partial"}
		}, "request_body_limit_action is an unknown key (removed in v0.6): a body over the limit is always rejected."},
		{"fail-open-timeout", contract.CodeSchema, func(m map[string]any) { m["waf"] = map[string]any{"on_timeout": "pass"} }, "on_timeout is an unknown key (removed in v0.6): a timeout always answers 503."},
		{"lab-http", contract.CodeSchema, func(m map[string]any) {
			m["labs"] = []any{labEntry("lab-a", "http://lab-a.schild.test:7080")}
		}, "D72: labs is an unknown key."},
		{"sample-rate", contract.CodeSchema, func(m map[string]any) { m["signals"] = map[string]any{"sample_rate": 0.001} }, "D72: signals is an unknown key."},
		{"allowlist-ip-and-cidr", contract.CodeSchema, func(m map[string]any) {
			m["allowlist"] = []any{map[string]any{"ip": "203.0.113.42", "cidr": "203.0.113.0/24", "label": "x", "level": "no_block", "expires": "never"}}
		}, "Exactly one of ip, cidr, host."},
		{"duplicate-lab", contract.CodeSchema, func(m map[string]any) {
			m["labs"] = []any{labEntry("lab-a", "https://lab-a.schild.test:7443"), labEntry("lab-a", "https://lab-a-2.schild.test:7443")}
		}, "D72: labs is an unknown key."},
		{"simulated-unknown-lab", contract.CodeSchema, func(m map[string]any) {
			m["profile"] = "test"
			m["test_profile"] = map[string]any{"simulated_operators": []any{map[string]any{"lab": "lab-x", "operator": "sim-1"}}}
		}, "D72: test_profile is an unknown key."},
		{"duplicate-public-key", contract.CodeSchema, func(m map[string]any) {
			m["labs"] = []any{labEntry("lab-a", "https://lab-a.schild.test:7443"), labEntry("lab-b", "https://lab-b.schild.test:7443")}
		}, "D72: labs is an unknown key."},
		{"duplicate-relay", contract.CodeSchema, func(m map[string]any) {
			m["relays"] = []any{map[string]any{"url": "https://relay-1.schild.test:7480"}, map[string]any{"url": "https://relay-1.schild.test:7480"}}
		}, "D72: relays is an unknown key."},
	} {
		if f.mut == nil {
			g.retire(c, false)
			continue
		}
		m = siteConfig()
		f.mut(m)
		add(false, f.code, f.name, f.desc, m)
	}
	g.add(c, "malformed", false, contract.CodeMalformed, "YAML is converted to JSON before validation; this JSON is broken.", ctx, []byte(`{"mode":"observe",}`), nil)
}

func labConfig() map[string]any {
	a, s1, s2 := testkeys.Get("lab-a"), testkeys.Get("site-a"), testkeys.Get("site-c")
	return map[string]any{
		"config_version": 0,
		"identity":       map[string]any{"operator": a.Operator, "lab": a.Lab},
		"channel":        channel,
		"keys":           []any{map[string]any{"keyid": a.KeyID, "private_key_file": "/etc/schild-lab/keys/lab.key", "purposes": a.Purposes}},
		"issuers":        []any{map[string]any{"id": "issuer-test-1"}, map[string]any{"id": "issuer-test-2"}},
		"clients": []any{
			map[string]any{"keyid": s1.KeyID, "public_key": s1.Public, "issuer": s1.Issuer},
			map[string]any{"keyid": s2.KeyID, "public_key": s2.Public, "issuer": s2.Issuer, "quota_per_day": 1000},
		},
	}
}

func genLabConfig(g *gen) {
	const c = "config/lab"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	add(true, "", "minimal", "Minimal lab config.", labConfig())
	m := labConfig()
	m["profile"] = "production"
	m["listen"] = map[string]any{"ingest": "0.0.0.0:7443", "feed": "0.0.0.0:7444", "dashboard": "127.0.0.1:8789", "metrics": "127.0.0.1:9102"}
	m["tls"] = map[string]any{"cert_file": "/etc/schild-lab/tls/cert.pem", "key_file": "/etc/schild-lab/tls/key.pem"}
	m["ingest"] = map[string]any{"max_body_bytes": 262144, "max_envelopes": 64, "rate_per_client_per_min": 600, "queue_max_depth": 1000000, "retry_after_ms": 5000, "max_clock_skew_s": 120, "max_signal_age_s": 86400, "replay_window_s": 86400}
	m["scoring"] = map[string]any{"min_issuers": 3, "max_issuer_share": 0.34, "window_minutes": 1440, "min_score": 40}
	m["publish"] = map[string]any{"bundle_validity_hours": 168, "checkpoint_interval_s": 60, "checkpoint_ttl_s": 180, "require_human_approval": true}
	m["storage"] = map[string]any{"path": "/var/lib/schild-lab"}
	m["retention"] = map[string]any{"signals_days": 30, "aggregates_days": 365}
	m["dashboard"] = map[string]any{"enabled": true, "session_ttl_minutes": 480}
	add(true, "", "full", "Every section set explicitly.", m)
	m = labConfig()
	b := testkeys.Get("lab-b")
	m["peers"] = []any{map[string]any{"lab": b.Lab, "operator": b.Operator, "endpoint": "https://lab-b.schild.test:7444", "keys": []any{map[string]any{"keyid": b.KeyID, "public_key": b.Public, "purposes": []string{"rules", "checkpoint"}}}, "accept_from": true, "share_with": true, "trust_weight": 0.7, "observe_only": false}}
	add(true, "", "peers", "Explicit federation peer (concept 21 §4.2).", m)
	m = labConfig()
	m["profile"] = "test"
	add(true, "", "test-profile", "Lab in the test lab.", m)
	m = labConfig()
	m["clients"].([]any)[0].(map[string]any)["revoked"] = true
	m["issuers"].([]any)[1].(map[string]any)["revoked"] = true
	add(true, "", "revoked", "Revoked client key and issuer stay listed.", m)

	for _, f := range []struct {
		name string
		code contract.Code
		mut  func(map[string]any)
		desc string
	}{
		{"unknown-issuer", contract.CodeConfig, func(m map[string]any) { m["clients"].([]any)[0].(map[string]any)["issuer"] = "issuer-x" }, "Client names an issuer that is not configured."},
		{"duplicate-issuer", contract.CodeConfig, func(m map[string]any) {
			m["issuers"] = append(m["issuers"].([]any), map[string]any{"id": "issuer-test-1"})
		}, "Duplicate issuer."},
		{"peer-self", contract.CodeConfig, func(m map[string]any) {
			a := testkeys.Get("lab-a")
			m["peers"] = []any{map[string]any{"lab": "lab-a", "operator": a.Operator, "endpoint": "https://lab-a.schild.test:7444", "keys": []any{map[string]any{"keyid": "test-lab-a-feed", "public_key": a.Public, "purposes": []string{"rules"}}}}}
		}, "A lab cannot be its own peer."},
		{"duplicate-keyid", contract.CodeConfig, func(m map[string]any) {
			m["clients"] = append(m["clients"].([]any), map[string]any{"keyid": "test-site-a", "public_key": testkeys.Get("site-b").Public, "issuer": "issuer-test-1"})
		}, "Duplicate client keyid."},
		{"duplicate-client-public-key", contract.CodeConfig, func(m map[string]any) {
			m["clients"] = append(m["clients"].([]any), map[string]any{"keyid": "test-site-a-again", "public_key": testkeys.Get("site-a").Public, "issuer": "issuer-test-2"})
		}, "One site key under two issuers would count its tips for both (Sybil)."},
		{"duplicate-peer-public-key", contract.CodeConfig, func(m map[string]any) {
			b, c := testkeys.Get("lab-b"), testkeys.Get("lab-c")
			m["peers"] = []any{
				map[string]any{"lab": b.Lab, "operator": b.Operator, "endpoint": "https://lab-b.schild.test:7444", "keys": []any{map[string]any{"keyid": b.KeyID, "public_key": b.Public, "purposes": []string{"rules"}}}},
				map[string]any{"lab": c.Lab, "operator": c.Operator, "endpoint": "https://lab-c.schild.test:7444", "keys": []any{map[string]any{"keyid": c.KeyID, "public_key": b.Public, "purposes": []string{"rules"}}}},
			}
		}, "The same key for two peers would count for two operators."},
		{"min-issuers", contract.CodeSchema, func(m map[string]any) { m["scoring"] = map[string]any{"min_issuers": 2} }, "At least 3 issuers (G2)."},
		{"issuer-share", contract.CodeSchema, func(m map[string]any) { m["scoring"] = map[string]any{"max_issuer_share": 0.5} }, "No issuer may carry more than a third."},
		{"no-human-approval", contract.CodeSchema, func(m map[string]any) { m["publish"] = map[string]any{"require_human_approval": false} }, "Humans approve proposals."},
		{"checkpoint-ttl", contract.CodeSchema, func(m map[string]any) { m["publish"] = map[string]any{"checkpoint_ttl_s": 900} }, "Checkpoint TTL above 10 minutes."},
		{"signals-retention", contract.CodeSchema, func(m map[string]any) { m["retention"] = map[string]any{"signals_days": 60} }, "Signals at most 30 days (concept 24)."},
		{"unknown-key", contract.CodeSchema, func(m map[string]any) { m["ai"] = map[string]any{"enabled": true} }, "Unknown key."},
		{"missing-identity", contract.CodeSchema, func(m map[string]any) { delete(m, "identity") }, "identity is required."},
		{"bad-public-key", contract.CodeSchema, func(m map[string]any) { m["clients"].([]any)[0].(map[string]any)["public_key"] = "ed25519:AAAA" }, "Malformed client public key."},
	} {
		m = labConfig()
		f.mut(m)
		add(false, f.code, f.name, f.desc, m)
	}
	g.add(c, "malformed", false, contract.CodeMalformed, "Broken JSON.", ctx, []byte(`{"identity":`), nil)
}

func baseResults() map[string]any {
	return map[string]any{
		"results_version": 0, "spec": "MVP-02", "run_id": "2026-10-26T1200-t0-42",
		"started_at": ts(-30 * time.Minute), "finished_at": ts(0), "seed": 42, "profile": "t0",
		"git_rev":   "642a7eb",
		"images":    []any{map[string]any{"name": "schild:dev", "digest": "sha256:" + strings.Repeat("1a", 32)}},
		"scenarios": []string{"T20", "B01"}, "hypotheses": []string{"M1"},
		"metrics": []any{
			map[string]any{"name": "p95_overhead_ms", "value": 1.9, "unit": "ms", "labels": map[string]any{"rps": "500"}, "samples": 150000},
			map[string]any{"name": "bypass_count", "value": 0, "unit": "count"},
		},
		"kill_criteria": []any{map[string]any{"expr": "p95_overhead_ms > 5 at 500 rps", "hit": false, "observed": "1.9 ms"}},
		"verdict":       "pass",
	}
}

func genResults(g *gen) {
	const c = "results"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	add(true, "", "pass", "Passing measurement.", baseResults())
	m := baseResults()
	m["verdict"] = "fail"
	m["kill_criteria"] = []any{map[string]any{"expr": "canary_found > 0", "hit": true, "observed": "1 canary in egress capture"}}
	m["artifacts"] = []string{"results/runs/2026-10-26/egress.pcap"}
	add(true, "", "fail-kill-hit", "Kill criterion hit; humans decide what follows.", m)
	m = baseResults()
	m["verdict"] = "inconclusive"
	m["notes"] = "Host too small for 100,000 clients; measured 10,000."
	m["host"] = map[string]any{"os": "linux", "arch": "arm64", "cpus": 8, "mem_mb": 16384}
	add(true, "", "inconclusive", "Inconclusive with notes and host info.", m)
	m = baseResults()
	m["spec"], m["profile"], m["images"], m["scenarios"], m["hypotheses"] = "MVP-01", "unit", []any{}, []string{}, []string{"M1", "M2", "M3", "M4", "M5", "M6", "M7"}
	m["metrics"] = []any{map[string]any{"name": "vectors_disagreeing", "value": 0, "unit": "count"}}
	add(true, "", "contracts", "Contract test result (MVP-01).", m)
	m = baseResults()
	m["git_rev"] = "642a7eb-dirty"
	m["verdict"] = "error"
	add(true, "", "error-dirty", "Run aborted on a dirty tree.", m)

	for _, f := range []struct {
		name string
		mut  func(map[string]any)
		desc string
	}{
		{"spec-format", func(m map[string]any) { m["spec"] = "MVP-2" }, "spec must be MVP-NN."},
		{"missing-seed", func(m map[string]any) { delete(m, "seed") }, "Every run has a fixed seed."},
		{"verdict", func(m map[string]any) { m["verdict"] = "ok" }, "Unknown verdict."},
		{"unit", func(m map[string]any) { m["metrics"].([]any)[0].(map[string]any)["unit"] = "milliseconds" }, "Unknown unit."},
		{"finished-before-started", func(m map[string]any) { m["finished_at"] = ts(-time.Hour) }, "finished_at before started_at."},
		{"image-digest", func(m map[string]any) { m["images"].([]any)[0].(map[string]any)["digest"] = "latest" }, "Images pinned by digest."},
		{"extra-field", func(m map[string]any) { m["builder"] = "agent-2" }, "Unknown field."},
		{"metric-name", func(m map[string]any) { m["metrics"].([]any)[0].(map[string]any)["name"] = "P95 Overhead" }, "Metric names are snake_case."},
		{"hypothesis", func(m map[string]any) { m["hypotheses"] = []string{"X1"} }, "Hypotheses are M1-M7 or D1-D3."},
		{"metric-value-string", func(m map[string]any) { m["metrics"].([]any)[0].(map[string]any)["value"] = "1.9" }, "Values are numbers."},
	} {
		m = baseResults()
		f.mut(m)
		add(false, contract.CodeSchema, f.name, f.desc, m)
	}
	g.add(c, "malformed", false, contract.CodeMalformed, "Broken JSON.", ctx, []byte(`{"spec":"MVP-02"`), nil)
}

func genSecLang(g *gen) {
	const c = "seclang"
	for _, sc := range seclang.Cases {
		code := contract.Code("")
		if !sc.Valid {
			code = contract.CodeSecLang
		}
		desc := fmt.Sprintf("SecLang subset case %s (max_action %s).", sc.Name, sc.MaxAction)
		g.add(c, sc.Name, sc.Valid, code, desc, vectors.Context{MaxAction: sc.MaxAction}, []byte(sc.Text), nil)
	}
}
