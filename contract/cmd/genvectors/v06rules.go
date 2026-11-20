//go:build !release

package main

import (
	"fmt"
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/rules"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// genRuleEffect writes the rule-effect vectors (D73): status and effect of a
// rule of any repository, its action on one request, the effect of a
// repository, the state switch and the scope check of the rule writes. They
// replace the effect, switch, gateway_effect and agent_write ops of the
// crowdsec-hub vectors and cover the same cases.
func genRuleEffect(g *gen) {
	const c = rules.Schema
	ctx := vectors.Context{}
	ok := func(name, desc string, m map[string]any) {
		res, err := rules.RunVector(mustJSON(m))
		if err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, res)
	}
	const now, until = 1000000, 1086400
	rule := func(op string, m map[string]any) map[string]any {
		out := map[string]any{"op": op, "mode": "autoblock", "state": "block", "origin": "release", "now": now}
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	eff := func(name, desc string, m map[string]any) { ok("effect-"+name, desc, rule("effect", m)) }
	req := func(name, desc string, m map[string]any) { ok("request-"+name, desc, rule("request", m)) }

	// ---- Status and effect of a rule
	eff("release-autoblock", "A rule of the release blocks.", nil)
	eff("release-observe", "Test profile (mode observe): nothing blocks, the rule would block (gateway_observe).", map[string]any{"mode": "observe"})
	eff("repository-detect", "Repository detect: the rule matches and is logged, never blocks (repository_detect).", map[string]any{"state": "detect"})
	eff("repository-detect-observe", "Repository detect in the test profile: detect, not would_block.", map[string]any{"state": "detect", "mode": "observe"})
	eff("repository-off", "Repository off: no rules, effect off.", map[string]any{"state": "off"})
	eff("disabled-config", "A rule disabled in schild.yaml does nothing, in any state.", map[string]any{"disabled": true, "disabled_by": "config"})
	eff("disabled-dashboard", "A rule disabled in the dashboard.", map[string]any{"disabled": true, "disabled_by": "dashboard"})
	eff("disabled-agent", "A rule disabled through the agent API.", map[string]any{"disabled": true, "disabled_by": "agent", "state": "detect"})
	eff("operator-detect", "The operator's rules in a repository set to detect.", map[string]any{"origin": "operator", "state": "detect"})
	eff("update-settling", "An update settles (settling) and only detects, one second before its end.",
		map[string]any{"origin": "update", "settling_until": until, "now": until - 1})
	eff("update-settled", "At the end of settling_s the update blocks on its own (D89: no approval).", map[string]any{"origin": "update", "settling_until": until, "now": until})
	eff("update-no-settling", "settling_s 0 blocks at once.", map[string]any{"origin": "update", "settling_until": 0})
	eff("update-observe", "Test profile: an update is not settling, it would block.", map[string]any{"origin": "update", "mode": "observe", "settling_until": until})
	eff("update-settling-detect", "Repository detect wins over settling as the reason: settled, it would not block either.",
		map[string]any{"origin": "update", "state": "detect", "settling_until": until})
	eff("update-settling-off", "Repository off: a settling update does nothing.", map[string]any{"origin": "update", "state": "off", "settling_until": until})
	eff("disabled-settling", "A disabled update is disabled, not settling.", map[string]any{"origin": "update", "settling_until": until, "disabled": true, "disabled_by": "agent"})
	eff("release-ignores-settling", "Only updates settle: a time on a release rule changes nothing.", map[string]any{"settling_until": until})

	// ---- What a matched rule does to one request
	req("block", "A block that happened: the only case that counts as a WAF hit.", nil)
	req("detect", "Repository detect (Erkennen): would_block with source_detect, the request passes, no behaviour counter sees it (D90).", map[string]any{"state": "detect"})
	req("off", "Repository off: nothing.", map[string]any{"state": "off"})
	req("disabled", "A disabled rule: nothing.", map[string]any{"disabled": true, "disabled_by": "config"})
	req("bypass", "bypass_waf skips the WAF.", map[string]any{"allow": "bypass_waf"})
	req("gateway-observe", "Test profile: would_block, gateway_observe.", map[string]any{"mode": "observe"})
	req("site-observe", "A website in observe: would_block, site_observe.", map[string]any{"site_mode": "observe"})
	req("site-protect", "A website in protect: the rule blocks.", map[string]any{"site_mode": "protect"})
	req("no-block-entry", "An allowlist no_block entry: would_block, allowlist.", map[string]any{"allow": "no_block"})
	req("excepted", "An unblock excepts the source for this client: logged.", map[string]any{"excepted": true})
	req("excepted-observe", "An exception is named before the test profile.", map[string]any{"excepted": true, "mode": "observe"})
	req("settling-no-block-entry", "A settling update with a no_block entry: the update explains it first.", map[string]any{"origin": "update", "settling_until": until, "allow": "no_block"})
	req("settling", "A settling update only detects: would_block with reason settling (D90).", map[string]any{"origin": "update", "settling_until": until})
	req("settling-site-observe", "Settling is named before a website in observe.", map[string]any{"origin": "update", "settling_until": until, "site_mode": "observe"})
	req("settled", "A settled update blocks.", map[string]any{"origin": "update", "settling_until": until, "now": until})

	// ---- What a repository does
	repo := func(name, desc, state, mode string) {
		ok("repository-"+name, desc, map[string]any{"op": "repository", "state": state, "mode": mode})
	}
	repo("block-autoblock", "A repository in block blocks; settling updates are rules, not the repository.", "block", "autoblock")
	repo("block-observe", "Test profile: the repository would block.", "block", "observe")
	repo("detect-autoblock", "Detect stays detect.", "detect", "autoblock")
	repo("detect-observe", "Detect in the test profile stays detect.", "detect", "observe")
	repo("off-autoblock", "Off is off.", "off", "autoblock")

	// ---- The state of a repository
	sw := func(name, desc string, m map[string]any) {
		m["op"] = "switch"
		ok("switch-"+name, desc, m)
	}
	sw("default-crowdsec", "Nothing set: crowdsec detects by default.", map[string]any{"repository": "crowdsec"})
	sw("default-crs", "Nothing set: crs blocks by default.", map[string]any{"repository": "crs"})
	sw("default-local", "Nothing set: local blocks by default.", map[string]any{"repository": "local"})
	sw("config", "schild.yaml counts while the overlay has no value.", map[string]any{"repository": "crowdsec", "config": "block"})
	sw("overlay-wins", "The value of the settings overlay wins over schild.yaml; the API shows that they differ.", map[string]any{"repository": "crs", "config": "block", "overlay": "detect"})
	sw("overlay-equal", "The same value in both: nothing to show.", map[string]any{"repository": "crowdsec", "config": "block", "overlay": "block"})
	sw("off-to-detect", "Off to detect loads the rules: a rebuild.", map[string]any{"repository": "crowdsec", "config": "off", "requested": "detect"})
	sw("detect-to-off", "Detect to off unloads the rules: a rebuild.", map[string]any{"repository": "local", "config": "detect", "requested": "off"})
	sw("crs-to-off", "The CRS can be switched off too: a rebuild.", map[string]any{"repository": "crs", "requested": "off"})
	sw("detect-to-block", "Detect to block needs no rebuild: the next request decides differently.", map[string]any{"repository": "crowdsec", "config": "detect", "requested": "block"})
	sw("block-to-detect", "Back to detect, the same.", map[string]any{"repository": "crs", "requested": "detect"})
	sw("no-change", "Asking for the current value changes nothing: no rebuild, no entry in the change history.", map[string]any{"repository": "crowdsec", "config": "detect", "requested": "detect"})
	sw("reset", "reset_state drops the overlay value: schild.yaml counts again.", map[string]any{"repository": "crowdsec", "config": "detect", "overlay": "off", "reset": true})
	sw("reset-default", "reset_state without a value in schild.yaml: the default counts.", map[string]any{"repository": "local", "overlay": "detect", "reset": true})
	sw("reset-nothing", "reset_state without an overlay value changes nothing.", map[string]any{"repository": "crowdsec", "config": "block", "reset": true})
	sw("agent-sets", "An agent sets block: state_source agent.", map[string]any{"repository": "crowdsec", "config": "detect", "requested": "block", "actor": "agent"})
	sw("agent-value-stays", "state_source stays agent while its value is in the overlay.", map[string]any{"repository": "crowdsec", "config": "detect", "overlay": "off", "overlay_by": "agent"})
	sw("dashboard-over-agent", "One overlay value per repository: the last writer owns it.",
		map[string]any{"repository": "crowdsec", "config": "detect", "overlay": "block", "overlay_by": "agent", "requested": "detect", "actor": "dashboard"})
	sw("agent-over-dashboard", "The same the other way round.", map[string]any{"repository": "crs", "overlay": "off", "overlay_by": "dashboard", "requested": "off", "actor": "agent"})
	sw("agent-reset", "An agent may reset_state, whoever set the value.", map[string]any{"repository": "crowdsec", "config": "block", "overlay": "off", "overlay_by": "dashboard", "reset": true, "actor": "agent"})

	// ---- The scopes of the rule writes in the agent API
	aw := func(name, desc, scope, op string) {
		ok("agent-write-"+name, desc, map[string]any{"op": "agent_write", "scope": scope, "operation": op})
	}
	aw("read-token", "A read token gets 403 scope_required.", "agent:read", "updateAgentRuleRepository")
	aw("export-token", "An export token gets the same.", "export:read", "updateAgentRule")
	aw("rules-write-state", "rules:write sets the state of a repository.", "rules:write", "updateAgentRuleRepository")
	aw("rules-write-sync", "rules:write runs a sync.", "rules:write", "syncAgentRuleRepository")
	aw("rules-write-reset", "rules:write runs a reset.", "rules:write", "resetAgentRuleRepository")
	aw("rules-write-disable", "rules:write disables a rule.", "rules:write", "updateAgentRule")
	aw("approve-gone", "D89: approving is gone, no scope may call it.", "rules:write", "approveAgentRule")
	aw("approve-scope-gone", "D89: the scope rules:approve is gone.", "rules:approve", "updateAgentRule")
	aw("exceptions-write", "exceptions:write has no rule write.", "exceptions:write", "updateAgentRule")
	aw("old-scope", "crowdsec:write is gone.", "crowdsec:write", "updateAgentRuleRepository")
	aw("no-wildcard", "No wildcard scope.", "rules:*", "updateAgentRule")
	aw("unknown-operation", "An operation that is no write.", "rules:write", "listAgentRules")

	// ---- Broken inputs of the vector itself
	bad := func(name, desc string, code contract.Code, raw []byte, decoded any) {
		g.add(c, name, false, code, desc, ctx, raw, decoded)
	}
	inv := func(name, desc string, m map[string]any) { bad(name, desc, contract.CodeSchema, mustJSON(m), m) }
	bad("oversize", "Input above 4 KiB.", contract.CodeOversize, []byte(`{"op":"switch","x":"`+strings.Repeat("a", rules.MaxInputBytes)+`"}`), nil)
	bad("not-json", "Not JSON.", contract.CodeMalformed, []byte(`{"op":`), nil)
	bad("duplicate-key", "Strict JSON: duplicate key.", contract.CodeMalformed, []byte(`{"op":"switch","op":"switch"}`), nil)
	inv("unknown-op", "Unknown op.", map[string]any{"op": "delete"})
	inv("effect-bad-state", "Three states only; enabled does not exist.", rule("effect", map[string]any{"state": "enabled"}))
	inv("effect-bad-mode", "The mode is observe or autoblock.", rule("effect", map[string]any{"mode": "strict"}))
	inv("effect-review", "D89: mode review is gone.", rule("effect", map[string]any{"mode": "review"}))
	inv("effect-no-origin", "Every rule has an origin.", func() map[string]any { m := rule("effect", nil); delete(m, "origin"); return m }())
	inv("effect-bad-origin", "Three origins only.", rule("effect", map[string]any{"origin": "network"}))
	inv("effect-approval", "D89: no approvals.", rule("effect", map[string]any{"approval": "approved"}))
	inv("effect-negative", "Times are not negative.", rule("effect", map[string]any{"now": -1}))
	inv("effect-request-field", "effect has no request: site_mode belongs to op request.", rule("effect", map[string]any{"site_mode": "observe"}))
	inv("request-bad-allow", "Two allowlist levels only.", rule("request", map[string]any{"allow": "trusted"}))
	inv("switch-no-repository", "The switch names its repository.", map[string]any{"op": "switch", "requested": "off"})
	inv("switch-unknown-repository", "Three repositories in this version; the network comes with its own decision.", map[string]any{"op": "switch", "repository": "network"})
	inv("switch-bad-actor", "The dashboard or an agent.", map[string]any{"op": "switch", "repository": "crs", "requested": "off", "actor": "cron"})
	inv("switch-extra", "No password on the switch.", map[string]any{"op": "switch", "repository": "crs", "password": "x"})
	inv("repository-bad-mode", "The mode is observe or autoblock.", map[string]any{"op": "repository", "state": "block", "mode": "strict"})
	inv("agent-write-no-operation", "The check names the operation.", map[string]any{"op": "agent_write", "scope": "rules:write"})
}

// genSiteConfigD73 writes the schild.yaml vectors of the rules block (D73):
// one block for the three repositories replaces waf.crs, crowdsec_hub and
// SCHILD_LOCAL_RULES; the old keys are refused, no aliases.
func genSiteConfigD73(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, name, desc string, edit func(m map[string]any)) {
		x := siteConfig()
		edit(x)
		var code contract.Code
		if !valid {
			code = contract.CodeSchema
		}
		g.add(c, name, valid, code, desc, ctx, mustJSON(x), x)
	}
	rulesOf := func(v map[string]any) func(map[string]any) { return func(x map[string]any) { x["rules"] = v } }
	add(true, "rules-full", "D73: every key of the three repositories.", rulesOf(map[string]any{
		"crs":      map[string]any{"state": "block", "paranoia_level": 2, "inbound_anomaly_threshold": 7, "livewire_exception": true, "disabled_rules": []any{"942100", "920350"}},
		"crowdsec": map[string]any{"state": "block", "auto_update": true, "interval_s": 3600, "settling_s": 0, "disabled_rules": []any{"crowdsecurity/vpatch-CVE-2026-1207"}},
		"local":    map[string]any{"state": "detect", "dir": "/srv/schild/rules.d", "disabled_rules": []any{"10001"}},
	}))
	add(true, "rules-empty", "D73: an empty block keeps the defaults: crs and local block, crowdsec detects.", rulesOf(map[string]any{}))
	add(true, "rules-crs-detect", "D73: the CRS can only detect: matches logged, never a block.", rulesOf(map[string]any{"crs": map[string]any{"state": "detect"}}))
	add(true, "rules-crs-off", "D73: the CRS can be switched off.", rulesOf(map[string]any{"crs": map[string]any{"state": "off"}}))
	add(true, "rules-local-off", "D73: local off: rules.d is not read.", rulesOf(map[string]any{"local": map[string]any{"state": "off"}}))
	add(false, "rules-old-crowdsec-hub", "D73: crowdsec_hub is gone, no alias.", func(x map[string]any) { x["crowdsec_hub"] = map[string]any{"state": "detect"} })
	add(false, "rules-old-waf-crs", "D73: waf.crs is gone, no alias; waf keeps the engine limits.", func(x map[string]any) {
		x["waf"] = map[string]any{"crs": map[string]any{"paranoia_level": 1}}
	})
	add(false, "rules-crs-enabled", "D73: the state replaces enabled.", rulesOf(map[string]any{"crs": map[string]any{"enabled": true}}))
	add(false, "rules-unknown-repository", "D73: three repositories in this version; the network comes with its own decision.", rulesOf(map[string]any{"network": map[string]any{"state": "block"}}))
	add(false, "rules-bad-state", "D73: three states only.", rulesOf(map[string]any{"local": map[string]any{"state": "on"}}))
	add(false, "rules-crs-disabled-not-crs", "D73: crs disabled_rules are CRS ids (900000 to 999999).", rulesOf(map[string]any{"crs": map[string]any{"disabled_rules": []any{"10001"}}}))
	add(false, "rules-crs-disabled-number", "D73: rule ids are strings.", rulesOf(map[string]any{"crs": map[string]any{"disabled_rules": []any{942100}}}))
	add(false, "rules-local-relative-dir", "D73: the directory is an absolute path.", rulesOf(map[string]any{"local": map[string]any{"dir": "rules.d"}}))
	add(false, "rules-local-duplicate", "D73: no duplicates.", rulesOf(map[string]any{"local": map[string]any{"disabled_rules": []any{"10001", "10001"}}}))
	add(false, "rules-local-crowdsec-key", "D73: repository keys stay with their repository.", rulesOf(map[string]any{"local": map[string]any{"auto_update": false}}))
}

// genEventsD73 writes the event vectors of the rule events (D73).
func genEventsD73(g *gen) {
	add := func(valid bool, name, desc, typ string, d map[string]any) {
		var code contract.Code
		if !valid {
			code = contract.CodeSchema
		}
		x := cloudEvent(typ, name, d)
		g.add("events", name, valid, code, desc, vectors.Context{}, mustJSON(x), x)
	}
	tok := func(d map[string]any) map[string]any {
		d["actor"], d["token_id"], d["token_label"] = "agent", "tok_000000000001", "Local agent"
		return d
	}
	const upd, sw = "schild.rule.repository_updated.v1", "schild.rule.repository_switched.v1"
	add(true, "rule-local-reloaded", "D73: a sync of local loaded rules.d again.", upd, map[string]any{"repository": "local", "outcome": "reloaded", "rules_loaded": 12, "added": []any{"10002"}})
	add(true, "rule-local-refused", "D73: a sync of local was refused, the running rules stay.", upd, map[string]any{"repository": "local", "outcome": "refused", "code": "id_range", "rules_loaded": 11})
	add(false, "rule-local-set-source", "D73: set_source is a crowdsec field.", upd, map[string]any{"repository": "local", "outcome": "reloaded", "set_source": "image", "rules_loaded": 1})
	add(false, "rule-local-reset", "D73: only crowdsec has a reset.", upd, map[string]any{"repository": "local", "outcome": "reset", "rules_loaded": 1})
	add(false, "rule-crowdsec-reloaded", "D73: crowdsec updates, it does not reload.", upd, map[string]any{"repository": "crowdsec", "outcome": "reloaded", "set_source": "stored", "rules_loaded": 1})
	add(false, "rule-updated-no-repository", "D73: every rule event names its repository.", upd, map[string]any{"outcome": "reloaded", "rules_loaded": 1})
	add(true, "rule-crs-switched", "D73: the CRS switched to detect in the dashboard.", sw, map[string]any{"repository": "crs", "from": "block", "to": "detect", "actor": "dashboard", "state_source": "dashboard"})
	add(true, "rule-local-switched-agent", "D73: an agent switched local off.", sw, tok(map[string]any{"repository": "local", "from": "block", "to": "off", "state_source": "agent"}))
	add(false, "rule-switched-network", "D73: three repositories in this version.", sw, map[string]any{"repository": "network", "from": "off", "to": "block", "actor": "dashboard", "state_source": "dashboard"})
	add(true, "rule-disabled-dashboard", "D73: a person disabled a CRS rule, with a note.", "schild.rule.disabled.v1",
		map[string]any{"repository": "crs", "rule": "942100", "actor": "dashboard", "note": "false positive on the search form"})
	add(true, "rule-enabled-agent", "D73: an agent enabled a crowdsec rule again.", "schild.rule.enabled.v1",
		tok(map[string]any{"repository": "crowdsec", "rule": "62846312", "name": "crowdsecurity/vpatch-CVE-2026-1207"}))
	add(false, "rule-disabled-agent-no-token", "D73: an agent write always names the token.", "schild.rule.disabled.v1", map[string]any{"repository": "local", "rule": "10001", "actor": "agent"})
	add(false, "rule-disabled-dashboard-token", "D73: the dashboard has no token.", "schild.rule.disabled.v1",
		map[string]any{"repository": "local", "rule": "10001", "actor": "dashboard", "token_id": "tok_000000000001", "token_label": "x"})
	add(false, "rule-disabled-bad-rule", "D73: a rule is its SecRule id as a string.", "schild.rule.disabled.v1", map[string]any{"repository": "crs", "rule": "rule-1", "actor": "dashboard"})
	add(true, "rule-approved", "D73: a person approved one version of a crowdsec update: it acts at once.", "schild.rule.approved.v1",
		map[string]any{"repository": "crowdsec", "rule": "62846312", "name": "crowdsecurity/vpatch-CVE-2026-1207", "version": "0.2", "actor": "dashboard"})
	add(true, "rule-rejected-agent", "D73: an agent with rules:approve rejected a version.", "schild.rule.rejected.v1",
		tok(map[string]any{"repository": "crowdsec", "rule": "62846312", "version": "0.3", "note": "breaks the shop search"}))
	add(false, "rule-approved-no-version", "D73: an approval is for one version.", "schild.rule.approved.v1", map[string]any{"repository": "crowdsec", "rule": "62846312", "actor": "dashboard"})
	add(false, "rule-old-hub-updated", "D73: schild.rule.hub_updated.v1 is gone.", "schild.rule.hub_updated.v1",
		map[string]any{"outcome": "accepted", "set_source": "stored", "rules_loaded": 1, "rules_skipped": 0})
	add(false, "rule-exception-crowdsec-int", "D73: exception rules are id strings.", "schild.rule.exception_set.v1",
		map[string]any{"id": 1900001, "website": "app.example.org", "path": "/search", "target": "ARGS:q", "repository": "crowdsec", "rules": []any{62846312},
			"token_id": "tok_000000000001", "token_label": "Local agent", "reason": "search field"})
	add(true, "rule-exception-crowdsec", "D73: an exception for a crowdsec rule names the repository and the base id.", "schild.rule.exception_set.v1",
		map[string]any{"id": 1900001, "website": "app.example.org", "path": "/search", "target": "ARGS:q", "repository": "crowdsec", "rules": []any{"62846312"},
			"token_id": "tok_000000000001", "token_label": "Local agent", "reason": "search field"})
	add(false, "rule-exception-local", "D73: local rules get no exception: they are the operator's own file.", "schild.rule.exception_set.v1",
		map[string]any{"id": 1900002, "website": "app.example.org", "path": "/search", "target": "ARGS:q", "repository": "local", "rules": []any{"10001"},
			"token_id": "tok_000000000001", "token_label": "Local agent", "reason": "x"})
}
