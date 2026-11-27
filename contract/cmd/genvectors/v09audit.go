//go:build !release

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/audit"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// Draft (MVP-36): the audit log (audit.md).
func genAudit(g *gen) {
	const c = "audit"
	ctx := vectors.Context{}
	type M = map[string]any
	type L = []any
	ok := func(name, desc string, m M) {
		res, err := audit.RunVector(mustJSON(m))
		if err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		g.addResult(c, name, true, "", desc, ctx, mustJSON(m), m, res)
	}
	bad := func(name, desc string, m M) {
		if _, err := audit.RunVector(mustJSON(m)); contract.CodeOf(err) != contract.CodeSchema {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(m), m)
	}
	const log = "0a1b2c3d4e5f6071"
	diff := func(action string, before, after any) M {
		return M{"op": "diff", "action": action, "before": before, "after": after}
	}

	// What an entry records.
	ok("diff-add", "A new own IP: every field of the action with its value.", diff("allowlist.add", nil, M{"ip": "203.0.113.7", "label": "Office", "level": "no_block", "expires": "2026-11-02T12:00:00Z"}))
	ok("diff-one-field", "Only what changed, not what stayed.", diff("rule_repository.set", M{"state": "detect", "paranoia_level": 1}, M{"state": "block", "paranoia_level": 1}))
	ok("diff-nothing", "The same state: no field.", diff("settings.set", M{"retention": M{"raw_ip_days": 14}}, M{"retention": M{"raw_ip_days": 14.0}}))
	ok("diff-nested", "Nested objects to their last field, * for one segment.", diff("behaviour.set", M{"thresholds": M{"path_probing": M{"count": 20, "window_s": 60}}, "scenarios": M{"path_probing": "observe"}}, M{"thresholds": M{"path_probing": M{"count": 30, "window_s": 60, "baseline_factor": 1.5}}, "scenarios": M{"path_probing": "block"}}))
	ok("diff-secret", "A password is listed for the action and still has no value: names that end like a secret never have one.", diff("access_lock.set", M{"scope": "site", "password": "old-marker-1"}, M{"scope": "site", "password": "new-marker-2"}))
	ok("diff-secret-set", "A first password reads as added.", diff("password.setup", nil, M{"password": "marker-3"}))
	ok("diff-unlisted-field", "A field the action does not list is named, its value is not recorded.", diff("token.add", nil, M{"scope": "agent:read", "label": "Laptop", "internal": "marker-4", "token_hash": "marker-5", "apiKey": "marker-6"}))
	ok("diff-list", "A list of texts as what came and what went.", diff("access_lock.set", M{"paths": L{"/admin", "/wp-admin/*"}}, M{"paths": L{"/wp-admin/*", "/backend", "/admin2", "/backend"}}))
	ok("diff-list-order", "The same items in another order.", diff("access_lock.set", M{"paths": L{"/a", "/b"}}, M{"paths": L{"/b", "/a"}}))
	ok("diff-list-first", "A first list: everything came.", diff("rule_exception.set", nil, M{"path": "/kontakt", "target": "ARGS:message", "repository": "crs", "rules": L{"942100", "942200"}}))
	ok("diff-list-of-objects", "A list of something else than texts is not recorded.", diff("access_lock.set", M{"paths": L{"/a"}}, M{"paths": L{M{"path": "/a", "password": "marker-7"}}}))
	many := L{}
	for i := 0; i < 40; i++ {
		many = append(many, fmt.Sprintf("/p%02d", i))
	}
	ok("diff-list-long", "32 items of a list, the rest as a number.", diff("access_lock.set", nil, M{"paths": many}))
	ok("diff-cut-value", "A value longer than 512 bytes is cut between two characters.", diff("maintenance.set", M{"message": ""}, M{"message": strings.Repeat("ä", 300)}))
	ok("diff-control-characters", "Control characters and characters that change the direction of text are replaced.", diff("maintenance.set", nil, M{"message": "a\nb‮c​d\u0000e"}))
	ok("diff-null-and-empty", "null and an empty object are not there.", diff("settings.set", M{"retention": M{}}, M{"retention": M{"raw_ip_days": nil, "events_days": 30}}))
	ok("diff-pointer-escape", "A name with / and ~ as in a JSON pointer.", diff("crawlers.set", nil, M{"bots": M{"a/b~c": "block"}}))
	ok("diff-scalar-to-list", "A value that becomes a list is not recorded.", diff("access_lock.set", M{"paths": "/a"}, M{"paths": L{"/a"}}))
	ok("diff-type-changes", "true is not 1 and \"1\" is not 1.", diff("settings.set", M{"retention": M{"a": true, "b": "1", "c": false}}, M{"retention": M{"a": 1, "b": 1, "c": 0}}))
	big := M{}
	for i := 0; i < 30; i++ {
		big[fmt.Sprintf("b%02d", i)] = strings.Repeat("x", 400)
	}
	ok("diff-size", "8192 bytes are recorded, the fields after that without a value.", diff("crawlers.set", nil, M{"bots": big}))
	wide := M{}
	for i := 0; i < 70; i++ {
		wide[fmt.Sprintf("b%02d", i)] = "block"
	}
	ok("diff-many-fields", "64 fields, the rest as a number.", diff("crawlers.set", nil, M{"bots": wide}))
	ok("diff-long-name", "A field with a name over 512 bytes is counted only.", diff("crawlers.set", nil, M{"bots": M{strings.Repeat("n", 600): "block", "gptbot": "block"}}))
	bad("diff-unknown-action", "An action outside the closed list.", diff("allowlist.replace", nil, M{}))
	bad("diff-not-object", "A state is an object or null.", diff("allowlist.add", nil, L{"203.0.113.7"}))

	// Entries.
	entry := func(kv ...any) M {
		m := M{"schema": "schild.audit/0.1", "id": log + "-k-17", "time": ts(0), "node": "gw-1", "class": "change", "action": "rule_exception.set",
			"operation": "agent:createAgentException", "result": "done", "actor": M{"kind": "agent", "id": "tok_0123456789ab", "label": "coding-agent"},
			"subject": M{"kind": "rule_exception", "id": "1900001"}, "website": "shop.example", "reason": "Contact form",
			"change": M{"fields": L{M{"field": "/path", "change": "added", "after": "/kontakt"}, M{"field": "/rules", "change": "added", "added": L{"942100"}}}}}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(m, kv[i].(string))
			} else {
				m[kv[i].(string)] = kv[i+1]
			}
		}
		return m
	}
	own := func(kv ...any) M {
		return entry(append([]any{"action", "allowlist.add", "operation", "dashboard:addAllowlistEntry", "actor", M{"kind": "dashboard", "user": "admin", "session": "0a1b2c3d"},
			"subject", M{"kind": "allowlist_entry", "id": "al_1"}, "address", "198.51.100.20", "reason", "Office 203.0.113.7, see ticket",
			"change", M{"fields": L{M{"field": "/ip", "change": "added", "after": "203.0.113.7"}, M{"field": "/label", "change": "added", "after": "CLI 203.0.113.7"}, M{"field": "/level", "change": "added", "after": "no_block"}}}}, kv...)...)
	}
	refused := func(kv ...any) M {
		return entry(append([]any{"id", log + "-r-3", "class", "refused", "result", "refused", "change", nil, "reason", nil, "website", nil, "count", 12, "last", ts(40 * time.Second)}, kv...)...)
	}
	in := func(from string, e M) M { return M{"op": "entry", "from": from, "entry": e} }
	ok("entry-agent", "A token sets an exception.", in("local", entry()))
	ok("entry-cause", "The exception names the event it was made from.", in("local", entry("cause", M{"event": "0b7e3f9a-5c2d-4e8f-9a1b-2c3d4e5f6a7b"})))
	bad("entry-cause-both", "One cause, an event or an incident.", in("local", entry("cause", M{"event": "0b7e3f9a-5c2d-4e8f-9a1b-2c3d4e5f6a7b", "incident": "K7QM-2XPA"})))
	ok("entry-dashboard", "The dashboard adds an own IP for one website.", in("local", own()))
	ok("entry-cli", "A command on the host; the account is a hint.", in("local", entry("class", "credential", "action", "token.add", "operation", "cli:token add", "actor", M{"kind": "cli", "account": "deploy"}, "subject", M{"kind": "token", "id": "tok_0123456789ab"}, "website", nil, "reason", nil,
		"change", M{"fields": L{M{"field": "/scope", "change": "added", "after": "exceptions:write"}}})))
	ok("entry-config", "A configuration that was applied: the names of the fields, no values.", in("local", entry("action", "config.apply", "operation", "config:schild_yaml", "actor", M{"kind": "config"}, "subject", M{"kind": "config"}, "website", nil, "reason", nil,
		"change", M{"fields": L{M{"field": "/digest", "change": "changed", "before": "1f2e3d", "after": "4c5b6a"}, M{"field": "/geo/ipinfo_key", "change": "changed", "hidden": "secret"}}})))
	ok("entry-sign-in", "A sign-in has an end of its own.", in("local", entry("id", log+"-a-5", "class", "access", "action", "session.start", "operation", "dashboard:login", "actor", M{"kind": "dashboard", "user": "admin", "session": "0a1b2c3d"}, "subject", M{"kind": "user"}, "address", "198.51.100.20", "website", nil, "reason", nil, "change", nil)))
	ok("entry-refused-sign-in", "A failed sign-in names no user: what was typed may be a password.", in("local", refused("action", "session.start", "operation", "dashboard:login", "actor", M{"kind": "dashboard"}, "subject", M{"kind": "user"}, "address", "198.51.100.66")))
	ok("entry-refused-write", "A token without the scope: the action it tried, refused.", in("local", refused()))
	ok("entry-unknown-token", "A call with an unknown token.", in("local", refused("action", "agent_api.call", "operation", "agent:any", "actor", M{"kind": "agent"}, "subject", M{"kind": "agent_api"})))
	ok("entry-member-unknown-action", "A member runs a later build: the entry is taken, its action is unknown here.", in("member", entry("action", "portal.add", "operation", "cli:portal add", "actor", M{"kind": "cli"}, "subject", M{"kind": "portal"}, "change", M{"fields": L{M{"field": "/label", "change": "added", "after": "Portal"}}})))
	ok("entry-member-value-not-listed", "A member records a value this build would not: the value is taken out, the entry stays.", in("member", entry("change", M{"fields": L{M{"field": "/later", "change": "added", "after": "x"}, M{"field": "/path", "change": "added", "after": "/kontakt"}}})))
	ok("entry-member-unknown-secret", "Also of an unknown action no field that is named like a secret keeps its value.", in("member", entry("action", "portal.add", "operation", "cli:portal add", "actor", M{"kind": "cli"}, "subject", M{"kind": "portal"}, "change", M{"fields": L{M{"field": "/portal_key", "change": "added", "after": "marker-8"}}})))
	bad("entry-unknown-action", "A node writes no action outside the list.", in("local", entry("action", "portal.add")))
	bad("entry-wrong-operation", "An action by an operation that does not belong to it.", in("local", entry("operation", "agent:createAgentBlock")))
	bad("entry-wrong-actor", "The actor does not fit the way.", in("local", entry("actor", M{"kind": "dashboard", "user": "admin"})))
	bad("entry-agent-without-id", "A change of a token names the token.", in("local", entry("actor", M{"kind": "agent", "label": "x"})))
	bad("entry-class", "The class of the action.", in("local", entry("class", "privacy")))
	bad("entry-letter", "A change is no refused call by its id.", in("local", entry("id", log+"-r-17")))
	bad("entry-website-missing", "An exception belongs to a website.", in("local", entry("website", nil)))
	bad("entry-website-none", "A rule does not.", in("local", entry("action", "rule.set", "operation", "agent:updateAgentRule", "subject", M{"kind": "rule"}, "change", nil)))
	bad("entry-value-not-listed", "A node records no value the action does not list.", in("local", entry("change", M{"fields": L{M{"field": "/reason_internal", "change": "added", "after": "x"}}})))
	bad("entry-secret-value", "Never the value of a secret, also from no member with a list that allows it.", in("local", entry("action", "access_lock.set", "operation", "cli:lock on", "actor", M{"kind": "cli"}, "subject", M{"kind": "website"}, "change", M{"fields": L{M{"field": "/password", "change": "added", "after": "marker-9"}}})))
	bad("entry-neither-value-nor-hidden", "A field says why it has no value.", in("local", entry("change", M{"fields": L{M{"field": "/path", "change": "added"}}})))
	bad("entry-refused-with-change", "A refused call changes nothing.", in("local", refused("change", M{"fields": L{}})))
	bad("entry-done-with-count", "Only refused calls are gathered.", in("local", entry("count", 2, "last", ts(0))))
	bad("entry-address-cut", "No field says that an address was cut: an entry is never rewritten.", in("local", own("address_cut", "short")))
	bad("entry-impossible-date", "A date that does not exist.", in("member", entry("time", "2026-02-30T12:00:00Z")))
	bad("entry-token-as-id", "The id of a token, never the token.", in("local", entry("actor", M{"kind": "agent", "id": "sat1_0123456789abcdef"})))
	bad("entry-subject-address", "A subject is never named by an address.", in("local", own("subject", M{"kind": "allowlist_entry", "id": "203.0.113.7"})))
	bad("entry-subject-client", "A client has no id.", in("member", entry("action", "client.release", "operation", "dashboard:releaseClient", "actor", M{"kind": "dashboard"}, "subject", M{"kind": "client", "id": "c1"}, "change", nil)))
	bad("entry-unknown-field", "No field outside the schema.", in("local", entry("user_agent", "curl")))
	bad("entry-number-zero", "Numbers start at 1.", in("local", entry("id", log+"-k-0")))

	// Refused calls.
	t0 := Now.UnixMilli()
	call := func(dt int64, kv ...any) M {
		m := M{"t": t0 + dt, "action": "session.start", "operation": "dashboard:login", "address": "198.51.100.66"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	calls := func(open int, cs ...M) M {
		l := L{}
		for _, x := range cs {
			l = append(l, x)
		}
		return M{"op": "refused", "max_open": open, "calls": l}
	}
	ok("refused-gathered", "One entry per client and minute.", calls(4, call(0), call(1000), call(59999), call(60000)))
	ok("refused-ipv6", "An IPv6 client is its /64.", calls(4, call(0, "address", "2001:db8:0:1::1"), call(1, "address", "2001:db8:0:1::2"), call(2, "address", "2001:db8:0:2::1")))
	ok("refused-per-token", "Per token and operation.", calls(4, call(0, "action", "rule.set", "operation", "agent:updateAgentRule", "actor", "tok_0123456789ab"), call(1, "action", "rule.set", "operation", "agent:updateAgentRule", "actor", "tok_ba9876543210"), call(2, "action", "rule.set", "operation", "agent:updateAgentRule", "actor", "tok_0123456789ab")))
	ok("refused-flood", "With every slot taken a new client counts in the entry without an address.", calls(1, call(0), call(1, "address", "198.51.100.67"), call(2, "address", "198.51.100.68"), call(3), call(60000, "address", "198.51.100.68")))
	ok("refused-late", "A call of an earlier minute counts in the open entry and widens it.", calls(4, call(60000), call(59000)))
	ok("refused-mapped", "An IPv4 address written as IPv6 is the same client.", calls(4, call(0), call(1, "address", "::ffff:198.51.100.66")))
	ok("refused-no-address", "A call without an address.", calls(0, M{"t": t0, "action": "agent_api.call", "operation": "agent:any"}, M{"t": t0 + 5, "action": "agent_api.call", "operation": "agent:any"}))
	bad("refused-cli", "Only what comes over the network is gathered.", calls(4, call(0, "operation", "cli:allow")))

	// What is deleted.
	const day = int64(24 * 3600 * 1000)
	row := func(letter, class string, n int, ago int64) M {
		return M{"id": fmt.Sprintf("%s-%s-%d", log, letter, n), "class": class, "t": t0 - ago}
	}
	keep := func(days any, max int, rows ...M) M {
		l := L{}
		for _, r := range rows {
			l = append(l, r)
		}
		return M{"op": "keep", "now": t0, "keep_days": days, "max_rows": max, "rows": l}
	}
	ok("keep-unlimited", "audit.keep_days unlimited: changes, credentials and privacy entries of ten years stay.", keep(nil, 10, row("k", "change", 1, 3650*day), row("k", "credential", 2, 3650*day), row("k", "privacy", 3, 3650*day), row("a", "access", 1, 3650*day)))
	ok("keep-year", "The default, 365 days: from this age on they go.", keep(audit.DefaultKeepDays, 10, row("k", "change", 1, 365*day), row("k", "change", 2, 365*day-1), row("k", "privacy", 3, 366*day)))
	ok("keep-access-90-days", "Sign-ins and refused calls: 90 days, also when keep_days is longer.", keep(3650, 10, row("a", "access", 1, 90*day), row("a", "access", 2, 90*day-1), row("r", "refused", 1, 91*day)))
	ok("keep-flood", "A flood of refused calls pushes out refused calls only.", keep(nil, 2, row("k", "change", 1, 50*day), row("a", "access", 1, 40*day), row("r", "refused", 1, 30), row("r", "refused", 2, 20), row("r", "refused", 3, 10), row("r", "refused", 4, 0)))
	ok("keep-same-time", "At the same time in the order of the ids.", keep(nil, 1, row("r", "refused", 2, 5), row("r", "refused", 1, 5), row("r", "refused", 10, 5)))
	bad("keep-days-long", "Not over 36500 days.", keep(36501, 10, row("k", "change", 1, 0)))
	bad("keep-days-zero", "0 is not unlimited.", keep(0, 10, row("k", "change", 1, 0)))
	bad("keep-letter", "The id says the class.", keep(nil, 10, row("k", "refused", 1, 0)))
	bad("keep-twice", "Every id once.", keep(nil, 10, row("k", "change", 1, 0), row("k", "change", 1, 0)))

	// What a viewer sees.
	view := func(who M, e M) M { return M{"op": "view", "viewer": who, "entry": e} }
	site := func(s string) M { return M{"kind": "website", "website": s} }
	portal := entry("operation", "integration:createException", "actor", M{"kind": "integration", "id": "pk_0123456789ab", "label": "Portal", "session": "0a1b2c3d", "on_behalf_of": "customer-17"}, "address", "198.51.100.20")
	ok("view-dashboard", "The dashboard sees everything.", view(M{"kind": "dashboard"}, own()))
	ok("view-agent", "An agent sees what changed and which token, not who signed in from where.", view(M{"kind": "agent"}, own()))
	ok("view-agent-sign-in", "No sign-ins.", view(M{"kind": "agent"}, refused("action", "session.start", "operation", "dashboard:login", "actor", M{"kind": "dashboard"}, "subject", M{"kind": "user"})))
	ok("view-website-portal", "A customer sees what the portal did for the website, without the portal's key and session.", view(site("shop.example"), portal))
	ok("view-website-operator", "What the operator did, without who, why and from where; addresses the operator set stay hidden.", view(site("shop.example"), own()))
	ok("view-website-agent", "A token of the operator is the operator.", view(site("shop.example"), entry()))
	ok("view-website-cause", "The customer can follow the exception to its event.", view(site("shop.example"), entry("actor", M{"kind": "integration", "id": "pk_0123456789ab", "label": "portal", "session": "0a1b2c3d", "on_behalf_of": "c-1042"}, "operation", "integration:createException", "cause", M{"event": "0b7e3f9a-5c2d-4e8f-9a1b-2c3d4e5f6a7b"})))
	ok("view-website-other", "Nothing of another website.", view(site("other.example"), portal))
	ok("view-website-global", "Nothing that belongs to no website.", view(site("shop.example"), own("website", nil)))
	ok("view-website-access-lock", "Only what a portal may change.", view(site("shop.example"), entry("action", "access_lock.set", "operation", "cli:lock on", "actor", M{"kind": "cli"}, "subject", M{"kind": "website"}, "change", nil)))
	ok("view-website-unknown-action", "Nothing this build does not know.", view(site("shop.example"), entry("action", "portal.add", "operation", "cli:portal add", "actor", M{"kind": "cli"}, "subject", M{"kind": "portal"}, "change", nil)))
	bad("view-website-without-id", "A website's viewer names the website.", view(M{"kind": "website"}, portal))

	// Short retention (2026-11-27): who needs addresses gone sets audit.keep_days.
	ok("keep-14-days", "audit.keep_days 14: from this age on a change goes, with every address it holds.", keep(14, 10, row("k", "change", 1, 14*day), row("k", "change", 2, 14*day-1), row("k", "privacy", 3, 15*day), row("k", "credential", 4, 13*day)))
	ok("keep-access-not-longer", "Sign-ins and refused calls are never kept longer than audit.keep_days.", keep(14, 10, row("a", "access", 1, 14*day), row("a", "access", 2, 14*day-1), row("r", "refused", 1, 89*day), row("r", "refused", 2, 13*day)))
	ok("keep-one-day", "The lower bound is one day.", keep(1, 10, row("k", "change", 1, day), row("k", "change", 2, day-1), row("a", "access", 1, day)))
	ok("view-dashboard-old", "An entry older than retention.raw_ip_days reads as it was written, with its addresses.", view(M{"kind": "dashboard"}, own("time", "2026-01-05T12:00:00Z")))
}
