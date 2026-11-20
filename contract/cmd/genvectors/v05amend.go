//go:build !release

package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/ingress"
	"github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// Initiator decisions of 2026-10-29 evening (after results/messung-2026-10-29-abend.md):
// the ingress order rule (D31 amendment, MVP-19) and re-checked requests
// counting once (D33 amendment). Appended after the D38 vectors.

func genIngressOrder(g *gen) {
	const c = "ingress-order"
	ctx := vectors.Context{}
	type M = map[string]any
	in := func(cs ingressCase) M {
		var servers any
		if err := json.Unmarshal([]byte(cs.servers), &servers); err != nil {
			panic(cs.name + ": " + err.Error())
		}
		return M{"caddyfile": cs.caddyfile, "servers": servers}
	}
	valid := func(cases []ingressCase, ref string) {
		for _, cs := range cases {
			m := in(cs)
			res, err := ingress.RunVector(mustJSON(m))
			if err != nil {
				panic(fmt.Sprintf("%s: %v", cs.name, err))
			}
			if len(res.Findings) != cs.findings {
				panic(fmt.Sprintf("%s: %d findings, want %d: %+v", cs.name, len(res.Findings), cs.findings, res.Findings))
			}
			g.addResult(c, cs.name, true, "", ref+": "+cs.desc, ctx, mustJSON(m), m, res)
		}
	}
	valid(ingressCases, "D31 amendment 2026-10-29")
	valid(ingressHeaderCases, "D40")
	valid(ingressD43Cases, "D43")

	bad := func(name, desc string, code contract.Code, m M) {
		g.add(c, name, false, code, "D31 amendment 2026-10-29: "+desc, ctx, mustJSON(m), m)
	}
	h := func(name string, kv ...any) M {
		x := M{"handler": name}
		for i := 0; i+1 < len(kv); i += 2 {
			x[kv[i].(string)] = kv[i+1]
		}
		return x
	}
	route := func(hs ...M) M {
		l := make([]any, len(hs))
		for i := range hs {
			l[i] = hs[i]
		}
		return M{"handle": l}
	}
	srv := func(routes ...M) M {
		l := make([]any, len(routes))
		for i := range routes {
			l[i] = routes[i]
		}
		return M{"servers": M{"srv0": M{"listen": []any{":443"}, "routes": l}}}
	}
	bad("no-servers", "servers is required.", contract.CodeSchema, M{"caddyfile": "http://a.example.test {\n}\n"})
	bad("empty-servers", "at least one server.", contract.CodeSchema, M{"servers": M{}})
	bad("extra-field", "only servers and caddyfile.", contract.CodeSchema, M{"servers": M{"srv0": M{}}, "admin": M{"disabled": true}})
	bad("handler-without-name", "every handler names its handler.", contract.CodeSchema, srv(route(M{"uri": "/x"})))
	bad("handler-not-object", "a handler is an object.", contract.CodeSchema, M{"servers": M{"srv0": M{"routes": []any{M{"handle": []any{"schild"}}}}}})
	bad("route-unknown-field", "a route has only group, match, handle and terminal.", contract.CodeSchema, srv(M{"handle": []any{h("schild")}, "order": 1}))
	bad("handle-not-array", "handle is an array.", contract.CodeSchema, srv(M{"handle": h("schild")}))
	bad("match-not-array", "match is an array of matcher sets.", contract.CodeSchema, srv(M{"match": M{"host": []any{"a.example.test"}}, "handle": []any{h("schild")}}))
	bad("group-not-string", "group is a string.", contract.CodeSchema, srv(M{"group": 1, "handle": []any{h("schild")}}))
	bad("subroute-routes-not-array", "a subroute's routes is an array.", contract.CodeSchema, srv(route(h("subroute", "routes", M{"handle": []any{}}))))
	bad("invoke-unknown", "an invoke names a named route of its server (Caddy refuses it too).", contract.CodeSchema, srv(route(h("invoke", "name", "missing"), h("schild"))))
	cyc := srv(route(h("invoke", "name", "loop")))
	cyc["servers"].(M)["srv0"].(M)["named_routes"] = M{"loop": route(h("invoke", "name", "loop"))}
	bad("invoke-cycle", "a named route that invokes itself cannot be walked.", contract.CodeSchema, cyc)
	bad("routes-not-array", "a server's routes is an array.", contract.CodeSchema, M{"servers": M{"srv0": M{"routes": M{}}}})
	bad("caddyfile-not-string", "caddyfile is the source text.", contract.CodeSchema, M{"caddyfile": 1, "servers": M{"srv0": M{}}})
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "D31 amendment 2026-10-29: duplicate keys are malformed JSON.", ctx,
		[]byte(`{"servers":{"srv0":{"routes":[]},"srv0":{"routes":[]}}}`), nil)
	big := M{"caddyfile": strings.Repeat("#", 65536), "servers": M{"srv0": M{"routes": []any{route(h("static_response", "body", strings.Repeat("x", 1<<20)))}}}}
	g.add(c, "oversize", false, contract.CodeOversize, "D31 amendment 2026-10-29: inputs over 1 MiB.", ctx, mustJSON(big), nil)
}

func genRequestRecheck(g *gen) {
	const c = "request-recheck"
	ctx := vectors.Context{}
	type M = map[string]any
	ev := func(path, outcome string, detection bool, score int, rules ...string) M {
		r := make([]any, len(rules))
		for i := range rules {
			r[i] = rules[i]
		}
		return M{"path": path, "outcome": outcome, "detection": detection, "rules": r, "score": score}
	}
	in := func(evs ...M) M {
		l := make([]any, len(evs))
		for i := range evs {
			l[i] = evs[i]
		}
		return M{"evaluations": l}
	}
	ok := func(name, desc string, m M) {
		res, err := monitoring.RunRecheckVector(mustJSON(m))
		if err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		g.addResult(c, name, true, "", "D33 amendment 2026-10-29: "+desc, ctx, mustJSON(m), m, res)
	}
	bad := func(name, desc string, m M) {
		g.add(c, name, false, contract.CodeSchema, "D33 amendment 2026-10-29: "+desc, ctx, mustJSON(m), m)
	}
	ok("single", "one evaluation: counted once, no checked_paths.", in(ev("/login", "passed", false, 0)))
	ok("p08-handle-path-error-passed", "measurement P08: handle_path stripped /app before the site's schild, the error route's schild checks /app/x again; one request (not two in schild_requests_total), one event naming both paths.",
		in(ev("/x", "passed", false, 0), ev("/app/x", "passed", false, 0)))
	ok("recheck-blocks", "the re-check in handle_errors finds the attack the first evaluation could not see: the request is blocked_waf, counted once.",
		in(ev("/x", "passed", false, 0), ev("/app/x", "blocked_waf", true, 10, "942100", "942110")))
	ok("observe-first-then-passed", "a would_block of the first evaluation (observe) stays would_block when the re-check passes: the overlay is counted once.",
		in(ev("/x", "would_block", true, 8, "941100"), ev("/app/x", "passed", false, 0)))
	ok("observe-both", "would_block in both: one would_block, one detection, rules merged without duplicates, the higher score.",
		in(ev("/x", "would_block", true, 5, "941100"), ev("/app/x", "would_block", true, 8, "941100", "941160")))
	ok("recheck-busy", "the re-check found no evaluation slot: fail_closed (waf_busy) is the outcome of the request.",
		in(ev("/x", "passed", false, 0), ev("/app/x", "fail_closed", false, 0)))
	ok("recheck-rate-limited", "a stop by a request limit in the re-check.", in(ev("/x", "passed", false, 0), ev("/app/x", "rate_limited", false, 0)))
	ok("three-evaluations", "a rewrite after schild and a second schild, then handle_errors: three paths in order.",
		in(ev("/a", "passed", false, 0), ev("/b", "passed", false, 0), ev("/c", "passed", false, 0)))
	ok("five-evaluations", "above four evaluations checked_paths keeps the first three and the last.",
		in(ev("/1", "passed", false, 0), ev("/2", "passed", false, 0), ev("/3", "passed", false, 0), ev("/4", "passed", false, 0), ev("/5", "passed", false, 0)))
	ok("same-path-twice", "the same path checked twice (another method or host after a rewrite) is listed twice: checked_paths lists evaluations, not distinct paths.",
		in(ev("/x", "passed", false, 0), ev("/x", "passed", false, 0)))

	bad("stop-not-last", "a stop ends the request: only the last evaluation may stop it.", in(ev("/x", "blocked_waf", true, 10, "942100"), ev("/app/x", "passed", false, 0)))
	bad("no-evaluation", "at least one evaluation.", in())
	bad("unknown-outcome", "outcomes are those of the request ring.", in(ev("/x", "logged", false, 0)))
	bad("path-relative", "a path starts with /.", in(ev("x", "passed", false, 0)))
	bad("path-with-control", "no control characters.", in(ev("/x\n", "passed", false, 0)))
	bad("score-too-high", "score 0..100.", in(ev("/x", "passed", false, 101)))
	bad("rule-id-format", "rule ids are CRS numbers or network rule ids.", in(ev("/x", "would_block", true, 5, "abc")))
	m := in(ev("/x", "passed", false, 0))
	m["evaluations"].([]any)[0].(M)["client_ip"] = "192.0.2.1"
	bad("extra-field", "no other fields (no address).", m)
	m = in(ev("/x", "passed", false, 0))
	delete(m["evaluations"].([]any)[0].(M), "detection")
	bad("missing-detection", "detection is required.", m)
	l := make([]M, 17)
	for i := range l {
		l[i] = ev("/x", "passed", false, 0)
	}
	bad("too-many", "at most 16 evaluations per request.", in(l...))
}

// genEventsRecheck: checked_paths on request events (D33 amendment
// 2026-10-29).
func genEventsRecheck(g *gen) {
	const c = "events"
	ctx := vectors.Context{}
	ev := func(name string, paths []any) map[string]any {
		d := reqData("req-recheck-" + name)
		if paths != nil {
			d["path"] = paths[len(paths)-1]
			d["checked_paths"] = paths
		}
		return cloudEvent("schild.request.evaluated.v1", "recheck-"+name, d)
	}
	add := func(valid bool, name, desc string, e map[string]any) {
		code := contract.Code("")
		if !valid {
			code = contract.CodeSchema
		}
		g.add(c, name, valid, code, "D33 amendment 2026-10-29: "+desc, ctx, mustJSON(e), e)
	}
	add(true, "checked-paths-two", "schild checked the request twice (handle_path stripped /app, then handle_errors): one event with both paths; path is the last.", ev("two", []any{"/x", "/app/x"}))
	add(true, "checked-paths-four", "at most four paths (above four evaluations the first three and the last).", ev("four", []any{"/1", "/2", "/3", "/5"}))
	add(false, "checked-paths-one", "checked_paths only when there was more than one evaluation (at least two items).", ev("one", []any{"/x"}))
	add(false, "checked-paths-five", "at most four items.", ev("five", []any{"/1", "/2", "/3", "/4", "/5"}))
	add(false, "checked-paths-not-strings", "paths are strings.", ev("num", []any{"/x", "/y", 2}))
}
