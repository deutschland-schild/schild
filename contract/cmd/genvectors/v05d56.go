//go:build !release

package main

import (
	"log"
	"reflect"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D56 (initiator, 2026-11-02; MVP-14 step 1), D58: the access lock. Which
// request passes a protected website and which gets the maintenance page,
// the login page or "Kein Zugriff"; how a path is compared. The expected
// results are written out by hand; the generator stops when the Go
// implementation disagrees.
func genAccessGate(g *gen) {
	const c = "access-gate"
	ctx := vectors.Context{}
	type M = map[string]any
	site := func(extra M) M {
		p := M{"website": "musterverein.example", "scope": "site", "password": true, "own_networks": false}
		for k, v := range extra {
			p[k] = v
		}
		return p
	}
	paths := func(extra M) M {
		p := M{"website": "musterverein.example", "scope": "paths", "paths": []any{"/wp-admin/*", "/wp-login.php"}, "password": true, "own_networks": false}
		for k, v := range extra {
			p[k] = v
		}
		return p
	}
	req := func(p M, path string, extra M) M {
		m := M{"protection": p, "path": path, "allowlisted": false, "session": "none"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	res := func(answer, reason string, status int, form bool, canonical string) M {
		return M{"answer": answer, "reason": reason, "status": status, "login_form": form, "canonical_path": canonical}
	}
	pass := func(reason, canonical string) M { return res("pass", reason, 0, false, canonical) }
	maint := func(form bool, canonical string) M { return res("maintenance", "locked", 503, form, canonical) }
	login := func(canonical string) M { return res("login", "locked", 403, true, canonical) }
	denied := func(canonical string) M { return res("denied", "locked", 403, false, canonical) }
	ok := func(name, desc string, in, want M) {
		got, err := access.RunVector(mustJSON(in))
		if err != nil {
			log.Fatalf("access-gate %s: %v", name, err)
		}
		if !reflect.DeepEqual(M{"answer": got.Answer, "reason": got.Reason, "status": got.Status, "login_form": got.LoginForm, "canonical_path": got.Canonical}, want) {
			log.Fatalf("access-gate %s: got %+v, want %v", name, got, want)
		}
		g.addResult(c, name, true, "", desc, ctx, mustJSON(in), in, want)
	}
	bad := func(name, desc string, in M) {
		if _, err := access.RunVector(mustJSON(in)); err == nil {
			log.Fatalf("access-gate %s: accepted", name)
		}
		g.add(c, name, false, contract.CodeSchema, desc, ctx, mustJSON(in), in)
	}

	// Scope site: the maintenance page.
	ok("site-anonymous-maintenance", "D56: a whole website locked with a password: an anonymous request gets the maintenance page (503) with the login form.",
		req(site(nil), "/", nil), maint(true, "/"))
	ok("site-asset-maintenance", "D56: assets get the maintenance page too, nothing of the app is served.",
		req(site(nil), "/wp-content/themes/x/style.css", nil), maint(true, "/wp-content/themes/x/style.css"))
	ok("site-session-valid", "D56: a valid session of this website and epoch passes on to the WAF.",
		req(site(nil), "/wp-admin/", M{"session": "valid"}), pass("session", "/wp-admin"))
	ok("site-session-invalid", "D56: a cookie that does not verify (other epoch, other website, expired, tampered) is no way in.",
		req(site(nil), "/", M{"session": "invalid"}), maint(true, "/"))
	ok("site-address-only", "D56: a website only for one address, without a password: the public gets the maintenance page without a form.",
		req(site(M{"password": false, "addresses": []any{"203.0.113.7"}}), "/", M{"client_ip": "198.51.100.20"}), maint(false, "/"))
	ok("site-address-passes", "D56: the listed address passes without login.",
		req(site(M{"password": false, "addresses": []any{"203.0.113.7"}}), "/", M{"client_ip": "203.0.113.7"}), pass("address", "/"))
	ok("site-network-passes", "D56: an address inside a listed network passes.",
		req(site(M{"password": false, "addresses": []any{"203.0.113.0/24"}}), "/kontakt", M{"client_ip": "203.0.113.99"}), pass("address", "/kontakt"))
	ok("site-ipv6-network-passes", "D56: IPv6 networks match like IPv4 ones.",
		req(site(M{"password": false, "addresses": []any{"2001:db8:1234::/48"}}), "/", M{"client_ip": "2001:db8:1234:5::1"}), pass("address", "/"))
	ok("site-mapped-client", "D56: a client address of IPv4 in IPv6 is compared as IPv4.",
		req(site(M{"password": false, "addresses": []any{"203.0.113.7"}}), "/", M{"client_ip": "::ffff:203.0.113.7"}), pass("address", "/"))
	ok("site-unknown-client", "D56, D58: without a resolved client address no address matches; a valid session does not make up for it.",
		req(site(M{"addresses": []any{"203.0.113.7"}}), "/", M{"session": "valid"}), maint(false, "/"))
	ok("site-own-networks", "D56: own networks: an allowlisted client passes, at any allowlist level.",
		req(site(M{"password": false, "own_networks": true}), "/", M{"allowlisted": true}), pass("own_network", "/"))
	ok("site-addresses-or-own-networks", "D58: addresses and own networks are one condition: either list is enough.",
		req(site(M{"password": false, "addresses": []any{"203.0.113.7"}, "own_networks": true}), "/", M{"client_ip": "198.51.100.20", "allowlisted": true}), pass("own_network", "/"))
	ok("site-own-networks-off", "D56: an allowlisted client without the own-networks switch is locked out like everyone.",
		req(site(nil), "/", M{"allowlisted": true}), maint(true, "/"))
	ok("site-session-without-password", "D56: without a password a session counts for nothing.",
		req(site(M{"password": false, "own_networks": true}), "/", M{"session": "valid"}), maint(false, "/"))

	// D58: password and address together, both must hold.
	both := site(M{"addresses": []any{"203.0.113.7"}})
	ok("site-and-address-session", "D58: password and address: the listed address with a valid session passes.",
		req(both, "/", M{"client_ip": "203.0.113.7", "session": "valid"}), pass("session", "/"))
	ok("site-and-address-no-session", "D58: password and address: the listed address without a session gets the login form.",
		req(both, "/", M{"client_ip": "203.0.113.7"}), maint(true, "/"))
	ok("site-and-address-other-ip", "D58: password and address: a valid session from another address stays out, without a form.",
		req(both, "/", M{"client_ip": "198.51.100.20", "session": "valid"}), maint(false, "/"))
	ownBoth := site(M{"own_networks": true})
	ok("site-and-own-networks-session", "D58: password and own networks: an allowlisted client with a valid session passes.",
		req(ownBoth, "/", M{"allowlisted": true, "session": "valid"}), pass("session", "/"))
	ok("site-and-own-networks-no-session", "D58: password and own networks: an allowlisted client without a session gets the login form.",
		req(ownBoth, "/", M{"allowlisted": true}), maint(true, "/"))
	ok("site-and-own-networks-not-listed", "D58: password and own networks: a valid session from outside the allowlist stays out, without a form.",
		req(ownBoth, "/", M{"session": "valid"}), maint(false, "/"))

	// Except paths of a site lock: strict.
	exc := site(M{"except": []any{"/api/stripe/webhook", "/hooks/*"}})
	ok("site-except-exact", "D56: an except path passes as written.",
		req(exc, "/api/stripe/webhook", nil), pass("except", "/api/stripe/webhook"))
	ok("site-except-below", "D56: below an except path ending in /* passes.",
		req(exc, "/hooks/paypal", nil), pass("except", "/hooks/paypal"))
	ok("site-except-case", "D56: except paths compare case-sensitively; any other spelling stays locked.",
		req(exc, "/API/stripe/webhook", nil), maint(true, "/api/stripe/webhook"))
	ok("site-except-escaped", "D56: an escape in the path is no except path, even when it decodes to one.",
		req(exc, "/api/stripe%2Fwebhook", nil), maint(true, "/api/stripe/webhook"))
	ok("site-except-traversal", "D56: dot segments leave an except path: /hooks/../wp-admin stays locked.",
		req(exc, "/hooks/../wp-admin/", nil), maint(true, "/wp-admin"))
	ok("site-except-semicolon", "D56: ';' parameters are no except path.",
		req(exc, "/hooks;x/paypal", nil), maint(true, "/hooks/paypal"))
	ok("site-except-trailing-slash", "D56: an exact except path without /* does not take a trailing slash.",
		req(exc, "/api/stripe/webhook/", nil), maint(true, "/api/stripe/webhook"))
	ok("site-except-double-slash", "D56: an empty segment is no except path.",
		req(exc, "/hooks//paypal", nil), maint(true, "/hooks/paypal"))
	ok("site-except-base-of-below", "D56: /hooks/* covers /hooks itself too, as a protected path does.",
		req(exc, "/hooks", nil), pass("except", "/hooks"))

	// Scope paths: only the listed paths.
	ok("paths-public", "D56: a path outside the protection passes untouched.",
		req(paths(nil), "/blog/2026/hallo", nil), pass("not_protected", "/blog/2026/hallo"))
	ok("paths-login", "D56: a protected path gets the login page (403).",
		req(paths(nil), "/wp-admin/", nil), login("/wp-admin"))
	ok("paths-below", "D56: below a pattern ending in /*.",
		req(paths(nil), "/wp-admin/plugins.php", nil), login("/wp-admin/plugins.php"))
	ok("paths-without-slash", "D56: /wp-admin/* covers /wp-admin itself.",
		req(paths(nil), "/wp-admin", nil), login("/wp-admin"))
	ok("paths-exact", "D56: an exact pattern.",
		req(paths(nil), "/wp-login.php", nil), login("/wp-login.php"))
	ok("paths-sibling", "D56: a sibling that only starts like a pattern is not protected.",
		req(paths(nil), "/wp-admin-old/x", nil), pass("not_protected", "/wp-admin-old/x"))
	ok("paths-denied-no-password", "D56: only for an address, without a password: \"Kein Zugriff\" without a form.",
		req(paths(M{"password": false, "addresses": []any{"203.0.113.7"}}), "/wp-admin/", M{"client_ip": "198.51.100.20"}), denied("/wp-admin"))
	ok("paths-address-passes", "D56: the listed address reaches the protected path.",
		req(paths(M{"password": false, "addresses": []any{"203.0.113.7"}}), "/wp-admin/", M{"client_ip": "203.0.113.7"}), pass("address", "/wp-admin"))
	ok("paths-session", "D56: a valid session passes a protected path.",
		req(paths(nil), "/wp-login.php", M{"session": "valid"}), pass("session", "/wp-login.php"))

	pathsBoth := paths(M{"own_networks": true})
	ok("paths-and-own-networks-session", "D58: password and own networks on paths: both hold, the request passes.",
		req(pathsBoth, "/wp-admin/", M{"allowlisted": true, "session": "valid"}), pass("session", "/wp-admin"))
	ok("paths-and-own-networks-no-session", "D58: password and own networks on paths: an allowlisted client without a session gets the login page.",
		req(pathsBoth, "/wp-admin/", M{"allowlisted": true}), login("/wp-admin"))
	ok("paths-and-own-networks-not-listed", "D58: password and own networks on paths: from outside the allowlist \"Kein Zugriff\", no form, also with a valid session.",
		req(pathsBoth, "/wp-admin/", M{"session": "valid"}), denied("/wp-admin"))

	// Path tricks: every spelling of a protected path is protected.
	trick := func(name, desc, path, canonical string) {
		ok(name, "D56 path trick: "+desc, req(paths(nil), path, nil), login(canonical))
	}
	trick("trick-upper-case", "ASCII upper case folds to lower case.", "/WP-ADMIN/", "/wp-admin")
	trick("trick-double-slash", "empty segments are dropped.", "//wp-admin//plugins.php", "/wp-admin/plugins.php")
	trick("trick-dot-segment", "'.' is dropped.", "/./wp-admin/./x", "/wp-admin/x")
	trick("trick-dot-dot", "'..' drops the segment before it.", "/blog/../wp-admin/", "/wp-admin")
	trick("trick-dot-dot-above-root", "'..' never climbs above the root.", "/../../wp-login.php", "/wp-login.php")
	trick("trick-encoded-dot", "%2e is a dot after decoding.", "/blog/%2e%2e/wp-admin", "/wp-admin")
	trick("trick-encoded-slash", "%2f is a slash after decoding.", "/wp-admin%2fplugins.php", "/wp-admin/plugins.php")
	trick("trick-double-encoded", "%252e decodes twice.", "/blog/%252e%252e/wp-admin", "/wp-admin")
	trick("trick-encoded-letter", "an escaped letter is the letter.", "/wp-%61dmin/", "/wp-admin")
	trick("trick-lower-hex", "escapes take lower-case hex.", "/wp%2dadmin", "/wp-admin")
	trick("trick-semicolon", "';' parameters are cut.", "/wp-admin;jsessionid=1/x", "/wp-admin/x")
	trick("trick-dot-dot-semicolon", "'..;' is '..' with a parameter.", "/blog/..;/wp-admin", "/wp-admin")
	trick("trick-trailing-dot", "trailing dots are cut (Windows file names).", "/wp-login.php.", "/wp-login.php")
	trick("trick-trailing-space", "trailing spaces are cut.", "/wp-login.php%20", "/wp-login.php")
	trick("trick-backslash", "a backslash is a slash.", `/wp-admin\plugins.php`, "/wp-admin/plugins.php")
	trick("trick-encoded-backslash", "%5c is a slash after decoding.", "/blog%5c..%5cwp-admin", "/wp-admin")
	trick("trick-nul", "a NUL ends the segment.", "/wp-login.php%00.jpg", "/wp-login.php")
	trick("trick-mixed", "all at once.", "//BLOG/.%2E/Wp-Admin;x/./Plugins.PHP.", "/wp-admin/plugins.php")
	ok("trick-non-ascii-kept", "D56: bytes outside ASCII are written as upper-case escapes in the canonical form and do not match.",
		req(paths(nil), "/wp-adm%C3%AFn/", nil), pass("not_protected", "/wp-adm%C3%AFn"))
	ok("trick-invalid-escape-kept", "D56: an invalid escape stays; its '%' is written %25.",
		req(paths(nil), "/blog/%zz", nil), pass("not_protected", "/blog/%25zz"))
	ok("trick-five-encodings", "D56: decoding stops after four rounds: a fifth layer stays escaped.",
		req(paths(nil), "/%2525252561", nil), pass("not_protected", "/%2561"))
	ok("pattern-upper-case", "D56: patterns are compared in the canonical form too.",
		req(paths(M{"paths": []any{"/Intern/*"}}), "/intern/plan.pdf", nil), login("/intern/plan.pdf"))

	// Invalid inputs.
	bad("until", "D58: a protection has no end; it is on until it is removed.", req(site(M{"until": "2026-11-04T12:00:00Z"}), "/", nil))
	bad("paths-empty", "D56: scope paths needs a path.", req(paths(M{"paths": []any{}}), "/", nil))
	bad("paths-root-wildcard", "D56: /* in scope paths is the whole website: use scope site.", req(paths(M{"paths": []any{"/*"}}), "/", nil))
	bad("paths-inner-wildcard", "D56: * only as /* at the end.", req(paths(M{"paths": []any{"/wp-*/x"}}), "/", nil))
	bad("paths-escape", "D56: no escapes in a pattern.", req(paths(M{"paths": []any{"/wp%2dadmin"}}), "/", nil))
	bad("paths-with-except", "D56: except paths only with scope site.", req(paths(M{"except": []any{"/hooks/*"}}), "/", nil))
	bad("site-with-paths", "D56: paths only with scope paths.", req(site(M{"paths": []any{"/wp-admin/*"}}), "/", nil))
	bad("except-dot-dot", "D56: an except path is plain: no '..'.", req(site(M{"except": []any{"/hooks/../x"}}), "/", nil))
	bad("except-double-slash", "D56: an except path is plain: no empty segment.", req(site(M{"except": []any{"/hooks//x"}}), "/", nil))
	bad("except-root", "D56: the root is no except path.", req(site(M{"except": []any{"/*"}}), "/", nil))
	bad("no-way-in", "D56: no password, no address, no own networks: nobody could get in.", req(site(M{"password": false}), "/", nil))
	bad("address-host-bits", "D56: a network with host bits set.", req(site(M{"addresses": []any{"203.0.113.7/24"}}), "/", nil))
	bad("address-too-wide-v4", "D56: IPv4 networks up to /16.", req(site(M{"addresses": []any{"10.0.0.0/8"}}), "/", nil))
	bad("address-too-wide-v6", "D56: IPv6 networks up to /32.", req(site(M{"addresses": []any{"2001:d00::/24"}}), "/", nil))
	bad("address-mapped", "D56: no IPv4 in IPv6 in an entry.", req(site(M{"addresses": []any{"::ffff:203.0.113.7"}}), "/", nil))
	bad("address-garbage", "D56: not an address.", req(site(M{"addresses": []any{"1.2.3"}}), "/", nil))
	bad("message-control", "D56: no control characters in the message but newline.", req(site(M{"message": "a\tb"}), "/", nil))
	bad("path-relative", "D56: the request path starts with /.", req(site(nil), "wp-admin", nil))
	bad("session-unknown", "D56: session is none, valid or invalid.", req(site(nil), "/", M{"session": "maybe"}))
	bad("unknown-field", "D56: no other fields.", req(site(M{"hash": "x"}), "/", nil))
}
