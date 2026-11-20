//go:build !release

package main

import (
	"log"
	"reflect"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D70 (2026-11-06): a protected path covers what lies below it, with or
// without /*, so /wp-login.php/x (path info) is /wp-login.php. The expected
// results are written out by hand; the generator stops when the Go
// implementation disagrees. The generator appends.
func genAccessGateD70(g *gen) {
	const c = "access-gate"
	type M = map[string]any
	paths := func(patterns ...any) M {
		return M{"website": "musterverein.example", "scope": "paths", "paths": patterns, "password": true, "own_networks": false}
	}
	ok := func(name, desc string, p M, path, answer, canonical string) {
		in := M{"protection": p, "path": path, "allowlisted": false, "session": "none"}
		want := M{"answer": "login", "reason": "locked", "status": 403, "login_form": true, "canonical_path": canonical}
		if answer == "pass" {
			want = M{"answer": "pass", "reason": "not_protected", "status": 0, "login_form": false, "canonical_path": canonical}
		}
		got, err := access.RunVector(mustJSON(in))
		if err != nil {
			log.Fatalf("access-gate %s: %v", name, err)
		}
		if !reflect.DeepEqual(M{"answer": got.Answer, "reason": got.Reason, "status": got.Status, "login_form": got.LoginForm, "canonical_path": got.Canonical}, want) {
			log.Fatalf("access-gate %s: got %+v, want %v", name, got, want)
		}
		g.addResult(c, name, true, "", desc, vectors.Context{}, mustJSON(in), in, want)
	}
	wp := paths("/wp-admin/*", "/wp-login.php")
	ok("paths-exact-path-info", "D70: an exact pattern covers what lies below it: PHP runs /wp-login.php for /wp-login.php/x (path info).",
		wp, "/wp-login.php/x", "login", "/wp-login.php/x")
	ok("paths-exact-path-info-encoded", "D70: path info behind an encoded slash.", wp, "/wp-login.php%2fx", "login", "/wp-login.php/x")
	ok("paths-exact-path-info-case", "D70: path info in upper case.", wp, "/WP-LOGIN.PHP/x", "login", "/wp-login.php/x")
	ok("paths-exact-path-info-semicolon", "D70: path info behind a ';' parameter.", wp, "/wp-login.php;/x", "login", "/wp-login.php/x")
	ok("paths-exact-sibling", "D70: a name that only starts like an exact pattern is not below it.", wp, "/wp-login.phpx", "pass", "/wp-login.phpx")
	ok("paths-exact-folder", "D70: an exact pattern without /* covers its folder too.", paths("/intern"), "/intern/plan.pdf", "login", "/intern/plan.pdf")
	ok("paths-root-only", "D70: only the root / covers nothing below it.", paths("/"), "/blog", "pass", "/blog")
}
