//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D69 (2026-11-06): a request Host resolves as Caddy's host matcher reads
// it, so a spelling Caddy routes to a site block never resolves to another
// website or to none. The generator appends.
func genWebsiteDeriveD69(g *gen) {
	const c = "website-derive"
	const P = "protected"
	in := map[string]any{"mode": "ingress", "blocks": []any{
		blk(true, true, "secret.example.org"),
		blk(true, true, "*.kunden.example.org"),
		blk(true, true, "[2001:db8::1]"),
	}, "resolve": []string{
		"secret.example.org:abc", "secret.example.org:", "secret.example.org:0443", "secret.example.org:70000",
		"[secret.example.org]", "[secret.example.org]:443", "ſecret.example.org",
		"a_b.kunden.example.org", ".kunden.example.org:443", "-a.kunden.example.org", "a.Kunden.example.org",
		"2001:DB8::1", "secret.example.org:443:443", "a.secret.example.org",
	}}
	r := map[string]any{"websites": []map[string]any{
		site("secret.example.org", "secret.example.org", P, true, "secret.example.org"),
		site("_.kunden.example.org", "*.kunden.example.org", P, true, "*.kunden.example.org"),
		site("ipv6-2001-db8--1", "[2001:db8::1]", P, true, "2001:db8::1"),
	}, "resolved": []any{
		"secret.example.org", "secret.example.org", "secret.example.org", "secret.example.org",
		"secret.example.org", "secret.example.org", "secret.example.org",
		"_.kunden.example.org", "_.kunden.example.org", "_.kunden.example.org", "_.kunden.example.org",
		"ipv6-2001-db8--1", nil, nil,
	}}
	g.addResult(c, "request-host-like-caddy", true, "", "D69: a request Host is read as Caddy's host matcher reads it: the port is not checked, brackets are stripped from any name, a * label matches any content (also _, empty or a leading hyphen), an unbracketed IPv6 literal is that IPv6 host, the long s and the Kelvin sign compare as s and k (strings.EqualFold); two ports and a deeper name resolve to none.",
		vectors.Context{}, mustJSON(in), in, r)
}
