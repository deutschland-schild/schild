//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D56 (2026-11-02, MVP-14 step 1): events of the access lock.
func genEventsD56(g *gen) {
	add := func(valid bool, name, desc, typ string, d m) {
		var code contract.Code
		if !valid {
			code = contract.CodeSchema
		}
		x := cloudEvent(typ, name, d)
		g.add("events", name, valid, code, desc, vectors.Context{}, mustJSON(x), x)
	}
	set := func(k string, v any) m {
		x := m{"website": "musterverein.example", "scope": "site", "except": []string{"/api/stripe/webhook"}, "password": true, "addresses": 2,
			"own_networks": true, "until": "2026-11-04T12:00:00Z", "actor": "dashboard", "user": "admin"}
		if v == nil {
			delete(x, k)
		} else if k != "" {
			x[k] = v
		}
		return x
	}
	add(true, "access-protection-set-site", "D56: a whole website locked from the dashboard.", "schild.access.protection_set.v1", set("", nil))
	add(true, "access-protection-set-paths-cli", "D56: paths protected with schild lock on the server, without an end.", "schild.access.protection_set.v1",
		m{"website": "musterverein.example", "scope": "paths", "paths": []string{"/wp-admin/*"}, "password": false, "addresses": 1, "own_networks": false, "actor": "cli"})
	add(true, "access-protection-removed-expired", "D56: the end of a lock came.", "schild.access.protection_removed.v1",
		m{"website": "musterverein.example", "scope": "site", "actor": "system", "reason": "expired"})
	add(true, "access-login", "D56: a login with the shared password, the address as its /24.", "schild.access.login.v1",
		m{"website": "musterverein.example", "address_prefix": "203.0.113.0/24"})
	add(true, "access-prefix-locked-v6", "D56: an IPv6 /48 guessed wrong too often.", "schild.access.prefix_locked.v1",
		m{"website": "musterverein.example", "address_prefix": "2001:db8:1234::/48", "until": "2026-11-02T12:15:00Z"})
	add(false, "access-protection-set-no-actor", "D56: every change names where it came from.", "schild.access.protection_set.v1", set("actor", nil))
	add(false, "access-protection-set-address-list", "D56: addresses are counted, never listed in an event.", "schild.access.protection_set.v1", set("addresses", []string{"203.0.113.7"}))
	add(false, "access-protection-removed-agent", "D56: an agent cannot lock or unlock.", "schild.access.protection_removed.v1",
		m{"website": "musterverein.example", "scope": "site", "actor": "agent", "reason": "removed"})
	add(false, "access-login-full-address", "D56: a login keeps the prefix, never the full address.", "schild.access.login.v1",
		m{"website": "musterverein.example", "address_prefix": "203.0.113.7"})
	add(false, "access-prefix-locked-no-until", "D56: a lockout has an end.", "schild.access.prefix_locked.v1",
		m{"website": "musterverein.example", "address_prefix": "203.0.113.0/24"})
}
