//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D51: the audit event of an incident download.

func genEventsD51(g *gen) {
	const c = "events"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, e map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(e), e)
	}
	add(true, "", "incident-exported", "D51: a dashboard user downloaded an incident; incident, user and number of events only.",
		cloudEvent("schild.incident.exported.v1", "exported", map[string]any{"incident": "K7QM-4XWD", "by": "admin", "events": 3}))
	add(false, contract.CodeSchema, "incident-exported-with-address", "D51: the record never carries an address (closed object).",
		cloudEvent("schild.incident.exported.v1", "exported-ip", map[string]any{"incident": "K7QM-4XWD", "by": "admin", "events": 3, "ip": "203.0.113.9"}))
	add(false, contract.CodeSchema, "incident-exported-bad-number", "D51: incident numbers have the form of the block page.",
		cloudEvent("schild.incident.exported.v1", "exported-no", map[string]any{"incident": "k7qm", "by": "admin", "events": 3}))
}
