package audit

// Viewers of the audit log.
const (
	ViewDashboard = "dashboard"
	ViewAgent     = "agent"
	ViewWebsite   = "website"
)

// View returns what a viewer sees of an entry, nil for nothing.
//
//   - dashboard: everything.
//   - agent: what was changed and by whom, without sign-ins, refused calls,
//     privacy entries, names of people, sessions and the address of the call.
//   - website: changes of its own website that a portal may make, without
//     who of the operator made them.
func View(e map[string]any, viewer, website string) map[string]any {
	e = clone(e).(map[string]any)
	switch viewer {
	case ViewDashboard:
		return e
	case ViewAgent:
		if c := str(e, "class"); c != ClassChange && c != ClassCredential {
			return nil
		}
		delete(e, "address")
		delete(e, "address_cut")
		actor := obj(e, "actor")
		for _, k := range []string{"user", "session", "account", "on_behalf_of"} {
			delete(actor, k)
		}
		return e
	case ViewWebsite:
		a := Lookup(str(e, "action"))
		if a == nil || !a.Portal || str(e, "class") != ClassChange || website == "" || str(e, "website") != website {
			return nil
		}
		out := map[string]any{"id": e["id"], "time": e["time"], "action": e["action"], "subject": e["subject"], "website": e["website"]}
		actor := obj(e, "actor")
		portal := str(actor, "kind") == "integration"
		if portal {
			by := map[string]any{"kind": "portal"}
			if s := str(actor, "on_behalf_of"); s != "" {
				by["on_behalf_of"] = s
			}
			out["actor"] = by
			if r, ok := e["reason"]; ok {
				out["reason"] = r
			}
		} else {
			out["actor"] = map[string]any{"kind": "operator"}
		}
		if c := obj(e, "change"); c != nil {
			if !portal {
				for _, f := range fields(e) {
					if _, hidden := f["hidden"]; !hidden && (a.isAddress(str(f, "field")) || str(f, "field") == "/label") {
						hide(f, HiddenOperator)
					}
				}
			}
			out["change"] = c
		}
		return out
	}
	return nil
}
