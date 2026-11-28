package app

// What stays on one node of a group, on purpose. Everything a person or an
// agent sets at runtime is shared (initiator, 2026-11-22): the keys of the
// key-value store travel unless contract.PerNodeSettings names them, and
// the tables below are the ones that do not travel row by row, each with
// its reason. A table that is neither shared (store.SharedTables) nor
// listed here fails TestEveryTableIsSharedOrPerNodeOnPurpose: whoever adds
// a table decides, and writes the reason down.
var perNodeTables = map[string]string{
	"kv":                "shared key by key as class settings (cluster_generic.go); the keys of contract.PerNodeSettings stay",
	"events":            "every node holds the events of every node through the pull of cluster_data.go, not row by row",
	"event_rules":       "the rules of an event; they travel with the events",
	"incidents":         "every node holds the incidents of every node through the pull of cluster_data.go",
	"summaries":         "hourly sums each node makes from the events it holds, which are those of the group",
	"kept_blocks":       "how this node keeps long blocks over a restart; the blocks themselves are shared as class incident_blocks",
	"cluster_outbox":    "the lifts this node still owes the group (store/outbox.go); each leaves as a record of class lifts",
	"audit_outbox":      "the audit entries this node wrote and has not moved to its audit.db yet (store/audit.go); the group asks for entries, contracts/audit.md section 9",
	"audit_state":       "the name of this node's audit log and the numbers of its entries",
	"audit_config":      "keyed digests of the configuration this node applied last, for config.apply",
	"config_changes":    "the log of when this node applied a change; every node applies a shared change and logs it itself",
	"schema_migrations": "the version of this node's schild.db",
	"agent_calls":       "the calls of agents this node served, and with them when a token was last used here; what an agent changed is an event on every node",
	"agent_nonces":      "replay protection for the reports this node took",
	"host_accepted":     "findings of the server check accepted for this machine: each server checks itself and has its own findings",
	"host_agents":       "the agents enrolled at this gateway for its server check",
	"host_enrolments":   "pending enrolments of agents at this gateway",
	"host_rejects":      "reports of agents this gateway refused",
	"host_reports":      "the reports of the server check of this machine and of the agents of this gateway",
}
