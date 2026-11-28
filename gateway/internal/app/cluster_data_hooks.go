//go:build !release

package app

import "sync/atomic"

// The hooks of the data exchange that tests and measurements use. A release
// build has none of them (cluster_data_hooks_release.go): it cannot be made
// to speak as an older build, and it counts nothing for a test.

// startAsBuildBefore makes the nodes started from now on speak as the build
// before this one (dataHooks.before).
var startAsBuildBefore bool

type dataHooks struct {
	// asks counts the questions this node asked the members for events,
	// incidents and requests.
	asks atomic.Int64
	// auditAsks counts the questions this node asked the members for the
	// audit log.
	auditAsks atomic.Int64
	// before: this node speaks as the build before this one did: it says
	// no heads, asks for requests as JSON and answers them so, to run two
	// builds side by side in one test.
	before atomic.Bool
}

func (h *dataHooks) initHooks()          { h.before.Store(startAsBuildBefore) }
func (h *dataHooks) asBuildBefore() bool { return h.before.Load() }
func (h *dataHooks) countAsk()           { h.asks.Add(1) }
func (h *dataHooks) countAuditAsk()      { h.auditAsks.Add(1) }
