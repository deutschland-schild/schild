//go:build release

package app

// A release build has no test hooks in the data exchange
// (cluster_data_hooks.go).
type dataHooks struct{}

func (dataHooks) initHooks()          {}
func (dataHooks) asBuildBefore() bool { return false }
func (dataHooks) countAsk()           {}
