//go:build !release

package app

// DataAsks is how many questions this node asked the members for events,
// incidents and requests since its start (cluster_data.go).
func (a *App) DataAsks() int64 {
	if a.groupData == nil {
		return 0
	}
	return a.groupData.asks.Load()
}

// StartAsBuildBefore makes every node started from now on speak as the
// build before this one did (no heads, requests as JSON), and returns how
// to undo it.
func StartAsBuildBefore() (undo func()) {
	startAsBuildBefore = true
	return func() { startAsBuildBefore = false }
}
