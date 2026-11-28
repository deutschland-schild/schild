//go:build !release

package app

// AuditAsks is how many questions this node asked the members for the
// audit log since its start (cluster_audit.go).
func (a *App) AuditAsks() int64 {
	if a.groupData == nil {
		return 0
	}
	return a.groupData.auditAsks.Load()
}
