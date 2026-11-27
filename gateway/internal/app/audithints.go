package app

import (
	"context"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
)

// auditStatusEvery: how often the state of the audit log is read for the
// hints audit_stuck and audit_size. The read counts the outbox in schild.db
// and, from 1 GiB on, the entries of 30 days in audit.db, so it runs on the
// slow path of the storage hints and never for a request.
const auditStatusEvery = 10 * time.Minute

// checkAuditStatus reads the state of the audit log and hands it to the
// monitor (contracts/audit.md sections 4, 6 and 10). A log that gets stuck
// or writes again is logged once.
func (a *App) checkAuditStatus(ctx context.Context) {
	if a.Audit == nil || a.Monitor == nil {
		return
	}
	s := auditHintStatus(a.Audit.Status(ctx))
	prev := a.Monitor.AuditStatus()
	a.Monitor.SetAuditStatus(s)
	was := prev != nil && prev.Stuck
	switch {
	case s.Stuck && !was:
		a.log.Warn("audit log: entries wait in schild.db because audit.db cannot be written (hint audit_stuck); changes are still recorded", "waiting", s.Waiting, "dir", a.dataDir)
	case !s.Stuck && was:
		a.log.Info("audit log: audit.db is written again")
	}
}

// auditHintStatus is the state of the log as the monitor takes it.
func auditHintStatus(s auditlog.Status) monitoring.AuditStatus {
	return monitoring.AuditStatus{Stuck: s.Stuck, Waiting: int64(s.Waiting), Large: s.Large, SizeBytes: s.SizeBytes,
		SizeHintBytes: auditlog.SizeHintBytes, Entries30d: s.Entries30d, TopActor: s.TopActor}
}
