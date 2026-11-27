package monitoring

import (
	"sync/atomic"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// Hints of the audit log (contracts/audit.md sections 4, 6 and 10):
// audit_stuck and audit_size. The app reads the state of the log on a slow
// path (it reads two databases) and hands it in with SetAuditStatus; the
// evaluation every 10 s reads only what was handed in.

// AuditStatus is the state of the audit log as the app read it.
type AuditStatus struct {
	// Stuck: entries wait in the outbox of schild.db because audit.db
	// cannot be written; Waiting is how many.
	Stuck   bool
	Waiting int64
	// Large: audit.db is SizeHintBytes or larger. SizeBytes is its size,
	// Entries30d the entries of the last 30 days and TopActor the actor
	// with the most of them (a token id, a portal key id or a way).
	Large         bool
	SizeBytes     int64
	SizeHintBytes int64
	Entries30d    int64
	TopActor      string
}

// auditState holds the last state the app handed in.
type auditState struct {
	status atomic.Pointer[AuditStatus]
}

// SetAuditStatus sets the inputs of audit_stuck and audit_size.
func (m *Monitor) SetAuditStatus(s AuditStatus) {
	if m == nil {
		return
	}
	m.audit.status.Store(&s)
}

// AuditStatus returns the last state handed in (nil before the first one).
func (m *Monitor) AuditStatus() *AuditStatus {
	if m == nil {
		return nil
	}
	return m.audit.status.Load()
}

// auditHints sets audit_stuck and audit_size from the last state (every
// 10 s from evaluate, mu held; no I/O).
func (st *hintState) auditHints(m *Monitor, now time.Time) {
	s := m.audit.status.Load()
	if s == nil {
		return
	}
	st.set(now, s.Stuck, 0, cm.HintAuditStuck, "warning", "", float64(s.Waiting), 1)
	// The object is the actor with the most entries, and a hint is kept by
	// code and object: when another actor leads, the hint moves to the new
	// one and keeps its start instead of standing twice for 5 min.
	key := cm.HintAuditSize + "\x00" + s.TopActor
	if s.Large {
		for k, a := range st.active {
			if a.h.Code != cm.HintAuditSize || k == key {
				continue
			}
			delete(st.active, k)
			delete(st.pending, k)
			if _, ok := st.active[key]; !ok {
				a.h.Object = s.TopActor
				st.active[key] = a
			}
		}
	}
	st.set(now, s.Large, 0, cm.HintAuditSize, "notice", s.TopActor, float64(s.SizeBytes), float64(s.SizeHintBytes))
	if a, ok := st.active[key]; ok && s.Large {
		n := s.Entries30d
		a.h.Count = &n
	}
}
