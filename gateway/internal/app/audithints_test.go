//go:build !release

package app_test

import (
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/auditlog"
)

// TestAuditStatusHandedToMonitor: the running gateway reads the state of
// its audit log at start and hands it to the monitor, which makes the hints
// audit_stuck and audit_size from it. A new log is neither stuck nor large.
func TestAuditStatusHandedToMonitor(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	if h.App.Monitor == nil {
		t.Skip("monitoring is off in this harness")
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.App.Monitor.AuditStatus() == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	s := h.App.Monitor.AuditStatus()
	if s == nil {
		t.Fatal("no state of the audit log after the start")
	}
	if s.Stuck || s.Large || s.SizeBytes <= 0 || s.SizeHintBytes != auditlog.SizeHintBytes {
		t.Errorf("%+v", *s)
	}
	for _, hint := range h.App.Monitor.ServerHints(time.Now()) {
		if hint.Code == "audit_stuck" || hint.Code == "audit_size" {
			t.Errorf("hint of a new log: %+v", hint)
		}
	}
}
