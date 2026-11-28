package monitoring

import (
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

// contracts/audit.md sections 4, 6 and 10: the state of the audit log the
// app hands in raises audit_stuck (warning, value = entries that wait) and
// audit_size (notice, value = bytes, threshold = 1 GiB, count = entries of
// the last 30 days, object = the actor with the most). Both are server-wide
// and clear with the condition.
func TestAuditHints(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)
	m, err := New(Config{StoragePath: t.TempDir(), Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14},
		Sampler:   SamplerConfig{Root: fixtureRoot(t), Linux: true, Host: true, Started: now, Version: "test"},
		Internals: func(bool) Internals { return Internals{EventQueueCapacity: 8192, EvalSlotsMax: 16} },
	}, now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	find := func(at time.Time, code string) []cm.HealthHint {
		var out []cm.HealthHint
		for _, h := range m.ServerHints(at) {
			if h.Code == code {
				out = append(out, h)
			}
		}
		return out
	}
	at := now
	step := func() time.Time {
		at = at.Add(10 * time.Second)
		m.Sample(at)
		m.Tick(at)
		return at
	}
	// Nothing handed in, and a log in order: no hint.
	step()
	m.SetAuditStatus(AuditStatus{SizeBytes: 4 << 20, SizeHintBytes: 1 << 30})
	step()
	if h := append(find(at, cm.HintAuditStuck), find(at, cm.HintAuditSize)...); len(h) != 0 {
		t.Fatalf("hints of a log in order: %+v", h)
	}

	const gib = 1 << 30
	m.SetAuditStatus(AuditStatus{Stuck: true, Waiting: 7, Large: true, SizeBytes: 3 * gib / 2, SizeHintBytes: gib, Entries30d: 412000, TopActor: "tok_0123456789ab"})
	step()
	stuck := find(at, cm.HintAuditStuck)
	if len(stuck) != 1 || stuck[0].Level != "warning" || stuck[0].Value == nil || *stuck[0].Value != 7 || stuck[0].Object != "" || stuck[0].Site != "" || stuck[0].Count != nil {
		t.Fatalf("audit_stuck: %+v", stuck)
	}
	size := find(at, cm.HintAuditSize)
	if len(size) != 1 || size[0].Level != "notice" || size[0].Value == nil || *size[0].Value != 3*gib/2 || size[0].Threshold == nil || *size[0].Threshold != gib ||
		size[0].Count == nil || *size[0].Count != 412000 || size[0].Object != "tok_0123456789ab" || size[0].Site != "" {
		t.Fatalf("audit_size: %+v", size)
	}
	since := size[0].Since

	// Another actor leads: one hint, with the new figures and the old start.
	m.SetAuditStatus(AuditStatus{Stuck: true, Waiting: 9, Large: true, SizeBytes: 2 * gib, SizeHintBytes: gib, Entries30d: 500000, TopActor: "dashboard"})
	for i := 0; i < 3; i++ {
		step()
	}
	size = find(at, cm.HintAuditSize)
	if len(size) != 1 || size[0].Object != "dashboard" || *size[0].Value != 2*gib || *size[0].Count != 500000 || size[0].Since != since {
		t.Fatalf("audit_size after the actor changed (since %s): %+v", since, size)
	}
	if stuck = find(at, cm.HintAuditStuck); len(stuck) != 1 || *stuck[0].Value != 9 {
		t.Fatalf("audit_stuck: %+v", stuck)
	}

	// Both conditions gone: the hints clear like every other one.
	m.SetAuditStatus(AuditStatus{SizeBytes: gib / 2, SizeHintBytes: gib})
	for s := 0; s < 400; s += 10 {
		step()
	}
	if h := append(find(at, cm.HintAuditStuck), find(at, cm.HintAuditSize)...); len(h) != 0 {
		t.Fatalf("hints still active: %+v", h)
	}
}
