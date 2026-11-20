package gate

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// TestIncidentQueueFullRateLimited (D36 fix round 2, re-measurement C; D38
// section 5): a flood of full-queue drops writes one line per minute with
// the count, not one line per incident, and a suppressed drop does not
// allocate.
func TestIncidentQueueFullRateLimited(t *testing.T) {
	var buf bytes.Buffer
	t0 := time.Unix(1_800_000_000, 0)
	now := t0
	g := &Gate{Log: slog.New(slog.NewTextHandler(&buf, nil)), Now: func() time.Time { return now }, incidents: make(chan *store.Incident)}
	in := &store.Incident{Incident: "inc"}
	for i := 0; i < 100_000; i++ {
		now = t0.Add(time.Duration(i) * time.Microsecond)
		g.QueueIncident(in)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `msg="incident queue full, incidents not stored"`) {
		t.Fatalf("first drop: %q", lines)
	}
	now = t0.Add(time.Minute + time.Second)
	g.QueueIncident(in)
	lines = strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "(99999 suppressed)") {
		t.Fatalf("summary: %q", lines)
	}
	if n := testing.AllocsPerRun(1000, func() { g.QueueIncident(in) }); n != 0 {
		t.Fatalf("a suppressed drop allocates: %v", n)
	}
}
