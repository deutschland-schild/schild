package app

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// D38: an unreachable cap sets the hint flag and logs at most one warning
// per hour; a pass that reaches the cap clears the flag.
func TestNoteCapWarnsOncePerHour(t *testing.T) {
	Parallel(t)
	var buf bytes.Buffer
	a := &App{log: slog.New(slog.NewTextHandler(&buf, nil))}
	now := time.Now()
	r := &store.CapResult{CapBytes: 10 << 20, UsedAfter: 12 << 20, Unreachable: true}
	a.noteCap(r, now)
	a.noteCap(r, now.Add(30*time.Minute))
	a.noteCap(r, now.Add(59*time.Minute))
	if n := strings.Count(buf.String(), "store_cap_unreachable"); n != 1 || !a.capUnreachable.Load() {
		t.Fatalf("%d warnings, flag %t:\n%s", n, a.capUnreachable.Load(), buf.String())
	}
	a.noteCap(r, now.Add(61*time.Minute))
	if n := strings.Count(buf.String(), "store_cap_unreachable"); n != 2 {
		t.Fatalf("%d warnings after an hour", n)
	}
	a.noteCap(&store.CapResult{CapBytes: 10 << 20, UsedAfter: 9 << 20}, now.Add(62*time.Minute))
	if a.capUnreachable.Load() {
		t.Fatal("flag not cleared")
	}
}
