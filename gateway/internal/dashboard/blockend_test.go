package dashboard

import (
	"testing"
	"time"
)

// TestBlockEndAt (evening measurement 2026-10-29 4.4, D29 rest): a 15 min
// block that ended with a restart ends at the start of the process, and a
// later click on "Freischalten" does not move that end to the click.
func TestBlockEndAt(t *testing.T) {
	t0 := time.Date(2026, 10, 29, 17, 40, 0, 0, time.UTC)
	until := t0.Add(15 * time.Minute)
	started := t0.Add(5 * time.Minute)
	var zero time.Time
	cases := []struct {
		name           string
		now            time.Time
		known, running bool
		unblocked      time.Time
		want           time.Time
		ended          bool // BehaviourBlock.ended_at set (contracts v0.5)
	}{
		{"running", t0.Add(6 * time.Minute), true, true, zero, until, false},
		{"ended with the restart", t0.Add(6 * time.Minute), true, false, zero, started, true},
		{"ended with the restart, unblocked later", t0.Add(8 * time.Minute), true, false, t0.Add(7 * time.Minute), started, true},
		{"unblocked while running", t0.Add(8 * time.Minute), true, false, t0.Add(4 * time.Minute), t0.Add(4 * time.Minute), true},
		{"expired, unblocked later", t0.Add(time.Hour), true, false, t0.Add(30 * time.Minute), until, true},
		{"expired", t0.Add(time.Hour), true, false, zero, until, true},
		{"no engine, unblocked", t0.Add(8 * time.Minute), false, false, t0.Add(7 * time.Minute), t0.Add(7 * time.Minute), true},
		{"no engine", t0.Add(8 * time.Minute), false, false, zero, until, false},
	}
	for _, c := range cases {
		got := blockEndAt(until, c.now, started, t0, c.known, c.running, c.unblocked)
		if !got.Equal(c.want) {
			t.Errorf("%s: end %v, want %v", c.name, got, c.want)
		}
		if blockEnded(got, c.now) != c.ended {
			t.Errorf("%s: ended %v, want %v", c.name, !c.ended, c.ended)
		}
	}
	// A block that began after this process started and does not run any
	// more ended now at the latest.
	if got := blockEndAt(until, t0.Add(9*time.Minute), started, t0.Add(6*time.Minute), true, false, zero); !got.Equal(t0.Add(9 * time.Minute)) {
		t.Errorf("block after the start: %v", got)
	}
}
