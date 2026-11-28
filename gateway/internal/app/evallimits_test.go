package app

import (
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/gate"
)

func TestEvalLimitsFromEnv(t *testing.T) {
	Parallel(t)
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	l, err := evalLimitsFromEnv(env(nil))
	if err != nil || l.MaxConcurrent != 0 || l.QueueWait != 0 {
		t.Fatalf("unset: %+v %v", l, err)
	}
	l, err = evalLimitsFromEnv(env(map[string]string{"SCHILD_WAF_MAX_EVALS": "6", "SCHILD_WAF_QUEUE_WAIT_MS": "250"}))
	if err != nil || l.MaxConcurrent != 6 || l.QueueWait != 250*time.Millisecond {
		t.Fatalf("set: %+v %v", l, err)
	}
	for _, bad := range []map[string]string{{"SCHILD_WAF_MAX_EVALS": "0"}, {"SCHILD_WAF_MAX_EVALS": "x"}, {"SCHILD_WAF_QUEUE_WAIT_MS": "-1"}} {
		if _, err := evalLimitsFromEnv(env(bad)); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

// waf.max_concurrent_evals and waf.queue_wait_ms (v0.4 addendum) set the
// slots; the test lab's environment variables win over them.
func TestEvalLimitsFromConfig(t *testing.T) {
	Parallel(t)
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cfg := &config.Site{}
	cfg.WAF.MaxConcurrentEvals = 8
	cfg.WAF.QueueWaitMS = 250
	l, err := evalLimits(cfg, env(nil), false)
	if err != nil || l.MaxConcurrent != 8 || l.QueueWait != 250*time.Millisecond {
		t.Fatalf("config: %+v %v", l, err)
	}
	l, err = evalLimits(cfg, env(map[string]string{"SCHILD_WAF_MAX_EVALS": "3"}), false)
	if err != nil || l.MaxConcurrent != 3 || l.QueueWait != 250*time.Millisecond {
		t.Fatalf("env wins for slots only: %+v %v", l, err)
	}
	l, err = evalLimits(cfg, env(map[string]string{"SCHILD_WAF_QUEUE_WAIT_MS": "40"}), false)
	if err != nil || l.MaxConcurrent != 8 || l.QueueWait != 40*time.Millisecond {
		t.Fatalf("env wins for the wait only: %+v %v", l, err)
	}
	// Reserved slots (D31 amendment 2026-10-29): the override sets the slot
	// count only; expensive evaluations stay at config.ExpensiveEvalSlots of
	// it, and an override of 1 counts as MinEvalSlots.
	for _, v := range []string{"1", "2", "3", "4", "9", "64", "1024"} {
		l, err := evalLimits(cfg, env(map[string]string{"SCHILD_WAF_MAX_EVALS": v}), false)
		if err != nil {
			t.Fatal(err)
		}
		g := gate.New(gate.Settings{})
		g.SetEvalLimits(l)
		got := g.EvalLimits()
		if got.MaxConcurrent < config.MinEvalSlots || got.MaxHeavy != config.ExpensiveEvalSlots(got.MaxConcurrent) ||
			got.MaxConcurrent-got.MaxHeavy != config.ReservedEvalSlots(got.MaxConcurrent) {
			t.Fatalf("SCHILD_WAF_MAX_EVALS=%s: %d slots, %d expensive", v, got.MaxConcurrent, got.MaxHeavy)
		}
	}
	cfg.WAF.MaxConcurrentEvals = 0 // absent: derived from GOMAXPROCS by the gate
	if l, _ := evalLimits(cfg, env(nil), false); l.MaxConcurrent != 0 {
		t.Fatalf("absent key: %+v", l)
	}
}

// D77: release builds do not read the test lab's variables, also not a
// broken value.
func TestEvalLimitsReleaseIgnoresEnv(t *testing.T) {
	Parallel(t)
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cfg := &config.Site{}
	cfg.WAF.MaxConcurrentEvals = 8
	cfg.WAF.QueueWaitMS = 250
	for _, e := range []map[string]string{{"SCHILD_WAF_MAX_EVALS": "3", "SCHILD_WAF_QUEUE_WAIT_MS": "40"}, {"SCHILD_WAF_MAX_EVALS": "x"}} {
		l, err := evalLimits(cfg, env(e), true)
		if err != nil || l.MaxConcurrent != 8 || l.QueueWait != 250*time.Millisecond {
			t.Fatalf("%v: %+v %v", e, l, err)
		}
	}
}
