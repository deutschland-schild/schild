package gate

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/decide"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/waf"
)

// liveCounters closes the current second and returns its counters.
func liveCounters(t *testing.T, m *monitoring.Monitor) cm.TrafficCounters {
	t.Helper()
	ch, _, cancel, ok := m.Subscribe(0)
	if !ok {
		t.Fatal("subscribe")
	}
	defer cancel()
	m.Tick(time.Now().Truncate(time.Second).Add(time.Second))
	select {
	case b := <-ch:
		var tick cm.LiveTick
		if err := json.Unmarshal(b, &tick); err != nil {
			t.Fatal(err)
		}
		return tick.Traffic
	case <-time.After(time.Second):
		t.Fatal("no tick")
	}
	return cm.TrafficCounters{}
}

// Observe-mode rate limits reach the monitor as would_rate_limit (MVP-21
// measurement finding 2: the counter stayed 0).
func TestMonitorCountsObservedRateLimits(t *testing.T) {
	e := newEnv(t, decide.ModeAutoblock)
	b := config.Behaviour{PresetLimits: config.BehaviourOff}
	for _, id := range config.ScenarioIDs {
		b.Scenarios.Get(id).Mode = config.BehaviourObserve
	}
	b.RateLimits = []config.RateLimit{{ID: "search", Route: "/search", Limit: 2, Per: "1m", Burst: 2, Mode: config.BehaviourObserve}}
	e.g.Behaviour = behaviour.New(behaviour.Config{Behaviour: b, InstalledAt: time.Now().Add(-60 * 24 * time.Hour)})
	m, err := monitoring.New(monitoring.Config{StoragePath: t.TempDir(), Log: quiet}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	e.g.Monitor = m
	for i := 0; i < 10; i++ {
		if r := e.do(t, "GET", "/search", "", "", nil); r.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, r.StatusCode)
		}
	}
	c := liveCounters(t, m)
	if c.Requests != 10 || c.Forwarded != 10 || c.WouldRateLimit != 8 || c.RateLimited != 0 {
		t.Fatalf("counters: %+v", c)
	}
}

// Every rule id of a detection is counted, not only the first eight (MVP-21
// measurement finding 3a).
func TestRuleIDsNotCut(t *testing.T) {
	var ms []waf.Match
	for i := 0; i < 23; i++ {
		ms = append(ms, waf.Match{ID: 941100 + i})
	}
	ms = append(ms, waf.Match{ID: 941100}, waf.Match{ID: 1000007})
	ids := ruleIDs(ms)
	if len(ids) != 24 {
		t.Fatalf("got %d ids: %v", len(ids), ids)
	}
	if ids[0] != "941100" || ids[22] != fmt.Sprint(941122) || ids[23] != "1000007" {
		t.Fatalf("ids: %v", ids)
	}
	if ruleIDs(nil) != nil {
		t.Fatal("no matches, no ids")
	}
}
