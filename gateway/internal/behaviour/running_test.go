package behaviour

import (
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
)

// The list of D87: blocks of the table and kept ones, each once, ended ones
// left out, newest first.
func TestRunningBlocks(t *testing.T) {
	e := New(Config{})
	now := time.Now()
	e.Now = func() time.Time { return now }
	put := func(ip string, since, until time.Duration, scenario string) {
		key, _ := KeyOf(netip.MustParseAddr(ip))
		e.blocks.with(key, true, func(b *blockState) {
			*b = blockState{started: now.Add(since).UnixNano(), until: now.Add(until).UnixNano(), level: 1, scenario: scenario, incident: "AAAA-" + ip[len(ip)-1:] + "BBB"}
		})
	}
	put("198.51.100.7", -10*time.Minute, 5*time.Minute, "waf_repeat")
	put("198.51.100.8", -time.Hour, -time.Minute, "path_probing")
	put("2001:db8:1:2::9", -time.Minute, time.Hour, AgentSource+"tok_1")
	// A kept block that is not in the table any more (after a restart).
	k6, _ := KeyOf(netip.MustParseAddr("203.0.113.5"))
	e.putLong(k6, longBlock{ab: events.ActiveBlock{ClientKey: "203.0.113.5", KeyBits: 32, Source: "behaviour:aggressive_crawl", Level: 2, DurationS: 172800,
		Since: now.Add(-2 * time.Hour).UTC().Format(time.RFC3339), Incident: "CCCC-DDDD", NetClass: "hosting"}, until: now.Add(46 * time.Hour).UnixNano()})
	got := e.RunningBlocks()
	if len(got) != 3 {
		t.Fatalf("%d blocks: %+v", len(got), got)
	}
	if got[0].Key.String() != "2001:db8:1:2::/64" || got[0].Scenario != AgentSource+"tok_1" {
		t.Errorf("newest first: %+v", got[0])
	}
	if got[1].Key.String() != "198.51.100.7/32" || got[1].Scenario != "waf_repeat" {
		t.Errorf("second: %+v", got[1])
	}
	if got[2].Scenario != "aggressive_crawl" || !got[2].Persisted || got[2].Level != 2 || got[2].Incident != "CCCC-DDDD" {
		t.Errorf("kept block: %+v", got[2])
	}
}
