package behaviour

import (
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/events"
)

func TestLiftKeepsCountersAndLadder(t *testing.T) {
	e := New(Config{})
	now := time.Now()
	ip := netip.MustParseAddr("198.51.100.7")
	key, _ := KeyOf(ip)
	e.blocks.with(key, true, func(b *blockState) {
		*b = blockState{until: now.Add(time.Hour).UnixNano(), lastUntil: now.Add(time.Hour).UnixNano(), level: 3, scenario: "waf_repeat", incident: "AAAA-BBBB"}
	})
	e.clients.with(key, true, func(*clientState) {})
	if !e.IncidentRunning("AAAA-BBBB") || !e.LiftIncident("AAAA-BBBB") {
		t.Fatal("not lifted")
	}
	if e.IncidentRunning("AAAA-BBBB") || e.LiftIncident("AAAA-BBBB") {
		t.Fatal("still running")
	}
	seen := false
	e.clients.with(key, false, func(c *clientState) { seen = c != nil })
	if !seen {
		t.Fatal("counters reset: that is Release, not a lift")
	}
	e.blocks.with(key, false, func(b *blockState) {
		if b == nil || b.level != 3 || b.lastUntil == 0 {
			t.Fatalf("ladder lost: %+v", b)
		}
	})
	if e.ReleasedSince(ip, now.Add(-time.Hour)) {
		t.Fatal("a lift is no release")
	}
}

func TestAgentBlockKeepsTheLadder(t *testing.T) {
	e := New(Config{})
	now := time.Now()
	ip := netip.MustParseAddr("198.51.100.7")
	key, _ := KeyOf(ip)
	e.blocks.with(key, true, func(b *blockState) {
		*b = blockState{until: now.Add(-time.Minute).UnixNano(), lastUntil: now.Add(-time.Minute).UnixNano(), level: 2, scenario: "waf_repeat"}
	})
	if _, created := e.SetAgentBlock(AgentBlock{IP: ip, TokenID: "t1", NetClass: "residential", Duration: time.Hour, Incident: "AAAA-CCCC", Time: now}); !created {
		t.Fatal("not created")
	}
	e.blocks.with(key, false, func(b *blockState) {
		if b.level != 1 || b.ladderLevel() != 2 {
			t.Fatalf("%+v", b)
		}
	})
	if _, created := e.SetAgentBlock(AgentBlock{IP: ip, TokenID: "t1", Duration: 2 * time.Hour, Incident: "AAAA-DDDD", Time: now}); created {
		t.Fatal("a running block was replaced")
	}
	if n := e.AgentBlocks(); n != 1 {
		t.Fatalf("agent blocks %d", n)
	}
}

func TestRestoreKeepsAgentBlocks(t *testing.T) {
	e := New(Config{})
	now := time.Now().UTC().Truncate(time.Second)
	ab := events.ActiveBlock{ClientKey: "203.0.113.5", KeyBits: 32, NetClass: "hosting", Source: "agent:tok-1", Level: 1, DurationS: 200000,
		Since: now.Format(time.RFC3339), Until: now.Add(200000 * time.Second).Format(time.RFC3339), Incident: "AAAA-EEEE"}
	if n, drop := e.RestoreBlocks([]events.ActiveBlock{ab}, nil); n != 1 || len(drop) != 0 {
		t.Fatalf("restored %d, dropped %v", n, drop)
	}
	bi, ok := e.ActiveBlock(netip.MustParseAddr("203.0.113.5"))
	if !ok || bi.Scenario != "agent:tok-1" || BlockSource(bi.Scenario) != "agent:tok-1" {
		t.Fatalf("%+v", bi)
	}
	over := ab
	over.ClientKey, over.NetClass, over.Incident = "203.0.113.6", "residential", "AAAA-FFFF"
	if n, drop := e.RestoreBlocks([]events.ActiveBlock{over}, nil); n != 0 || len(drop) != 1 {
		t.Fatalf("a residential 2-day block came back: %d %v", n, drop)
	}
}
