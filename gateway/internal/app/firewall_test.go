package app

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/firewall"
	"github.com/deutschland-schild/schild/gateway/internal/allowlist"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
	"github.com/deutschland-schild/schild/gateway/internal/clientip"
	"github.com/deutschland-schild/schild/gateway/internal/gate"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

func TestFirewallBlocksExcludesOwnAndKeepsLongest(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	eng := behaviour.New(behaviour.Config{Behaviour: config.Behaviour{}})
	eng.Now = func() time.Time { return now }

	res, err := clientip.New([]string{"198.51.100.2/32"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	al := allowlist.New()
	al.Set([]store.AllowEntry{{ID: "allow-1", CIDR: "198.51.100.3/32", Level: allowlist.NoBlock}})

	a := &App{
		Behaviour: eng,
		Allow:     al,
		Gate:      gate.New(gate.Settings{Resolver: res}),
	}

	addBlock := func(ip string, dur time.Duration, inc string) {
		eng.SetAgentBlock(behaviour.AgentBlock{
			IP:       netip.MustParseAddr(ip),
			Source:   behaviour.DashboardSource,
			NetClass: "hosting",
			Duration: dur,
			Incident: inc,
			Time:     now,
		})
	}

	// Trusted proxy and allowlisted IP must never be exported to nftables.
	addBlock("198.51.100.2", 24*time.Hour, "inc-proxy")
	addBlock("198.51.100.3", 24*time.Hour, "inc-allow")

	// Long-lived block that must survive truncation above firewall.MaxBlocks.
	addBlock("203.0.113.1", 7*24*time.Hour, "inc-long")

	// Fill > firewall.MaxBlocks short-lived blocks with lexicographically smaller IPs.
	for i := 0; i < firewall.MaxBlocks+5; i++ {
		ip := fmt.Sprintf("198.18.%d.%d", i/250, i%250+1)
		addBlock(ip, 15*time.Minute, "inc-short")
	}

	got := a.firewallBlocks()
	if len(got) != firewall.MaxBlocks {
		t.Fatalf("got %d blocks, want %d", len(got), firewall.MaxBlocks)
	}
	var hasLong bool
	for _, b := range got {
		if b.Client == "198.51.100.2" || b.Client == "198.51.100.3" {
			t.Fatalf("own/allowlisted address %s exported to firewall", b.Client)
		}
		if b.Client == "203.0.113.1" {
			hasLong = true
		}
	}
	if !hasLong {
		t.Fatal("longest-lived block 203.0.113.1 was evicted by short-lived blocks")
	}
}
