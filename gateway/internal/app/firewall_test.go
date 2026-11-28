package app

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
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

func TestFirewallBlocksLeaveOutOwnAndCutAsD87(t *testing.T) {
	Parallel(t)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	eng := behaviour.New(behaviour.Config{Behaviour: config.Behaviour{}})
	eng.Now = func() time.Time { return now }

	res, err := clientip.New([]string{"198.51.100.2/32"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	al := allowlist.New()
	al.Set([]store.AllowEntry{
		{ID: "allow-1", CIDR: "198.51.100.3/32", Level: allowlist.NoBlock},
		// One address inside an IPv6 /64: the block of the /64 would drop it.
		{ID: "allow-2", CIDR: "2001:db8:1:2::5/128", Level: allowlist.NoBlock},
	})

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

	// A trusted proxy, an allowlisted address and the /64 of an allowlisted
	// address never go to the firewall; the /64 next to it does.
	addBlock("198.51.100.2", 15*time.Minute, "inc-proxy")
	addBlock("198.51.100.3", 15*time.Minute, "inc-allow")
	addBlock("2001:db8:1:2::99", 15*time.Minute, "inc-allow-64")
	addBlock("2001:db8:1:3::99", 15*time.Minute, "inc-v6")
	addBlock("203.0.113.1", 15*time.Minute, "inc-short")

	got := a.firewallBlocks()
	var clients []string
	for _, b := range got {
		clients = append(clients, b.Client)
	}
	if want := []string{"2001:db8:1:3::/64", "203.0.113.1"}; !slices.Equal(clients, want) {
		t.Fatalf("clients %v, want %v", clients, want)
	}

	// Above firewall.MaxBlocks the blocks ending last are left out (D87, the
	// agent API says so), and two calls cut at the same place.
	for i := 0; i < firewall.MaxBlocks+5; i++ {
		addBlock(fmt.Sprintf("198.18.%d.%d", i/250, i%250+1), 7*24*time.Hour, "inc-long")
	}
	got = a.firewallBlocks()
	if len(got) != firewall.MaxBlocks {
		t.Fatalf("got %d blocks, want %d", len(got), firewall.MaxBlocks)
	}
	short := 0
	for _, b := range got {
		if b.Client == "198.51.100.2" || b.Client == "198.51.100.3" || b.Client == "2001:db8:1:2::/64" {
			t.Fatalf("own address %s in the blocks for the firewall", b.Client)
		}
		if b.Client == "203.0.113.1" || b.Client == "2001:db8:1:3::/64" {
			short++
		}
	}
	if short != 2 {
		t.Fatalf("%d of the 2 blocks ending first are in the cut, want both", short)
	}
	if !slices.IsSortedFunc(got, func(x, y firewall.Block) int { return strings.Compare(x.Client, y.Client) }) {
		t.Fatal("blocks are not sorted by client")
	}
	if again := a.firewallBlocks(); firewall.Revision(again) != firewall.Revision(got) {
		t.Fatal("the cut differs between two calls: the revision would never settle")
	}
}
