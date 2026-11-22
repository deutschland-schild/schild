//go:build !release

package app_test

import (
	"slices"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/behaviour"
)

// loginsOf is what the scenarios of a node count of failed logins of one
// client key, read through the pages a member would get.
func loginsOf(g *groupNode, client string) float64 {
	for cur := 0; cur >= 0; {
		var page *behaviour.Warm
		page, cur = g.h.App.Behaviour.WarmPage(cur)
		for _, c := range page.Clients {
			if c.Client == client {
				return c.LoginFast
			}
		}
	}
	return 0
}

// The group counted four failed logins of a client; a node that restarts
// holds them at its first ready answer, where it would start at zero and
// give the client a fresh allowance. The counts that follow are not added a
// second time by the second pass.
func TestRestartedNodeHoldsTheCountsOfTheGroupWhenItIsReady(t *testing.T) {
	a, b := pair(t)
	b.h.WaitFor("web-2 is in service", func() bool { return b.h.App.InService() })
	const client = "198.51.100.90/32"
	// As if four failed logins had reached web-1 (the engine's own tests
	// cover how they are counted).
	a.h.App.Behaviour.ApplyWarm(&behaviour.Warm{Clients: []behaviour.WarmClient{{Client: client, LoginFast: 4, LoginSlow: 4, LoginN: 4}}}, false, nil)
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	b.h.WaitFor("web-2 is in service again", func() bool { return b.h.App.InService() })
	if !b.h.App.WarmDone() || b.h.App.WarmFailed() {
		t.Fatalf("web-2 is ready, handover done %v, failed %v", b.h.App.WarmDone(), b.h.App.WarmFailed())
	}
	if got := loginsOf(b, client); got < 3.9 || got > 4.1 {
		t.Fatalf("at its first ready answer web-2 counts %.2f failed logins of the client, want the 4 the group counted", got)
	}
	// The second pass follows a few seconds later and only raises.
	time.Sleep(4 * time.Second)
	if got := loginsOf(b, client); got < 3.9 || got > 4.1 {
		t.Errorf("after the second pass web-2 counts %.2f failed logins of the client, want 4", got)
	}
	if slices.Contains(b.h.App.ClusterReasons(), "cluster_counts_not_taken") {
		t.Error("the overview of web-2 says the counts were not taken")
	}
}

// The first node of a group has nobody to ask and is ready without a wait.
func TestOnlyNodeOfAGroupNeedsNoHandover(t *testing.T) {
	a, _ := pair(t)
	a.h.WaitFor("web-1 is in service", func() bool { return a.h.App.InService() })
	if !a.h.App.WarmDone() {
		t.Error("web-1 is in service without the handover being settled")
	}
}

func TestClockOddRule(t *testing.T) {
	s := time.Second
	for _, c := range []struct {
		name  string
		skews []time.Duration
		want  bool
	}{
		{"no other gateway", nil, false},
		{"a pair, 90 s apart: nobody can know who is wrong", []time.Duration{90 * s}, false},
		{"two others agree, this node 90 s behind them", []time.Duration{90 * s, 91 * s}, true},
		{"two others agree, this node 90 s ahead of them", []time.Duration{-90 * s, -88 * s}, true},
		{"two others agree with this node", []time.Duration{0, 2 * s}, false},
		{"this node is right, one other is 90 s ahead", []time.Duration{0, 90 * s}, false},
		{"two others off in different directions", []time.Duration{-90 * s, 90 * s}, false},
		{"all different", []time.Duration{70 * s, 100 * s, 130 * s}, false},
		{"others agree, 30 s off: within what the group takes", []time.Duration{30 * s, 31 * s}, false},
		{"others agree, exactly a minute off", []time.Duration{60 * s, 62 * s}, true},
		{"fifteen others agree, this node far behind", slices.Repeat([]time.Duration{600 * s}, 15), true},
		{"three agree, a fourth does not: no clear picture", []time.Duration{90 * s, 90 * s, 91 * s, 0}, false},
	} {
		if got := app.ClockOdd(c.skews); got != c.want {
			t.Errorf("%s: clockOdd(%v) = %v, want %v", c.name, c.skews, got, c.want)
		}
	}
}

// A node that sees the other gateways agree and itself a minute off leaves
// traffic, says why on the overview, and returns when its clock is right.
func TestNodeWithTheOddClockLeavesTrafficAndReturns(t *testing.T) {
	a, b := pair(t)
	b.h.WaitFor("web-2 is in service", func() bool { return b.h.App.InService() })
	b.h.App.SetClocks(func() []time.Duration { return []time.Duration{-90 * time.Second, -91 * time.Second} })
	b.h.WaitFor("web-2 leaves traffic", func() bool { return !b.h.App.InService() })
	if !slices.Contains(b.h.App.ClusterReasons(), "cluster_clock_out_of_service") {
		t.Error("the overview of web-2 does not say that it left traffic because of its clock")
	}
	if !a.h.App.InService() {
		t.Error("web-1, whose clock is right, left traffic too")
	}
	b.h.App.SetClocks(func() []time.Duration { return []time.Duration{0, time.Second} })
	b.h.WaitFor("web-2 takes traffic again", func() bool { return b.h.App.InService() })
	if slices.Contains(b.h.App.ClusterReasons(), "cluster_clock_out_of_service") {
		t.Error("the overview of web-2 still names the clock")
	}
}
