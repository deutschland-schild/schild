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
		{"three of four agree, the fourth with this node: a majority", []time.Duration{90 * s, 90 * s, 91 * s, 0}, true},
		{"three of four agree, the fourth a little off: a majority", []time.Duration{90 * s, 92 * s, 93 * s, 99 * s}, true},
		{"two of three agree, the third far off: two of four in view, no majority", []time.Duration{90 * s, 91 * s, 400 * s}, false},
		{"two against two: no majority", []time.Duration{90 * s, 91 * s, 0}, false},
		{"the majority straddles this node's clock", []time.Duration{58 * s, 62 * s, 61 * s}, false},
		{"unsorted, a majority 70 s ahead", []time.Duration{71 * s, 0, 70 * s, 73 * s, 70 * s}, true},
	} {
		if got := app.ClockOdd(c.skews); got != c.want {
			t.Errorf("%s: clockOdd(%v) = %v, want %v", c.name, c.skews, got, c.want)
		}
	}
}

// The rule across a whole group: every node judges by the clocks of all the
// others, and never every node leaves.
func TestClockOddRuleAcrossTheGroup(t *testing.T) {
	s := time.Second
	nodes := func(n int, clock time.Duration) []time.Duration { return slices.Repeat([]time.Duration{clock}, n) }
	for _, c := range []struct {
		name   string
		clocks []time.Duration
		out    []int // the nodes that leave, by index
	}{
		{"2 nodes, 90 s apart", []time.Duration{0, 90 * s}, nil},
		{"3 nodes, one 90 s ahead", []time.Duration{0, 1 * s, 90 * s}, []int{2}},
		{"3 nodes, all apart", []time.Duration{0, 70 * s, 140 * s}, nil},
		{"4 nodes, one off", []time.Duration{0, 1 * s, 4 * s, -120 * s}, []int{3}},
		{"4 nodes, one off, one 8 s off the others: no three agree", []time.Duration{0, 1 * s, 8 * s, -120 * s}, nil},
		{"5 nodes, one off, one 8 s off the others", []time.Duration{0, 1 * s, 2 * s, 8 * s, -120 * s}, []int{4}},
		{"4 nodes, two against two", []time.Duration{0, 1 * s, 90 * s, 91 * s}, nil},
		{"5 nodes, two off together", []time.Duration{0, 2 * s, 3 * s, 300 * s, 301 * s}, []int{3, 4}},
		{"5 nodes, two off apart", []time.Duration{0, 2 * s, 4 * s, 300 * s, -300 * s}, []int{3, 4}},
		{"16 nodes, one far behind", append(nodes(15, 0), -10*time.Minute), []int{15}},
		{"16 nodes, eight against eight", append(nodes(8, 0), nodes(8, 90*s)...), nil},
		{"16 nodes, nine against seven", append(nodes(9, 0), nodes(7, 90*s)...), []int{9, 10, 11, 12, 13, 14, 15}},
	} {
		var out []int
		for i, mine := range c.clocks {
			var skews []time.Duration
			for j, theirs := range c.clocks {
				if j != i {
					skews = append(skews, theirs-mine)
				}
			}
			if app.ClockOdd(skews) {
				out = append(out, i)
			}
		}
		if !slices.Equal(out, c.out) {
			t.Errorf("%s: nodes %v leave, want %v", c.name, out, c.out)
		}
		if len(out) == len(c.clocks) {
			t.Errorf("%s: every node leaves", c.name)
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
