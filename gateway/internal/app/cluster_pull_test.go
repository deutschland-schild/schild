//go:build !release

package app_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
)

// A group that has nothing to say asks nothing: the nodes ask each other
// for events, incidents and requests when one of them said that it has
// some, and otherwise about twice a minute. Before, each asked each three
// times a second.
func TestIdleGroupAsksAlmostNothing(t *testing.T) {
	// Not parallel: the test counts the questions of an idle group in a window of real time.
	a, b := pair(t)
	a.h.WaitFor("the nodes reach each other", func() bool { return a.h.App.Cluster.Synced() && b.h.App.Cluster.Synced() })
	// The first words and the pulls they set off are through.
	time.Sleep(4 * time.Second)
	a0, b0 := a.h.App.DataAsks(), b.h.App.DataAsks()
	time.Sleep(5 * time.Second)
	da, db := a.h.App.DataAsks()-a0, b.h.App.DataAsks()-b0
	// Five idle seconds were 15 questions per node before. A safety pull
	// may fall into them: three questions.
	if da > 3 || db > 3 {
		t.Errorf("idle for 5 s, web-1 asked %d times and web-2 %d times; at most 3 each are expected", da, db)
	}

	// What happens is still on the other node within the second.
	const ip = "203.0.113.190"
	start := time.Now()
	a.h.Visit("GET", "/impressum", ip, "", "")
	a.h.Visit("GET", attack, ip, "", "")
	b.h.WaitFor("web-2 holds the requests web-1 served", func() bool { return requestsOf(t, b, ip) == 2 })
	b.h.WaitFor("web-2 holds the events of web-1", func() bool { return eventsOf(t, b, ip) >= 1 })
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("the requests and events of web-1 took %s to reach web-2", d.Round(10*time.Millisecond))
	}
	if b.h.App.DataAsks() == b0+db {
		t.Error("web-2 holds the data of web-1 without having asked for it")
	}
	// And then it is quiet again.
	time.Sleep(4 * time.Second)
	a1, b1 := a.h.App.DataAsks(), b.h.App.DataAsks()
	time.Sleep(4 * time.Second)
	if da, db := a.h.App.DataAsks()-a1, b.h.App.DataAsks()-b1; da > 3 || db > 3 {
		t.Errorf("idle again for 4 s, web-1 asked %d times and web-2 %d times", da, db)
	}
}

// A node of the build before this one and a node of this build exchange
// their requests and events in the form the older one speaks, in both
// directions, and nothing is lost or doubled when the older one is
// upgraded (a rolling upgrade).
func TestNodeOfTheBuildBeforeAndThisOneExchangeEverything(t *testing.T) {
	undo := app.StartAsBuildBefore()
	a, b := pair(t) // both as the build before
	undo()
	visits := func(g *groupNode, ip string, n int) {
		for i := 0; i < n; i++ {
			g.h.Visit("GET", fmt.Sprintf("/seite/%d", i), ip, "", "")
		}
	}
	holds := func(what string, ip string, n int) {
		t.Helper()
		for _, g := range []*groupNode{a, b} {
			g.h.WaitFor(fmt.Sprintf("%s: %s holds the %d requests of %s", what, g.name, n, ip), func() bool { return requestsOf(t, g, ip) == n })
		}
	}
	visits(a, "203.0.113.191", 7)
	visits(b, "203.0.113.192", 5)
	holds("both of the build before", "203.0.113.191", 7)
	holds("both of the build before", "203.0.113.192", 5)

	// web-2 is upgraded: it restarts as this build, web-1 stays.
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	visits(a, "203.0.113.193", 9) // served while web-2 is down
	b.start(t)
	visits(a, "203.0.113.194", 6)
	visits(b, "203.0.113.195", 4)
	holds("mixed", "203.0.113.193", 9)
	holds("mixed", "203.0.113.194", 6)
	holds("mixed", "203.0.113.195", 4)
	if resp := b.h.Visit("GET", attack, "203.0.113.196", "", ""); resp.StatusCode == 200 {
		t.Fatal("the attack passed on web-2")
	}
	a.h.WaitFor("mixed: web-1 holds the event of web-2", func() bool { return eventsOf(t, a, "203.0.113.196") >= 1 })

	// web-1 follows.
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	visits(b, "203.0.113.197", 8)
	a.start(t)
	visits(a, "203.0.113.198", 3)
	holds("both of this build", "203.0.113.197", 8)
	holds("both of this build", "203.0.113.198", 3)
	// Nothing arrived twice on the way.
	time.Sleep(2500 * time.Millisecond)
	for ip, n := range map[string]int{"203.0.113.191": 7, "203.0.113.192": 5, "203.0.113.193": 9, "203.0.113.194": 6, "203.0.113.195": 4, "203.0.113.197": 8, "203.0.113.198": 3} {
		for _, g := range []*groupNode{a, b} {
			if got := requestsOf(t, g, ip); got != n {
				t.Errorf("%s holds %d requests of %s, %d were served", g.name, got, ip, n)
			}
		}
	}
}
