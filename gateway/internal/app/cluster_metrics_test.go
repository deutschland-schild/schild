//go:build !release

package app_test

import (
	"context"
	"testing"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/monitoring"
)

// The counters and charts of a group: a gateway holds the metric buckets of
// the other gateway, shows that node alone and adds it to the group.
func TestGroupShowsTheCountersOfEveryNode(t *testing.T) {
	a, b := pair(t)
	if a.h.App.Monitor == nil || b.h.App.Monitor == nil {
		t.Skip("monitoring is off in this harness")
	}
	for i := 0; i < 25; i++ {
		a.h.Visit("GET", "/", "203.0.113.180", "", "")
	}
	idA := a.h.App.Cluster.ID()
	requests := func(v monitoring.NodeView) float64 {
		now := time.Now()
		res, err := v.Series(monitoring.SeriesQuery{Metrics: []string{"traffic.requests:rate"}, From: now.Add(-2 * time.Minute), To: now, Resolution: "10s"}, now)
		if err != nil {
			t.Fatal(err)
		}
		var sum float64
		for _, p := range res.Series[0].Values {
			if p != nil {
				sum += *p * float64(res.StepS)
			}
		}
		return sum
	}
	// A 10 s bucket of web-1 closes within ten seconds; then web-2 asks for it.
	deadline := time.Now().Add(40 * time.Second)
	var theirs monitoring.NodeView
	for {
		b.h.App.PullGroupMetrics(context.Background())
		if !b.h.App.Monitor.NodeNewest(idA, cm.Res10s).IsZero() {
			v, err := b.h.App.Monitor.Nodes(idA)
			if err != nil {
				t.Fatal(err)
			}
			if theirs = v; requests(v) >= 25 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("web-2 never held the requests web-1 counted")
		}
		time.Sleep(250 * time.Millisecond)
	}
	own, err := b.h.App.Monitor.Nodes(b.h.App.Cluster.ID())
	if err != nil {
		t.Fatal(err)
	}
	all, _ := b.h.App.Monitor.Nodes("")
	if got, want := requests(all), requests(theirs)+requests(own); got < 25 || got != want {
		t.Fatalf("the group shows %v requests, the nodes %v", got, want)
	}
	if requests(own) >= 25 {
		t.Fatal("web-2 counts the requests of web-1 as its own")
	}
	now := time.Now()
	sc := all.Scope(now.Add(-time.Minute), now, now)
	if sc == nil || len(sc.Nodes) != 2 || !sc.ClientsAtLeast {
		t.Fatalf("scope of the group on web-2: %+v", sc)
	}
	// Two running nodes name nobody as partial, also the one without a
	// visitor: its buckets arrive like any other (the rule of N2 looks at the
	// end of what is held, so an idle member must hand over buckets too).
	if len(sc.PartialNodes) != 0 {
		t.Fatalf("web-2 names web-1 as partial right after it took its buckets: %+v", sc.PartialNodes)
	}
	a.h.WaitFor("web-1 holds buckets of web-2, which had no visitor, and names nobody", func() bool {
		a.h.App.PullGroupMetrics(context.Background())
		v, err := a.h.App.Monitor.Nodes("")
		if err != nil {
			return false
		}
		now := time.Now()
		s := v.Scope(now.Add(-time.Minute), now, now)
		return s != nil && len(s.Nodes) == 2 && len(s.PartialNodes) == 0
	})
	// A node hands over what it measured itself, never what it holds of others.
	a.h.App.PullGroupMetrics(context.Background())
	if v, err := a.h.App.Monitor.Nodes(b.h.App.Cluster.ID()); err == nil && requests(v) >= 25 {
		t.Fatal("web-2 handed the buckets of web-1 back to it as its own")
	}
}
