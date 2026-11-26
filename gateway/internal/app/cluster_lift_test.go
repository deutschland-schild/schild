//go:build !release

package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
)

// trio: three gateways in one group, set up by their configuration.
func trio(t *testing.T) []*groupNode {
	t.Helper()
	nodes := newGroup(t, "web-1", "web-2", "web-3")
	for _, g := range nodes {
		g.start(t)
	}
	return nodes
}

// liveBlocks are the block records of the group a node holds that are not
// lifted: what a node applies at its start.
func liveBlocks(t *testing.T, g *groupNode) []string {
	t.Helper()
	return recordIDs(t, g, contract.ClassIncidentBlocks)
}

// A block set on one node and lifted on another a moment later ends for the
// cluster: no node lists it and no node holds a live record of it (finding
// N1 of the second lab measurement: 116 of 1 600 such blocks stayed listed
// on every node and could not be lifted again).
func TestBlockLiftedOnAnotherNodeAMomentLaterEndsForTheCluster(t *testing.T) {
	nodes := trio(t)
	for _, g := range nodes {
		g.h.Login()
	}
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" is in step", func() bool { return g.h.App.InService() })
	}
	const n = 120
	rng := rand.New(rand.NewSource(27))
	type pairing struct {
		set, lift int
		pause     time.Duration
		ip        string
	}
	var plan []pairing
	for i := 0; i < n; i++ {
		s := rng.Intn(3)
		l := (s + 1 + rng.Intn(2)) % 3
		plan = append(plan, pairing{s, l, time.Duration(200+rng.Intn(800)) * time.Millisecond, fmt.Sprintf("198.51.100.%d", i+1)})
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed []string
	sem := make(chan struct{}, 12)
	for _, p := range plan {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			code, body := nodes[p.set].h.API("POST", "/blocks", map[string]any{"address": p.ip, "duration_s": 604800, "reason": "test"})
			if code != 200 {
				mu.Lock()
				failed = append(failed, fmt.Sprintf("block %s: %d %s", p.ip, code, body))
				mu.Unlock()
				return
			}
			var rb struct {
				Incident string `json:"incident"`
			}
			_ = json.Unmarshal(body, &rb)
			time.Sleep(p.pause)
			deadline := time.Now().Add(10 * time.Second)
			for {
				code, body = nodes[p.lift].h.API("POST", "/incidents/"+rb.Incident+"/unblock", map[string]any{})
				if code == 200 || time.Now().After(deadline) {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if code != 200 {
				mu.Lock()
				failed = append(failed, fmt.Sprintf("unblock %s on %s: %d %s", p.ip, nodes[p.lift].name, code, body))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(failed) > 0 {
		t.Fatalf("%d calls failed, first: %s", len(failed), failed[0])
	}
	time.Sleep(5 * time.Second)
	for _, g := range nodes {
		if run := g.h.App.Behaviour.RunningBlocks(); len(run) != 0 {
			t.Errorf("%s still lists %d of %d lifted blocks, first %s (incident %s)", g.name, len(run), n, run[0].Key.Addr(), run[0].Incident)
		}
		if live := liveBlocks(t, g); len(live) != 0 {
			t.Errorf("%s holds %d live block records of %d lifted blocks, first %s", g.name, len(live), n, live[0])
		}
	}
}

// The status of an incident keeps no block from running. A node that holds
// the incident of a block as unblocked runs the block all the same: that
// status also comes from the end of a block by the allowlist of the node
// that decided it, travels with the incident and arrives before or after
// the record, so a rule on it made the nodes of a group enforce different
// blocks with equal hashes. What ends a block is its lift. (Until D109 a
// node that held such an incident wrote the tombstone itself at its start.)
func TestBlockRunsWhateverTheStatusOfItsIncident(t *testing.T) {
	a, b := pair(t)
	const ip, incident = "203.0.113.230", "K7QM-STAY"
	a.block(ip, incident, 15*time.Minute)
	b.h.WaitFor("web-2 holds the block", func() bool { return b.blocked(ip) == incident })
	b.h.WaitFor("web-2 holds the incident of the block, as unblocked", func() bool {
		return b.h.App.Store.MarkUnblocked(context.Background(), incident, time.Now(), "") == nil
	})
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	b.h.WaitFor("web-2 runs the block again after its start", func() bool { return b.blocked(ip) == incident })
	time.Sleep(time.Second)
	for _, g := range []*groupNode{a, b} {
		if got := g.blocked(ip); got != incident {
			t.Errorf("%s runs %q, want the block nobody lifted", g.name, got)
		}
		if lifts := recordIDs(t, g, contract.ClassLifts); len(lifts) != 0 {
			t.Errorf("%s holds lifts %v, and nobody released", g.name, lifts)
		}
		if live := liveBlocks(t, g); len(live) != 1 {
			t.Errorf("%s holds the block records %v, want the one block", g.name, live)
		}
	}
}

// Released before the record came: a node that holds only the incident of
// a block (it travels with the events of its node) releases it in the
// dashboard. The lift ends the block on the node that decided it, and when
// the record of the block arrives after the lift, the block runs nowhere.
func TestReleaseBeforeTheRecordCameKeepsTheBlockFromRunning(t *testing.T) {
	a, b := pair(t)
	b.h.Login()
	inService(t, a, b)
	const ip, incident = "203.0.113.231", "K7QM-SXXN"
	// web-1 decides the block and has not written its record yet.
	a.h.App.SetGroupBlocksMax(0)
	a.block(ip, incident, 15*time.Minute)
	time.Sleep(600 * time.Millisecond)
	if ids := liveBlocks(t, b); len(ids) != 0 || b.blocked(ip) != "" {
		t.Fatalf("web-2 holds %v and runs %q before the record was written", ids, b.blocked(ip))
	}
	b.unblock(t, incident, ip)
	a.h.WaitFor("web-1 ended its block by the lift of web-2", func() bool { return a.blocked(ip) == "" && holds(t, a, contract.ClassLifts, incident) })
	// The record of the block arrives after the lift.
	if err := a.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.writeStopped(t, nil, func(n *cluster.Node) {
		until := blockUntil()
		old := blockBefore(ip, incident, "web-1", until)
		if _, err := n.Publish(contract.ClassIncidentBlocks, incident, &contract.IncidentBlock{Client: ip, Bits: 32, Scope: contract.ScopeGateway, Source: old.Source, Level: 1,
			Since: old.Since, Until: old.Until, DurationS: old.DurationS, NetClass: old.NetClass, Node: old.Node}, false, until); err != nil {
			t.Fatal(err)
		}
	})
	a.start(t)
	inService(t, a, b)
	time.Sleep(1500 * time.Millisecond)
	for _, g := range []*groupNode{a, b} {
		if got := g.blocked(ip); got != "" {
			t.Errorf("%s runs %q: the record that came after the release started the block", g.name, got)
		}
		if live := liveBlocks(t, g); len(live) != 0 {
			t.Errorf("%s stored the block records %v although it holds the lift", g.name, live)
		}
	}
}
