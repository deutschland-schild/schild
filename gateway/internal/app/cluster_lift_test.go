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
	recs, err := g.h.App.Cluster.State(contract.ClassBlocks)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		if !r.Deleted {
			out = append(out, r.ID)
		}
	}
	return out
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
	if recs, err := nodes[0].h.App.Cluster.State(contract.ClassBlocks); err == nil {
		ids := map[string]string{}
		for _, g := range nodes {
			ids[g.h.App.Cluster.ID()] = g.name
		}
		shown := 0
		for _, r := range recs {
			if r.Deleted || shown >= 8 {
				continue
			}
			shown++
			for _, p := range plan {
				if p.ip == r.ID {
					t.Logf("left %s: set on %s, lifted on %s after %s; winning record by %s seq %d", r.ID, nodes[p.set].name, nodes[p.lift].name, p.pause, ids[r.Origin], r.Seq)
				}
			}
		}
	}
	for _, g := range nodes {
		if run := g.h.App.Behaviour.RunningBlocks(); len(run) != 0 {
			t.Errorf("%s still lists %d of %d lifted blocks, first %s (incident %s)", g.name, len(run), n, run[0].Key.Addr(), run[0].Incident)
		}
		if live := liveBlocks(t, g); len(live) != 0 {
			t.Errorf("%s holds %d live block records of %d lifted blocks, first %s", g.name, len(live), n, live[0])
		}
	}
}

// A block that stayed in the records although its incident was released (a
// node of the build before N1 was fixed left such blocks behind) ends when
// the node that holds the release starts: it tells the group the lift.
func TestStartRepairsABlockWhoseIncidentIsReleased(t *testing.T) {
	a, b := pair(t)
	const ip, incident = "203.0.113.230", "K7QM-STAY"
	a.block(ip, incident, 7*24*time.Hour)
	b.h.WaitFor("web-2 holds the block", func() bool { return b.blocked(ip) == incident })
	// The release is in the store of web-2 and nothing else happened: the
	// state a lift before the record's arrival used to leave.
	b.h.WaitFor("web-2 holds the incident of the block", func() bool {
		return b.h.App.Store.MarkUnblocked(context.Background(), incident, time.Now(), "") == nil
	})
	b.h.App.FlushBlocks()
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	b.start(t)
	a.h.WaitFor("web-1 serves the address again", func() bool { return a.blocked(ip) == "" })
	b.h.WaitFor("web-2 does not block it", func() bool { return b.blocked(ip) == "" })
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" holds no live record of the block", func() bool { return len(liveBlocks(t, g)) == 0 })
	}
}
