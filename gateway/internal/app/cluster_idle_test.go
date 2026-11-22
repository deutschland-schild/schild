//go:build !release

package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// An idle node of a group does not read its shared values and does not
// hash its state again and again: both work when something changed, and
// once per safety interval otherwise.
func TestIdleNodeLeavesItsSharedStateAlone(t *testing.T) {
	a, b := pair(t)
	a.h.WaitFor("both nodes are in service", func() bool { return a.h.App.InService() && b.h.App.InService() })
	time.Sleep(8 * time.Second) // the first sync, its writes and what follows them are through
	for _, g := range []*groupNode{a, b} {
		r0, h0 := g.h.App.SharedRounds(), g.h.App.StateHashesComputed()
		const idle = 12 * time.Second
		time.Sleep(idle)
		rounds, hashes := g.h.App.SharedRounds()-r0, g.h.App.StateHashesComputed()-h0
		t.Logf("%s idle for %s: %d rounds of the shared things, %d hashes", g.name, idle, rounds, hashes)
		// Four looks a second would be 48 rounds, a hash every 5 s two or
		// three. The safety interval is 15 s; a write of another loop of
		// the node into its store may add a round.
		if rounds > 6 {
			t.Errorf("%s: the loop of the shared things worked %d times in %s of idling", g.name, rounds, idle)
		}
		if hashes > 2 {
			t.Errorf("%s: the state was hashed %d times in %s of idling", g.name, hashes, idle)
		}
	}
}

// A change made on a node still leaves within about a quarter of a second,
// and the loop still sees what a command on the host writes into the same
// database (schild token): the look is the change counter of the file,
// which moves with a commit of any process.
func TestChangeAndCommandLineWriteStillLeaveQuickly(t *testing.T) {
	a, b := pair(t)
	a.h.WaitFor("both nodes are in service", func() bool { return a.h.App.InService() && b.h.App.InService() })
	time.Sleep(3 * time.Second)
	ctx := context.Background()

	// A setting stored by this process.
	start := time.Now()
	if err := a.h.App.Store.Put(ctx, "some_feature_v1", []byte(`{"on":true}`)); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 holds the value web-1 stored", func() bool {
		v, err := b.h.App.Store.Get(ctx, "some_feature_v1")
		return err == nil && string(v) == `{"on":true}`
	})
	t.Logf("a change of this process reached the other node after %s", time.Since(start))
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("a change took %s to reach the other node", d)
	}

	// The same through another handle on the file, as a command on the host
	// has it: this process is told nothing.
	cli, err := store.Open(a.h.App.Store.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	start = time.Now()
	if err := cli.Put(ctx, "some_feature_v1", []byte(`{"on":false}`)); err != nil {
		t.Fatal(err)
	}
	b.h.WaitFor("web-2 holds what the command line wrote on web-1", func() bool {
		v, err := b.h.App.Store.Get(ctx, "some_feature_v1")
		return err == nil && string(v) == `{"on":false}`
	})
	t.Logf("a write of the command line reached the other node after %s", time.Since(start))
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("a write of the command line took %s to reach the other node", d)
	}
}

// A hashed block that ends changes the state without a write: the hashes
// are computed again when it comes near its end, so two nodes never
// disagree for longer than a look.
func TestStateIsHashedAgainWhenABlockNearsItsEnd(t *testing.T) {
	a, b := pair(t)
	a.h.WaitFor("both nodes are in service", func() bool { return a.h.App.InService() && b.h.App.InService() })
	a.block("203.0.113.77", "S-ENDS-SOON", 14*time.Second)
	b.h.WaitFor("web-2 holds the block", func() bool { return b.blocked("203.0.113.77") == "S-ENDS-SOON" })
	with := func(g *groupNode) string { return g.h.App.StateHashes()["blocks"] }
	a.h.WaitFor("both hash the block", func() bool { return with(a) != "" && with(a) == with(b) })
	held := with(a)
	// Within its last five seconds the block leaves the hash on both.
	a.h.WaitFor("the hash of both moved when the block neared its end", func() bool { return with(a) != held && with(a) == with(b) })
}
