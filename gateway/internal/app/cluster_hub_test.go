//go:build !release

package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/hub"
)

// fakeHub stands for the hub source of a node: what it runs, and what it
// was handed.
type fakeHub struct {
	mu     sync.Mutex
	info   hub.IndexInfo
	gz     []byte
	has    bool
	refuse bool
	took   []hub.IndexInfo
}

func (f *fakeHub) SharedIndex() (hub.IndexInfo, []byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.info, f.gz, f.has
}

func (f *fakeHub) WantsIndex(in hub.IndexInfo) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.has || (in.Digest != f.info.Digest && in.FetchedAt > f.info.FetchedAt)
}

func (f *fakeHub) TakeIndex(_ context.Context, in hub.IndexInfo, gz []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.took = append(f.took, in)
	if f.refuse {
		return errors.New("refused by this node's checks")
	}
	f.info, f.gz, f.has = in, gz, true
	return nil
}

func (f *fakeHub) runs() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.info.Digest
}

// The node that downloaded a new hub index says so; the other fetches it
// from that node and takes it, once. An older one never comes back.
func TestGroupHandsOnTheHubIndex(t *testing.T) {
	a, b := pair(t)
	fa, fb := &fakeHub{}, &fakeHub{}
	a.h.App.SetHubShare(fa)
	b.h.App.SetHubShare(fb)
	a.h.WaitFor("the nodes reach each other", func() bool { return a.h.App.Cluster.Synced() && b.h.App.Cluster.Synced() })

	first := hub.IndexInfo{Digest: "aaaa", FetchedAt: "2026-11-22T10:00:00Z"}
	fa.mu.Lock()
	fa.info, fa.gz, fa.has = first, []byte("index one"), true
	fa.mu.Unlock()
	b.h.WaitFor("web-2 took the index web-1 downloaded", func() bool { return fb.runs() == "aaaa" })
	fb.mu.Lock()
	if string(fb.gz) != "index one" || len(fb.took) != 1 {
		t.Errorf("web-2 holds %q after %d takes", fb.gz, len(fb.took))
	}
	fb.mu.Unlock()

	// web-2 downloads a newer one: it goes the other way.
	second := hub.IndexInfo{Digest: "bbbb", FetchedAt: "2026-11-22T11:00:00Z"}
	fb.mu.Lock()
	fb.info, fb.gz = second, []byte("index two")
	fb.mu.Unlock()
	a.h.WaitFor("web-1 took the newer index of web-2", func() bool { return fa.runs() == "bbbb" })
	// Both keep saying what they run; nobody takes the older one back.
	b.h.WaitFor("both nodes run the newer index", func() bool { return fa.runs() == "bbbb" && fb.runs() == "bbbb" })
	fb.mu.Lock()
	takes := len(fb.took)
	fb.mu.Unlock()
	if takes != 1 {
		t.Errorf("web-2 took %d indexes, want only the first", takes)
	}
}

// A node whose own checks refuse the index of another keeps what it runs.
func TestGroupNodeKeepsItsHubRulesWhenItRefusesAnothers(t *testing.T) {
	a, b := pair(t)
	fa, fb := &fakeHub{}, &fakeHub{refuse: true}
	a.h.App.SetHubShare(fa)
	b.h.App.SetHubShare(fb)
	a.h.WaitFor("the nodes reach each other", func() bool { return a.h.App.Cluster.Synced() && b.h.App.Cluster.Synced() })
	fa.mu.Lock()
	fa.info, fa.gz, fa.has = hub.IndexInfo{Digest: "aaaa", FetchedAt: "2026-11-22T10:00:00Z"}, []byte("index one"), true
	fa.mu.Unlock()
	b.h.WaitFor("web-2 was handed the index", func() bool {
		fb.mu.Lock()
		defer fb.mu.Unlock()
		return len(fb.took) > 0
	})
	if fb.runs() != "" {
		t.Error("web-2 runs an index its checks refused")
	}
}
