//go:build !release

package app_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// The sync reads a value, puts the entries of another node into it and
// stores the whole value. A change made on this node between the read and
// the write (the dashboard, a command on the host) was written over and
// gone on every node: the marks of the node said the entry never was.
func TestAChangeMadeWhileTheSyncWritesAValueIsKept(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	ctx := context.Background()
	const key = "lost_update_v1"
	put := func(g *groupNode, v string) {
		if err := g.h.App.Store.Put(ctx, key, []byte(v)); err != nil {
			t.Error(err)
		}
	}
	put(a, `{"x":1,"y":1}`)
	b.h.WaitFor("web-2 holds the value of web-1", func() bool { return sameJSON(kvOf(b, key), `{"x":1,"y":1}`) })

	// web-2 is about to write the change of web-1 when a field is set on it.
	var ran atomic.Int32
	b.h.App.BeforeSharedWrite(func(thing string) {
		if strings.HasSuffix(thing, "/"+key) && ran.Add(1) == 1 {
			put(b, `{"x":1,"y":1,"z":3}`)
		}
	})
	put(a, `{"x":2,"y":1}`)

	want := `{"x":2,"y":1,"z":3}`
	for _, g := range []*groupNode{b, a} {
		g.h.WaitFor(g.name+" holds the change of web-1 and the one made on web-2 meanwhile", func() bool { return sameJSON(kvOf(g, key), want) })
	}
	if ran.Load() == 0 {
		t.Fatal("the sync of web-2 never wrote the value: the test did not reach the moment it is about")
	}
}

// The same for a table the group shares: the sync replaces its rows as a
// whole, and a row written meanwhile was gone.
func TestARowWrittenWhileTheSyncReplacesATableIsKept(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	ctx := context.Background()
	add := func(g *groupNode, id, ip string) {
		e := &store.AllowEntry{ID: id, IP: ip, Level: "no_block", Expires: "never", CreatedAt: time.Now(), Source: "dashboard"}
		if err := g.h.App.Store.AddAllow(ctx, e); err != nil {
			t.Error(err)
		}
	}
	holds := func(g *groupNode, ids ...string) bool {
		rows, err := g.h.App.Store.ListAllow(ctx)
		if err != nil {
			return false
		}
		have := map[string]bool{}
		for _, r := range rows {
			have[r.ID] = true
		}
		for _, id := range ids {
			if !have[id] {
				return false
			}
		}
		return true
	}
	add(a, "al_first", "198.51.100.1")
	b.h.WaitFor("web-2 holds the entry of web-1", func() bool { return holds(b, "al_first") })

	var ran atomic.Int32
	b.h.App.BeforeSharedWrite(func(thing string) {
		if strings.HasSuffix(thing, "/allowlist") && ran.Add(1) == 1 {
			add(b, "al_meanwhile", "198.51.100.3")
		}
	})
	add(a, "al_second", "198.51.100.2")

	for _, g := range []*groupNode{b, a} {
		g.h.WaitFor(g.name+" holds the entries of web-1 and the one made on web-2 meanwhile", func() bool {
			return holds(g, "al_first", "al_second", "al_meanwhile")
		})
	}
	if ran.Load() == 0 {
		t.Fatal("the sync of web-2 never replaced the table: the test did not reach the moment it is about")
	}
}
