//go:build !release

package app_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
)

func replacedKeys(t *testing.T, g *groupNode) map[string][]byte {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(g.clusterDir(), "cluster.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT k, v FROM replaced`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][]byte{}
	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatal(err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// A node that already holds its own value for a shared setting and joins a
// group holding a different value takes the group's value and keeps its own in
// cluster.db (table replaced).
func TestJoinKeepsReplacedOwnValue(t *testing.T) {
	a, b := pair(t)
	ctx := context.Background()

	a.h.WaitFor("web-1 is in service", func() bool { return a.h.App.InService() })
	if err := a.h.App.Store.Put(ctx, "custom_join_test_v1", []byte(`{"choice":"from-group"}`)); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("web-1 published its key", func() bool {
		rec, err := a.h.App.Cluster.Get(contract.ClassSettings, contract.EntryID("custom_join_test_v1", `o["choice"]`))
		return err == nil && rec != nil
	})
	b.h.WaitFor("web-2 received the key", func() bool {
		v, err := b.h.App.Store.Get(ctx, "custom_join_test_v1")
		return err == nil && strings.Contains(string(v), `"from-group"`)
	})

	// Prepare web-3 with its own conflicting value before it joins the group.
	c := &groupNode{
		dir:        t.TempDir(),
		addr:       apptest.FreeAddr(t),
		name:       "web-3",
		secretFile: a.secretFile,
		peers:      []string{a.addr, b.addr},
	}
	pre := apptest.New(t, apptest.Options{Dir: c.dir})
	if err := pre.App.Store.Put(ctx, "custom_join_test_v1", []byte(`{"choice":"from-joiner"}`)); err != nil {
		t.Fatal(err)
	}
	if err := pre.Stop(); err != nil {
		t.Fatal(err)
	}

	// Now start web-3 as a member of the group.
	c.start(t)
	c.h.WaitFor("web-3 took the group's value", func() bool {
		v, err := c.h.App.Store.Get(ctx, "custom_join_test_v1")
		return err == nil && strings.Contains(string(v), `"from-group"`)
	})

	// Kept after the value of the group was written.
	wantKey := `settings/custom_join_test_v1 o["choice"]`
	c.h.WaitFor("web-3 kept its own value in cluster.db (table replaced)", func() bool {
		return string(replacedKeys(t, c)[wantKey]) == `"from-joiner"`
	})
}

// When two fresh nodes start a new group, the non-keeper takes the first
// browser-check keys from the keeper and keeps its own replaced keys in
// cluster.db (table replaced).
func TestFirstBrowserCheckKeysKeepReplacedValues(t *testing.T) {
	a, b := pair(t)
	b.h.WaitFor("both nodes share browser-check keys", func() bool {
		x, y := a.h.App.HumanCheck.State(), b.h.App.HumanCheck.State()
		return x != nil && y != nil && len(x.ClearanceKey) > 0 &&
			string(x.ClearanceKey) == string(y.ClearanceKey) &&
			string(x.ChallengeKey) == string(y.ChallengeKey)
	})

	// The node that took the other's keys must have kept its replaced
	// human_check_v1 keys in cluster.db.
	hasHumanCheckReplaced := func(g *groupNode) bool {
		for k := range replacedKeys(t, g) {
			if strings.HasPrefix(k, "settings/human_check_v1 ") {
				return true
			}
		}
		return false
	}
	b.h.WaitFor("one node kept its replaced human_check_v1 keys in cluster.db", func() bool {
		return hasHumanCheckReplaced(a) || hasHumanCheckReplaced(b)
	})
}
