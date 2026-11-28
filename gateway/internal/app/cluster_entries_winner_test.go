//go:build !release

package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/humancheck"
)

// A note of a change that is not the state of its entry any more is not
// applied: the record that won decides. (Third lab measurement, S2: a node
// noted the record of another node, published its own a moment later, which
// won, and then put the noted value in. It ran with a value no record held,
// its marks said "in step", and only the repair half a minute later ended
// it.)
func TestNoteOfARecordThatLostIsNotApplied(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	ctx := context.Background()
	const key = "future_winner_v1"
	if err := b.h.App.Store.Put(ctx, key, []byte(`{"mode":"won"}`)); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("web-1 holds the value web-2 set", func() bool { return sameJSON(kvOf(a, key), `{"mode":"won"}`) })
	b.h.WaitFor("the record of web-2 is the state", func() bool {
		v, origin := b.h.App.SharedEntryRecord(key, `o["mode"]`)
		return v == `"won"` && origin == b.h.App.Cluster.ID()
	})
	// The note of a record that lost against it, as the handler left it.
	rounds := b.h.App.SharedRounds()
	b.h.App.NoteSharedEntry(key, `o["mode"]`, []byte(`"lost"`))
	b.h.WaitFor("web-2 looked at the note", func() bool { return b.h.App.SharedRounds() > rounds })
	if got := kvOf(b, key); !sameJSON(got, `{"mode":"won"}`) {
		t.Fatalf("web-2 applied the value of a record that lost: %s", got)
	}
	time.Sleep(time.Second)
	if got := kvOf(a, key); !sameJSON(got, `{"mode":"won"}`) {
		t.Fatalf("web-1 holds %s", got)
	}
}

// Two nodes that write the same entries at the same moment end with the
// same values, those of the records that won, without a repair. Each value
// has many fields, so a node is still handing its fields over one by one
// when the fields of the other arrive: that is the moment of the fault
// above (a field of the other node is noted, the node's own record of it
// follows and wins, and the note used to be applied all the same).
func TestTwoNodesWritingOneEntryAtOnceEndWithTheWinner(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	ctx := context.Background()
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" is in step", func() bool { return g.h.App.InService() })
	}
	const keys, fields = 6, 60
	value := func(name string) []byte {
		m := map[string]string{}
		for f := 0; f < fields; f++ {
			m[fmt.Sprintf("f%02d", f)] = name
		}
		v, _ := json.Marshal(m)
		return v
	}
	for i := 0; i < keys; i++ {
		key := fmt.Sprintf("future_race_%d_v1", i)
		var wg sync.WaitGroup
		for _, g := range []*groupNode{a, b} {
			g := g
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := g.h.App.Store.Put(ctx, key, value(g.name)); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		time.Sleep(300 * time.Millisecond)
	}
	// Both hold, for every field, the value of its record, soon and by
	// themselves.
	agree := func() string {
		for i := 0; i < keys; i++ {
			key := fmt.Sprintf("future_race_%d_v1", i)
			var va, vb map[string]string
			if json.Unmarshal([]byte(kvOf(a, key)), &va) != nil || json.Unmarshal([]byte(kvOf(b, key)), &vb) != nil || len(va) != fields {
				return key + ": not there yet"
			}
			for f := 0; f < fields; f++ {
				name := fmt.Sprintf("f%02d", f)
				ra, _ := a.h.App.SharedEntryRecord(key, `o["`+name+`"]`)
				rb, _ := b.h.App.SharedEntryRecord(key, `o["`+name+`"]`)
				if ra == "" || ra != rb {
					return fmt.Sprintf("%s.%s: records %q and %q", key, name, ra, rb)
				}
				if want := strings.Trim(ra, `"`); va[name] != want || vb[name] != want {
					return fmt.Sprintf("%s.%s: the record says %s, web-1 holds %s, web-2 holds %s", key, name, want, va[name], vb[name])
				}
			}
		}
		return ""
	}
	// The wait is long for the race detector on a busy CI machine, which took
	// up to 12 s, and shorter than the repair, which must not have run.
	deadline := time.Now().Add(25 * time.Second)
	for agree() != "" && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if d := agree(); d != "" {
		t.Fatalf("after two nodes wrote the same entries at once: %s", d)
	}
	if n := a.h.App.StateRepairs() + b.h.App.StateRepairs(); n != 0 {
		t.Fatalf("%d repairs ran", n)
	}
}

// A change made on this node while a value of another node is written is a
// change of its own: it goes to the group. The round used to read the value
// back after it wrote it and to note what it read as in step, so a change
// that landed between the two stayed on this node only, and the repair put
// the value of the group back over it.
func TestChangeWhileAValueOfTheGroupIsWrittenLeaves(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	ctx := context.Background()
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" is in step", func() bool { return g.h.App.InService() })
	}
	const key = "future_meanwhile_v1"
	var once sync.Once
	// The reload runs after web-1 stored the value of web-2 and before it
	// reads the value back.
	a.h.App.OnSharedKey(key, func(ctx context.Context, v []byte) {
		once.Do(func() {
			if err := a.h.App.Store.Put(ctx, key, []byte(`{"mode":"meanwhile"}`)); err != nil {
				t.Error(err)
			}
		})
	})
	if err := b.h.App.Store.Put(ctx, key, []byte(`{"mode":"group"}`)); err != nil {
		t.Fatal(err)
	}
	for _, g := range []*groupNode{b, a} {
		g := g
		g.h.WaitFor(g.name+" holds the change web-1 made meanwhile", func() bool { return sameJSON(kvOf(g, key), `{"mode":"meanwhile"}`) })
	}
	if n := a.h.App.StateRepairs() + b.h.App.StateRepairs(); n != 0 {
		t.Fatalf("%d repairs ran", n)
	}
}

// The first keys of the browser check leave the node that writes them entry
// by entry. A node that holds only some of them so far still waits for the
// rest and does not add its own: one node writes the first keys.
func TestFirstKeysThatArriveInPartsAreNotMixed(t *testing.T) {
	// Nobody hands its own over for the length of this test.
	defer app.SetFirstKeysTimes(time.Minute, time.Minute)()
	a, b := pair(t)
	for _, g := range []*groupNode{a, b} {
		g := g
		g.h.WaitFor(g.name+" is in step", func() bool { return g.h.App.InService() })
	}
	hand := func(entry, value string) {
		t.Helper()
		if _, err := a.h.App.Cluster.Publish(contract.ClassSettings, contract.EntryID(humancheck.StoreKey, entry),
			contract.NewValue(entry, []byte(value), a.name), false, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	st := *a.h.App.HumanCheck.State()
	js := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	hand(`["prefix"]`, js(st.Prefix))
	b.h.WaitFor("web-2 took the first of the keys", func() bool { return b.h.App.HumanCheck.State().Prefix == st.Prefix })
	// Several looks of the loop later the rest of web-2 is still its own.
	time.Sleep(1500 * time.Millisecond)
	for _, entry := range []string{`["challenge_key"]`, `["clearance_key"]`, `["keys_rotated_at"]`} {
		if _, origin := b.h.App.SharedEntryRecord(humancheck.StoreKey, entry); origin != "" {
			t.Errorf("web-2 handed over %s of its own keys", entry)
		}
	}
	hand(`["challenge_key"]`, js(st.ChallengeKey))
	hand(`["clearance_key"]`, js(st.ClearanceKey))
	hand(`["keys_rotated_at"]`, js(st.KeysRotatedAt))
	b.h.WaitFor("web-2 runs the keys of web-1", func() bool {
		x := b.h.App.HumanCheck.State()
		return string(x.ChallengeKey) == string(st.ChallengeKey) && string(x.ClearanceKey) == string(st.ClearanceKey)
	})
}

// The first keys of the browser check are made once for a new cluster:
// three nodes set up by the same files and started one after the other
// come in step at about the same moment, each with keys of its own. One of
// them, the node that keeps the cluster's tasks, hands its keys over; the
// others take them and publish none. (Third lab measurement, S2: two nodes
// wrote them in the first second.)
func TestFirstKeysOfTheBrowserCheckAreWrittenByOneNode(t *testing.T) {
	// The wait is long here: under the race detector in CI a whole package
	// runs for minutes, and a keeper that comes in step after another node's
	// wait ended makes that node hand its own keys on as well (two writers).
	defer app.SetFirstKeysTimes(1500*time.Millisecond, 20*time.Second)()
	secretFile := filepath.Join(t.TempDir(), "cluster.secret")
	secret, err := cluster.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var nodes []*groupNode
	for i := 1; i <= 3; i++ {
		nodes = append(nodes, &groupNode{dir: t.TempDir(), addr: apptest.FreeAddr(t), name: fmt.Sprintf("web-%d", i)})
	}
	for _, g := range nodes {
		g.h = apptest.New(t, apptest.Options{Dir: g.dir, Extra: fmt.Sprintf("cluster: {enabled: true, name: %q, listen: %q, secret_file: %q, peers: [%q, %q, %q]}\n",
			g.name, g.addr, secretFile, nodes[0].addr, nodes[1].addr, nodes[2].addr)})
		if g.h.App.Cluster == nil {
			t.Fatalf("%s: no cluster node", g.name)
		}
	}
	for _, g := range nodes {
		g := g
		g.h.WaitFor(g.name+" is in service", func() bool { return g.h.App.InService() })
	}
	// Every node ends with the same keys.
	nodes[0].h.WaitFor("the three nodes run the same keys", func() bool {
		x := nodes[0].h.App.HumanCheck.State()
		for _, g := range nodes[1:] {
			y := g.h.App.HumanCheck.State()
			if x == nil || y == nil || string(x.ClearanceKey) != string(y.ClearanceKey) || string(x.ChallengeKey) != string(y.ChallengeKey) || x.Prefix != y.Prefix {
				return false
			}
		}
		return true
	})
	// And one node wrote every entry of them. Usually the keeper, the node
	// with the lowest id; on a slow machine (the race detector in CI) the
	// keeper may come in step after another node's wait ended and that node
	// handed on its own keys: either way it is one writer, never a mix.
	writer := ""
	for _, g := range nodes {
		recs, err := g.h.App.Cluster.State(contract.ClassSettings)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range recs {
			if thing, ok := contract.ThingOf(r.Class, r.ID); !ok || thing != humancheck.StoreKey {
				continue
			}
			n++
			if writer == "" {
				writer = r.Origin
			}
			if r.Origin != writer {
				t.Errorf("%s holds entries of the browser check from two writers (%s and %s)", g.name, writer, r.Origin)
			}
		}
		if n == 0 {
			t.Errorf("%s holds no record of the browser check", g.name)
		}
	}
	for _, g := range nodes {
		if n := g.h.App.StateRepairs(); n != 0 {
			t.Errorf("%s repaired %d times", g.name, n)
		}
	}
}
