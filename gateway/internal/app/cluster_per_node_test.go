//go:build !release

package app_test

import (
	"context"
	"slices"
	"sort"
	"testing"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// Everything set at runtime is shared in a group, except what describes one
// node. These tests make the next feature decide: a new table is shared or
// listed as per node with a reason, and a new key of the store is shared
// without anybody doing anything.

func TestEveryTableIsSharedOrPerNodeOnPurpose(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: "host_check: {}\n"})
	tables, err := h.App.Store.Tables(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	shared, perNode := store.SharedTables(), app.PerNodeTables()
	for _, name := range tables {
		_, listed := perNode[name]
		switch {
		case slices.Contains(shared, name) && listed:
			t.Errorf("table %s is shared and listed as per node: decide", name)
		case !slices.Contains(shared, name) && !listed:
			t.Errorf("table %s is new to the group: share it (store.sharedTables and a thing in sharedThings of cluster_state.go) or list it in perNodeTables (cluster_per_node.go) with the reason why it stays on one node", name)
		}
	}
	for name, reason := range perNode {
		if !slices.Contains(tables, name) {
			t.Errorf("perNodeTables names %s, which schild.db does not have", name)
		}
		if len(reason) < 20 {
			t.Errorf("perNodeTables: %s has no reason", name)
		}
	}
}

func TestEveryKeyOfTheStoreIsSharedOrPerNodeOnPurpose(t *testing.T) {
	h := apptest.New(t, apptest.Options{Extra: "host_check: {}\n"})
	h.Login()
	h.Visit("GET", "/", "203.0.113.5", "", "")
	keys, err := h.App.Store.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) < 2 {
		t.Fatalf("the test app wrote too few keys to say anything: %v", keys)
	}
	for _, k := range keys {
		if _, perNode := contract.PerNodeSettings[k]; !perNode && !contract.SettingKey(k) {
			t.Errorf("key %q of the store can not be shared in a group: name it in lower case with digits and _ (at most 64), or list it in contract.PerNodeSettings with the reason why it stays on one node", k)
		}
	}
	for k, reason := range contract.PerNodeSettings {
		if len(reason) < 20 {
			t.Errorf("contract.PerNodeSettings: %s has no reason", k)
		}
		if contract.SettingKey(k) {
			t.Errorf("a per-node key passes as a shared one: %s", k)
		}
	}
}

func TestWhatTheGatewaySharesIsWhatTheContractTakes(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	registered := h.App.SharedThingIDs()
	for _, class := range []string{contract.ClassSettings, contract.ClassAccess, contract.ClassLogins} {
		for _, id := range registered[class] {
			if thing, ok := contract.ThingOf(class, contract.EntryID(id, "x")); !ok || thing != id {
				t.Errorf("the gateway shares %s/%s, the contract refuses its records", class, id)
			}
		}
	}
	// The closed classes: exactly the contract's list.
	for _, class := range []string{contract.ClassAccess, contract.ClassLogins} {
		got, want := append([]string{}, registered[class]...), append([]string{}, contract.Things(class)...)
		sort.Strings(got)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Errorf("class %s: the gateway shares %v, the contract names %v", class, got, want)
		}
	}
	// Every named setting has its own codec and reload in the gateway.
	for _, id := range contract.Things(contract.ClassSettings) {
		if !slices.Contains(registered[contract.ClassSettings], id) {
			t.Errorf("the contract names the setting %s, the gateway has no thing for it", id)
		}
	}
	// A shared table is a thing of a closed class.
	var things []string
	for _, class := range []string{contract.ClassAccess, contract.ClassLogins} {
		things = append(things, registered[class]...)
	}
	if len(things) != len(store.SharedTables()) {
		t.Errorf("%d shared tables, %d things of access and logins", len(store.SharedTables()), len(things))
	}
}
