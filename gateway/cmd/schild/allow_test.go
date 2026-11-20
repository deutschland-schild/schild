//go:build !release

package main

import (
	"context"
	"flag"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

func TestParseInterleaved(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	cfg := fs.String("config", "", "")
	mine := fs.Bool("mine", false, "")
	pos := parseInterleaved(fs, []string{"rm", "ID", "-config", "/x.yaml", "--mine", "--", "-tail"})
	if !reflect.DeepEqual(pos, []string{"rm", "ID", "-tail"}) || *cfg != "/x.yaml" || !*mine {
		t.Fatalf("pos %q config %q mine %v", pos, *cfg, *mine)
	}
}

// TestAllowRmHonoursConfig (D36 fix round 2, re-measurement C): flags after
// the ID of `schild allow rm ID` count; -config was ignored there and
// /etc/schild/schild.yaml opened instead.
func TestAllowRmHonoursConfig(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	cfg := filepath.Join(h.Dir, "schild.yaml")
	data := filepath.Dir(h.App.Store.Path())
	if err := cmdAllow([]string{"203.0.113.7", "-ttl", "24h", "-config", cfg, "-data", data}); err != nil {
		t.Fatal(err)
	}
	list := func() []store.AllowEntry {
		st, err := store.Open(filepath.Join(data, "schild.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		es, err := st.ListAllow(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return es
	}
	var id string
	for _, e := range list() {
		if e.IP == "203.0.113.7" {
			id = e.ID
		}
	}
	if id == "" {
		t.Fatal("entry not stored")
	}
	if err := cmdAllow([]string{"rm", id, "-config", cfg, "-data", data}); err != nil {
		t.Fatal(err)
	}
	for _, e := range list() {
		if e.ID == id {
			t.Fatal("entry still there after allow rm ID -config FILE")
		}
	}
}
