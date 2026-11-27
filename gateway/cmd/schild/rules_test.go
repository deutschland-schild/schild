//go:build !release

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/control"
)

// The host command syncs rules.d of the running gateway (D46, D73), and says
// why when the new set does not build.
func TestRulesSyncRunningGateway(t *testing.T) {
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	data := filepath.Dir(h.App.Store.Path())
	release, err := control.Lock(data)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := h.App.ServeControl(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	dir := filepath.Join(h.Dir, "rules.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "a.conf"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	write(`SecRule REQUEST_URI "@beginsWith /x" "id:1000001,phase:1,deny"` + "\n")
	if err := syncRules(ctx, data, "local", "deploy", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "local rules synced: 1 rules") {
		t.Fatalf("%s", out.String())
	}
	out.Reset()
	if err := syncRules(ctx, data, "local", "deploy", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "unchanged") {
		t.Fatalf("%s", out.String())
	}
	write(`SecRule REQUEST_URI "@nosuchoperator x" "id:1000002,deny"` + "\n")
	err = syncRules(ctx, data, "local", "deploy", &out)
	if err == nil || !strings.Contains(err.Error(), "the running rules stay") {
		t.Fatalf("%v", err)
	}
	write(`SecRule REQUEST_URI "@beginsWith /x" "id:942100,phase:1,deny"` + "\n")
	err = syncRules(ctx, data, "local", "deploy", &out)
	if err == nil || !strings.Contains(err.Error(), "range of crs") {
		t.Fatalf("a local rule in the range of crs: %v", err)
	}
	if err := syncRules(ctx, data, "crs", "deploy", &out); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("crs has no sync: %v", err)
	}
}

func TestRulesSyncNoGateway(t *testing.T) {
	err := syncRules(context.Background(), shortDir(t), "local", "deploy", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "next start") {
		t.Fatalf("%v", err)
	}
}
