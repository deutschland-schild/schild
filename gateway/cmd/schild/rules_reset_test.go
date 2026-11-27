//go:build !release

package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/control"
	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// D43, D73: schild rules reset crowdsec; with schild running, the host command goes through the control path
// and the image's rules run at once.
func TestCrowdsecResetRunningGateway(t *testing.T) {
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	data := filepath.Dir(h.App.Store.Path())
	if err := h.App.Store.Put(context.Background(), crowdsec.StoreKey, []byte(`{"set":{}}`)); err != nil {
		t.Fatal(err)
	}
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
	var out bytes.Buffer
	if err := resetCrowdsec(context.Background(), "test-node", data, "deploy", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "through the running schild") || !strings.Contains(out.String(), "set image") {
		t.Fatalf("%s", out.String())
	}
	if _, err := h.App.Store.Get(context.Background(), crowdsec.StoreKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stored set still there: %v", err)
	}
}

// D43: with schild stopped, the command drops the row itself.
func TestCrowdsecResetStopped(t *testing.T) {
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	data := filepath.Dir(h.App.Store.Path())
	if err := h.App.Store.Put(context.Background(), crowdsec.StoreKey, []byte(`{"set":{}}`)); err != nil {
		t.Fatal(err)
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := resetCrowdsec(context.Background(), "test-node", data, "deploy", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "schild is stopped") {
		t.Fatalf("%s", out.String())
	}
	st, err := store.Open(filepath.Join(data, "schild.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Get(context.Background(), crowdsec.StoreKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stored set still there: %v", err)
	}
}

// With a gateway that does not answer, nothing changes.
func TestCrowdsecResetRefused(t *testing.T) {
	h := apptest.New(t, apptest.Options{Dir: shortDir(t)})
	data := filepath.Dir(h.App.Store.Path())
	if err := h.App.Store.Put(context.Background(), crowdsec.StoreKey, []byte(`{"set":{}}`)); err != nil {
		t.Fatal(err)
	}
	release, err := control.Lock(data)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := resetCrowdsec(context.Background(), "test-node", data, "deploy", &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err %v, want refused", err)
	}
	if _, err := h.App.Store.Get(context.Background(), crowdsec.StoreKey); err != nil {
		t.Fatalf("row gone although refused: %v", err)
	}
}
