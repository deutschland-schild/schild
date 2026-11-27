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
)

// The host command reloads the Caddyfile of the running gateway (D106), and
// says why when the gateway refuses.
func TestIngressReloadRunningGateway(t *testing.T) {
	const site = "{\n\tauto_https off\n}\nhttp://shop.example:{port} {\n\tschild\n\treverse_proxy {backend}\n}\n"
	h := apptest.New(t, apptest.Options{Dir: shortDir(t), Listeners: true, Caddyfile: site})
	data := filepath.Dir(h.App.Store.Path())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	if err := reloadIngress(ctx, data, false, &out); err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("without a control path: %v", err)
	}
	srv, err := h.App.ServeControl(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if err := reloadIngress(ctx, data, false, &out); err != nil || !strings.Contains(out.String(), "Caddyfile unchanged: 1 websites") {
		t.Fatalf("%v %s", err, out.String())
	}
	out.Reset()
	f := filepath.Join(h.Dir, "Caddyfile")
	text, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	neu := strings.ReplaceAll(string(text), "shop.example", "neu.example")
	if err := os.WriteFile(f, []byte(string(text)+neu[strings.Index(neu, "http://"):]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadIngress(ctx, data, false, &out); err != nil || !strings.Contains(out.String(), "Caddyfile reloaded: 2 websites") {
		t.Fatalf("%v %s", err, out.String())
	}
	if err := os.WriteFile(f, []byte(strings.ReplaceAll(string(text), "\tschild\n", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadIngress(ctx, data, false, &out); err == nil || !strings.Contains(err.Error(), "the running Caddyfile stays") || !strings.Contains(err.Error(), "without schild") {
		t.Fatalf("refused: %v", err)
	}
}
