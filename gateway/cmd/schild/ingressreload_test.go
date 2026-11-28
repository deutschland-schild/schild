//go:build !release

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/control"
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

// The host command sends a Caddyfile to the running gateway, which writes
// and loads it; a refused one leaves the file as it was.
func TestIngressLoadRunningGateway(t *testing.T) {
	const site = "{\n\tauto_https off\n}\nhttp://shop.example:{port} {\n\tschild\n\treverse_proxy {backend}\n}\n"
	h := apptest.New(t, apptest.Options{Dir: shortDir(t), Listeners: true, Caddyfile: site})
	data := filepath.Dir(h.App.Store.Path())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := filepath.Join(h.Dir, "Caddyfile")
	text, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	neu := strings.ReplaceAll(string(text), "shop.example", "neu.example")
	two := string(text) + neu[strings.Index(neu, "http://"):]
	var out bytes.Buffer
	if err := loadIngress(ctx, data, strings.NewReader(two), control.Request{}, false, &out); err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("without a control path: %v", err)
	}
	srv, err := h.App.ServeControl(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if err := loadIngress(ctx, data, strings.NewReader(two), control.Request{}, false, &out); err != nil || !strings.Contains(out.String(), "Caddyfile written and loaded: 2 websites") {
		t.Fatalf("%v %s", err, out.String())
	}
	if now, _ := os.ReadFile(f); string(now) != two {
		t.Fatalf("the file holds %q", now)
	}
	bad := strings.ReplaceAll(two, "\tschild\n", "")
	if err := loadIngress(ctx, data, strings.NewReader(bad), control.Request{}, false, &out); err == nil || !strings.Contains(err.Error(), "the running Caddyfile stays") || !strings.Contains(err.Error(), "without schild") {
		t.Fatalf("refused: %v", err)
	}
	if now, _ := os.ReadFile(f); string(now) != two {
		t.Fatalf("a refused Caddyfile changed the file: %q", now)
	}
	if err := loadIngress(ctx, data, strings.NewReader(strings.Repeat("#", 8<<20+1)), control.Request{}, false, &out); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("too large: %v", err)
	}
}

// -json: one object per call, with a code for a program to act on.
func TestIngressLoadJSON(t *testing.T) {
	const site = "{\n\tauto_https off\n}\nhttp://shop.example:{port} {\n\tschild\n\treverse_proxy {backend}\n}\n"
	h := apptest.New(t, apptest.Options{Dir: shortDir(t), Listeners: true, Caddyfile: site})
	data := filepath.Dir(h.App.Store.Path())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := filepath.Join(h.Dir, "Caddyfile")
	text, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	neu := strings.ReplaceAll(string(text), "shop.example", "neu.example")
	two := string(text) + neu[strings.Index(neu, "http://"):]
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	call := func(in string, req control.Request) (ingressAnswer, error) {
		t.Helper()
		var out bytes.Buffer
		err := loadIngress(ctx, data, strings.NewReader(in), req, true, &out)
		var a ingressAnswer
		if strings.Count(out.String(), "\n") != 1 || json.Unmarshal(out.Bytes(), &a) != nil || a.Warnings == nil {
			t.Fatalf("not one JSON object with a list of warnings: %q", out.String())
		}
		return a, err
	}
	if a, err := call(two, control.Request{}); err == nil || a.Result != "failed" || a.Error == nil || a.Error.Code != "unavailable" {
		t.Fatalf("without a control path: %+v %v", a, err)
	}
	srv, err := h.App.ServeControl(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if a, err := call(two, control.Request{Check: true}); err != nil || a.Result != "accepted" || a.Websites != 2 || a.SHA256 != sum(string(text)) {
		t.Fatalf("check: %+v %v", a, err)
	}
	if now, _ := os.ReadFile(f); string(now) != string(text) {
		t.Fatal("a check changed the file")
	}
	if a, err := call(two, control.Request{}); err != nil || a.Result != "loaded" || a.Websites != 2 || a.SHA256 != sum(two) || a.Error != nil {
		t.Fatalf("load: %+v %v", a, err)
	}
	if a, err := call(two, control.Request{}); err != nil || a.Result != "unchanged" || a.SHA256 != sum(two) {
		t.Fatalf("again: %+v %v", a, err)
	}
	for code, bad := range map[string]string{
		"check_refused":     strings.ReplaceAll(two, "\tschild\n", ""),
		"invalid_caddyfile": "{\n",
		"needs_restart":     two + "http://other.example:1 {\n\tschild\n\treverse_proxy 127.0.0.1:9\n}\n",
	} {
		for _, check := range []bool{false, true} {
			a, err := call(bad, control.Request{Check: check})
			if err == nil || a.Result != "refused" || a.Error == nil || a.Error.Code != code || a.Error.Message == "" || a.SHA256 != sum(two) {
				t.Fatalf("%s (check %v): %+v %v", code, check, a, err)
			}
		}
	}
	if a, err := call(strings.Repeat("#", 8<<20+1), control.Request{}); err == nil || a.Result != "refused" || a.Error.Code != "invalid_caddyfile" {
		t.Fatalf("too large: %+v %v", a, err)
	}
	// The reload answers in the same form.
	var out bytes.Buffer
	if err := callIngress(ctx, data, "reload", control.Request{Op: control.OpIngressReload, Check: true}, true, &out); err != nil || !strings.Contains(out.String(), `"result":"accepted"`) {
		t.Fatalf("reload -check: %v %s", err, out.String())
	}
}
