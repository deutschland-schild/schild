//go:build !release

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/access"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/control"
)

func TestLockSpec(t *testing.T) {
	if s := lockSpec(nil, nil, nil, false, ""); s.Scope != access.ScopeSite {
		t.Fatalf("site: %+v", s)
	}
	if s := lockSpec([]string{"/wp-admin/*"}, nil, nil, false, ""); s.Scope != access.ScopePaths {
		t.Fatalf("paths: %+v", s)
	}
	if _, err := readPassword(strings.NewReader("kurz\n")); err == nil {
		t.Fatal("short password")
	}
	if pw, err := readPassword(strings.NewReader("korrekt-pferd\r\n")); err != nil || pw != "korrekt-pferd" {
		t.Fatalf("password %q %v", pw, err)
	}
}

// D56: schild lock on, status and off through the running gateway.
func TestLockRunningGateway(t *testing.T) {
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
	var out bytes.Buffer
	set := lockSpec(nil, nil, []string{"198.51.100.0/24"}, false, "")
	set.Password = "korrekt-pferd"
	if err := lockCall(ctx, data, control.Request{Op: control.OpAccessSet, Website: "default", Access: set}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "default: whole website") || !strings.Contains(out.String(), "needs: password and from addresses 198.51.100.0/24") {
		t.Fatalf("%s", out.String())
	}
	if r := h.Visit("GET", "/", "203.0.113.5", "", ""); r.StatusCode != 503 {
		t.Fatalf("locked: %d", r.StatusCode)
	}
	err = lockCall(ctx, data, control.Request{Op: control.OpAccessSet, Website: "nope.example", Access: set}, &out)
	if err == nil || !strings.Contains(err.Error(), "unknown website") {
		t.Fatalf("unknown website: %v", err)
	}
	out.Reset()
	if err := lockCall(ctx, data, control.Request{Op: control.OpAccessRemove, Website: "default"}, &out); err != nil || !strings.Contains(out.String(), "access lock off for default") {
		t.Fatalf("off: %v %s", err, out.String())
	}
	if r := h.Visit("GET", "/", "203.0.113.5", "", ""); r.StatusCode != 200 {
		t.Fatalf("after off: %d", r.StatusCode)
	}
	out.Reset()
	if err := lockCall(ctx, data, control.Request{Op: control.OpAccessList}, &out); err != nil || !strings.Contains(out.String(), "no access lock in force") {
		t.Fatalf("status: %v %s", err, out.String())
	}
}
