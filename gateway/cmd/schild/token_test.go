//go:build !release

package main

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/apptest"
)

func TestTokenCLI(t *testing.T) {
	h := apptest.New(t, apptest.Options{})
	cfg := filepath.Join(h.Dir, "schild.yaml")
	data := h.App.Store.Path()
	data = filepath.Dir(data)
	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := runToken(append(args, "-config", cfg, "-data", data), &out, time.Now)
		return out.String(), err
	}
	if _, err := run("add", "--scope", "agent:read"); err == nil || !strings.Contains(err.Error(), "--expires") {
		t.Errorf("expiry must be required: %v", err)
	}
	if _, err := run("add", "--scope", "agent:read", "--expires", "400d"); err == nil {
		t.Error("400d accepted")
	}
	if _, err := run("add", "--scope", "admin", "--expires", "30d"); err == nil {
		t.Error("unknown scope accepted")
	}
	if _, err := run("add", "--scope", "crowdsec:write", "--expires", "30d", "--label", "x"); err == nil || !strings.Contains(err.Error(), "rules:write") {
		t.Errorf("the old scope crowdsec:write: %v", err)
	}
	if _, err := run("add", "--scope", "rules:approve", "--expires", "30d", "--label", "x"); err == nil {
		t.Error("D89: the scope rules:approve is gone")
	}
	for _, sc := range []string{"rules:write", "blocks:write"} {
		if _, err := run("add", "--scope", sc, "--expires", "30d"); err == nil || !strings.Contains(err.Error(), "--label") {
			t.Errorf("%s without a label: %v", sc, err)
		}
		if _, err := run("add", "--scope", sc, "--expires", "30d", "--label", "   "); err == nil {
			t.Errorf("%s with a blank label accepted", sc)
		}
		if _, err := run("add", "--scope", sc, "--expires", "30d", "--label", "Local agent"); err != nil {
			t.Errorf("%s: %v", sc, err)
		}
	}
	out, err := run("add", "--scope", "agent:read", "--expires", "90d", "--label", "Claude Code Laptop")
	if err != nil {
		t.Fatal(err)
	}
	tok := regexp.MustCompile(`sat1_[A-Za-z0-9_-]{43}`).FindString(out)
	id := regexp.MustCompile(`tok_[0-9a-f]{12}`).FindString(out)
	if tok == "" || id == "" {
		t.Fatalf("add output: %s", out)
	}
	list, _ := run("list")
	if !strings.Contains(list, id) || !strings.Contains(list, "active") || strings.Contains(list, tok) {
		t.Errorf("list: %s", list)
	}
	if _, err := run("revoke", id); err != nil {
		t.Fatal(err)
	}
	if _, err := run("revoke", id); err == nil {
		t.Error("second revoke accepted")
	}
	list, _ = run("list")
	if !strings.Contains(list, "revoked") {
		t.Errorf("list after revoke: %s", list)
	}
	if _, err := run("log"); err != nil {
		t.Errorf("log: %v", err)
	}
}
