package main

import (
	"os/exec"
	"strings"
	"testing"
)

// forbidden are packages schild-agent must never link: the proxy (Caddy),
// the WAF (Coraza, CRS) and the gateway's own parts (app, dashboard,
// gateway side of the agent listener, embedded UI, store). An app VM gets
// the server check and the agent, nothing that could listen or filter.
var forbidden = []string{
	"github.com/caddyserver/",
	"github.com/corazawaf/",
	"github.com/deutschland-schild/schild/gateway/internal/app",
	"github.com/deutschland-schild/schild/gateway/internal/caddymod",
	"github.com/deutschland-schild/schild/gateway/internal/waf",
	"github.com/deutschland-schild/schild/gateway/internal/dashboard",
	"github.com/deutschland-schild/schild/gateway/internal/webui",
	"github.com/deutschland-schild/schild/gateway/internal/hosts",
	"github.com/deutschland-schild/schild/gateway/internal/store",
	"modernc.org/sqlite",
}

// TestNoProxyDependencies fails when schild-agent links Caddy, Coraza, the
// WAF or the dashboard (go list -deps, both build tag sets).
func TestNoProxyDependencies(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not in PATH")
	}
	for _, tags := range []string{"", "release"} {
		out, err := exec.Command("go", "list", "-deps", "-tags", tags, ".").CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps (tags %q): %v\n%s", tags, err, out)
		}
		deps := strings.Fields(string(out))
		if len(deps) < 10 {
			t.Fatalf("go list -deps returned %d packages", len(deps))
		}
		var hostagent bool
		for _, d := range deps {
			for _, f := range forbidden {
				if d == f || strings.HasPrefix(d, f) && (strings.HasSuffix(f, "/") || strings.HasPrefix(d, f+"/")) {
					t.Errorf("schild-agent (tags %q) links %s", tags, d)
				}
			}
			hostagent = hostagent || d == "github.com/deutschland-schild/schild/gateway/internal/hostagent"
		}
		if !hostagent {
			t.Errorf("schild-agent (tags %q) does not link internal/hostagent", tags)
		}
	}
}
