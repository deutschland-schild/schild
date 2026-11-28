//go:build !release

package app_test

import (
	"context"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/control"
)

// A node that starts without logins generates a first-run setup code. Once
// logins arrive from the cluster, that code must be cleared so a later
// reset-password on another node cannot re-enable it. A local reset on the
// node itself must still work.
func TestClusterLoginsClearStartupSetupCode(t *testing.T) {
	app.Parallel(t)
	a, b := pair(t)
	ctx := context.Background()

	codeB := b.h.App.SetupCode()
	if codeB == "" {
		t.Fatal("web-2 started without a first-run setup code")
	}

	// Set up the dashboard password on web-1 and wait until web-2 takes the user.
	a.h.Login()
	b.h.WaitFor("web-2 received logins from cluster", func() bool {
		return b.h.App.Store.HasUsers(ctx)
	})

	// Reset dashboard access on web-1; web-2 receives the user removal.
	if _, _, err := a.h.App.Dashboard.ResetAccess(ctx, "operator"); err != nil {
		t.Fatalf("reset on web-1: %v", err)
	}
	b.h.WaitFor("web-2 cleared users after reset on web-1", func() bool {
		return !b.h.App.Store.HasUsers(ctx)
	})

	// web-2's old startup setup code must no longer work.
	if resp := b.h.App.Control(ctx, control.Request{Op: control.OpSetupCode}); resp.OK {
		t.Fatalf("web-2 control still returns a first-run setup code: %q", resp.SetupCode)
	}
	code, body := b.h.API("POST", "/auth/setup", map[string]string{
		"password":   "new-password-long-enough",
		"setup_code": codeB,
	})
	if code != 403 {
		t.Fatalf("POST /auth/setup on web-2 with stale startup code: status %d, want 403 (body: %s)", code, body)
	}

	// A local reset on web-2 itself must still work with its fresh reset code.
	resetCodeB, _, err := b.h.App.Dashboard.ResetAccess(ctx, "operator")
	if err != nil {
		t.Fatalf("reset on web-2: %v", err)
	}
	code, body = b.h.API("POST", "/auth/setup", map[string]string{
		"password":   "local-reset-password-123",
		"setup_code": resetCodeB,
	})
	if code != 200 {
		t.Fatalf("POST /auth/setup on web-2 with local reset code: status %d, want 200 (body: %s)", code, body)
	}
}
