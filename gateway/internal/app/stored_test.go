//go:build !release

package app_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/apptest"
	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
)

func hasReason(t *testing.T, h *apptest.Harness, code string) bool {
	t.Helper()
	st, b := h.API("GET", "/overview", nil)
	if st != 200 {
		t.Fatalf("overview: %d %s", st, b)
	}
	var ov dashboard.Overview
	if err := json.Unmarshal(b, &ov); err != nil {
		t.Fatal(err)
	}
	for _, r := range ov.Baseline.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

// TestDroppedSettingsAreVisible: settings stored by the dashboard that no
// longer fit schild.yaml are not applied at start. The gateway starts with
// the file's values and says so: in the overview (reason
// dashboard_settings_dropped), and to `schild status` and `schild
// preflight` (app.DroppedSettings). Saving settings again ends it (D78).
func TestDroppedSettingsAreVisible(t *testing.T) {
	dir := t.TempDir()
	h := apptest.New(t, apptest.Options{Mode: "observe", Dir: dir})
	h.Login()
	if hasReason(t, h, "dashboard_settings_dropped") {
		t.Fatal("reason without dropped settings")
	}
	ctx := context.Background()
	_, base, err := app.LoadConfig(filepath.Join(dir, "schild.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if n := app.DroppedSettings(ctx, h.App.Store, base); len(n) != 0 {
		t.Fatalf("notes without an overlay: %v", n)
	}
	if code, b := h.API("PATCH", "/settings", map[string]any{"retention": map[string]any{"raw_ip_days": 3}}); code != 200 {
		t.Fatalf("settings: %d %s", code, b)
	}
	if n := app.DroppedSettings(ctx, h.App.Store, base); len(n) != 0 {
		t.Fatalf("notes for a valid overlay: %v", n)
	}
	// D89: a mode an older version stored means nothing and drops nothing.
	if err := h.App.Store.Put(ctx, "settings_overlay_v1", []byte(`{"mode":"learn"}`)); err != nil {
		t.Fatal(err)
	}
	if n := app.DroppedSettings(ctx, h.App.Store, base); len(n) != 0 {
		t.Fatalf("notes for an old mode: %v", n)
	}
	// What an older version stored, or what a changed schild.yaml no longer
	// allows: here a retention outside the schema.
	if err := h.App.Store.Put(ctx, "settings_overlay_v1", []byte(`{"retention":{"raw_ip_days":999}}`)); err != nil {
		t.Fatal(err)
	}
	notes := app.DroppedSettings(ctx, h.App.Store, base)
	if len(notes) != 1 || !strings.Contains(notes[0], "NOT applied") || !strings.Contains(notes[0], "schild.yaml") {
		t.Fatalf("notes: %v", notes)
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}

	h2 := apptest.New(t, apptest.Options{Mode: "observe", Dir: dir})
	if !h2.App.SettingsDropped() || h2.App.Config().Mode != "observe" {
		t.Fatalf("after the restart: dropped %v, mode %q (want the file's observe)", h2.App.SettingsDropped(), h2.App.Config().Mode)
	}
	h2.Login()
	if !hasReason(t, h2, "dashboard_settings_dropped") {
		t.Fatal("the overview does not say that the settings were dropped")
	}
	if code, b := h2.API("PATCH", "/settings", map[string]any{"retention": map[string]any{"raw_ip_days": 3}}); code != 200 {
		t.Fatalf("settings: %d %s", code, b)
	}
	if h2.App.SettingsDropped() || hasReason(t, h2, "dashboard_settings_dropped") {
		t.Fatal("still reported after the settings were saved again")
	}
	if n := app.DroppedSettings(ctx, h2.App.Store, base); len(n) != 0 {
		t.Fatalf("notes after saving again: %v", n)
	}
}
