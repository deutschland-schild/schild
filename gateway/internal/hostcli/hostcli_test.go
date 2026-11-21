package hostcli

import (
	"os"
	"path/filepath"
	"testing"
)

// The request file of "Jetzt prüfen" is removed before anything can fail: a
// file left behind would make schild-check.path start the unit in a loop.
func TestCheckRemovesTriggerBeforeConfigError(t *testing.T) {
	dir := t.TempDir()
	trigger := filepath.Join(dir, "request")
	cfg := filepath.Join(dir, "schild.yaml")
	if err := os.WriteFile(trigger, []byte("now\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("config_version: [broken\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if code := Check("schild check", []string{"-config", cfg, "-trigger-file", trigger}); code != ExitCheckError {
		t.Fatalf("exit %d, want %d", code, ExitCheckError)
	}
	if _, err := os.Stat(trigger); !os.IsNotExist(err) {
		t.Errorf("request file still there: %v", err)
	}
}
