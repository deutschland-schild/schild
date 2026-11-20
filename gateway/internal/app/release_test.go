//go:build release

package app_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/app"
)

const releaseYAML = `config_version: 0
profile: test
mode: observe
node_name: rel
upstream: { url: "http://127.0.0.1:9" }
storage: { path: %s }
`

// Release builds refuse the test profile (E5, D05). Test keys are refused by
// the preflight before app.New runs (contract/preflight, the agent keys of
// host_check); the gateway holds no other key (D72).
func TestReleaseRefusesTestProfile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "schild.yaml")
	if err := os.WriteFile(p, []byte(strings.Replace(releaseYAML, "%s", filepath.Join(dir, "data"), 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.New(context.Background(), app.Options{ConfigPath: p, NoListeners: true}); err == nil || !strings.Contains(err.Error(), "test") {
		t.Fatalf("test profile accepted in a release build: %v", err)
	}
}
