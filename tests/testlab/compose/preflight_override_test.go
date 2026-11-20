package composecfg

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestPreflightOverride: every schild, schild-lab and schild-relay service of
// the test lab runs with TEST ONLY keys and the test CA, so it must set the
// D24 override SCHILD_ALLOW_TEST_KEYS=1 or it refuses to start. `schild
// front` holds no keys and needs none.
func TestPreflightOverride(t *testing.T) {
	images := map[string]bool{"schild:dev": true, "schild-lab:dev": true, "schild-relay:dev": true}
	for _, f := range []string{"docker-compose.t0.yaml", "docker-compose.t1.yaml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			Services map[string]struct {
				Image       string            `yaml:"image"`
				Command     []string          `yaml:"command"`
				Environment map[string]string `yaml:"environment"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		n := 0
		for name, s := range c.Services {
			if !images[s.Image] || (len(s.Command) > 0 && s.Command[0] == "front") {
				continue
			}
			n++
			if s.Environment["SCHILD_ALLOW_TEST_KEYS"] != "1" {
				t.Errorf("%s: service %s (%s) lacks SCHILD_ALLOW_TEST_KEYS=1", f, name, s.Image)
			}
		}
		t.Logf("%s: %d schild services checked", f, n)
		if n == 0 {
			t.Errorf("%s: no schild services found", f)
		}
	}
}
