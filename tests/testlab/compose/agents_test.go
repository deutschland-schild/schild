package composecfg

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/deutschland-schild/schild/testlab/internal/hostcanary"
)

type overlay struct {
	Services map[string]struct {
		Image       string            `yaml:"image"`
		Hostname    string            `yaml:"hostname"`
		Profiles    []string          `yaml:"profiles"`
		NetworkMode string            `yaml:"network_mode"`
		Networks    any               `yaml:"networks"`
		Environment map[string]string `yaml:"environment"`
		Volumes     []any             `yaml:"volumes"`
	} `yaml:"services"`
}

func readYAML(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func netNames(n any) []string {
	switch v := n.(type) {
	case []any:
		var out []string
		for _, x := range v {
			out = append(out, x.(string))
		}
		return out
	case map[string]any:
		var out []string
		for k := range v {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	return nil
}

// TestAgentOverlayWiring guards the MVP-11 agent lab: app VMs only on the
// sites network (no route to labs), the gateway report dir read-only, the
// canary values in sync with internal/hostcanary, profiles keep the default
// stack unchanged.
func TestAgentOverlayWiring(t *testing.T) {
	var c overlay
	readYAML(t, "docker-compose.t1.agents.yaml", &c)
	for _, name := range []string{"app-vm", "app-revoked", "app-unenrolled"} {
		s, ok := c.Services[name]
		if !ok {
			t.Fatalf("service %s missing", name)
		}
		if got := netNames(s.Networks); !reflect.DeepEqual(got, []string{"sites"}) {
			t.Errorf("%s networks %v: app VMs sit on sites only (never federation: agents never talk to labs)", name, got)
		}
		if !slices.Equal(s.Profiles, []string{"agents"}) {
			t.Errorf("%s profiles %v, want [agents]", name, s.Profiles)
		}
		if s.Environment["APP_SECRET_TOKEN"] != hostcanary.SecretEnv {
			t.Errorf("%s: APP_SECRET_TOKEN is not the env secret canary", name)
		}
	}
	if h := c.Services["app-vm"].Hostname; h != hostcanary.Hostname {
		t.Errorf("app-vm hostname %q, want the canary %q", h, hostcanary.Hostname)
	}
	if gw := c.Services["gw-host-check"]; gw.NetworkMode != "none" {
		t.Errorf("gw-host-check network_mode %q: the check needs no network", gw.NetworkMode)
	}
	var ro bool
	for _, v := range c.Services["schild-api"].Volumes {
		if s, ok := v.(string); ok && s == "hostcheck-api:/var/lib/schild/host-check:ro" {
			ro = true
		}
	}
	if !ro {
		t.Error("schild-api must mount the host report dir read-only")
	}

	b, err := os.ReadFile("../dockerfiles/app-vm.Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "ARG CANARY_PKG="+hostcanary.Package+"\n") {
		t.Errorf("app-vm.Dockerfile: CANARY_PKG is not %s", hostcanary.Package)
	}
	for path, secret := range map[string]string{
		"../dockerfiles/app-vm/rootfs/var/www/html/wp-config.php": hostcanary.SecretDB,
		"../dockerfiles/app-vm/dotenv.canary":                     hostcanary.SecretDotEnv, // copied to /var/www/html/.env
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), secret) {
			t.Errorf("%s does not plant %s", path, secret)
		}
	}
}

// TestAgentConfigInSync: config/t1/api-agents is config/t1/api plus host_check.
func TestAgentConfigInSync(t *testing.T) {
	var base, agents map[string]any
	readYAML(t, "config/t1/api/schild.yaml", &base)
	readYAML(t, "config/t1/api-agents/schild.yaml", &agents)
	hc, ok := agents["host_check"].(map[string]any)
	if !ok {
		t.Fatal("api-agents has no host_check")
	}
	delete(agents, "host_check")
	if !reflect.DeepEqual(base, agents) {
		t.Error("config/t1/api-agents/schild.yaml drifted from config/t1/api/schild.yaml (only host_check may differ)")
	}
	a := hc["agents"].(map[string]any)
	if a["enabled"] != true || a["listen"] != "0.0.0.0:8790" {
		t.Errorf("agents %v: want enabled on 0.0.0.0:8790", a)
	}
}
