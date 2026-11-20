// Package composecfg exists only to validate the example schild.yaml and
// lab.yaml files that the compose stacks mount, against the frozen contract
// config loaders. A drifted or invalid config fails here rather than at
// container start (where the schild images are not yet available).
package composecfg

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/deutschland-schild/schild/contract/config"
)

func TestSiteConfigsValid(t *testing.T) {
	matches, err := filepath.Glob("config/*/*/schild.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no schild.yaml configs found")
	}
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if _, err := config.ParseSite(b); err != nil {
			t.Errorf("%s: invalid: %v", p, err)
		}
	}
}

func TestLabConfigsValid(t *testing.T) {
	matches, err := filepath.Glob("config/*/lab-*/lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no lab.yaml configs found")
	}
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if _, err := config.ParseLab(b); err != nil {
			t.Errorf("%s: invalid: %v", p, err)
		}
	}
}

// TestT12FrontProxyTopology guards the T12 wiring (finding: the stripper
// pointed straight at schild, so killing schild exercised no fail-open path).
// The front proxy must reach schild over loopback in a shared network
// namespace: only then does a dead schild process mean "connection refused"
// (fail-open) and a hung one a timeout (503), as on a real host.
func TestT12FrontProxyTopology(t *testing.T) {
	b, err := os.ReadFile("docker-compose.t0.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Services map[string]struct {
			Profiles    []string          `yaml:"profiles"`
			Command     []string          `yaml:"command"`
			NetworkMode string            `yaml:"network_mode"`
			Environment map[string]string `yaml:"environment"`
			Volumes     []string          `yaml:"volumes"`
			Restart     string            `yaml:"restart"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	st, front, sch := c.Services["stripper-t12"], c.Services["front-api"], c.Services["schild-t12"]
	for name, p := range map[string][]string{"stripper-t12": st.Profiles, "front-api": front.Profiles, "schild-t12": sch.Profiles} {
		if len(p) != 1 || p[0] != "t12" {
			t.Errorf("%s: profiles %v, want [t12] (the default stack stays unchanged)", name, p)
		}
	}
	if st.Environment["STRIPPER_UPSTREAM"] != "http://front-api:8090" {
		t.Errorf("stripper-t12 upstream %q, want the front proxy", st.Environment["STRIPPER_UPSTREAM"])
	}
	cmd := strings.Join(front.Command, " ")
	if !strings.HasPrefix(cmd, "front ") || !strings.Contains(cmd, "-schild http://127.0.0.1:8080") || !strings.Contains(cmd, "-app http://site-api:8080") {
		t.Errorf("front-api command %q: want `schild front` to schild on loopback, app site-api", cmd)
	}
	if !strings.Contains(cmd, "-access-dir /var/lib/schild") || !slices.Contains(front.Volumes, "data-api-t12:/var/lib/schild:ro") {
		t.Errorf("front-api %q, volumes %v: want schild-t12's storage read-only as -access-dir (D71: else it never fails open)", cmd, front.Volumes)
	}
	if sch.NetworkMode != "service:front-api" {
		t.Errorf("schild-t12 network_mode %q, want service:front-api (shared namespace)", sch.NetworkMode)
	}
	if sch.Restart != "no" {
		t.Errorf("schild-t12 restart %q: a restart policy would hide the outage T12 measures", sch.Restart)
	}
	if !slices.Contains(sch.Volumes, "./config/t0/api-t12:/etc/schild:ro") {
		t.Errorf("schild-t12 volumes %v: want config/t0/api-t12", sch.Volumes)
	}
	var site struct {
		Ingress struct {
			TrustedProxies []string `yaml:"trusted_proxies"`
		} `yaml:"ingress"`
		Listen struct {
			Proxy string `yaml:"proxy"`
		} `yaml:"listen"`
	}
	sb, err := os.ReadFile("config/t0/api-t12/schild.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(sb, &site); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(site.Ingress.TrustedProxies, "127.0.0.1/32") || !slices.Contains(site.Ingress.TrustedProxies, "10.66.1.7/32") {
		t.Errorf("schild-t12 trusted_proxies %v: want the front (127.0.0.1) and stripper-t12", site.Ingress.TrustedProxies)
	}
	if !strings.HasSuffix(site.Listen.Proxy, ":8080") {
		t.Errorf("schild-t12 listens on %q, the front expects :8080", site.Listen.Proxy)
	}
}
