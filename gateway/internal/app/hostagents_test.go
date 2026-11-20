package app

import (
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/keys"
)

// D60b: app servers with schild-agent are not part of the first gateway
// version; the server check of the gateway itself stays.
func TestCheckHostAgents(t *testing.T) {
	on, off := true, false
	env := func(v string) func(string) string { return func(string) string { return v } }
	cases := []struct {
		name    string
		hc      *config.HostCheck
		env     string
		release bool
		ok      bool
	}{
		{"no host_check", nil, "", false, true},
		{"server check only", &config.HostCheck{Agents: config.AgentConfig{Enabled: &off}}, "", false, true},
		{"agents on", &config.HostCheck{Agents: config.AgentConfig{Enabled: &on}}, "", false, false},
		{"agent keys", &config.HostCheck{Agents: config.AgentConfig{Enabled: &off, Keys: []config.AgentKey{{KeyID: "a"}}}}, "", false, false},
		{"test switch", &config.HostCheck{Agents: config.AgentConfig{Enabled: &on}}, "1", false, true},
		// D77: release builds ignore the test switch.
		{"test switch in a release build", &config.HostCheck{Agents: config.AgentConfig{Enabled: &on}}, "1", true, false},
		{"agent keys with the switch in a release build", &config.HostCheck{Agents: config.AgentConfig{Enabled: &off, Keys: []config.AgentKey{{KeyID: "a"}}}}, "1", true, false},
		{"server check only in a release build", &config.HostCheck{Agents: config.AgentConfig{Enabled: &off}}, "1", true, true},
	}
	for _, c := range cases {
		err := checkHostAgents(&config.Site{HostCheck: c.hc}, env(c.env), c.release)
		if c.release && err != nil && !strings.Contains(err.Error(), "ignored in release builds") {
			t.Errorf("%s: message %q does not say the switch is ignored", c.name, err)
		}
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "not part of this version") {
			t.Errorf("%s: message %q", c.name, err)
		}
	}
}

// The exported check follows the build: the switch works only without
// -tags release.
func TestCheckHostAgentsFollowsBuild(t *testing.T) {
	on := true
	cfg := &config.Site{HostCheck: &config.HostCheck{Agents: config.AgentConfig{Enabled: &on}}}
	err := CheckHostAgents(cfg, func(string) string { return "1" })
	if (err != nil) != keys.Release {
		t.Fatalf("release build %v: %v", keys.Release, err)
	}
}
