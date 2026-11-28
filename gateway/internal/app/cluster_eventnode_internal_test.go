package app

import (
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/contract/config"
)

// The events of a node of a group carry its name in the group, with the
// start of its node id; a single gateway carries node_name.
func TestEventSourceNamesTheMember(t *testing.T) {
	Parallel(t)
	cfg := &config.Site{NodeName: "schild"}
	cfg.Cluster.Name = "web-3"
	a := &App{}
	if got := a.eventNode(cfg); got != "schild" {
		t.Errorf("a single gateway: %q", got)
	}
	a.groupNodeID = "n-0123456789abcdef0123456789abcdef"
	if got := a.eventNode(cfg); got != "web-3.0123456789ab" {
		t.Errorf("a node named web-3: %q", got)
	}
	cfg.Cluster.Name = strings.Repeat("x", 60)
	if got := a.eventNode(cfg); len(got) != 48+1+12 {
		t.Errorf("a long name is not cut: %q", got)
	}
}
