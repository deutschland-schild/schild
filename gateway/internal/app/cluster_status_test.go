//go:build !release

package app_test

import (
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/app"
)

// The config version a node tells its group leaves out what differs from
// node to node by design, and nothing else.
func TestGroupConfigVersionLeavesOutWhatDiffersByDesign(t *testing.T) {
	one := "node_name: web-1\nmode: autoblock\ncluster:\n  enabled: true\n  listen: \"10.0.0.1:8790\"\n  peers: [\"10.0.0.1:8790\", \"10.0.0.2:8790\"]\n"
	two := "cluster:\n  peers: [\"10.0.0.1:8790\", \"10.0.0.2:8790\"]\n  advertise: \"10.0.0.2:8790\"\n  enabled: true\n  listen: \"0.0.0.0:8790\"\nmode: autoblock\nnode_name: web-2\n"
	v := app.GroupConfigVersion([]byte(one), "rules")
	if len(v) != 64 {
		t.Fatalf("version %q", v)
	}
	if got := app.GroupConfigVersion([]byte(two), "rules"); got != v {
		t.Error("two nodes of one deployment (other name, listen, advertise, order of keys) have different config versions")
	}
	for name, other := range map[string]string{
		"another mode":  "node_name: web-1\nmode: observe\ncluster:\n  enabled: true\n  listen: \"10.0.0.1:8790\"\n  peers: [\"10.0.0.1:8790\", \"10.0.0.2:8790\"]\n",
		"another peers": "node_name: web-1\nmode: autoblock\ncluster:\n  enabled: true\n  listen: \"10.0.0.1:8790\"\n  peers: [\"10.0.0.1:8790\"]\n",
	} {
		if app.GroupConfigVersion([]byte(other), "rules") == v {
			t.Errorf("%s: same config version", name)
		}
	}
	if app.GroupConfigVersion([]byte(one), "other rules") == v {
		t.Error("other rules.d: same config version")
	}
	// A file that does not parse still has a version, and not the one of
	// another file.
	if a, b := app.GroupConfigVersion([]byte("a: [1"), ""), app.GroupConfigVersion([]byte("a: [2"), ""); a == b || len(a) != 64 {
		t.Errorf("unparsable files: %q %q", a, b)
	}
}
