//go:build !release

package app_test

import (
	"slices"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/dashboard"

	"github.com/deutschland-schild/schild/contract/config"
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

func TestVitalsOfAnotherNodeAreBounded(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	f := func(v float64) *float64 { return &v }
	if app.CleanVitals(nil, now) != nil || app.CleanVitals(&dashboard.GroupVitals{Service: "fine"}, now) != nil {
		t.Fatal("vitals without a known service state were kept")
	}
	got := app.CleanVitals(&dashboard.GroupVitals{At: "1999-01-01T00:00:00Z", Service: "draining", StartedAt: "2030-01-01T00:00:00Z", RequestsPerS: -4,
		StoppedShare: f(1.5), LatencyP95MS: f(-1), CPUUsage: f(0.4), MemoryUsedRatio: f(-0.1), DiskUsedRatio: f(1)}, now)
	if got == nil {
		t.Fatal("vitals dropped")
	}
	// The time is this node's, a start in the future is dropped, values outside their range are null.
	if got.At != dashboard.Stamp(now) || got.StartedAt != "" || got.RequestsPerS != 0 || got.StoppedShare != nil || got.LatencyP95MS != nil || got.MemoryUsedRatio != nil {
		t.Fatalf("out of range values kept: %+v", got)
	}
	if got.Service != "draining" || got.CPUUsage == nil || *got.CPUUsage != 0.4 || got.DiskUsedRatio == nil || *got.DiskUsedRatio != 1 {
		t.Fatalf("valid values lost: %+v", got)
	}
}

func TestGroupStatusShowsHowEveryGatewayIsDoing(t *testing.T) {
	a, b := pair(t)
	// web-1 names itself at once and web-2 within the next word of web-2.
	a.h.WaitFor("web-1 shows the vitals of both gateways", func() bool {
		st := a.h.App.GroupStatus()
		n := 0
		for _, m := range st.Members {
			if m.Vitals != nil && m.Vitals.Service == "ready" && m.Vitals.StartedAt != "" {
				n++
			}
		}
		return n == 2
	})
	// Both run on one machine: the clocks agree, and the overview names nothing of the group.
	a.h.WaitFor("web-1 knows the clock of web-2", func() bool {
		for _, m := range a.h.App.GroupStatus().Members {
			if m.Name == b.name && m.ClockSkewMS != nil {
				return *m.ClockSkewMS > -2000 && *m.ClockSkewMS < 2000
			}
		}
		return false
	})
	// (The two test nodes differ in their files, so a config drift is named rightly.)
	for _, code := range []string{"cluster_peers_unreachable", "cluster_clock_skew"} {
		if slices.Contains(a.h.App.ClusterReasons(), code) {
			t.Errorf("overview of web-1 carries %s although the pair is in step", code)
		}
	}
	// A node that leaves traffic says so to the others.
	b.h.App.LeaveTraffic()
	a.h.WaitFor("web-1 shows web-2 draining", func() bool {
		for _, m := range a.h.App.GroupStatus().Members {
			if m.Name == b.name {
				return m.Vitals != nil && m.Vitals.Service == "draining"
			}
		}
		return false
	})
}

// With the same files on every node (cluster.secret_file) a node takes its
// host name in the group, so the nodes differ in the dashboard although
// node_name is the same; cluster.name always wins, and by hand node_name stays.
func TestMemberNameOfANode(t *testing.T) {
	site := func(name, secret string) *config.Site {
		s := &config.Site{NodeName: "schild-1"}
		s.Cluster.Name, s.Cluster.SecretFile = name, secret
		return s
	}
	for _, c := range []struct {
		name, secret, host, want string
	}{
		{"", "/etc/schild/cluster.secret", "Web-3.example.net", "web-3"},
		{"", "/etc/schild/cluster.secret", "not a name", "schild-1"},
		{"", "/etc/schild/cluster.secret", "", "schild-1"},
		{"", "", "web-3", "schild-1"},
		{"gw-a", "/etc/schild/cluster.secret", "web-3", "gw-a"},
	} {
		if got := site(c.name, c.secret).MemberName(c.host); got != c.want {
			t.Errorf("MemberName(name %q, secret %q, host %q) = %q, want %q", c.name, c.secret, c.host, got, c.want)
		}
	}
}

func TestOverviewNamesAGatewayThatIsNotReached(t *testing.T) {
	a, b := pair(t)
	a.h.WaitFor("web-1 reaches web-2", func() bool { return a.h.App.GroupStatus().State == "active" })
	if err := b.h.Stop(); err != nil {
		t.Fatal(err)
	}
	a.h.WaitFor("the overview of web-1 says a gateway is not reached", func() bool { return slices.Contains(a.h.App.ClusterReasons(), "cluster_peers_unreachable") })
}
