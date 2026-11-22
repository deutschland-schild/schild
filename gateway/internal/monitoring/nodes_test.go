package monitoring

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
)

const (
	nodeSelf  = "n-00000000000000000000000000000001"
	nodeOther = "n-00000000000000000000000000000002"
	nodeThird = "n-00000000000000000000000000000003"
)

// groupMonitor is a monitor that is a node of a group: its own 1 min ring
// holds the last hour, and it holds the same hour of one other member.
func groupMonitor(t *testing.T, end time.Time) *Monitor {
	t.Helper()
	m, err := New(Config{StoragePath: t.TempDir(), Keep: config.MonitoringKeep{TenSecondsHours: 6, MinuteHours: 48, TenMinuteDays: 14}}, end)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	m.SetSelf(nodeSelf, "web-1")
	var theirs []cm.MetricBucket
	for i := 1; i <= 60; i++ {
		start := end.Add(-time.Duration(i) * time.Minute)
		b := heavyBucket(start, cm.Res1m, 60, i)
		if err := m.store.put(m.rings[1], start, &b); err != nil {
			t.Fatal(err)
		}
		theirs = append(theirs, heavyBucket(start, cm.Res1m, 60, i))
	}
	if _, err := m.PutNodeBuckets(nodeOther, "web-2", cm.Res1m, theirs, end); err != nil {
		t.Fatal(err)
	}
	return m
}

func requestsOf(t *testing.T, v NodeView, from, to, now time.Time) int64 {
	t.Helper()
	c, err := v.Totals("", from, to, now)
	if err != nil || c == nil {
		t.Fatalf("totals: %v %v", c, err)
	}
	return c.Requests
}

func TestGroupAddsUpTheNodesAndShowsEachAlone(t *testing.T) {
	end := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	m := groupMonitor(t, end)
	from := end.Add(-30 * time.Minute)
	all, _ := m.Nodes("")
	self, err := m.Nodes(nodeSelf)
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.Nodes(nodeOther)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Nodes(nodeThird); err == nil {
		t.Fatal("a node that is no member was accepted")
	}
	own, theirs, sum := requestsOf(t, self, from, end, end), requestsOf(t, other, from, end, end), requestsOf(t, all, from, end, end)
	if own == 0 || own != theirs || sum != own+theirs {
		t.Fatalf("requests: own %d, other %d, group %d", own, theirs, sum)
	}
	// The monitor itself answers for the group.
	if c, _ := m.Totals("", from, end, end); c == nil || c.Requests != sum {
		t.Fatalf("the monitor does not answer for the group: %+v", c)
	}

	// Distinct clients are never added: the group shows the larger estimate.
	clients := func(v NodeView) float64 {
		res, err := v.Series(SeriesQuery{Metrics: []string{"traffic.clients_unique"}, From: from, To: end, Resolution: "1m"}, end)
		if err != nil {
			t.Fatal(err)
		}
		var top float64
		for _, p := range res.Series[0].Values {
			if p != nil && *p > top {
				top = *p
			}
		}
		return top
	}
	if a, g := clients(self), clients(all); a == 0 || g != a {
		t.Fatalf("distinct clients were added across nodes: one node %v, group %v", a, g)
	}

	// Host values are those of one machine: a node shows its own.
	cpu := func(v NodeView) int {
		res, err := v.Series(SeriesQuery{Metrics: []string{"server.cpu_usage:avg"}, From: from, To: end, Resolution: "1m"}, end)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, p := range res.Series[0].Values {
			if p != nil {
				n++
			}
		}
		return n
	}
	if cpu(other) == 0 {
		t.Fatal("the host values of another node are not shown for that node")
	}

	sc := all.Scope(from, end, end)
	if sc == nil || sc.Node != "all" || len(sc.Nodes) != 2 || !sc.Nodes[0].Self || !sc.ClientsAtLeast || len(sc.PartialNodes) != 0 {
		t.Fatalf("scope of the group: %+v", sc)
	}
	if sc := other.Scope(from, end, end); sc.Node != nodeOther || len(sc.Nodes) != 1 || sc.ClientsAtLeast {
		t.Fatalf("scope of one node: %+v", sc)
	}
}

func TestGroupNamesANodeWhoseHistoryEndsEarly(t *testing.T) {
	end := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	m := groupMonitor(t, end)
	// Ten minutes later this gateway has written on, the other member was not reached.
	later := end.Add(10 * time.Minute)
	for i := 0; i < 10; i++ {
		start := end.Add(time.Duration(i) * time.Minute)
		b := heavyBucket(start, cm.Res1m, 60, i+1)
		if err := m.store.put(m.rings[1], start, &b); err != nil {
			t.Fatal(err)
		}
	}
	all := m.all()
	sc := all.Scope(end.Add(-30*time.Minute), later, later)
	if len(sc.PartialNodes) != 1 || sc.PartialNodes[0].Node != nodeOther || sc.PartialNodes[0].Until == nil || *sc.PartialNodes[0].Until != ts(end) {
		t.Fatalf("the node whose history ends early is not named: %+v", sc.PartialNodes)
	}
	// A span that ends before its history does lacks nothing.
	if sc := all.Scope(end.Add(-30*time.Minute), end.Add(-5*time.Minute), later); len(sc.PartialNodes) != 0 {
		t.Fatalf("a node is named partial for a span it covers: %+v", sc.PartialNodes)
	}
	// The points the member has not handed over are marked partial.
	res, err := all.Series(SeriesQuery{Metrics: []string{"traffic.requests:rate"}, From: end.Add(-5 * time.Minute), To: later, Resolution: "1m"}, later)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Partial) == 0 || res.Partial[0] || !res.Partial[len(res.Partial)-2] {
		t.Fatalf("partial flags of the points: %v", res.Partial)
	}
}

func TestGroupBoundsWhatAnotherNodeHandsOver(t *testing.T) {
	end := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	m := groupMonitor(t, end)
	ahead := heavyBucket(end.Add(time.Hour), cm.Res1m, 60, 1)
	off := heavyBucket(end.Add(-90*time.Second), cm.Res1m, 60, 1) // no start of a minute
	old := heavyBucket(end.Add(-100*24*time.Hour), cm.Res1m, 60, 1)
	newest, err := m.PutNodeBuckets(nodeOther, "web-2", cm.Res1m, []cm.MetricBucket{ahead, off, old}, end)
	if err != nil || !newest.IsZero() {
		t.Fatalf("buckets outside the ring were taken: %v %v", newest, err)
	}
	if _, err := m.PutNodeBuckets("../../etc", "x", cm.Res1m, nil, end); err == nil {
		t.Fatal("a name that is no node id was taken")
	}
	if _, err := m.PutNodeBuckets(nodeSelf, "x", cm.Res1m, nil, end); err == nil {
		t.Fatal("buckets under this gateway's own id were taken")
	}
}

func TestGroupDropsTheHistoryOfARemovedMember(t *testing.T) {
	end := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	m := groupMonitor(t, end)
	file := filepath.Join(m.nodesPath(), nodeOther+".db")
	if _, err := os.Stat(file); err != nil {
		t.Fatal(err)
	}
	m.OpenNodes(map[string]string{nodeThird: "web-3"})
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("the history of a removed member is still on disk: %v", err)
	}
	if _, err := m.Nodes(nodeOther); err == nil {
		t.Fatal("a removed member can still be asked for")
	}
	if _, err := m.Nodes(nodeThird); err != nil {
		t.Fatalf("a new member has no history store: %v", err)
	}
}

func TestSingleGatewayHasNoScopeAndNoNodes(t *testing.T) {
	end := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	m := filledMonitor(t, end)
	if sc := m.all().Scope(end.Add(-time.Hour), end, end); sc != nil {
		t.Fatalf("a single gateway answers with a scope: %+v", sc)
	}
	if _, err := m.Nodes(nodeSelf); err == nil {
		t.Fatal("a single gateway knows a node id")
	}
	if _, err := os.Stat(m.nodesPath()); !os.IsNotExist(err) {
		t.Fatal("a single gateway made a directory for other nodes")
	}
}
