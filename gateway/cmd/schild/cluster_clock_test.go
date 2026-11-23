package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/gateway/internal/cluster"
)

// `schild cluster status` names a member whose clock is five seconds or
// more off, while the note of the running node is fresh (the spec's "reports
// a skew over 5 s"; finding F4 of the lab measurement).
func TestClusterStatusNamesAClockThatIsOff(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	member := func(id, name string, clock time.Duration, at time.Time) cluster.MemberStatus {
		return cluster.MemberStatus{Entry: contract.Entry{ID: id, Member: contract.Member{Name: name, Role: contract.RoleGateway, Address: "192.0.2.1:8790"}}, Clock: clock, ClockAt: at}
	}
	st := &cluster.Status{Group: "g-1", Node: "n-1", Records: map[string]int{}, Counters: map[string]uint64{}, Seen: now, Members: []cluster.MemberStatus{
		{Entry: contract.Entry{ID: "n-1", Member: contract.Member{Name: "web-1", Role: contract.RoleGateway}}, Self: true},
		member("n-2", "web-2", 90*time.Second, now.Add(-10*time.Second)),
		member("n-3", "web-3", -30*time.Second, now.Add(-10*time.Second)),
		member("n-4", "web-4", 3*time.Second, now.Add(-10*time.Second)),
		member("n-5", "web-5", 90*time.Second, now.Add(-10*time.Minute)),
	}}
	var out bytes.Buffer
	printClusterStatus(&out, st, &config.Site{}, now)
	text := out.String()
	for _, want := range []string{"Clock: web-2 is 1m30s ahead of this node", "Clock: web-3 is 30s behind this node"} {
		if !strings.Contains(text, want) {
			t.Errorf("status lacks %q:\n%s", want, text)
		}
	}
	for _, not := range []string{"Clock: web-4", "Clock: web-5"} {
		if strings.Contains(text, not) {
			t.Errorf("status names %q (under five seconds, or an old note):\n%s", not, text)
		}
	}
}
