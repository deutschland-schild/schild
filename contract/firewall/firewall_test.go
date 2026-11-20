package firewall

import (
	"net/netip"
	"testing"
	"time"
)

func TestClient(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":         "203.0.113.7",
		"203.0.113.7/32":      "203.0.113.7",
		"::ffff:203.0.113.7":  "203.0.113.7",
		"2001:db8:1:2::/64":   "2001:db8:1:2::/64",
		"2001:db8:1:2:3::/64": "2001:db8:1:2::/64",
		"2001:db8::1":         "2001:db8::1",
		"203.0.113.0/24":      "",
		"2001:db8::/48":       "",
		"fe80::1%eth0":        "",
		"not an address":      "",
	} {
		got, ok := Client(in)
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v, want %q", in, got, ok, want)
		}
	}
	if ClientOf(netip.MustParsePrefix("203.0.113.7/32")) != "203.0.113.7" || ClientOf(netip.MustParsePrefix("2001:db8:1:2::/64")) != "2001:db8:1:2::/64" {
		t.Fatal("ClientOf")
	}
}

func TestRevisionAndValid(t *testing.T) {
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	a := []Block{{Client: "203.0.113.7", Until: now.Add(time.Hour)}, {Client: "2001:db8:1:2::/64", Until: now.Add(-time.Minute)}}
	b := []Block{{Client: "203.0.113.7", Until: now.Add(2 * time.Hour)}, {Client: "2001:db8:1:2::/64", Until: now.Add(-time.Minute)}}
	if Revision(a) == Revision(b) || Revision(a) != Revision(append([]Block{}, a...)) || len(Revision(a)) != 16 {
		t.Fatal("revision")
	}
	if got := Running(a, now); len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("running %v", got)
	}
	if !(SyncResponse{Revision: Revision(a), Blocks: a}).Valid() || (SyncResponse{Revision: "x", Blocks: []Block{{Client: "203.0.113.0/24"}}}).Valid() || (SyncResponse{}).Valid() {
		t.Fatal("valid")
	}
}
