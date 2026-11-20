package geo

import (
	"net/netip"
	"path/filepath"
	"testing"
)

func TestFixtureLookup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "geo.mmdb")
	if err := WriteFixture(p); err != nil {
		t.Fatal(err)
	}
	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Info{
		"203.0.113.42": {"NL", "Amsterdam", 64500, "Example Hosting B.V.", "hosting"},
		"198.51.100.7": {"DE", "Berlin", 64496, "Example Telekom", "residential"},
		"2001:db8::17": {"NL", "Amsterdam", 64500, "Example Hosting B.V.", "hosting"},
		"8.8.8.8":      Unknown,
		"100.64.1.1":   {"ZZ", "", 0, "", "cgnat"},
	}
	for ip, want := range cases {
		if got := db.Lookup(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: got %+v want %+v", ip, got, want)
		}
	}
	src, built, ok := db.Status()
	if !ok || src == "" || built.Year() != 2026 {
		t.Fatalf("status %q %v %v", src, built, ok)
	}
}

func TestMissingDB(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "nope.mmdb"))
	if err == nil {
		t.Skip("image geo db present on this machine")
	}
	if db.Loaded() {
		t.Fatal("should not be loaded")
	}
	if got := db.Lookup(netip.MustParseAddr("203.0.113.1")); got.Country != "ZZ" {
		t.Fatal(got)
	}
}

func TestClassify(t *testing.T) {
	a := netip.MustParseAddr("203.0.113.1")
	cases := map[string]string{"Hetzner Online GmbH": "hosting", "Deutsche Telekom AG": "residential", "Freie Universitaet Berlin": "education", "": "unknown", "Some Org": "unknown"}
	for org, want := range cases {
		if got := Classify(a, org); got != want {
			t.Errorf("%s: %s want %s", org, got, want)
		}
	}
}
