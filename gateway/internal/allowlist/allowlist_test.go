package allowlist

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/store"
)

func TestMatch(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	l := New()
	l.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.99")}, nil
	}
	errs := l.Set([]store.AllowEntry{
		{ID: "a", IP: "192.0.2.10", Label: "admin", Level: NoBlock, Expires: "never"},
		{ID: "b", CIDR: "203.0.113.0/24", Label: "office", Level: NoBlock, Expires: "2026-10-27T00:00:00Z"},
		{ID: "c", IP: "203.0.113.5", Label: "monitor", Level: BypassWAF, Expires: "never"},
		{ID: "d", Host: "home.dyndns.example", Label: "home", Level: NoBlock, Expires: "never"},
		{ID: "e", IP: "2001:db8::1", Label: "expired", Level: NoBlock, Expires: "2026-10-01T00:00:00Z"},
		{ID: "bad", IP: "nope", Label: "x", Level: NoBlock, Expires: "never"},
	})
	if len(errs) != 1 {
		t.Fatalf("errs %v", errs)
	}
	l.RefreshDNS(context.Background())
	cases := map[string]string{
		"192.0.2.10":    NoBlock,
		"203.0.113.77":  NoBlock,
		"203.0.113.5":   BypassWAF,
		"198.51.100.99": NoBlock,
		"2001:db8::1":   "",
		"8.8.8.8":       "",
	}
	for ip, want := range cases {
		if got, _ := l.Match(netip.MustParseAddr(ip), now); got != want {
			t.Errorf("%s: got %q want %q", ip, got, want)
		}
	}
	if got, _ := l.Match(netip.MustParseAddr("203.0.113.77"), now.Add(24*time.Hour)); got != "" {
		t.Error("expired range still matches")
	}
}

func TestValidate(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	e, errs := Validate(Input{IP: "203.0.113.42", Label: "Meine IP", Level: NoBlock, TTL: "7d"}, now)
	if len(errs) != 0 || e.Expires != "2026-11-02T12:00:00Z" {
		t.Fatalf("%v %+v", errs, e)
	}
	for _, in := range []Input{
		{CIDR: "0.0.0.0/0", Label: "x", Level: NoBlock},
		{CIDR: "::/0", Label: "x", Level: NoBlock},
		{IP: "1.2.3.4", CIDR: "1.2.3.0/24", Label: "x", Level: NoBlock},
		{IP: "1.2.3.4", Label: "", Level: NoBlock},
		{IP: "1.2.3.4", Label: "x", Level: "allow"},
		{IP: "1.2.3.4", Label: "x", Level: NoBlock, TTL: "1y"},
		{Host: "not a host", Label: "x", Level: NoBlock},
	} {
		if _, errs := Validate(in, now); len(errs) == 0 {
			t.Errorf("accepted %+v", in)
		}
	}
}

// Set and RefreshDNS run on different goroutines (allowlist reload, DNS
// ticker). A refresh replaces the resolved addresses, it never changes a map
// another goroutine may still read (go test -race).
func TestRefreshDNSWhileSet(t *testing.T) {
	l := New()
	l.Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.99")}, nil
	}
	entries := []store.AllowEntry{
		{ID: "a", Host: "home.dyndns.example", Label: "home", Level: NoBlock, Expires: "never"},
		{ID: "b", Host: "office.dyndns.example", Label: "office", Level: NoBlock, Expires: "never"},
	}
	l.Set(entries)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			l.RefreshDNS(context.Background())
		}
	}()
	for i := 0; i < 2000; i++ {
		l.Set(entries)
	}
	<-done
	l.Set(entries)
	if got, _ := l.Match(netip.MustParseAddr("198.51.100.99"), time.Now()); got != NoBlock {
		t.Fatalf("resolved host lost: %q", got)
	}
}
