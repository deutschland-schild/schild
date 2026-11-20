//go:build linux

package nftfw

import (
	"net/netip"
	"testing"
)

func TestAfter(t *testing.T) {
	for in, want := range map[string]string{
		"2001:db8:1:2::/64":    "2001:db8:1:3::",
		"2001:db8:1:ffff::/64": "2001:db8:2::",
	} {
		got, ok := after(netip.MustParsePrefix(in))
		if !ok || got.String() != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
