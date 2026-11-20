package gate

import (
	"net/netip"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/store"
)

// MVP-26 finding 6: an incident folds a whole /64, so its unblock frees the /64.
func TestExceptionCoversTheIPv6Client(t *testing.T) {
	e := NewExceptions()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	e.Add(netip.MustParseAddr("2001:db8:1:2::1"), []string{"crs"}, now.Add(time.Hour))
	if !e.Has(netip.MustParseAddr("2001:db8:1:2:ffff::9"), "crs", now) {
		t.Fatal("another address of the same /64 stayed blocked")
	}
	if e.Has(netip.MustParseAddr("2001:db8:1:3::1"), "crs", now) {
		t.Fatal("another /64 got through")
	}
	// Running (the agent API's "released" check) keys the client the same way:
	// an agent must not block an address of a /64 the operator released.
	if !e.Running(netip.MustParseAddr("2001:db8:1:2:ffff::9"), now) || !e.Running(netip.MustParseAddr("2001:db8:1:2::1"), now) {
		t.Fatal("a released /64 is not running for its addresses")
	}
	if e.Running(netip.MustParseAddr("2001:db8:1:3::1"), now) || e.Running(netip.MustParseAddr("2001:db8:1:2::1"), now.Add(2*time.Hour)) {
		t.Fatal("Running outside the /64 or after the expiry")
	}
	v4 := NewExceptions()
	v4.Add(netip.MustParseAddr("203.0.113.7"), []string{"crs"}, now.Add(time.Hour))
	if !v4.Has(netip.MustParseAddr("::ffff:203.0.113.7"), "crs", now) || v4.Has(netip.MustParseAddr("203.0.113.8"), "crs", now) {
		t.Fatal("IPv4 exception")
	}
	loaded := NewExceptions()
	loaded.Load([]store.Exception{{IP: "2001:db8:1:2::1", Sources: []string{"crs"}, Expires: now.Add(time.Hour)}})
	if !loaded.Has(netip.MustParseAddr("2001:db8:1:2::2"), "crs", now) {
		t.Fatal("a stored exception does not cover the /64")
	}
}
