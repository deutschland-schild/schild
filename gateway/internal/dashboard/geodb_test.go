//go:build !release

package dashboard_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/gateway/internal/dashboard"
	"github.com/deutschland-schild/schild/gateway/internal/geo"
)

// TestGeoDBMatchesContract: every geo source state is a valid
// Overview.geo_db.
func TestGeoDBMatchesContract(t *testing.T) {
	built := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	cases := map[string]geo.Source{
		"dbip": {Provider: "dbip", Loaded: true, Source: "DB-IP Lite", BuiltAt: built},
		"ipinfo before first download": {Provider: "ipinfo", Downloads: true, Loaded: true, Source: "DB-IP Lite", BuiltAt: built,
			LastError: geo.ErrTokenRejected, LastErrorAt: built},
		"ipinfo nothing loaded": {Provider: "ipinfo", Downloads: true, LastError: geo.ErrTokenMissing, LastErrorAt: built},
		"maxmind paid": {Provider: "maxmind", Downloads: true, Loaded: true, Source: "GeoLite2-Country, GeoIP2-Anonymous-IP", BuiltAt: built,
			Databases: []string{"GeoLite2-Country", "GeoIP2-Anonymous-IP"}, OptionalFields: []string{"is_vpn", "is_proxy", "is_tor", "is_hosting"}, RefreshedAt: built},
	}
	for name, src := range cases {
		b, err := json.Marshal(dashboard.GeoDBOf(src))
		if err != nil {
			t.Fatal(err)
		}
		validate(t, "Overview/properties/geo_db", b)
		if src.Downloads != strings.Contains(string(b), `"refreshed_at"`) {
			t.Errorf("%s: refreshed_at: %s", name, b)
		}
		if name == "ipinfo before first download" && !strings.Contains(string(b), `"refreshed_at":null`) {
			t.Errorf("%s: want null refreshed_at: %s", name, b)
		}
	}
	if dashboard.GeoDBOf(geo.Source{}) != nil {
		t.Fatal("no database, no download: geo_db must be absent")
	}
}
