package geo

import (
	"encoding/json"
	"testing"
)

// The geo-map vectors cover the rules with JSON input; the gateway maps
// records decoded from MMDB files, whose integers are Go integers.
func TestMMDBNativeTypes(t *testing.T) {
	r, err := Map(MaxMind, map[string]any{"country": map[string]any{"iso_code": "de"}, "autonomous_system_number": uint64(64496),
		"traits": map[string]any{"is_tor_exit_node": true, "is_anonymous_vpn": true}})
	if err != nil || r.Country != "DE" || r.ASN == nil || *r.ASN != 64496 || r.NetClass == nil || *r.NetClass != "tor" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := Map(DBIP, map[string]any{"autonomous_system_number": float64(64496)}); err == nil {
		t.Fatal("a float AS number accepted")
	}
	if _, err := Map(DBIP, map[string]any{"autonomous_system_number": json.Number("64496.0")}); err == nil {
		t.Fatal("a fractional JSON number accepted")
	}
	if r, err := Map(IPInfo, map[string]any{"asn": "AS4294967295"}); err != nil || *r.ASN != MaxASN {
		t.Fatalf("largest AS number: %+v %v", r, err)
	}
	if _, err := Map("ip2location", map[string]any{}); err == nil {
		t.Fatal("unknown provider")
	}
}
