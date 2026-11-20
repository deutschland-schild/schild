package geo

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// FixtureEntry is one network of the test fixture database.
type FixtureEntry struct {
	CIDR, Country, City, ASOrg, NetClass string
	ASN                                  uint32
}

// FixtureEntries covers the documentation ranges (RFC 5737, RFC 3849) with
// documentation ASNs (RFC 5398). TEST ONLY data, no real network.
var FixtureEntries = []FixtureEntry{
	{"203.0.113.0/24", "NL", "Amsterdam", "Example Hosting B.V.", "hosting", 64500},
	{"198.51.100.0/24", "DE", "Berlin", "Example Telekom", "residential", 64496},
	{"192.0.2.0/24", "DE", "Hamburg", "Example University", "education", 64501},
	{"2001:db8::/32", "NL", "Amsterdam", "Example Hosting B.V.", "hosting", 64500},
	{"10.66.0.0/16", "DE", "Testlab", "Schild Testlab", "residential", 64511},
}

// WriteFixture writes a tiny combined country+ASN database for tests and the
// local test lab (DatabaseType "schild-geo-fixture").
func WriteFixture(path string) error {
	t, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "schild-geo-fixture",
		Description:             map[string]string{"en": "schild-geo-fixture (TEST ONLY, documentation ranges)"},
		IncludeReservedNetworks: true,
		IPVersion:               6,
		RecordSize:              28,
		Languages:               []string{"en"},
		BuildEpoch:              1790812800, // 2026-10-01T00:00:00Z, fixed for reproducible files
	})
	if err != nil {
		return err
	}
	for _, e := range FixtureEntries {
		_, n, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			return fmt.Errorf("geo fixture %s: %w", e.CIDR, err)
		}
		rec := mmdbtype.Map{
			"country":                        mmdbtype.Map{"iso_code": mmdbtype.String(e.Country)},
			"city":                           mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String(e.City)}},
			"autonomous_system_number":       mmdbtype.Uint32(e.ASN),
			"autonomous_system_organization": mmdbtype.String(e.ASOrg),
			"schild_net_class":               mmdbtype.String(e.NetClass),
		}
		if err := t.Insert(n, rec); err != nil {
			return fmt.Errorf("geo fixture %s: %w", e.CIDR, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // TEST ONLY reference data, readable like any GeoIP database
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := t.WriteTo(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
