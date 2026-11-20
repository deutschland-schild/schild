package main

// TEST ONLY geo database for the MVP-21 measurement: the documentation
// ranges of the schild fixture plus 256 synthetic /16 networks in 10.0.0.0/8
// with their own AS numbers (64512+i, private-use ASNs, RFC 6996), countries
// and net classes, so top-K lists for ASNs and the exact country and
// net-class breakdowns can be checked against a known table.

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

type geoEntry struct {
	CIDR     string `json:"cidr"`
	Country  string `json:"country"`
	ASN      uint32 `json:"asn"`
	ASOrg    string `json:"as_org"`
	NetClass string `json:"net_class"`
}

var geoCountries = []string{"DE", "NL", "FR", "AT", "CH", "US", "GB", "PL", "IT", "ES", "SE", "DK", "BE", "CZ", "FI", "NO", "IE", "PT", "JP", "BR",
	"IN", "CA", "AU", "CN", "RU", "UA", "TR", "MX", "ZA", "KR", "SG", "HK", "AR", "RO", "HU", "GR", "BG", "HR", "SK", "SI"}

// geoNetClasses avoids cgnat and mobile so that the per-client WAF budget is
// the same for every synthetic client.
var geoNetClasses = []string{"residential", "hosting", "business", "education", "government", "residential"}

func geoTable() []geoEntry {
	t := []geoEntry{
		{"203.0.113.0/24", "NL", 64500, "Example Hosting B.V.", "hosting"},
		{"198.51.100.0/24", "DE", 64496, "Example Telekom", "residential"},
		{"192.0.2.0/24", "DE", 64501, "Example University", "education"},
		{"2001:db8::/32", "NL", 64500, "Example Hosting B.V.", "hosting"},
	}
	for i := 0; i < 256; i++ {
		t = append(t, geoEntry{fmt.Sprintf("10.%d.0.0/16", i), geoCountries[i%len(geoCountries)], uint32(64512 + i),
			fmt.Sprintf("Test Net %03d e.V.", i), geoNetClasses[i%len(geoNetClasses)]})
	}
	return t
}

// lookup returns the table entry of an address (nil: not covered, ZZ).
func lookup(t []geoEntry, a netip.Addr) *geoEntry {
	for i := range t {
		p := netip.MustParsePrefix(t[i].CIDR)
		if p.Contains(a) {
			return &t[i]
		}
	}
	return nil
}

func cmdGeo(args []string) error {
	fs := flag.NewFlagSet("geo", flag.ExitOnError)
	out := fs.String("out", "geo.mmdb", "")
	tbl := fs.String("table", "", "write the table as JSON")
	_ = fs.Parse(args)
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "schild-geo-fixture", IncludeReservedNetworks: true, IPVersion: 6, RecordSize: 28,
		Languages: []string{"en"}, Description: map[string]string{"en": "TEST ONLY spec21 measurement"}})
	if err != nil {
		return err
	}
	t := geoTable()
	for _, e := range t {
		_, n, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			return err
		}
		rec := mmdbtype.Map{
			"country":                        mmdbtype.Map{"iso_code": mmdbtype.String(e.Country)},
			"city":                           mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Testcity")}},
			"autonomous_system_number":       mmdbtype.Uint32(e.ASN),
			"autonomous_system_organization": mmdbtype.String(e.ASOrg),
			"schild_net_class":               mmdbtype.String(e.NetClass),
		}
		if err := w.Insert(n, rec); err != nil {
			return err
		}
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	if _, err := w.WriteTo(f); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if *tbl != "" {
		b, _ := json.MarshalIndent(t, "", " ")
		return os.WriteFile(*tbl, b, 0o644)
	}
	return nil
}
