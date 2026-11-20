package geo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"math"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/maxminddb-golang/v2"
)

// TEST ONLY databases shaped like IPinfo Lite and MaxMind GeoLite2. The
// networks include real public resolver addresses because the download
// sanity check looks those up; the data itself is made up.

const testBuild = 1792800000 // 2026-10-24T00:00:00Z

type testNet struct {
	cidr, country, asOrg, domain string
	asn                          uint32
}

var testNets = []testNet{
	{"8.8.8.0/24", "US", "Example Search LLC", "search.example", 64510},
	{"1.1.1.0/24", "AU", "Example Edge Inc", "edge.example", 64511},
	{"9.9.9.0/24", "CH", "Example Resolver", "resolver.example", 64512},
	{"2001:4860::/32", "US", "Example Search LLC", "search.example", 64510},
	{"203.0.113.0/24", "NL", "Example Hosting B.V.", "hosting.example", 64500},
	{"198.51.100.0/24", "DE", "Example Telekom", "telekom.example", 64496},
}

func newWriter(t testing.TB, dbType string, build int) *mmdbwriter.Tree {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, Description: map[string]string{"en": dbType + " (TEST ONLY)"},
		IncludeReservedNetworks: true, IPVersion: 6, RecordSize: 28, BuildEpoch: int64(build)})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func insert(t testing.TB, w *mmdbwriter.Tree, cidr string, rec mmdbtype.Map) {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Insert(n, rec); err != nil {
		t.Fatal(err)
	}
}

func bytesOf(t testing.TB, w *mmdbwriter.Tree) []byte {
	t.Helper()
	var b bytes.Buffer
	if _, err := w.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// ipinfoLite builds an IPinfo-Lite-shaped database; extra adds fields to
// every record (paid tiers).
func ipinfoLite(t testing.TB, build int, extra mmdbtype.Map) []byte {
	w := newWriter(t, "ipinfo ipinfo_lite.mmdb", build)
	for _, n := range testNets {
		rec := mmdbtype.Map{
			"country_code": mmdbtype.String(n.country), "country": mmdbtype.String("Example Country"),
			"continent_code": mmdbtype.String("EU"), "continent": mmdbtype.String("Europe"),
			"asn": mmdbtype.String("AS" + strconv.Itoa(int(n.asn))), "as_name": mmdbtype.String(n.asOrg), "as_domain": mmdbtype.String(n.domain),
		}
		for k, v := range extra {
			rec[k] = v
		}
		insert(t, w, n.cidr, rec)
	}
	return bytesOf(t, w)
}

func geoliteCountry(t testing.TB, build int) []byte {
	w := newWriter(t, "GeoLite2-Country", build)
	for _, n := range testNets {
		c := mmdbtype.Map{"iso_code": mmdbtype.String(n.country), "names": mmdbtype.Map{"en": mmdbtype.String("Example")}}
		insert(t, w, n.cidr, mmdbtype.Map{"country": c, "registered_country": c, "continent": mmdbtype.Map{"code": mmdbtype.String("EU")}})
	}
	return bytesOf(t, w)
}

func geoliteASN(t testing.TB, build int) []byte {
	w := newWriter(t, "GeoLite2-ASN", build)
	for _, n := range testNets {
		insert(t, w, n.cidr, mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(n.asn), "autonomous_system_organization": mmdbtype.String(n.asOrg)})
	}
	return bytesOf(t, w)
}

func anonymousIP(t testing.TB, build int) []byte {
	w := newWriter(t, "GeoIP2-Anonymous-IP", build)
	insert(t, w, "203.0.113.0/24", mmdbtype.Map{"is_anonymous": mmdbtype.Bool(true), "is_anonymous_vpn": mmdbtype.Bool(true), "is_hosting_provider": mmdbtype.Bool(true)})
	insert(t, w, "8.8.8.0/24", mmdbtype.Map{"is_hosting_provider": mmdbtype.Bool(true)})
	return bytesOf(t, w)
}

// tarGz wraps an MMDB like the MaxMind download (directory with date,
// licence files).
func tarGz(t testing.TB, name string, mmdb []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	tw := tar.NewWriter(zw)
	add := func(n string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.WriteHeader(&tar.Header{Name: name + "_20261024/", Mode: 0o755, Typeflag: tar.TypeDir})
	add(name+"_20261024/COPYRIGHT.txt", []byte("TEST ONLY"))
	add(name+"_20261024/LICENSE.txt", []byte("TEST ONLY"))
	add(name+"_20261024/"+name+".mmdb", mmdb)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func reader(t testing.TB, b []byte) *maxminddb.Reader {
	t.Helper()
	r, err := maxminddb.OpenBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// toMMDB converts a decoded JSON value (numbers as json.Number) to an MMDB
// value; ok is false for what MMDB cannot hold (null, out of range numbers).
func toMMDB(v any) (mmdbtype.DataType, bool) {
	switch x := v.(type) {
	case nil:
		return nil, false
	case bool:
		return mmdbtype.Bool(x), true
	case string:
		return mmdbtype.String(x), true
	case json.Number:
		s := string(x)
		if strings.ContainsAny(s, ".eE") {
			f, err := strconv.ParseFloat(s, 64)
			return mmdbtype.Float64(f), err == nil
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			switch {
			case n >= 0 && n <= math.MaxUint32:
				return mmdbtype.Uint32(n), true
			case n >= 0:
				return mmdbtype.Uint64(n), true
			case n >= math.MinInt32:
				return mmdbtype.Int32(n), true
			}
			return nil, false
		}
		if n, err := strconv.ParseUint(s, 10, 64); err == nil {
			return mmdbtype.Uint64(n), true
		}
		return nil, false
	case []any:
		out := mmdbtype.Slice{}
		for _, e := range x {
			d, ok := toMMDB(e)
			if !ok {
				return nil, false
			}
			out = append(out, d)
		}
		return out, true
	case map[string]any:
		out := mmdbtype.Map{}
		for k, e := range x {
			d, ok := toMMDB(e)
			if !ok {
				return nil, false
			}
			out[mmdbtype.String(k)] = d
		}
		return out, true
	}
	return nil, false
}

// singleRecordDB holds rec for 8.8.8.0/24.
func singleRecordDB(t testing.TB, rec mmdbtype.Map) *maxminddb.Reader {
	w := newWriter(t, "test", testBuild)
	insert(t, w, "8.8.8.0/24", rec)
	return reader(t, bytesOf(t, w))
}
