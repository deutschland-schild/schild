package geo

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	cgeo "github.com/deutschland-schild/schild/contract/geo"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/maxminddb-golang/v2"
)

var sampleIP = netip.MustParseAddr("8.8.8.8")

// checkSame asserts that the hot path (typed, with fallback) gives exactly
// what contract geo.Map gives for the merged records.
func checkSame(t *testing.T, label, provider string, readers []*maxminddb.Reader) (typed, contractMaps bool) {
	t.Helper()
	_, _, typed = lookupTyped(provider, readers, sampleIP)
	want, werr := lookupGeneric(provider, readers, sampleIP)
	contractMaps = werr == nil
	n, mapped := lookupNorm(provider, readers, sampleIP)
	if werr != nil {
		if mapped {
			t.Errorf("%s: contract rejects (%v), hot path mapped %+v", label, werr, n.record())
		}
		return
	}
	if !mapped {
		t.Errorf("%s: contract maps %+v, hot path rejects", label, want)
		return
	}
	if got := n.record(); !reflect.DeepEqual(got, want) {
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want)
		t.Errorf("%s:\n got  %s\n want %s", label, gj, wj)
	}
	return
}

func TestTypedMatchesContractOnVectors(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts", "vectors", "geo-map")
	files, _ := filepath.Glob(filepath.Join(root, "*", "*.json"))
	if len(files) == 0 {
		t.Fatal("no geo-map vectors")
	}
	used := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			InputDecoded struct {
				Provider string         `json:"provider"`
				Record   map[string]any `json:"record"`
			} `json:"input_decoded"`
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if err := d.Decode(&v); err != nil || v.InputDecoded.Record == nil {
			continue // not an object record (schema/malformed vectors)
		}
		p := v.InputDecoded.Provider
		if p != cgeo.IPInfo && p != cgeo.MaxMind {
			continue // dbip keeps its own unchanged path
		}
		rec, ok := toMMDB(v.InputDecoded.Record)
		if !ok {
			continue // null values cannot be stored in an MMDB file
		}
		used++
		checkSame(t, filepath.Base(f), p, []*maxminddb.Reader{singleRecordDB(t, rec.(mmdbtype.Map))})
	}
	if used < 20 {
		t.Fatalf("only %d vectors used", used)
	}
}

// TestTypedMatchesContractRandom compares both paths on random records,
// merged over up to three databases, with well and badly typed values.
func TestTypedMatchesContractRandom(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	vals := func() mmdbtype.DataType {
		pool := []mmdbtype.DataType{
			mmdbtype.String("DE"), mmdbtype.String("de"), mmdbtype.String("DEU"), mmdbtype.String(""), mmdbtype.String("AS64496"),
			mmdbtype.String("AS0"), mmdbtype.String("64496"), mmdbtype.String("Cellular"), mmdbtype.String("Cable/DSL"),
			mmdbtype.String("Example\nOrg"), mmdbtype.String("telekom.example"), mmdbtype.String("Telekom.Example"),
			mmdbtype.Bool(true), mmdbtype.Bool(false), mmdbtype.Uint32(64496), mmdbtype.Uint32(0), mmdbtype.Uint64(1 << 40),
			mmdbtype.Int32(-1), mmdbtype.Float64(1.5), mmdbtype.Map{"iso_code": mmdbtype.String("AT")}, mmdbtype.Map{"name": mmdbtype.String("Example Mobil")},
			mmdbtype.Map{}, mmdbtype.Slice{mmdbtype.String("x")},
		}
		return pool[rnd.Intn(len(pool))]
	}
	str := func(xs ...string) func() mmdbtype.DataType {
		return func() mmdbtype.DataType { return mmdbtype.String(xs[rnd.Intn(len(xs))]) }
	}
	boolean := func() mmdbtype.DataType { return mmdbtype.Bool(rnd.Intn(2) == 0) }
	country := str("DE", "at", "US", "DEU", "")
	name := str("Example Telekom", "Example\nOrg", "", "Example Mobil")
	asnNum := func() mmdbtype.DataType {
		return []mmdbtype.DataType{mmdbtype.Uint32(64496), mmdbtype.Uint32(0), mmdbtype.Uint64(1 << 40), mmdbtype.Uint16(13335)}[rnd.Intn(4)]
	}
	gens := map[string]map[string]func() mmdbtype.DataType{
		cgeo.MaxMind: {"autonomous_system_number": asnNum, "autonomous_system_organization": name, "is_anonymous_vpn": boolean,
			"is_public_proxy": boolean, "is_residential_proxy": boolean, "is_tor_exit_node": boolean, "is_hosting_provider": boolean,
			"connection_type": str("Cellular", "Cable/DSL", "Corporate"), "mobile_network_code": str("01", "02"), "isp": name, "unrelated": name},
		cgeo.IPInfo: {"country_code": country, "asn": str("AS64496", "AS0", "", "64496", "AS4294967296", "AS13335"), "as_name": name,
			"as_domain": str("telekom.example", "Telekom.Example", ""), "is_vpn": boolean, "vpn": boolean, "is_proxy": boolean, "proxy": boolean,
			"is_tor": boolean, "tor": boolean, "is_hosting": boolean, "hosting": boolean, "is_mobile": boolean, "carrier_name": name, "unrelated": name},
	}
	traitKeys := []string{"is_anonymous_vpn", "is_public_proxy", "is_tor_exit_node", "connection_type", "mobile_network_code", "isp"}
	keyLists := map[string][]string{}
	for _, p := range []string{cgeo.MaxMind, cgeo.IPInfo} {
		var keys []string
		for k := range gens[p] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		switch p {
		case cgeo.MaxMind:
			keys = append(keys, "country", "registered_country", "traits")
		case cgeo.IPInfo:
			keys = append(keys, "carrier")
		}
		gens[p]["country"], gens[p]["registered_country"] = func() mmdbtype.DataType { return mmdbtype.Map{"iso_code": country()} }, func() mmdbtype.DataType { return mmdbtype.Map{"iso_code": country()} }
		gens[p]["carrier"] = func() mmdbtype.DataType { return mmdbtype.Map{"name": name()} }
		gens[p]["traits"] = func() mmdbtype.DataType {
			tr := mmdbtype.Map{}
			for _, tk := range traitKeys {
				if rnd.Intn(2) == 0 {
					tr[mmdbtype.String(tk)] = gens[cgeo.MaxMind][tk]()
				}
			}
			return tr
		}
		keyLists[p] = keys
	}
	for _, p := range []string{cgeo.MaxMind, cgeo.IPInfo} {
		count := map[[2]bool]int{}
		for i := 0; i < 400; i++ {
			var readers []*maxminddb.Reader
			for k := 0; k <= rnd.Intn(3); k++ {
				rec := mmdbtype.Map{}
				for _, key := range keyLists[p] {
					if rnd.Intn(3) != 0 {
						continue
					}
					rec[mmdbtype.String(key)] = gens[p][key]()
					if rnd.Intn(40) == 0 {
						rec[mmdbtype.String(key)] = vals() // any type, also for nested keys
					}
				}
				readers = append(readers, singleRecordDB(t, rec))
			}
			typed, maps := checkSame(t, p, p, readers)
			count[[2]bool{typed, maps}]++
		}
		// Every combination must occur: typed and mapped, typed and
		// rejected by the rules, fallback and mapped, fallback and rejected.
		for _, k := range [][2]bool{{true, true}, {true, false}, {false, true}, {false, false}} {
			if count[k] < 5 {
				t.Errorf("%s: case typed=%v maps=%v seen %d times (%v)", p, k[0], k[1], count[k], count)
			}
		}
		t.Logf("%s: %v", p, count)
	}
}

// TestProvidersMapToSameFields: IPinfo Lite and MaxMind GeoLite2 test
// databases give the same gateway records.
func TestProvidersMapToSameFields(t *testing.T) {
	ipi := []*maxminddb.Reader{reader(t, ipinfoLite(t, testBuild, nil))}
	mm := []*maxminddb.Reader{reader(t, geoliteCountry(t, testBuild)), reader(t, geoliteASN(t, testBuild))}
	for _, n := range testNets {
		ip, _, _ := net.ParseCIDR(n.cidr)
		ip[len(ip)-1] |= 7
		a, _ := netip.AddrFromSlice(ip)
		la := lookupAddr(a)
		ni, oki := lookupNorm(cgeo.IPInfo, ipi, la)
		nm, okm := lookupNorm(cgeo.MaxMind, mm, la)
		gi, gm := infoFrom(a, ni, oki), infoFrom(a, nm, okm)
		want := Info{Country: n.country, ASN: n.asn, ASOrg: n.asOrg, NetClass: Classify(a, n.asOrg)}
		if gi != want || gm != want {
			t.Errorf("%s: ipinfo %+v maxmind %+v want %+v", n.cidr, gi, gm, want)
		}
		for _, rs := range []struct {
			p string
			r []*maxminddb.Reader
		}{{cgeo.IPInfo, ipi}, {cgeo.MaxMind, mm}} {
			want, err := lookupGeneric(rs.p, rs.r, la)
			got, _ := lookupNorm(rs.p, rs.r, la)
			if err != nil || !reflect.DeepEqual(got.record(), want) {
				t.Errorf("%s %s: typed %+v contract %+v (%v)", rs.p, n.cidr, got.record(), want, err)
			}
		}
	}
}

func TestOptionalFieldsAndNetClass(t *testing.T) {
	mm := []*maxminddb.Reader{reader(t, geoliteCountry(t, testBuild)), reader(t, geoliteASN(t, testBuild)), reader(t, anonymousIP(t, testBuild))}
	if got := optionalFields(cgeo.MaxMind, mm); !reflect.DeepEqual(got, []string{"is_vpn", "is_proxy", "is_tor", "is_hosting"}) {
		t.Fatalf("maxmind optional %v", got)
	}
	if got := optionalFields(cgeo.MaxMind, mm[:2]); len(got) != 0 {
		t.Fatalf("geolite optional %v", got)
	}
	a := netip.MustParseAddr("203.0.113.9")
	n, ok := lookupNorm(cgeo.MaxMind, mm, a)
	if got := infoFrom(a, n, ok); got.NetClass != "vpn" || got.Country != "NL" {
		t.Fatalf("anonymous ip: %+v", got)
	}
	ipi := []*maxminddb.Reader{reader(t, ipinfoLite(t, testBuild, mmdbtype.Map{"is_mobile": mmdbtype.Bool(true), "carrier_name": mmdbtype.String("Example Mobil")}))}
	if got := optionalFields(cgeo.IPInfo, ipi); !reflect.DeepEqual(got, []string{"is_mobile", "carrier"}) {
		t.Fatalf("ipinfo optional %v", got)
	}
	n, ok = lookupNorm(cgeo.IPInfo, ipi, a)
	if got := infoFrom(a, n, ok); got.NetClass != "mobile" {
		t.Fatalf("ipinfo mobile: %+v", got)
	}
}

// Benchmarks: the bundled DB-IP path against the provider paths (typed hot
// path and the generic map path it replaces).
func benchDB(b *testing.B, provider string, files map[string][]byte, order []string) *DB {
	dir := b.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name+".mmdb"), data, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	db, err := OpenProvider(provider, dir, order, filepath.Join(dir, "none.mmdb"))
	if err != nil {
		b.Fatal(err)
	}
	return db
}

var benchAddr = netip.MustParseAddr("198.51.100.7")

func BenchmarkLookupDBIP(b *testing.B) {
	p := filepath.Join(b.TempDir(), "geo.mmdb")
	if err := WriteFixture(p); err != nil {
		b.Fatal(err)
	}
	db, err := Open(p)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = db.Lookup(benchAddr)
	}
}

func BenchmarkLookupIPInfoLite(b *testing.B) {
	db := benchDB(b, cgeo.IPInfo, map[string][]byte{"ipinfo_lite": ipinfoLite(b, testBuild, nil)}, []string{"ipinfo_lite"})
	b.ReportAllocs()
	for b.Loop() {
		_ = db.Lookup(benchAddr)
	}
}

func BenchmarkLookupMaxMindGeoLite2(b *testing.B) {
	db := benchDB(b, cgeo.MaxMind, map[string][]byte{"GeoLite2-Country": geoliteCountry(b, testBuild), "GeoLite2-ASN": geoliteASN(b, testBuild)},
		[]string{"GeoLite2-Country", "GeoLite2-ASN"})
	b.ReportAllocs()
	for b.Loop() {
		_ = db.Lookup(benchAddr)
	}
}

func BenchmarkLookupIPInfoLiteGenericMap(b *testing.B) {
	rs := []*maxminddb.Reader{reader(b, ipinfoLite(b, testBuild, nil))}
	ip := benchAddr
	b.ReportAllocs()
	for b.Loop() {
		r, _ := lookupGeneric(cgeo.IPInfo, rs, ip)
		_ = infoFrom(benchAddr, fromRecord(r), true)
	}
}

func BenchmarkLookupMaxMindGeoLite2GenericMap(b *testing.B) {
	rs := []*maxminddb.Reader{reader(b, geoliteCountry(b, testBuild)), reader(b, geoliteASN(b, testBuild))}
	ip := benchAddr
	b.ReportAllocs()
	for b.Loop() {
		r, _ := lookupGeneric(cgeo.MaxMind, rs, ip)
		_ = infoFrom(benchAddr, fromRecord(r), true)
	}
}
