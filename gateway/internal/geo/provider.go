package geo

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	cgeo "github.com/deutschland-schild/schild/contract/geo"
	"github.com/oschwald/maxminddb-golang/v2"
)

// Records of a downloaded database (MVP-22, D35). The hot path decodes into
// these typed structs instead of map[string]any and normalises them with the
// same rules as contract geo.Map; every field Map reads is here, pointers
// mark presence where Map distinguishes absent from empty (plain strings
// where it does not, to save allocations). A record that does
// not fit the types (a decode error) is mapped through the generic path
// (map[string]any + contract geo.Map), so the result is always the contract's.
// provider_test.go proves the equality on the geo-map vectors and on the test
// databases.

type isoCode struct {
	ISOCode *string `maxminddb:"iso_code"`
}

type maxmindTraits struct {
	IsAnonymousVPN     *bool   `maxminddb:"is_anonymous_vpn"`
	IsPublicProxy      *bool   `maxminddb:"is_public_proxy"`
	IsResidentialProxy *bool   `maxminddb:"is_residential_proxy"`
	IsTorExitNode      *bool   `maxminddb:"is_tor_exit_node"`
	IsHostingProvider  *bool   `maxminddb:"is_hosting_provider"`
	ConnectionType     *string `maxminddb:"connection_type"`
	MobileNetworkCode  any     `maxminddb:"mobile_network_code"`
	ISP                *string `maxminddb:"isp"`
}

// maxmindRecord covers GeoLite2/GeoIP2 Country, City, ASN, ISP,
// Anonymous-IP, Connection-Type and Enterprise (top level and traits).
type maxmindRecord struct {
	Country           isoCode `maxminddb:"country"`
	RegisteredCountry isoCode `maxminddb:"registered_country"`
	ASN               *int64  `maxminddb:"autonomous_system_number"`
	ASOrg             string  `maxminddb:"autonomous_system_organization"` // absent and "" map alike
	maxmindTraits
	Traits maxmindTraits `maxminddb:"traits"`
}

// ipinfoRecord covers IPinfo Lite and the paid IPinfo databases.
type ipinfoRecord struct {
	CountryCode *string `maxminddb:"country_code"`
	ASN         string  `maxminddb:"asn"`       // absent and "" map alike
	ASName      string  `maxminddb:"as_name"`   // absent and "" map alike
	ASDomain    string  `maxminddb:"as_domain"` // absent and "" map alike
	IsVPN       *bool   `maxminddb:"is_vpn"`
	VPN         *bool   `maxminddb:"vpn"`
	IsProxy     *bool   `maxminddb:"is_proxy"`
	Proxy       *bool   `maxminddb:"proxy"`
	IsTor       *bool   `maxminddb:"is_tor"`
	Tor         *bool   `maxminddb:"tor"`
	IsHosting   *bool   `maxminddb:"is_hosting"`
	Hosting     *bool   `maxminddb:"hosting"`
	IsMobile    *bool   `maxminddb:"is_mobile"`
	CarrierName *string `maxminddb:"carrier_name"`
	Carrier     struct {
		Name *string `maxminddb:"name"`
	} `maxminddb:"carrier"`
}

// Flags of norm, in contract net class order.
const (
	flagTor = 1 << iota
	flagVPN
	flagProxy
	flagMobile
	flagHosting
)

var flagFields = []struct {
	bit   uint8
	field string
	class string
}{{flagTor, "is_tor", "tor"}, {flagVPN, "is_vpn", "vpn"}, {flagProxy, "is_proxy", "proxy"}, {flagMobile, "is_mobile", "mobile"}, {flagHosting, "is_hosting", "hosting"}}

// norm is the allocation-free form of contract geo.Record.
type norm struct {
	country  string
	asn      int64 // 0 = absent
	asName   string
	asDomain string
	carrier  string
	present  uint8 // flag present in the database
	set      uint8 // flag true
}

func (n *norm) flag(bit uint8, vs ...*bool) {
	for _, v := range vs {
		if v != nil {
			n.present |= bit
			if *v {
				n.set |= bit
			}
		}
	}
}

func (n norm) netClass() string {
	for _, f := range flagFields {
		if n.set&f.bit != 0 {
			return f.class
		}
	}
	return ""
}

// record converts to the contract type (tests and the generic path).
func (n norm) record() cgeo.Record {
	r := cgeo.Record{Country: n.country, ASName: n.asName, ASDomain: n.asDomain, Carrier: n.carrier}
	if n.asn > 0 {
		a := n.asn
		r.ASN = &a
	}
	for _, f := range []struct {
		bit uint8
		dst **bool
	}{{flagTor, &r.IsTor}, {flagVPN, &r.IsVPN}, {flagProxy, &r.IsProxy}, {flagMobile, &r.IsMobile}, {flagHosting, &r.IsHosting}} {
		if n.present&f.bit != 0 {
			b := n.set&f.bit != 0
			*f.dst = &b
		}
	}
	if c := n.netClass(); c != "" {
		r.NetClass = &c
	}
	return r
}

func fromRecord(r cgeo.Record) norm {
	n := norm{country: r.Country, asName: r.ASName, asDomain: r.ASDomain, carrier: r.Carrier}
	if r.ASN != nil {
		n.asn = *r.ASN
	}
	n.flag(flagTor, r.IsTor)
	n.flag(flagVPN, r.IsVPN)
	n.flag(flagProxy, r.IsProxy)
	n.flag(flagMobile, r.IsMobile)
	n.flag(flagHosting, r.IsHosting)
	return n
}

func countryOf(vs ...*string) (string, bool) {
	for _, v := range vs {
		if v == nil {
			continue
		}
		s := *v
		if len(s) != 2 || !isAlpha(s[0]) || !isAlpha(s[1]) {
			return "", false
		}
		return strings.ToUpper(s), true
	}
	return cgeo.UnknownCountry, true
}

func isAlpha(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

// safeName is contract geo name(): at most MaxNameBytes, valid UTF-8, no
// control characters; anything else is dropped.
func safeName(vs ...*string) string {
	for _, v := range vs {
		if v == nil {
			continue
		}
		s := *v
		if len(s) > cgeo.MaxNameBytes || !utf8.ValidString(s) {
			return ""
		}
		for _, r := range s {
			if r < 0x20 || r >= 0x7f && r <= 0x9f {
				return ""
			}
		}
		return s
	}
	return ""
}

func domainOK(s string) bool {
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func (r *maxmindRecord) norm() (norm, bool) {
	var n norm
	var ok bool
	if n.country, ok = countryOf(r.Country.ISOCode, r.RegisteredCountry.ISOCode); !ok {
		return n, false
	}
	if r.ASN != nil {
		a := *r.ASN
		if a < 0 || a > cgeo.MaxASN {
			return n, false
		}
		n.asn = a
	}
	n.asName = safeName(&r.ASOrg)
	t, tt := &r.maxmindTraits, &r.Traits
	n.flag(flagVPN, t.IsAnonymousVPN, tt.IsAnonymousVPN)
	n.flag(flagProxy, t.IsPublicProxy, tt.IsPublicProxy, t.IsResidentialProxy, tt.IsResidentialProxy)
	n.flag(flagTor, t.IsTorExitNode, tt.IsTorExitNode)
	n.flag(flagHosting, t.IsHostingProvider, tt.IsHostingProvider)
	ct := t.ConnectionType
	if ct == nil {
		ct = tt.ConnectionType
	}
	if ct != nil {
		m := *ct == "Cellular"
		n.flag(flagMobile, &m)
	}
	if t.MobileNetworkCode != nil || tt.MobileNetworkCode != nil {
		n.carrier = safeName(t.ISP, tt.ISP)
	}
	return n, true
}

func (r *ipinfoRecord) norm() (norm, bool) {
	var n norm
	var ok bool
	if n.country, ok = countryOf(r.CountryCode); !ok {
		return n, false
	}
	if r.ASN != "" {
		s := r.ASN
		if len(s) < 3 || len(s) > 12 || s[0] != 'A' || s[1] != 'S' {
			return n, false
		}
		for i := 2; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return n, false
			}
		}
		a, err := strconv.ParseInt(s[2:], 10, 64)
		if err != nil || a > cgeo.MaxASN {
			return n, false
		}
		n.asn = a
	}
	n.asName = safeName(&r.ASName)
	if domainOK(r.ASDomain) {
		n.asDomain = r.ASDomain
	}
	n.flag(flagVPN, r.IsVPN, r.VPN)
	n.flag(flagProxy, r.IsProxy, r.Proxy)
	n.flag(flagTor, r.IsTor, r.Tor)
	n.flag(flagHosting, r.IsHosting, r.Hosting)
	n.flag(flagMobile, r.IsMobile)
	n.carrier = safeName(r.CarrierName, r.Carrier.Name)
	return n, true
}

// lookupTyped looks ip up in every reader; the first database that has a
// field wins (decoding the last database first lets earlier ones overwrite
// what they have). ok is false when a record does not fit the typed struct.
func lookupTyped(provider string, readers []*maxminddb.Reader, ip netip.Addr) (n norm, mapped bool, ok bool) {
	switch provider {
	case cgeo.IPInfo:
		var r ipinfoRecord
		for i := len(readers) - 1; i >= 0; i-- {
			if err := readers[i].Lookup(ip).Decode(&r); err != nil {
				return n, false, false
			}
		}
		n, mapped = r.norm()
		return n, mapped, true
	case cgeo.MaxMind:
		var r maxmindRecord
		for i := len(readers) - 1; i >= 0; i-- {
			if err := readers[i].Lookup(ip).Decode(&r); err != nil {
				return n, false, false
			}
		}
		n, mapped = r.norm()
		return n, mapped, true
	}
	return n, false, false
}

// lookupGeneric is the reference path: every database's record as
// map[string]any, merged (first database wins per field) and mapped by
// contract geo.Map.
func lookupGeneric(provider string, readers []*maxminddb.Reader, ip netip.Addr) (cgeo.Record, error) {
	merged := map[string]any{}
	for _, rd := range readers {
		var m map[string]any
		if err := rd.Lookup(ip).Decode(&m); err != nil {
			return cgeo.Record{}, err
		}
		mergeFirst(merged, m)
	}
	return cgeo.Map(provider, merged)
}

// mergeFirst adds the fields of src that dst does not have yet; nested
// objects are merged the same way.
func mergeFirst(dst, src map[string]any) {
	for k, v := range src {
		cur, ok := dst[k]
		if !ok {
			dst[k] = v
			continue
		}
		cm, ok1 := cur.(map[string]any)
		sm, ok2 := v.(map[string]any)
		if ok1 && ok2 {
			mergeFirst(cm, sm)
		}
	}
}

// lookupAddr is the address as the databases know it: an IPv4-mapped address
// is the IPv4 address, and a zone means nothing to them.
func lookupAddr(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// lookupNorm is the hot path: typed, falling back to the generic path when
// a record does not fit.
func lookupNorm(provider string, readers []*maxminddb.Reader, ip netip.Addr) (norm, bool) {
	n, mapped, ok := lookupTyped(provider, readers, ip)
	if ok {
		return n, mapped
	}
	r, err := lookupGeneric(provider, readers, ip)
	if err != nil {
		return norm{}, false
	}
	return fromRecord(r), true
}

// infoFrom turns a normalised record into the gateway's geo record. The net
// class comes from the database flags (tor, vpn, proxy, mobile, hosting)
// and otherwise from the heuristic on the AS name, as with DB-IP.
func infoFrom(addr netip.Addr, n norm, mapped bool) Info {
	info := Unknown
	if mapped {
		info.Country = n.country
		if n.asn > 0 && n.asn <= maxEventASN {
			info.ASN = uint32(n.asn)
		}
		info.ASOrg = n.asName
		if c := n.netClass(); c != "" {
			info.NetClass = c
		}
	}
	if len(info.Country) != 2 {
		info.Country = cgeo.UnknownCountry
	}
	if info.NetClass == "unknown" {
		info.NetClass = Classify(addr, info.ASOrg)
	}
	return info
}

// maxEventASN is the largest ASN events carry (common.schema.json asn).
const maxEventASN = 16777215
