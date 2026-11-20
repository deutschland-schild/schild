// Package geo is the v0.5 (MVP-22, D35) contract of the geo field mapping:
// how a record of the bundled DB-IP Lite database or of a database the
// gateway downloaded with the operator's own IPinfo or MaxMind key (BYOK)
// becomes the gateway's geo record (contracts/geo-map.schema.json). The
// lookup is always local; no visitor address is sent to a provider. The same
// rules run on sample lookups before a downloaded database replaces the last
// good one. contracts/tools/crosscheck.py implements them independently; the
// geo-map vectors keep both in step.
package geo

import (
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Providers (schild.yaml geo.provider).
const (
	DBIP    = "dbip"    // bundled DB-IP Lite country + ASN (default)
	IPInfo  = "ipinfo"  // operator's own IPinfo token
	MaxMind = "maxmind" // operator's own MaxMind account and licence key
)

// Providers in the order of the schema enum.
var Providers = []string{DBIP, IPInfo, MaxMind}

// SchemaMap is the name of the vector input schema.
const SchemaMap = "geo-map"

// Limits.
const (
	MaxInputBytes = 64 << 10
	MaxNameBytes  = 256
	MaxASN        = math.MaxUint32
	// UnknownCountry when the database has none.
	UnknownCountry = "ZZ"
)

// Record is the normalised result of one lookup. Optional fields are nil
// (absent) when the database does not provide them.
type Record struct {
	Country   string  `json:"country"`
	ASN       *int64  `json:"asn"`
	ASName    string  `json:"as_name,omitempty"`
	ASDomain  string  `json:"as_domain,omitempty"`
	IsVPN     *bool   `json:"is_vpn,omitempty"`
	IsProxy   *bool   `json:"is_proxy,omitempty"`
	IsTor     *bool   `json:"is_tor,omitempty"`
	IsHosting *bool   `json:"is_hosting,omitempty"`
	IsMobile  *bool   `json:"is_mobile,omitempty"`
	Carrier   string  `json:"carrier,omitempty"`
	NetClass  *string `json:"net_class,omitempty"`
}

// OptionalFields are the paid-tier fields a database may provide.
var OptionalFields = []string{"is_vpn", "is_proxy", "is_tor", "is_hosting", "is_mobile", "carrier"}

var (
	countryRe  = regexp.MustCompile(`^[A-Za-z]{2}$`)
	ipinfoASRe = regexp.MustCompile(`^AS[0-9]{1,10}$`)
	domainRe   = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)
)

func schemaErr(format string, args ...any) error {
	return contract.Errf(contract.CodeSchema, format, args...)
}

// get returns the value at a dotted path; a missing key or a non-object on
// the way is absent.
func get(rec map[string]any, path string) (any, bool) {
	var cur any = rec
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[p]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// first returns the first present source.
func first(rec map[string]any, paths ...string) (any, string, bool) {
	for _, p := range paths {
		if v, ok := get(rec, p); ok {
			return v, p, true
		}
	}
	return nil, "", false
}

// flag is the OR of every present source; each must be a boolean.
func flag(rec map[string]any, paths ...string) (*bool, error) {
	var out *bool
	for _, p := range paths {
		v, ok := get(rec, p)
		if !ok {
			continue
		}
		b, ok := v.(bool)
		if !ok {
			return nil, schemaErr("%s: not a boolean", p)
		}
		if out == nil {
			out = new(bool)
		}
		*out = *out || b
	}
	return out, nil
}

// name keeps a string of at most MaxNameBytes without control characters;
// another string is dropped, another type is an error.
func name(rec map[string]any, paths ...string) (string, error) {
	v, p, ok := first(rec, paths...)
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", schemaErr("%s: not a string", p)
	}
	if len(s) > MaxNameBytes || !utf8.ValidString(s) {
		return "", nil
	}
	for _, r := range s {
		if r < 0x20 || r >= 0x7f && r <= 0x9f {
			return "", nil
		}
	}
	return s, nil
}

// integer accepts an integer JSON number (no fraction or exponent) or a Go
// integer as decoded from an MMDB file.
func integer(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		return n, err == nil
	case int:
		return int64(x), true
	case int64:
		return x, true
	case uint32:
		return int64(x), true
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	}
	return 0, false
}

func country(rec map[string]any, paths ...string) (string, error) {
	v, p, ok := first(rec, paths...)
	if !ok {
		return UnknownCountry, nil
	}
	s, ok := v.(string)
	if !ok || !countryRe.MatchString(s) {
		return "", schemaErr("%s: not a two-letter country code", p)
	}
	return strings.ToUpper(s), nil
}

// Map normalises one record of provider.
func Map(provider string, rec map[string]any) (Record, error) {
	var r Record
	var err error
	switch provider {
	case DBIP, MaxMind:
		if r.Country, err = country(rec, "country.iso_code", "registered_country.iso_code"); err != nil {
			return r, err
		}
		if v, ok := get(rec, "autonomous_system_number"); ok {
			n, ok := integer(v)
			if !ok || n < 0 || n > MaxASN {
				return r, schemaErr("autonomous_system_number: not an AS number")
			}
			if n > 0 {
				r.ASN = &n
			}
		}
		if r.ASName, err = name(rec, "autonomous_system_organization"); err != nil {
			return r, err
		}
		if provider == MaxMind {
			if err = r.maxmindOptional(rec); err != nil {
				return r, err
			}
		}
	case IPInfo:
		if r.Country, err = country(rec, "country_code"); err != nil {
			return r, err
		}
		if v, ok := get(rec, "asn"); ok {
			s, ok := v.(string)
			if !ok || s != "" && !ipinfoASRe.MatchString(s) {
				return r, schemaErr("asn: not AS<n>")
			}
			if s != "" {
				n, err := strconv.ParseInt(s[2:], 10, 64)
				if err != nil || n > MaxASN {
					return r, schemaErr("asn: out of range")
				}
				if n > 0 {
					r.ASN = &n
				}
			}
		}
		if r.ASName, err = name(rec, "as_name"); err != nil {
			return r, err
		}
		if v, ok := get(rec, "as_domain"); ok {
			s, ok := v.(string)
			if !ok {
				return r, schemaErr("as_domain: not a string")
			}
			if domainRe.MatchString(s) {
				r.ASDomain = s
			}
		}
		for _, f := range []struct {
			dst   **bool
			paths []string
		}{
			{&r.IsVPN, []string{"is_vpn", "vpn"}}, {&r.IsProxy, []string{"is_proxy", "proxy"}}, {&r.IsTor, []string{"is_tor", "tor"}},
			{&r.IsHosting, []string{"is_hosting", "hosting"}}, {&r.IsMobile, []string{"is_mobile"}},
		} {
			if *f.dst, err = flag(rec, f.paths...); err != nil {
				return r, err
			}
		}
		if r.Carrier, err = name(rec, "carrier_name", "carrier.name"); err != nil {
			return r, err
		}
	default:
		return r, schemaErr("unknown provider %q", provider)
	}
	r.NetClass = netClass(r)
	return r, nil
}

func (r *Record) maxmindOptional(rec map[string]any) error {
	var err error
	both := func(k string) []string { return []string{k, "traits." + k} }
	if r.IsVPN, err = flag(rec, both("is_anonymous_vpn")...); err != nil {
		return err
	}
	if r.IsProxy, err = flag(rec, append(both("is_public_proxy"), both("is_residential_proxy")...)...); err != nil {
		return err
	}
	if r.IsTor, err = flag(rec, both("is_tor_exit_node")...); err != nil {
		return err
	}
	if r.IsHosting, err = flag(rec, both("is_hosting_provider")...); err != nil {
		return err
	}
	if v, p, ok := first(rec, both("connection_type")...); ok {
		s, ok := v.(string)
		if !ok {
			return schemaErr("%s: not a string", p)
		}
		m := s == "Cellular"
		r.IsMobile = &m
	}
	if _, _, ok := first(rec, both("mobile_network_code")...); ok {
		if r.Carrier, err = name(rec, both("isp")...); err != nil {
			return err
		}
	}
	return nil
}

// netClass derives the net class from the flags (tor, vpn, proxy, mobile,
// hosting; the first one that is true), nil when none is.
func netClass(r Record) *string {
	for _, f := range []struct {
		v *bool
		c string
	}{{r.IsTor, "tor"}, {r.IsVPN, "vpn"}, {r.IsProxy, "proxy"}, {r.IsMobile, "mobile"}, {r.IsHosting, "hosting"}} {
		if f.v != nil && *f.v {
			c := f.c
			return &c
		}
	}
	return nil
}

// RunVector maps one geo-map input (geo-map.schema.json).
func RunVector(raw []byte) (Record, error) {
	if len(raw) > MaxInputBytes {
		return Record{}, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return Record{}, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(SchemaMap, v); err != nil {
		return Record{}, err
	}
	return Map(v["provider"].(string), v["record"].(map[string]any))
}
