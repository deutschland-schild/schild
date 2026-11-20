// Package geo derives country, ASN and net class of a visitor address from a
// bundled MaxMind-format database (DB-IP Lite country + ASN, CC BY 4.0,
// "IP Geolocation by DB-IP", https://db-ip.com) or, with geo.provider ipinfo
// or maxmind, from the provider database the gateway downloads with the
// operator's own token (MVP-22, D35, download.go). Lookups are local only:
// nothing is ever looked up at a third party (MVP-02).
package geo

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cgeo "github.com/deutschland-schild/schild/contract/geo"
	"github.com/oschwald/maxminddb-golang/v2"
)

// ImageDir is where the image ships the geo database (outside the data
// volume, so mounting /var/lib/schild does not hide it).
const ImageDir = "/usr/share/schild/geo"

// Info is the local view of an address (events.Geo without the JSON tags).
type Info struct {
	Country  string
	City     string
	ASN      uint32
	ASOrg    string
	NetClass string
}

// Unknown is returned when nothing is known.
var Unknown = Info{Country: "ZZ", NetClass: "unknown"}

type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	ASN      uint32 `maxminddb:"autonomous_system_number"`
	ASOrg    string `maxminddb:"autonomous_system_organization"`
	NetClass string `maxminddb:"schild_net_class"`
}

type dbs struct {
	country *maxminddb.Reader
	asn     *maxminddb.Reader
	// provider is set when downloaded databases (ipinfo, maxmind) are in
	// use; readers are in configuration order (the first that has a field
	// wins) and names their database ids.
	provider string
	readers  []*maxminddb.Reader
	names    []string
	optional []string
	source   string
	builtAt  time.Time
	paths    []string
	mtimes   []time.Time
}

func (c *dbs) close() {
	if c.country != nil {
		c.country.Close()
	}
	if c.asn != nil {
		c.asn.Close()
	}
	for _, r := range c.readers {
		r.Close()
	}
}

// DB is a hot-swappable geo database.
type DB struct {
	cur  atomic.Pointer[dbs]
	mu   sync.Mutex
	path string
	// Download providers (BYOK, MVP-22): dir holds <database>.mmdb.
	provider  string
	dir       string
	databases []string
	refresh   atomic.Pointer[refreshState]
}

// refreshState is the outcome of the last download (memory only).
type refreshState struct {
	lastError   string
	lastErrorAt time.Time
}

// Open loads the country database at path (and asn.mmdb next to it). If
// path does not exist, ImageDir/country.mmdb is tried. A missing database is
// not fatal: lookups return Unknown and Status reports it.
func Open(path string) (*DB, error) {
	d := &DB{path: path}
	err := d.Reload()
	return d, err
}

// OpenProvider loads the downloaded databases of provider (ipinfo, maxmind)
// from dir (<database>.mmdb each). Until the first download succeeded the
// bundled DB-IP database at path is used, so lookups never get worse than
// without a token.
func OpenProvider(provider, dir string, databases []string, path string) (*DB, error) {
	d := &DB{path: path, provider: provider, dir: dir, databases: append([]string(nil), databases...)}
	err := d.Reload()
	return d, err
}

func candidates(path string) (country, asn string) {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return path, filepath.Join(filepath.Dir(path), "asn.mmdb")
		}
	}
	return filepath.Join(ImageDir, "country.mmdb"), filepath.Join(ImageDir, "asn.mmdb")
}

// providerFiles lists the downloaded databases that exist, in
// configuration order.
func (d *DB) providerFiles() (names, paths []string) {
	if d.provider == "" {
		return nil, nil
	}
	for _, name := range d.databases {
		p := filepath.Join(d.dir, name+".mmdb")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			names, paths = append(names, name), append(paths, p)
		}
	}
	return names, paths
}

func mtimes(paths []string) []time.Time {
	mt := make([]time.Time, 0, len(paths))
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			mt = append(mt, time.Time{})
			continue
		}
		mt = append(mt, st.ModTime())
	}
	return mt
}

func unchanged(old *dbs, paths []string, mt []time.Time) bool {
	if old == nil || len(old.paths) != len(paths) {
		return false
	}
	for i := range paths {
		if old.paths[i] != paths[i] || !old.mtimes[i].Equal(mt[i]) {
			return false
		}
	}
	return true
}

// Reload (re)opens the files if they changed.
func (d *DB) Reload() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if names, paths := d.providerFiles(); len(paths) > 0 {
		return d.reloadProvider(names, paths)
	}
	cp, ap := candidates(d.path)
	paths := []string{cp, ap}
	mt := mtimes(paths)
	if unchanged(d.cur.Load(), paths, mt) {
		return nil
	}
	n := &dbs{paths: paths, mtimes: mt}
	c, err := maxminddb.Open(cp)
	if err != nil {
		d.swap(nil)
		return fmt.Errorf("geo: %w", err)
	}
	n.country = c
	if a, err := maxminddb.Open(ap); err == nil {
		n.asn = a
	}
	n.source = c.Metadata.DatabaseType
	if desc := c.Metadata.Description["en"]; desc != "" && !strings.Contains(n.source, desc) {
		n.source = desc
	}
	n.builtAt = time.Unix(int64(c.Metadata.BuildEpoch), 0).UTC()
	d.swap(n)
	return nil
}

func (d *DB) reloadProvider(names, paths []string) error {
	mt := mtimes(paths)
	if unchanged(d.cur.Load(), paths, mt) {
		return nil
	}
	n := &dbs{provider: d.provider, names: names, paths: paths, mtimes: mt}
	for _, p := range paths {
		r, err := maxminddb.Open(p)
		if err != nil {
			n.close()
			// Keep what is loaded; the downloader only swaps in checked files.
			return fmt.Errorf("geo: open %s: %w", filepath.Base(p), err)
		}
		n.readers = append(n.readers, r)
		built := time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC()
		if n.builtAt.IsZero() || built.Before(n.builtAt) {
			n.builtAt = built
		}
	}
	n.source = strings.Join(names, ", ")
	n.optional = optionalFields(d.provider, n.readers)
	d.swap(n)
	return nil
}

func (d *DB) swap(n *dbs) {
	old := d.cur.Swap(n)
	if old != nil {
		// Readers may still use the old mmap for an in-flight lookup; close later.
		go func() {
			time.Sleep(10 * time.Second)
			old.close()
		}()
	}
}

// Loaded reports whether a database is available.
func (d *DB) Loaded() bool { return d != nil && d.cur.Load() != nil }

// Status describes the loaded database for the overview.
func (d *DB) Status() (source string, builtAt time.Time, ok bool) {
	if d == nil {
		return "", time.Time{}, false
	}
	c := d.cur.Load()
	if c == nil {
		return "", time.Time{}, false
	}
	return c.source, c.builtAt, true
}

// Source is the geo source for the dashboard overview (Overview.geo_db).
// It never contains the token.
type Source struct {
	Provider       string    // schild.yaml geo.provider
	Loaded         bool      // a database is in use
	Source         string    // description of the database in use
	BuiltAt        time.Time // build date of the database (oldest of a set)
	Databases      []string  // downloaded databases in use; empty while the bundled one is used
	OptionalFields []string  // paid-tier fields the databases provide
	Downloads      bool      // provider downloads (ipinfo, maxmind)
	RefreshedAt    time.Time // last successful download (zero: none yet)
	LastError      string    // Overview.geo_db.last_error code of the last failed download
	LastErrorAt    time.Time
}

// SourceInfo reports the geo source.
func (d *DB) SourceInfo() Source {
	if d == nil {
		return Source{}
	}
	s := Source{Provider: d.provider, Downloads: d.provider != ""}
	if s.Provider == "" {
		s.Provider = cgeo.DBIP
	}
	if c := d.cur.Load(); c != nil {
		s.Loaded, s.Source, s.BuiltAt = true, c.source, c.builtAt
		if c.provider != "" {
			s.Databases = append([]string(nil), c.names...)
			s.OptionalFields = append([]string(nil), c.optional...)
			for _, m := range c.mtimes {
				if m.After(s.RefreshedAt) {
					s.RefreshedAt = m.UTC()
				}
			}
		}
	}
	if r := d.refresh.Load(); r != nil {
		s.LastError, s.LastErrorAt = r.lastError, r.lastErrorAt
	}
	return s
}

// Lookup returns what is known about addr.
func (d *DB) Lookup(addr netip.Addr) Info {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return Unknown
	}
	info := Unknown
	if d != nil {
		if c := d.cur.Load(); c != nil && c.provider != "" {
			n, mapped := lookupNorm(c.provider, c.readers, lookupAddr(addr))
			return infoFrom(addr, n, mapped)
		} else if c != nil {
			ip := lookupAddr(addr)
			var r record
			if err := c.country.Lookup(ip).Decode(&r); err == nil {
				if r.Country.ISOCode != "" {
					info.Country = strings.ToUpper(r.Country.ISOCode)
				}
				info.City = r.City.Names["en"]
				info.ASN, info.ASOrg = r.ASN, r.ASOrg
				if r.NetClass != "" {
					info.NetClass = r.NetClass
				}
			}
			if c.asn != nil {
				var ar record
				if err := c.asn.Lookup(ip).Decode(&ar); err == nil && ar.ASN != 0 {
					info.ASN, info.ASOrg = ar.ASN, ar.ASOrg
				}
			}
		}
	}
	if info.ASN > 16777215 {
		info.ASN = 0
	}
	if len(info.Country) != 2 {
		info.Country = "ZZ"
	}
	if info.NetClass == "unknown" {
		info.NetClass = Classify(addr, info.ASOrg)
	}
	return info
}

// ErrNoDB is returned by tools when no database is configured.
var ErrNoDB = errors.New("geo: no database")

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

var classWords = []struct {
	class string
	words []string
}{
	{"tor", []string{"tor exit", "torservers", "tor project"}},
	{"vpn", []string{" vpn", "vpn ", "mullvad", "nordvpn", "proton ag", "expressvpn", "private internet access"}},
	{"education", []string{"university", "universitaet", "universität", "hochschule", "college", "dfn", "research and education", "school"}},
	{"government", []string{"government", "bundes", "ministry", "ministerium", "landesamt", "itzbund"}},
	{"mobile", []string{"mobile", "wireless", "cellular", "vodafone gmbh", "telefonica germany", "o2 "}},
	{"hosting", []string{"hosting", "cloud", "server", "datacenter", "data center", "amazon", "aws", "google llc", "microsoft",
		"hetzner", "ovh", "digitalocean", "linode", "akamai", "contabo", "scaleway", "ionos", "strato", "alibaba", "tencent",
		"oracle", "vultr", "leaseweb", "netcup", "m247", "choopa", "colocrossing"}},
	{"residential", []string{"telekom", "kabel", "vodafone", "comcast", "telecom", "broadband", "dsl", "fiber", "versatel", "netcologne", "1&1"}},
}

// Classify guesses a net class from the address and the AS organisation.
// DB-IP Lite has no net class; this is a coarse heuristic and "unknown" is
// the honest default.
func Classify(addr netip.Addr, asOrg string) string {
	if cgnat.Contains(addr) {
		return "cgnat"
	}
	o := " " + strings.ToLower(asOrg) + " "
	if strings.TrimSpace(o) == "" {
		return "unknown"
	}
	for _, cw := range classWords {
		for _, w := range cw.words {
			if strings.Contains(o, w) {
				return cw.class
			}
		}
	}
	return "unknown"
}
