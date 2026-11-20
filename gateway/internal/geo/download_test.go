package geo

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cgeo "github.com/deutschland-schild/schild/contract/geo"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// Fake tokens (TEST ONLY): distinctive strings to search for.
const (
	testIPInfoToken = "TESTONLYipinfoTok3n0000"
	testMMAccount   = "999001"
	testMMKey       = "TESTONLYmaxmindLic3nse00"
)

// provider is a fake IPinfo/MaxMind download host.
type provider struct {
	mu       sync.Mutex
	files    map[string][]byte // path -> body
	status   int
	chunked  bool
	requests atomic.Int64
	paths    []string
}

func (p *provider) set(path string, body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.files == nil {
		p.files = map[string][]byte{}
	}
	p.files[path] = body
}

func (p *provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.requests.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paths = append(p.paths, r.URL.Path)
	if p.status != 0 {
		http.Error(w, "nope "+r.URL.String(), p.status) // echo the URL like some servers do
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/data/"):
		if r.URL.Query().Get("token") != testIPInfoToken {
			http.Error(w, "bad token", http.StatusForbidden)
			return
		}
	case strings.HasPrefix(r.URL.Path, "/geoip/databases/"):
		u, pw, ok := r.BasicAuth()
		if !ok || u != testMMAccount || pw != testMMKey || r.URL.Query().Get("suffix") != "tar.gz" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	b, ok := p.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if p.chunked {
		// No Content-Length: the cap must hold while streaming.
		_, _ = w.Write(b[:1])
		w.(http.Flusher).Flush()
		b = b[1:]
	}
	_, _ = w.Write(b)
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type harness struct {
	t    *testing.T
	srv  *httptest.Server
	prov *provider
	u    *Updater
	db   *DB
	logs *logBuf
}

func newHarness(t *testing.T, providerName string, databases []string) *harness {
	t.Helper()
	h := &harness{t: t, prov: &provider{}, logs: &logBuf{}}
	h.srv = httptest.NewServer(h.prov)
	t.Cleanup(h.srv.Close)
	root := t.TempDir()
	tokFile := filepath.Join(root, "geo.token")
	tok := testIPInfoToken
	if providerName == cgeo.MaxMind {
		tok = testMMAccount + ":" + testMMKey
	}
	if err := os.WriteFile(tokFile, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := config.Geo{DBPath: filepath.Join(root, "geo", "geo.mmdb"), Provider: providerName, TokenFile: tokFile, Database: databases, RefreshHours: 24}
	var err error
	var u *Updater
	h.db, u, err = FromConfig(g, slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err == nil && h.db.Loaded() {
		t.Skip("a bundled geo database is installed on this machine")
	}
	h.u = u
	h.u.baseURL = h.srv.URL
	h.u.client = h.srv.Client()
	return h
}

func (h *harness) files() []string {
	ents, _ := os.ReadDir(h.u.Dir)
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func (h *harness) wantFiles(want ...string) {
	h.t.Helper()
	sort.Strings(want)
	if got := h.files(); strings.Join(got, ",") != strings.Join(want, ",") {
		h.t.Fatalf("geo dir holds %v, want %v", got, want)
	}
}

func (h *harness) update(want string) {
	h.t.Helper()
	if got := h.u.Update(context.Background()); got != want {
		h.t.Fatalf("update: %q, want %q; log:\n%s", got, want, h.logs)
	}
	src := h.db.SourceInfo()
	if src.LastError != want {
		h.t.Fatalf("last_error %q want %q", src.LastError, want)
	}
}

func (h *harness) noSecrets() {
	h.t.Helper()
	ov, _ := json.Marshal(h.db.SourceInfo())
	cfg, _ := json.Marshal(config.Geo{Provider: h.u.Provider, TokenFile: h.u.TokenFile, Database: h.u.Databases})
	for _, where := range []struct{ name, text string }{{"log", h.logs.String()}, {"overview", string(ov)}, {"config", string(cfg)}} {
		for _, s := range []string{testIPInfoToken, testMMKey, testMMAccount + ":"} {
			if strings.Contains(where.text, s) {
				h.t.Fatalf("token in %s: %s", where.name, where.text)
			}
		}
	}
}

var probe = netip.MustParseAddr("8.8.8.8")

func TestIPInfoDownload(t *testing.T) {
	h := newHarness(t, cgeo.IPInfo, []string{"ipinfo_lite"})
	if got := h.db.Lookup(probe); got.Country != "ZZ" {
		t.Fatalf("before download: %+v", got)
	}
	if d := h.u.firstDelay(time.Now()); d != 0 {
		t.Fatalf("no database yet: first download after %v", d)
	}
	h.prov.set("/data/ipinfo_lite.mmdb", ipinfoLite(t, testBuild, nil))
	h.update("")
	h.wantFiles("ipinfo_lite.mmdb")
	if got := h.db.Lookup(probe); got.Country != "US" || got.ASN != 64510 || got.ASOrg != "Example Search LLC" {
		t.Fatalf("after download: %+v", got)
	}
	src := h.db.SourceInfo()
	if src.Provider != "ipinfo" || !src.Downloads || !src.Loaded || strings.Join(src.Databases, ",") != "ipinfo_lite" ||
		src.BuiltAt.Unix() != testBuild || src.RefreshedAt.IsZero() || src.LastError != "" {
		t.Fatalf("source %+v", src)
	}
	if d := h.u.firstDelay(time.Now()); d < 23*time.Hour {
		t.Fatalf("fresh database: next download after %v", d)
	}
	h.noSecrets()
}

func TestMaxMindDownload(t *testing.T) {
	h := newHarness(t, cgeo.MaxMind, []string{"GeoLite2-Country", "GeoLite2-ASN"})
	h.prov.set("/geoip/databases/GeoLite2-Country/download", tarGz(t, "GeoLite2-Country", geoliteCountry(t, testBuild)))
	h.prov.set("/geoip/databases/GeoLite2-ASN/download", tarGz(t, "GeoLite2-ASN", geoliteASN(t, testBuild)))
	h.update("")
	h.wantFiles("GeoLite2-Country.mmdb", "GeoLite2-ASN.mmdb")
	for _, n := range testNets {
		a := netip.MustParsePrefix(n.cidr).Addr().Next()
		want := Info{Country: n.country, ASN: n.asn, ASOrg: n.asOrg, NetClass: Classify(a, n.asOrg)}
		if got := h.db.Lookup(a); got != want {
			t.Errorf("%s: %+v want %+v", a, got, want)
		}
	}
	src := h.db.SourceInfo()
	if src.Provider != "maxmind" || strings.Join(src.Databases, ",") != "GeoLite2-Country,GeoLite2-ASN" || len(src.OptionalFields) != 0 {
		t.Fatalf("source %+v", src)
	}
	h.noSecrets()
}

func TestMaxMindPaidOptionalFields(t *testing.T) {
	dbs := []string{"GeoLite2-Country", "GeoLite2-ASN", "GeoIP2-Anonymous-IP"}
	h := newHarness(t, cgeo.MaxMind, dbs)
	h.prov.set("/geoip/databases/GeoLite2-Country/download", tarGz(t, "GeoLite2-Country", geoliteCountry(t, testBuild)))
	h.prov.set("/geoip/databases/GeoLite2-ASN/download", tarGz(t, "GeoLite2-ASN", geoliteASN(t, testBuild)))
	h.prov.set("/geoip/databases/GeoIP2-Anonymous-IP/download", tarGz(t, "GeoIP2-Anonymous-IP", anonymousIP(t, testBuild)))
	h.update("")
	if got := h.db.Lookup(netip.MustParseAddr("203.0.113.5")); got.NetClass != "vpn" {
		t.Fatalf("anonymous vpn: %+v", got)
	}
	if got := h.db.Lookup(probe); got.NetClass != "hosting" {
		t.Fatalf("hosting: %+v", got)
	}
	if got := h.db.SourceInfo().OptionalFields; strings.Join(got, ",") != "is_vpn,is_proxy,is_tor,is_hosting" {
		t.Fatalf("optional fields %v", got)
	}
}

// TestFailuresKeepLastGood: every kind of failure keeps the database in
// use, records last_error, leaves no temp file and never shows the token.
func TestFailuresKeepLastGood(t *testing.T) {
	h := newHarness(t, cgeo.IPInfo, []string{"ipinfo_lite"})
	good := ipinfoLite(t, testBuild, nil)
	h.prov.set("/data/ipinfo_lite.mmdb", good)
	h.update("")
	before := h.db.SourceInfo()
	path := "/data/ipinfo_lite.mmdb"

	badCountry := newWriter(t, "ipinfo ipinfo_lite.mmdb", testBuild+86400)
	insert(t, badCountry, "8.8.8.0/24", mmdbtype.Map{"country_code": mmdbtype.String("USA")})
	old := newWriter(t, "ipinfo ipinfo_lite.mmdb", 1000)
	insert(t, old, "8.8.8.0/24", mmdbtype.Map{"country_code": mmdbtype.String("US")})
	empty := newWriter(t, "ipinfo ipinfo_lite.mmdb", testBuild+86400)
	insert(t, empty, "203.0.113.0/24", mmdbtype.Map{"country_code": mmdbtype.String("NL")})
	truncated := good[:len(good)/2]

	cases := []struct {
		name    string
		status  int
		chunked bool
		body    []byte
		cap     int64
		want    string
	}{
		{"oversized", 0, false, ipinfoLite(t, testBuild+86400, nil), 1024, ErrTooLarge},
		{"oversized chunked", 0, true, ipinfoLite(t, testBuild+86400, nil), 1024, ErrTooLarge},
		{"broken", 0, false, []byte("<html>not a database</html>"), 0, ErrInvalidFormat},
		{"truncated", 0, false, truncated, 0, ErrInvalidFormat},
		{"sample does not map", 0, false, bytesOf(t, badCountry), 0, ErrSanity},
		{"implausible build date", 0, false, bytesOf(t, old), 0, ErrSanity},
		{"no sample address", 0, false, bytesOf(t, empty), 0, ErrSanity},
		{"401", http.StatusUnauthorized, false, nil, 0, ErrTokenRejected},
		{"403", http.StatusForbidden, false, nil, 0, ErrTokenRejected},
		{"500", http.StatusInternalServerError, false, nil, 0, ErrDownload},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h.t = t
			h.prov.mu.Lock()
			h.prov.status, h.prov.chunked = c.status, c.chunked
			h.prov.mu.Unlock()
			if c.body != nil {
				h.prov.set(path, c.body)
			}
			h.u.maxBytes = c.cap
			h.update(c.want)
			h.wantFiles("ipinfo_lite.mmdb")
			now := h.db.SourceInfo()
			if !now.BuiltAt.Equal(before.BuiltAt) || !now.RefreshedAt.Equal(before.RefreshedAt) || h.db.Lookup(probe).Country != "US" {
				t.Fatalf("database changed: %+v", now)
			}
			if now.LastErrorAt.IsZero() {
				t.Fatal("no last_error_at")
			}
			h.noSecrets()
		})
	}
	h.t = t
	h.prov.mu.Lock()
	h.prov.status, h.prov.chunked = 0, false
	h.prov.mu.Unlock()
	h.u.maxBytes = 0
	h.prov.set(path, ipinfoLite(t, testBuild+86400, nil))
	h.update("")
	h.wantFiles("ipinfo_lite.mmdb")
	if src := h.db.SourceInfo(); src.BuiltAt.Unix() != testBuild+86400 {
		t.Fatalf("not swapped: %+v", src)
	}
}

func TestMaxMindArchiveFailures(t *testing.T) {
	h := newHarness(t, cgeo.MaxMind, []string{"GeoLite2-Country"})
	p := "/geoip/databases/GeoLite2-Country/download"
	h.prov.set(p, tarGz(t, "GeoLite2-Country", geoliteCountry(t, testBuild)))
	h.update("")
	// A small archive that inflates beyond the cap (zip bomb).
	big := bytes.Repeat([]byte{0}, 4<<20)
	h.prov.set(p, tarGz(t, "GeoLite2-Country", big))
	h.u.maxBytes = 1 << 20
	h.update(ErrTooLarge)
	h.u.maxBytes = 0
	h.prov.set(p, tarGz(t, "Other", geoliteCountry(t, testBuild)))
	h.update(ErrInvalidFormat)
	h.prov.set(p, []byte("not gzip"))
	h.update(ErrInvalidFormat)
	// The ASN database where the country database is expected.
	h.prov.set(p, tarGz(t, "GeoLite2-Country", geoliteASN(t, testBuild)))
	h.update(ErrSanity)
	h.wantFiles("GeoLite2-Country.mmdb")
	if h.db.Lookup(probe).Country != "US" {
		t.Fatal("lost the last good database")
	}
}

func TestTokenMissingAndMalformed(t *testing.T) {
	h := newHarness(t, cgeo.MaxMind, []string{"GeoLite2-Country"})
	if err := os.WriteFile(h.u.TokenFile, []byte(testMMKey+"\n"), 0o600); err != nil { // no account id
		t.Fatal(err)
	}
	h.update(ErrTokenMissing)
	os.Remove(h.u.TokenFile)
	h.update(ErrTokenMissing)
	if n := h.prov.requests.Load(); n != 0 {
		t.Fatalf("%d requests without a token", n)
	}
	// Environment variable when no token_file is set.
	h.u.TokenFile = ""
	h.u.Getenv = func(k string) string {
		if k == config.GeoTokenEnv {
			return testMMAccount + ":" + testMMKey
		}
		return ""
	}
	h.prov.set("/geoip/databases/GeoLite2-Country/download", tarGz(t, "GeoLite2-Country", geoliteCountry(t, testBuild)))
	h.update("")
	h.noSecrets()
}

// TestTokenNeverLogged provokes errors that carry the request URL (which
// for IPinfo holds the token): a closed server and a redirect loop.
func TestTokenNeverLogged(t *testing.T) {
	h := newHarness(t, cgeo.IPInfo, []string{"ipinfo_lite"})
	h.srv.Close()
	h.update(ErrDownload)
	h.noSecrets()
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	}))
	defer loop.Close()
	h.u.baseURL, h.u.client = loop.URL, loop.Client()
	h.update(ErrDownload)
	h.noSecrets()
	if !strings.Contains(h.logs.String(), "geo download failed") || strings.Contains(h.logs.String(), "/data/") {
		t.Fatalf("expected scrubbed failure logs:\n%s", h.logs)
	}
	// The production client refuses redirects to plain http.
	h.u.client = nil
	h.u.baseURL = loop.URL
	h.update(ErrDownload)
	h.noSecrets()
}

func TestScrub(t *testing.T) {
	tok := "s3cr3t+token/x"
	for _, msg := range []string{
		`Get "https://ipinfo.io/data/x.mmdb?token=s3cr3t%2Btoken%2Fx": dial tcp: refused`,
		"failed for s3cr3t+token/x",
		"url ?license_key=abc&x=1 password=hunter2",
	} {
		got := scrub(errString(msg), tok)
		if strings.Contains(got, "s3cr3t") || strings.Contains(got, "abc&") || strings.Contains(got, "hunter2") {
			t.Errorf("scrub(%q) = %q", msg, got)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// TestTempFilesCleaned: stale temp files from a crash go at start, and
// databases no longer configured go after the next swap (D38).
func TestTempFilesCleaned(t *testing.T) {
	h := newHarness(t, cgeo.IPInfo, []string{"ipinfo_lite"})
	if err := os.MkdirAll(h.u.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".ipinfo_lite.download-123", ".ipinfo_plus.download-9", "ipinfo_plus.mmdb"} {
		if err := os.WriteFile(filepath.Join(h.u.Dir, f), []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h.u.CleanTemps()
	h.wantFiles("ipinfo_plus.mmdb")
	h.prov.set("/data/ipinfo_lite.mmdb", ipinfoLite(t, testBuild, nil))
	for i := 0; i < 3; i++ {
		h.update("")
		h.wantFiles("ipinfo_lite.mmdb")
	}
}

// TestLookupsDoNoNetworkIO: lookups after a download never touch the
// network: no request reaches the provider and the default transport is
// never used.
func TestLookupsDoNoNetworkIO(t *testing.T) {
	h := newHarness(t, cgeo.IPInfo, []string{"ipinfo_lite"})
	h.prov.set("/data/ipinfo_lite.mmdb", ipinfoLite(t, testBuild, nil))
	h.update("")
	n := h.prov.requests.Load()
	orig := http.DefaultTransport
	var used atomic.Bool
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		used.Store(true)
		return nil, http.ErrHandlerTimeout
	})
	defer func() { http.DefaultTransport = orig }()
	for _, a := range []string{"8.8.8.8", "1.1.1.1", "203.0.113.9", "2001:4860::1", "100.64.0.1", "192.0.2.1"} {
		for i := 0; i < 100; i++ {
			_ = h.db.Lookup(netip.MustParseAddr(a))
		}
	}
	if h.prov.requests.Load() != n || used.Load() {
		t.Fatal("a lookup did network I/O")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestRunDownloadsAtStart: the loop downloads at once without a database.
func TestRunDownloadsAtStart(t *testing.T) {
	h := newHarness(t, cgeo.IPInfo, []string{"ipinfo_lite"})
	h.prov.set("/data/ipinfo_lite.mmdb", ipinfoLite(t, testBuild, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.u.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for h.db.Lookup(probe).Country != "US" {
		if time.Now().After(deadline) {
			t.Fatal("no download at start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

// TestFallbackToBundled: until the first download the bundled database
// stays in use; the overview names the configured provider.
func TestFallbackToBundled(t *testing.T) {
	root := t.TempDir()
	bundled := filepath.Join(root, "geo", "geo.mmdb")
	if err := WriteFixture(bundled); err != nil {
		t.Fatal(err)
	}
	db, u, err := FromConfig(config.Geo{DBPath: bundled, Provider: cgeo.IPInfo, Database: []string{"ipinfo_lite"}, RefreshHours: 24}, nil)
	if err != nil || u == nil {
		t.Fatal(err)
	}
	if got := db.Lookup(netip.MustParseAddr("203.0.113.1")); got.Country != "NL" {
		t.Fatalf("bundled fallback: %+v", got)
	}
	src := db.SourceInfo()
	if src.Provider != "ipinfo" || len(src.Databases) != 0 || !src.Loaded {
		t.Fatalf("%+v", src)
	}
	if u.Dir != filepath.Join(root, "geo", "ipinfo") {
		t.Fatal(u.Dir)
	}
	// dbip: no updater.
	if _, u, _ := FromConfig(config.Geo{DBPath: bundled, Provider: cgeo.DBIP}, nil); u != nil {
		t.Fatal("dbip must not download")
	}
}
