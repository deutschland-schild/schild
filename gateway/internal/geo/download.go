package geo

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/config"
	cgeo "github.com/deutschland-schild/schild/contract/geo"
	"github.com/oschwald/maxminddb-golang/v2"
)

// BYOK download (MVP-22, D35, D38). With geo.provider ipinfo or maxmind the
// gateway downloads the provider's MMDB with the operator's own token from
// the provider's fixed host, checks size, format and sample lookups through
// the contract mapping and swaps it in atomically. No visitor address is
// ever sent anywhere: the database is looked up locally.
//
// Token formats (token_file, one line, or $SCHILD_GEO_TOKEN):
//
//	ipinfo:  the IPinfo access token
//	maxmind: "<account id>:<licence key>"
//
// The token is never logged, never part of an error, of Overview.geo_db or
// of the config. Errors are reduced to the Overview.geo_db.last_error codes
// plus a scrubbed detail for the log.

// Overview.geo_db.last_error codes.
const (
	ErrTokenMissing  = "token_missing"
	ErrTokenRejected = "token_rejected"
	ErrDownload      = "download_failed"
	ErrTooLarge      = "too_large"
	ErrInvalidFormat = "invalid_format"
	ErrSanity        = "sanity_failed"
)

// Fixed provider hosts. Not configurable from schild.yaml; tests replace
// Updater.baseURL.
const (
	ipinfoBase  = "https://ipinfo.io"
	maxmindBase = "https://download.maxmind.com"
)

// MaxDownloadBytes caps one download (compressed) and one extracted
// database. IPinfo Lite and GeoLite2 are well below it.
const MaxDownloadBytes = 512 << 20

const (
	maxTokenBytes  = 4096
	maxTarEntries  = 64
	retryAfter     = time.Hour
	downloadTimout = 15 * time.Minute
	tempMarker     = ".download-"
)

var (
	databaseRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	maxmindTokenRe = regexp.MustCompile(`^([0-9]{1,20}):([!-~]{1,256})$`)
	ipinfoTokenRe  = regexp.MustCompile(`^[!-~]{1,512}$`)
	tokenQueryRe   = regexp.MustCompile(`(?i)(token|license_key|password)=[^&\s"]*`)
)

// sampleAddrs are looked up in every downloaded database before it is used.
var sampleAddrs = []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "2001:4860:4860::8888", "2606:4700:4700::1111"}

// FromConfig opens the geo database of g and, for a downloading provider,
// returns the updater that keeps it fresh (nil otherwise).
func FromConfig(g config.Geo, log *slog.Logger) (*DB, *Updater, error) {
	if !g.Downloads() {
		db, err := Open(g.DBPath)
		return db, nil, err
	}
	dir := ProviderDir(g)
	db, err := OpenProvider(g.Provider, dir, g.Database, g.DBPath)
	u := &Updater{DB: db, Provider: g.Provider, Dir: dir, Databases: g.Database, TokenFile: g.TokenFile,
		Getenv: os.Getenv, Refresh: time.Duration(g.RefreshHours) * time.Hour, Log: log}
	return db, u, err
}

// ProviderDir is where the downloaded databases of g live: a directory per
// provider next to db_path (default /var/lib/schild/geo/<provider>).
func ProviderDir(g config.Geo) string {
	return filepath.Join(filepath.Dir(g.DBPath), g.Provider)
}

// Updater downloads the provider databases.
type Updater struct {
	DB        *DB
	Provider  string
	Dir       string
	Databases []string
	TokenFile string
	Getenv    func(string) string
	Refresh   time.Duration
	Log       *slog.Logger

	// Test hooks (never from schild.yaml).
	baseURL  string
	maxBytes int64
	client   *http.Client
}

func (u *Updater) log() *slog.Logger {
	if u.Log != nil {
		return u.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (u *Updater) limit() int64 {
	if u.maxBytes > 0 {
		return u.maxBytes
	}
	return MaxDownloadBytes
}

func (u *Updater) refresh() time.Duration {
	if u.Refresh > 0 {
		return u.Refresh
	}
	return time.Duration(config.DefaultGeoRefreshHr) * time.Hour
}

func (u *Updater) httpClient() *http.Client {
	if u.client != nil {
		return u.client
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	return &http.Client{Transport: t, Timeout: downloadTimout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("redirect to a non-https URL")
		}
		// net/http drops the Authorization header on a redirect to another
		// host (MaxMind redirects to its storage host with a signed URL).
		return nil
	}}
}

// Run cleans stale temp files, downloads at once when a database is missing
// or older than the refresh interval and then every refresh interval; after a
// failure it retries within an hour. Failures never touch request handling:
// the last good database stays in use.
func (u *Updater) Run(ctx context.Context) {
	u.CleanTemps()
	t := time.NewTimer(u.firstDelay(time.Now()))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		next := u.refresh()
		if code := u.Update(ctx); code != "" {
			next = min(next, retryAfter)
		}
		t.Reset(next)
	}
}

func (u *Updater) firstDelay(now time.Time) time.Duration {
	var oldest time.Time
	for _, name := range u.Databases {
		st, err := os.Stat(filepath.Join(u.Dir, name+".mmdb"))
		if err != nil {
			return 0
		}
		if oldest.IsZero() || st.ModTime().Before(oldest) {
			oldest = st.ModTime()
		}
	}
	if len(u.Databases) == 0 {
		return u.refresh()
	}
	return max(oldest.Add(u.refresh()).Sub(now), 0)
}

// CleanTemps removes download temp files (stale from a crash, D38).
func (u *Updater) CleanTemps() {
	ents, err := os.ReadDir(u.Dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") && strings.Contains(e.Name(), tempMarker) {
			_ = os.Remove(filepath.Join(u.Dir, e.Name()))
		}
	}
}

// removeStale deletes databases of this directory that are no longer
// configured, so only the current files stay (D38).
func (u *Updater) removeStale() {
	keep := map[string]bool{}
	for _, n := range u.Databases {
		keep[n+".mmdb"] = true
	}
	ents, err := os.ReadDir(u.Dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".mmdb") && !keep[e.Name()] {
			_ = os.Remove(filepath.Join(u.Dir, e.Name()))
		}
	}
}

// dlErr is a download failure: a last_error code and a detail that never
// contains the token.
type dlErr struct {
	code   string
	detail string
}

func (e *dlErr) Error() string { return e.code + ": " + e.detail }

func fail(code, detail string) *dlErr { return &dlErr{code: code, detail: detail} }

// scrub reduces err to a message without URLs (net/http errors carry the
// request URL, which for IPinfo holds the token) and without the token.
func scrub(err error, secrets ...string) string {
	if err == nil {
		return ""
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := err.Error()
	for _, s := range secrets {
		if len(s) >= 4 {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
			msg = strings.ReplaceAll(msg, url.QueryEscape(s), "[redacted]")
		}
	}
	msg = tokenQueryRe.ReplaceAllString(msg, "$1=[redacted]")
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// token reads the operator's token: token_file first, else $SCHILD_GEO_TOKEN.
func (u *Updater) token() (string, *dlErr) {
	var raw string
	if u.TokenFile != "" {
		f, err := os.Open(u.TokenFile)
		if err != nil {
			return "", fail(ErrTokenMissing, "token_file not readable")
		}
		b, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+1))
		f.Close()
		if err != nil || len(b) > maxTokenBytes {
			return "", fail(ErrTokenMissing, "token_file not readable or too long")
		}
		raw = string(b)
	} else if u.Getenv != nil {
		raw = u.Getenv(config.GeoTokenEnv)
	}
	if i := strings.IndexAny(raw, "\r\n"); i >= 0 {
		raw = raw[:i]
	}
	tok := strings.TrimSpace(raw)
	if tok == "" {
		return "", fail(ErrTokenMissing, "no token in token_file or "+config.GeoTokenEnv)
	}
	switch u.Provider {
	case cgeo.MaxMind:
		if !maxmindTokenRe.MatchString(tok) {
			return "", fail(ErrTokenMissing, `maxmind token is not "<account id>:<licence key>"`)
		}
	case cgeo.IPInfo:
		if !ipinfoTokenRe.MatchString(tok) {
			return "", fail(ErrTokenMissing, "ipinfo token has unexpected characters")
		}
	}
	return tok, nil
}

// Update downloads every configured database once. It returns "" on success
// or the last_error code of the first failure (also recorded for the
// overview); databases that succeeded are swapped in either way.
func (u *Updater) Update(ctx context.Context) string {
	code := u.update(ctx)
	if code == "" {
		u.DB.refresh.Store(nil)
	} else {
		u.DB.refresh.Store(&refreshState{lastError: code, lastErrorAt: time.Now().UTC()})
	}
	return code
}

func (u *Updater) update(ctx context.Context) string {
	tok, e := u.token()
	if e != nil {
		u.log().Warn("geo download skipped, the last good database stays in use", "provider", u.Provider, "error", e.code, "detail", e.detail)
		return e.code
	}
	secrets := []string{tok}
	if i := strings.IndexByte(tok, ':'); i > 0 {
		secrets = append(secrets, tok[i+1:])
	}
	// The databases are the provider's public reference data (no visitor
	// data, no token), readable like any GeoIP database; the directory
	// lies below storage.path (0700) by default anyway.
	if err := os.MkdirAll(u.Dir, 0o755); err != nil { //nolint:gosec // see above
		u.log().Warn("geo download failed, the last good database stays in use", "provider", u.Provider, "error", ErrDownload, "detail", scrub(err, secrets...))
		return ErrDownload
	}
	first := ""
	swapped := false
	for _, name := range u.Databases {
		info, e := u.fetch(ctx, name, tok)
		if e != nil {
			e.detail = scrub(errors.New(e.detail), secrets...)
			u.log().Warn("geo download failed, the last good database stays in use", "provider", u.Provider, "database", name, "error", e.code, "detail", e.detail)
			if first == "" {
				first = e.code
			}
			continue
		}
		swapped = true
		u.log().Info("geo database updated", "provider", u.Provider, "database", name, "built_at", info.built.Format(time.RFC3339), "bytes", info.size)
	}
	if swapped {
		u.removeStale()
		if err := u.DB.Reload(); err != nil {
			u.log().Warn("geo reload after download", "provider", u.Provider, "detail", scrub(err, secrets...))
		}
	}
	return first
}

type fetched struct {
	built time.Time
	size  int64
}

// fetch downloads one database into a temp file in Dir, checks it and
// renames it over <name>.mmdb. The temp file never survives a failure.
func (u *Updater) fetch(ctx context.Context, name, tok string) (fetched, *dlErr) {
	if !databaseRe.MatchString(name) {
		return fetched{}, fail(ErrDownload, "invalid database id")
	}
	req, err := u.request(ctx, name, tok)
	if err != nil {
		return fetched{}, fail(ErrDownload, scrub(err, tok))
	}
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return fetched{}, fail(ErrDownload, scrub(err, tok))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fetched{}, fail(ErrTokenRejected, fmt.Sprintf("HTTP %d", resp.StatusCode))
	case resp.StatusCode != http.StatusOK:
		return fetched{}, fail(ErrDownload, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}
	limit := u.limit()
	if resp.ContentLength > limit {
		return fetched{}, fail(ErrTooLarge, fmt.Sprintf("%d bytes > %d", resp.ContentLength, limit))
	}
	tmp, err := os.CreateTemp(u.Dir, "."+name+tempMarker+"*")
	if err != nil {
		return fetched{}, fail(ErrDownload, scrub(err, tok))
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()
	body := &capReader{r: resp.Body, left: limit}
	var n int64
	if u.Provider == cgeo.MaxMind {
		n, err = extractMMDB(tmp, body, name, limit)
	} else {
		n, err = io.Copy(tmp, body)
	}
	if err != nil {
		var de *dlErr
		switch {
		case errors.Is(err, errTooLarge):
			return fetched{}, fail(ErrTooLarge, fmt.Sprintf("more than %d bytes", limit))
		case errors.As(err, &de):
			return fetched{}, de
		case ctx.Err() != nil:
			return fetched{}, fail(ErrDownload, "cancelled")
		}
		return fetched{}, fail(ErrDownload, scrub(err, tok))
	}
	if err := tmp.Sync(); err != nil {
		return fetched{}, fail(ErrDownload, scrub(err, tok))
	}
	if err := tmp.Close(); err != nil {
		return fetched{}, fail(ErrDownload, scrub(err, tok))
	}
	built, e := checkDatabase(u.Provider, name, tmpPath, time.Now())
	if e != nil {
		return fetched{}, e
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil { //nolint:gosec // public reference data, see update
		return fetched{}, fail(ErrDownload, scrub(err, tok))
	}
	if err := os.Rename(tmpPath, filepath.Join(u.Dir, name+".mmdb")); err != nil {
		return fetched{}, fail(ErrDownload, scrub(err, tok))
	}
	keep = true
	return fetched{built: built, size: n}, nil
}

// request builds the download request. IPinfo documents the token only as
// query parameter (https://ipinfo.io/data/<db>.mmdb?token=...); MaxMind uses
// HTTP basic auth with account id and licence key
// (https://download.maxmind.com/geoip/databases/<db>/download?suffix=tar.gz).
func (u *Updater) request(ctx context.Context, name, tok string) (*http.Request, error) {
	var raw string
	switch u.Provider {
	case cgeo.IPInfo:
		base := u.baseURL
		if base == "" {
			base = ipinfoBase
		}
		raw = base + "/data/" + url.PathEscape(name) + ".mmdb?token=" + url.QueryEscape(tok)
	case cgeo.MaxMind:
		base := u.baseURL
		if base == "" {
			base = maxmindBase
		}
		raw = base + "/geoip/databases/" + url.PathEscape(name) + "/download?suffix=tar.gz"
	default:
		return nil, fmt.Errorf("provider %q does not download", u.Provider)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, errors.New("invalid download request")
	}
	if u.Provider == cgeo.MaxMind {
		id, key, _ := strings.Cut(tok, ":")
		req.SetBasicAuth(id, key)
	}
	req.Header.Set("User-Agent", "schild-geo")
	return req, nil
}

var errTooLarge = errors.New("too large")

// capReader fails once more than left bytes were read.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return n, errTooLarge
	}
	return n, err
}

// extractMMDB copies <name>.mmdb out of a MaxMind tar.gz into dst. Paths of
// the archive are never used for writing.
func extractMMDB(dst io.Writer, src io.Reader, name string, limit int64) (int64, error) {
	zr, err := gzip.NewReader(src)
	if err != nil {
		if errors.Is(err, errTooLarge) {
			return 0, err
		}
		return 0, fail(ErrInvalidFormat, "not a gzip archive")
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for i := 0; i < maxTarEntries; i++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, errTooLarge) {
				return 0, err
			}
			return 0, fail(ErrInvalidFormat, "broken tar archive")
		}
		if h.Typeflag != tar.TypeReg || path.Base(h.Name) != name+".mmdb" {
			continue
		}
		if h.Size > limit {
			return 0, errTooLarge
		}
		n, err := io.Copy(dst, &capReader{r: tr, left: limit})
		if err != nil {
			if errors.Is(err, errTooLarge) {
				return n, err
			}
			return n, fail(ErrInvalidFormat, "broken tar archive")
		}
		return n, nil
	}
	return 0, fail(ErrInvalidFormat, "archive has no "+name+".mmdb")
}

var minBuild = time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)

// checkDatabase opens and verifies a downloaded file: MMDB format, plausible
// metadata and sample lookups that map through contract geo.Map.
func checkDatabase(provider, name, file string, now time.Time) (time.Time, *dlErr) {
	r, err := maxminddb.Open(file)
	if err != nil {
		return time.Time{}, fail(ErrInvalidFormat, "not an MMDB file")
	}
	defer r.Close()
	if err := r.Verify(); err != nil {
		return time.Time{}, fail(ErrInvalidFormat, "MMDB verification failed")
	}
	md := r.Metadata
	built := time.Unix(int64(md.BuildEpoch), 0).UTC()
	switch {
	case md.BinaryFormatMajorVersion != 2 || md.IPVersion != 4 && md.IPVersion != 6 || md.NodeCount == 0:
		return time.Time{}, fail(ErrSanity, "unexpected MMDB metadata")
	case built.Before(minBuild) || built.After(now.Add(48*time.Hour)):
		return time.Time{}, fail(ErrSanity, "implausible build date")
	case md.DatabaseType == "":
		return time.Time{}, fail(ErrSanity, "no database type")
	case provider == cgeo.MaxMind && !strings.EqualFold(md.DatabaseType, name):
		return time.Time{}, fail(ErrSanity, "database type "+safeType(md.DatabaseType)+" is not "+name)
	}
	found := false
	for _, s := range sampleAddrs {
		ip, perr := netip.ParseAddr(s)
		if perr != nil || !ip.Is4() && md.IPVersion == 4 {
			continue
		}
		var m map[string]any
		res := r.Lookup(ip)
		if err := res.Decode(&m); err != nil {
			return time.Time{}, fail(ErrSanity, "sample lookup "+s+" failed")
		}
		if !res.Found() {
			continue
		}
		rec, err := cgeo.Map(provider, m)
		if err != nil {
			return time.Time{}, fail(ErrSanity, "sample record "+s+" does not map")
		}
		if rec.Country != cgeo.UnknownCountry || rec.ASN != nil {
			found = true
		}
	}
	if !found && carriesLocation(provider, md.DatabaseType) {
		return time.Time{}, fail(ErrSanity, "no sample address found")
	}
	return built, nil
}

// carriesLocation reports whether a database covers every public address
// with a country or an ASN, so the sample addresses must be found. Flag-only
// databases (MaxMind Anonymous-IP, Connection-Type) need not list them.
func carriesLocation(provider, dbType string) bool {
	if provider != cgeo.MaxMind {
		return true
	}
	t := strings.ToLower(dbType)
	for _, k := range []string{"country", "city", "asn", "isp", "enterprise"} {
		if strings.Contains(t, k) {
			return true
		}
	}
	return false
}

func safeType(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return fmt.Sprintf("%q", s)
}

// optionalFields lists the paid-tier fields (contract geo.OptionalFields)
// the databases provide: probed on the first networks of each database and
// known from the MaxMind database types.
func optionalFields(provider string, readers []*maxminddb.Reader) []string {
	const probe = 20000
	var present uint8
	carrier := false
	for _, r := range readers {
		t := strings.ToLower(r.Metadata.DatabaseType)
		if provider == cgeo.MaxMind {
			if strings.Contains(t, "anonymous-ip") {
				present |= flagVPN | flagProxy | flagTor | flagHosting
			}
			if strings.Contains(t, "connection-type") || strings.Contains(t, "enterprise") {
				present |= flagMobile
			}
		}
		i := 0
		for res := range r.Networks() {
			if i++; i > probe {
				break
			}
			var n norm
			var ok bool
			switch provider {
			case cgeo.IPInfo:
				var rec ipinfoRecord
				if err := res.Decode(&rec); err != nil {
					continue
				}
				n, ok = rec.norm()
			case cgeo.MaxMind:
				var rec maxmindRecord
				if err := res.Decode(&rec); err != nil {
					continue
				}
				n, ok = rec.norm()
			}
			if ok {
				present |= n.present
				carrier = carrier || n.carrier != ""
			}
		}
	}
	var out []string
	for _, f := range cgeo.OptionalFields {
		switch f {
		case "carrier":
			if carrier {
				out = append(out, f)
			}
		default:
			for _, ff := range flagFields {
				if ff.field == f && present&ff.bit != 0 {
					out = append(out, f)
				}
			}
		}
	}
	return out
}
