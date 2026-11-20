package geo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deutschland-schild/schild/contract/config"
)

// PreflightNotes are the `schild preflight` lines of a downloading geo
// provider (none for dbip). They name the token source, never the token.
func PreflightNotes(g config.Geo, getenv func(string) string) []string {
	if !g.Downloads() {
		return nil
	}
	out := []string{fmt.Sprintf("ok        geo provider %s: downloads %s every %d h into %s (outbound to the provider only, no visitor address)",
		g.Provider, strings.Join(g.Database, ", "), g.RefreshHours, ProviderDir(g))}
	src := "$" + config.GeoTokenEnv
	if g.TokenFile != "" {
		src = "token_file " + g.TokenFile
		if st, err := os.Stat(g.TokenFile); err == nil && st.Mode().Perm()&0o077 != 0 {
			out = append(out, fmt.Sprintf("WARN      geo token_file %s is readable by other users (mode %04o): chmod 600", g.TokenFile, st.Mode().Perm()))
		}
	}
	u := &Updater{Provider: g.Provider, TokenFile: g.TokenFile, Getenv: getenv}
	if _, e := u.token(); e != nil {
		out = append(out, fmt.Sprintf("WARN      geo token (%s): %s; the bundled DB-IP database stays in use", src, e.detail))
	} else {
		out = append(out, fmt.Sprintf("ok        geo token from %s", src))
	}
	return out
}

// Found returns the country database schild would open for db_path path:
// the file itself or the one the image ships. ok is false when neither
// exists.
func Found(path string) (file string, ok bool) {
	cp, _ := candidates(path)
	if st, err := os.Stat(cp); err == nil && st.Mode().IsRegular() {
		return cp, true
	}
	return "", false
}

// MissingNote is the one text of the start log and `schild preflight` for
// an installation without a geo database: what is missing, what still works
// and how to add one. Not an error: the tarball ships none.
func MissingNote(g config.Geo) string {
	return fmt.Sprintf("no geo database at %s or %s: country and network of an address stay unknown (ZZ), country rules match nothing; "+
		"the WAF, blocks, events and the dashboard work as usual. The container image ships one; "+
		"for other installations put a country database (.mmdb, e.g. DB-IP Lite) at geo.db_path or set geo.provider with your own token",
		g.DBPath, filepath.Join(ImageDir, "country.mmdb"))
}
