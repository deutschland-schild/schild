// Package buildinfo holds version information set at link time.
package buildinfo

import (
	"runtime/debug"

	"github.com/deutschland-schild/schild/contract/keys"
)

// Version is set with -ldflags "-X github.com/deutschland-schild/schild/gateway/internal/buildinfo.Version=...".
var Version = "0.1.0-alpha"

// CRSVersion is the OWASP CRS release embedded via coraza-coreruleset.
const CRSVersion = "4.30.0"

// String renders the version line shown by `schild version` and the dashboard.
func String() string {
	s := "schild " + Version
	if keys.Release {
		s += " (release)"
	} else {
		s += " (non-release: test keys and test profile allowed)"
	}
	return s
}

// Deps lists the main module versions compiled into the binary.
func Deps() map[string]string {
	out := map[string]string{}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return out
	}
	for _, d := range bi.Deps {
		switch d.Path {
		case "github.com/caddyserver/caddy/v2", "github.com/corazawaf/coraza/v3", "github.com/corazawaf/coraza-caddy/v2",
			"github.com/corazawaf/coraza-coreruleset/crs/v4", "modernc.org/sqlite", "github.com/oschwald/maxminddb-golang/v2":
			out[d.Path] = d.Version
		}
	}
	return out
}
