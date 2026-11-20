package hostcheck

import (
	"regexp"
	"strings"
)

// CompareVersions compares two package or kernel versions with the dpkg
// algorithm (epoch, then upstream and revision by alternating non-digit and
// digit runs, '~' sorts before everything). It is good enough for RPM
// versions and kernel release strings as well. Result: -1, 0 or 1.
func CompareVersions(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if c := cmpPart(ea, eb); c != 0 {
		return c
	}
	return cmpPart(ra, rb)
}

func splitEpoch(v string) (string, string) {
	if i := strings.IndexByte(v, ':'); i > 0 && strings.Trim(v[:i], "0123456789") == "" {
		return v[:i], v[i+1:]
	}
	return "0", v
}

func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func cmpPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// non-digit run
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ac, bc int
			if i < len(a) && !isDigit(a[i]) {
				ac = order(a[i])
			}
			if j < len(b) && !isDigit(b[j]) {
				bc = order(b[j])
			}
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			if i < len(a) && !isDigit(a[i]) {
				i++
			}
			if j < len(b) && !isDigit(b[j]) {
				j++
			}
		}
		// digit run
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		si, sj := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		da, db := a[si:i], b[sj:j]
		if len(da) != len(db) {
			if len(da) < len(db) {
				return -1
			}
			return 1
		}
		if da != db {
			if da < db {
				return -1
			}
			return 1
		}
	}
	return 0
}

var upstreamRe = regexp.MustCompile(`^(?:[0-9]+:)?([0-9]+(?:\.[0-9]+)*)`)

// Upstream returns the leading dotted number of a version ("2:8.2.7-1~deb12u1"
// -> "8.2.7"), or "".
func Upstream(v string) string {
	m := upstreamRe.FindStringSubmatch(v)
	if m == nil {
		return ""
	}
	return m[1]
}

// Cycle returns the first n dotted components of a version ("8.2.7", 2 ->
// "8.2").
func Cycle(v string, n int) string {
	parts := strings.Split(Upstream(v), ".")
	if len(parts) < n || parts[0] == "" {
		return ""
	}
	return strings.Join(parts[:n], ".")
}

var versionTokenRe = regexp.MustCompile(`^[A-Za-z0-9.+~:_-]{1,128}$`)

// cleanVersion returns v when it fits the contract's version pattern.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	if versionTokenRe.MatchString(v) {
		return v
	}
	return ""
}
