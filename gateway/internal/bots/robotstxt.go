package bots

import (
	"bytes"
	"strings"
)

// robots.txt parsing and matching after RFC 9309: groups of user-agent
// lines with their allow and disallow rules (groups naming the same agent
// are merged), the product token compared case-insensitively, "*" as the
// fallback group, the longest matching rule wins and on equal length allow
// wins, "*" matches any sequence and a trailing "$" anchors at the end,
// /robots.txt itself is always allowed. Observation only: schild never
// enforces it.

// MaxRobotsBytes: a longer robots.txt is parsed up to this size (RFC 9309
// asks crawlers to parse at least 500 KiB).
const MaxRobotsBytes = 512 << 10

type robotsRule struct {
	segs   []string // the pattern split at '*'
	n      int      // pattern length in bytes (precedence)
	allow  bool
	anchor bool // trailing '$'
}

type robotsGroup struct {
	rules []robotsRule
}

// robotsFile is one parsed robots.txt; nil groups and star mean "allow
// everything" (a 4xx answer, or an empty file).
type robotsFile struct {
	groups map[string]*robotsGroup // lower-case product token
	star   *robotsGroup
}

// parseRobots parses a robots.txt body (cut at MaxRobotsBytes).
func parseRobots(body []byte) *robotsFile {
	if len(body) > MaxRobotsBytes {
		body = body[:MaxRobotsBytes]
	}
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	f := &robotsFile{groups: map[string]*robotsGroup{}}
	var cur []*robotsGroup
	inRules := false
	for len(body) > 0 {
		var line []byte
		if i := bytes.IndexAny(body, "\r\n"); i >= 0 {
			line, body = body[:i], body[i+1:]
		} else {
			line, body = body, nil
		}
		if i := bytes.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		k, v, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		key := strings.ToLower(string(bytes.TrimSpace(k)))
		val := string(bytes.TrimSpace(v))
		switch key {
		case "user-agent":
			if inRules {
				cur, inRules = nil, false
			}
			tok := productToken(val)
			if tok == "" {
				continue
			}
			if tok == "*" {
				if f.star == nil {
					f.star = &robotsGroup{}
				}
				cur = append(cur, f.star)
				continue
			}
			g := f.groups[tok]
			if g == nil {
				g = &robotsGroup{}
				f.groups[tok] = g
			}
			cur = append(cur, g)
		case "allow", "disallow":
			if len(cur) == 0 {
				continue // a rule before any user-agent line
			}
			inRules = true
			if val == "" {
				continue // "Disallow:" with no path allows everything
			}
			r := newRule(val, key == "allow")
			for _, g := range cur {
				g.rules = append(g.rules, r)
			}
		}
	}
	return f
}

// productToken: the user-agent value up to the first character that is
// not part of a product token ("Googlebot/2.1" -> "googlebot"), lower case.
func productToken(v string) string {
	if v == "*" || strings.HasPrefix(v, "* ") {
		return "*"
	}
	n := 0
	for n < len(v) && isTokenChar(v[n]) {
		n++
	}
	return strings.Map(lowerASCII, v[:n])
}

func isTokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

func newRule(pat string, allow bool) robotsRule {
	pat = normalizePath(pat)
	r := robotsRule{n: len(pat), allow: allow}
	if strings.HasSuffix(pat, "$") {
		r.anchor = true
		pat = pat[:len(pat)-1]
	}
	r.segs = strings.Split(pat, "*")
	return r
}

// normalizePath percent-encodes bytes outside ASCII and upper-cases the
// hex digits of %xx, so patterns and paths compare octet by octet.
func normalizePath(s string) string {
	if !needsNormalize(s) {
		return s
	}
	return string(appendNormalized(nil, s))
}

func needsNormalize(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x80 || c == '%' && i+2 < len(s) && (isLowerHex(s[i+1]) || isLowerHex(s[i+2])) {
			return true
		}
	}
	return false
}

func isLowerHex(c byte) bool { return c >= 'a' && c <= 'f' }

func appendNormalized(dst []byte, s string) []byte {
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 0x80:
			dst = append(dst, '%', hex[c>>4], hex[c&15])
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			dst = append(dst, '%', upperHex(s[i+1]), upperHex(s[i+2]))
			i += 2
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

func upperHex(c byte) byte {
	if isLowerHex(c) {
		return c - 'a' + 'A'
	}
	return c
}

// match reports whether the rule matches path (normalized).
func (r *robotsRule) match(path string) bool {
	segs := r.segs
	if !strings.HasPrefix(path, segs[0]) {
		return false
	}
	pos := len(segs[0])
	if len(segs) == 1 {
		return !r.anchor || pos == len(path)
	}
	last := len(segs) - 1
	for _, s := range segs[1:last] {
		i := strings.Index(path[pos:], s)
		if i < 0 {
			return false
		}
		pos += i + len(s)
	}
	if !r.anchor {
		return strings.Contains(path[pos:], segs[last])
	}
	return len(path)-len(segs[last]) >= pos && strings.HasSuffix(path, segs[last])
}

// disallowed reports whether the group of token or else the "*" group
// disallows path (tests and tools; Robots.Disallowed is the request-path
// form).
func (f *robotsFile) disallowed(token, path string) bool {
	return f.disallowedB([]byte(strings.Map(lowerASCII, token)), normalizePath(path))
}
