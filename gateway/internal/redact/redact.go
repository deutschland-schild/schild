// Package redact removes secrets from what Schild stores locally (concept 24,
// V1): passwords, tokens, cookies, Authorization and e-mail addresses in
// paths, query strings and rule messages are replaced before anything is
// written. Request bodies are never stored.
package redact

import (
	"net/url"
	"regexp"
	"strings"
)

// Marker replaces a redacted value.
const Marker = "[redacted]"

// secretNames are parameter names (lower case, separators removed) whose
// values are always redacted. A name carries one when it is, starts with or
// ends in one of them ("csrfmiddlewaretoken", "user_password").
var secretNames = []string{
	"passwd", "password", "passcode", "secret", "token", "nonce", "authorization", "apikey", "privatekey",
	"session", "phpsessid", "jsessionid", "bearer", "signature", "credential", "cookie", "creditcard",
	"authcode", "resetcode", "accesscode", "invitecode", "verificationcode",
}

// secretWords are short names that are part of many harmless ones ("monkey",
// "zipcode", "bypass", "shipping"): they count only as a word of their own,
// as in "api_key", "apiKey" or "pwd".
var secretWords = map[string]bool{
	"pass": true, "pwd": true, "pw": true, "pin": true, "otp": true, "totp": true, "csrf": true, "xsrf": true,
	"auth": true, "key": true, "sid": true, "jwt": true, "sig": true, "hash": true, "ssn": true, "iban": true,
	"cc": true, "cvv": true, "cvc": true,
}

func normName(s string) string {
	s = strings.ToLower(s)
	return strings.NewReplacer("-", "", "_", "", ".", "", "[", "", "]", "").Replace(s)
}

// words splits a parameter name at separators and at camel case: "apiKey",
// "api_key" and "api[key]" are api and key.
func words(name string) []string {
	var out []string
	start := 0
	flush := func(end int) {
		if end > start {
			out = append(out, strings.ToLower(name[start:end]))
		}
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '-' || c == '_' || c == '.' || c == '[' || c == ']' || c == ' ':
			flush(i)
			start = i + 1
		case c >= 'A' && c <= 'Z' && i > start && name[i-1] >= 'a' && name[i-1] <= 'z':
			flush(i)
			start = i
		}
	}
	flush(len(name))
	return out
}

// IsSecretName reports whether a parameter name looks like it carries a secret.
// "code" alone is the OAuth code; "zip_code" or "country_code" are not secret.
func IsSecretName(name string) bool {
	n := normName(name)
	if n == "code" || secretWords[n] {
		return true
	}
	for _, s := range secretNames {
		if strings.HasSuffix(n, s) || strings.HasPrefix(n, s) {
			return true
		}
	}
	for _, w := range words(name) {
		if secretWords[w] {
			return true
		}
	}
	return false
}

var (
	emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+-]+(@|%40)[a-z0-9.-]+\.[a-z]{2,}`)
	jwtRe   = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
	// Long opaque tokens: 32+ chars of the base64/hex alphabet that look random, see looksLikeToken.
	tokenRe = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{32,}`)
)

// looksLikeToken tells a random value from a long name. A token mixes digits
// and letters within its parts ("9f8a7b6c…", "Ab3dE5gH…"); a slug, a file name
// or an app name is made of words and numbers ("my-long-post-title-2024",
// "IMG_20240101_123456789_HDR", "SomeLongAppName-iOS/20261"). At least half of
// the characters must sit in parts that hold both a digit and a letter.
func looksLikeToken(s string) bool {
	mixed, start := 0, 0
	hasDigit, hasLetter := false, false
	flush := func(end int) {
		if hasDigit && hasLetter {
			mixed += end - start
		}
		hasDigit, hasLetter = false, false
		start = end + 1
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			hasLetter = true
		default:
			flush(i)
		}
	}
	flush(len(s))
	return mixed*2 >= len(s)
}

// Text redacts e-mail addresses, JWTs and long opaque tokens in free text
// (path segments, query values, rule messages).
func Text(s string) string {
	if s == "" {
		return s
	}
	s = emailRe.ReplaceAllString(s, Marker)
	s = jwtRe.ReplaceAllString(s, Marker)
	s = tokenRe.ReplaceAllStringFunc(s, func(m string) string {
		if looksLikeToken(m) {
			return Marker
		}
		return m
	})
	return s
}

// Query redacts a raw query string: values of secret-looking parameters and
// values that contain e-mail addresses or tokens. Parameter order and names
// are kept (names are redacted too when they look like an e-mail).
func Query(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		k, v, hasV := strings.Cut(p, "=")
		dk, err := url.QueryUnescape(k)
		if err != nil {
			dk = k
		}
		if emailRe.MatchString(dk) {
			k = Marker
		}
		if !hasV {
			parts[i] = k
			continue
		}
		dv, err := url.QueryUnescape(v)
		if err != nil {
			dv = v
		}
		switch {
		case IsSecretName(dk):
			v = Marker
		case Text(dv) != dv:
			v = url.QueryEscape(Text(dv))
		}
		parts[i] = k + "=" + v
	}
	out := strings.Join(parts, "&")
	if len(out) > 4096 {
		out = out[:4096]
	}
	return out
}

// Path redacts e-mail addresses and tokens in a URL path, one segment at a
// time: the token alphabet includes '/', so on the whole path a run like
// "/build/assets/app-Bx12AbCd" became one token and the path "[redacted].js".
func Path(p string) string {
	if len(p) > 2048 {
		p = p[:2048]
	}
	seg := strings.Split(p, "/")
	for i := range seg {
		seg[i] = Text(seg[i])
	}
	return strings.Join(seg, "/")
}

// UserAgent keeps the user agent as sent, cut to 1024 bytes. It names
// software, not a person: an app name with a build number is no token and the
// contact address of a crawler is public (D85).
func UserAgent(ua string) string {
	if len(ua) > 1024 {
		ua = ua[:1024]
	}
	return ua
}
