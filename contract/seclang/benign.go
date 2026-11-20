package seclang

import (
	"regexp"
	"strings"
)

// BenignCorpus holds values that occur in ordinary traffic of almost every
// site: paths, methods, protocols, header names, browser user agents, accept
// headers, short parameter values. A rule needs at least one line whose
// operator matches none of them; otherwise it is a catch-all (contracts/
// seclang-subset.md, section Catch-all check). The list is part of the
// contract: the Python cross-check has the same values in the same order.
// All values are printable ASCII without newlines.
var BenignCorpus = []string{
	"",
	" ",
	"0",
	"1",
	"2",
	"10",
	"100",
	"a",
	"x",
	"id",
	"q",
	"page",
	"en",
	"de",
	"true",
	"false",
	"null",
	"test",
	"hello world",
	"Max Mustermann",
	"max@example.org",
	"2026-10-26",
	"2026-10-26T12:00:00Z",
	"/",
	"/index.php",
	"/index.html",
	"/favicon.ico",
	"/robots.txt",
	"/search?q=test",
	"q=test",
	"page=2&sort=asc",
	"GET",
	"POST",
	"HEAD",
	"OPTIONS",
	"HTTP/1.0",
	"HTTP/1.1",
	"HTTP/2",
	"HTTP/2.0",
	"HTTP/3",
	"GET / HTTP/1.1",
	"GET /index.php?page=2 HTTP/1.1",
	"Host",
	"host",
	"User-Agent",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
	"Connection",
	"Cookie",
	"Content-Type",
	"Content-Length",
	"Referer",
	"Origin",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"*/*",
	"application/json",
	"application/x-www-form-urlencoded",
	"multipart/form-data; boundary=----schild",
	"text/plain;charset=UTF-8",
	"de-DE,de;q=0.9,en;q=0.8",
	"gzip, deflate, br, zstd",
	"keep-alive",
	"max-age=0",
	"same-origin",
	"session=0123456789abcdef",
	"{\"a\":1}",
	"<p>Hallo</p>",
}

// MatchesBenign reports whether the string operator op with argument arg
// matches at least one value of BenignCorpus, with Coraza's semantics:
// @rx searches (RE2), @pm is an ASCII case-insensitive substring search for
// any space-separated phrase, @streq is equality, @contains, @beginsWith and
// @endsWith are case-sensitive, @within reports whether the value occurs in
// the argument (so the empty value always matches).
func MatchesBenign(op, arg string) bool {
	var match func(string) bool
	switch op {
	case "rx":
		re, err := regexp.Compile(arg)
		if err != nil {
			return true
		}
		match = re.MatchString
	case "pm":
		phrases := strings.Split(asciiLower(arg), " ")
		match = func(v string) bool {
			v = asciiLower(v)
			for _, ph := range phrases {
				if strings.Contains(v, ph) {
					return true
				}
			}
			return false
		}
	case "streq":
		match = func(v string) bool { return v == arg }
	case "contains":
		match = func(v string) bool { return strings.Contains(v, arg) }
	case "beginsWith":
		match = func(v string) bool { return strings.HasPrefix(v, arg) }
	case "endsWith":
		match = func(v string) bool { return strings.HasSuffix(v, arg) }
	case "within":
		match = func(v string) bool { return strings.Contains(arg, v) }
	default:
		return true
	}
	for _, v := range BenignCorpus {
		if match(v) {
			return true
		}
	}
	return false
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
