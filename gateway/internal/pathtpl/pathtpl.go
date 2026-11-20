// Package pathtpl turns a request path into the path template of the
// canonical request shape (signal.md): values that identify objects become
// {n}, {uuid}, {hex} or {slug}.
package pathtpl

import (
	"regexp"
	"strings"
)

var (
	numRe  = regexp.MustCompile(`^[0-9]+$`)
	uuidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexRe  = regexp.MustCompile(`(?i)^[0-9a-f]{8,}$`)
	safeRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)
	// Long opaque tokens with digits and letters (session ids, base64).
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,}$`)
)

// Collections whose next segment is an object name (slug).
var collections = map[string]bool{
	"posts": true, "post": true, "blog": true, "news": true, "article": true, "articles": true, "product": true,
	"products": true, "produkte": true, "category": true, "categories": true, "kategorie": true, "tag": true, "tags": true,
	"author": true, "user": true, "users": true, "profile": true, "profiles": true, "page": true, "pages": true,
	"item": true, "items": true, "shop": true, "p": true, "u": true, "files": true, "uploads": true, "download": true,
	"downloads": true, "media": true, "images": true, "img": true, "static": true, "assets": true,
}

// MaxLen bounds the template length.
const MaxLen = 512

// Template returns the path template of an (escaped) URL path.
func Template(path string) string {
	if path == "" {
		return "/"
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	segs := strings.Split(path, "/")
	prevCollection := false
	for i, s := range segs {
		if s == "" {
			prevCollection = false
			continue
		}
		low := strings.ToLower(s)
		switch {
		case numRe.MatchString(s):
			segs[i] = "{n}"
		case uuidRe.MatchString(s):
			segs[i] = "{uuid}"
		case hexRe.MatchString(s):
			segs[i] = "{hex}"
		case !safeRe.MatchString(s):
			segs[i] = "{slug}"
		case prevCollection && i == len(segs)-1 || prevCollection && i+1 < len(segs) && segs[i+1] == "":
			// last object name after a collection prefix, e.g. /blog/my-first-post/
			if !strings.Contains(s, ".") {
				segs[i] = "{slug}"
			}
		case tokenRe.MatchString(s) && hasDigitAndLetter(s):
			segs[i] = "{slug}"
		}
		prevCollection = collections[low]
	}
	out := strings.Join(segs, "/")
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	if len(out) > MaxLen {
		out = out[:MaxLen]
	}
	return out
}

func hasDigitAndLetter(s string) bool {
	d, l := false, false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			d = true
		} else if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			l = true
		}
	}
	return d && l
}
