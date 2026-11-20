package behaviour

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/deutschland-schild/schild/gateway/internal/agent"
)

// Fingerprints (MVP-18). A fingerprint is a property of the client stack
// that stays when IP and user agent rotate. Only JA4 (BSD-3-Clause, FoxIO),
// never JA4+ (FoxIO licence). Outside schild a fingerprint is only a local
// id: a keyed hash with the per-process key, never stored beyond a window.

// FingerprintKinds.
const (
	FPJA4     = "ja4"
	FPHeaders = "headers"
)

// ja4Re is the JA4 format (a header of a trusted TLS terminator).
var ja4Re = regexp.MustCompile(`^[tqd][0-9s]{2}[di][0-9]{2}[0-9]{2}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

// ValidJA4 reports whether v is a JA4 fingerprint (not JA4+).
func ValidJA4(v string) bool { return ja4Re.MatchString(v) }

// HeaderFingerprint is the fallback when no JA4 is available: a
// low-entropy set of what the client stack sends. Go's net/http does not
// keep header order, so the order is not part of it.
// h is the request's header map with canonical keys (net/http's Header).
func HeaderFingerprint(proto string, h map[string][]string) string {
	get := func(k string) string {
		if v := h[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	var names []string
	for k := range h {
		lk := strings.ToLower(k)
		switch lk {
		case "cookie", "authorization", "x-forwarded-for", "x-real-ip", "forwarded", "x-request-id", "content-length", "referer", "origin", "user-agent", "host":
			continue
		}
		if strings.HasPrefix(lk, "x-") {
			continue
		}
		names = append(names, lk)
	}
	sort.Strings(names)
	norm := func(v string) string {
		v = strings.ToLower(v)
		if len(v) > 128 {
			v = v[:128]
		}
		return v
	}
	lang := get("Accept-Language")
	langShape := "none"
	if lang != "" {
		langShape = strconv.Itoa(strings.Count(lang, ",") + 1) // number of languages, not which
	}
	return strings.Join([]string{
		proto, strings.Join(names, ","), norm(get("Accept")), norm(get("Accept-Encoding")), langShape,
		norm(get("Sec-Fetch-Mode")), norm(get("Sec-Fetch-Dest")), strconv.FormatBool(get("Sec-Ch-Ua") != ""),
	}, "|")
}

// FingerprintID turns raw fingerprint material into the local id (12 hex,
// keyed per process; the raw value is not kept).
func FingerprintID(kind, raw string) string {
	return fmt.Sprintf("%012x", hashString(kind+"\x00"+raw)>>16)
}

var chromium = map[string]bool{"chrome": true, "edge": true, "opera": true, "samsung": true, "headless-chrome": true}
var browsers = map[string]bool{"chrome": true, "edge": true, "opera": true, "samsung": true, "firefox": true, "safari": true}

// Inconsistent applies the stage-0 checks of concept 24 section 10 to one
// request: the user agent contradicts the headers the browser sends by
// itself. Nothing is requested from the browser; the result is only used
// for counting and cluster membership, never to block a request by itself.
func Inconsistent(ua string, hdr map[string][]string, https bool) bool {
	ag := agent.Parse(ua)
	get := func(k string) string {
		if v := hdr[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if get("Sec-Ch-Ua") != "" && !chromium[ag.Family] {
		return true // client hints from a non-Chromium user agent
	}
	if !browsers[ag.Family] {
		return false // tools say what they are; nothing contradicts
	}
	if get("Accept-Language") == "" {
		return true
	}
	isChrome := chromium[ag.Family] && strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "CriOS")
	if (isChrome && ag.Major >= 80) || (ag.Family == "firefox" && ag.Major >= 90 && !strings.Contains(ua, "FxiOS")) {
		if get("Sec-Fetch-Mode") == "" {
			return true
		}
	}
	if isChrome && ag.Major >= 90 && https && get("Sec-Ch-Ua") == "" {
		return true
	}
	return false
}
