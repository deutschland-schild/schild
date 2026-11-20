package monitoring

import (
	"bytes"
	"hash/maphash"
	"strings"
	"sync/atomic"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// Classification of a request for the breakdown dimensions. Everything here
// runs on the request path: no allocation for the common case (the user
// agent is lower-cased into a stack buffer, tokens are byte slices).

// Indices into the fixed value lists of the contract (cm.UAClasses, ...).
const (
	uaBrowser = iota
	uaBotVerified
	uaBotUnverified
	uaTool
	uaNone
	uaOther
)

const (
	brChrome = iota
	brEdge
	brFirefox
	brSafari
	brOpera
	brSamsung
	brIE
	brOther
	brNone
)

const (
	osWindows = iota
	osMacOS
	osIOS
	osAndroid
	osLinux
	osChromeOS
	osOther
	osNone
)

const (
	devDesktop = iota
	devMobile
	devTablet
	devOther
	devUnknown
)

// Bot categories in the order of cm.BotCategories.
const (
	botSearch = iota
	botAITraining
	botAISearch
	botAIAssistant
	botPreview
	botFeed
	botMonitoring
	botSEO
	botArchive
	botScanner
	botTool
	botLikelyAutomated
	botLikelyBrowser
)

// uaInfo is the classification of one user agent. id is the bot catalogue
// entry (internal/bots, 0: none); bot is the category index into
// cm.BotCategories.
type uaInfo struct {
	class, browser, os, device, bot int
	id                              uint16
}

const uaScan = bots.MaxUABytes

// UAClass returns the contract UAClass of a user agent (the classification
// of the monitoring counters; listEvents ua_class, D36 amendment). Without
// the client address it cannot verify a bot, so a catalogue bot is
// bot_unverified here.
func UAClass(ua string) string { return cm.UAClasses[classifyUA(ua).class] }

// Methods are the methods of the method breakdown; every other method is
// OTHER (listEvents method, D36 amendment).
func Methods() []string { return append([]string(nil), methods[:len(methods)-1]...) }

// NetClasses are the net classes of the net_class breakdown.
func NetClasses() []string { return append([]string(nil), netClasses...) }

// classifyUA classifies a user agent with the shipped bot catalogue.
func classifyUA(ua string) uaInfo { return classifyWith(bots.Default(), ua) }

// classifyWith classifies a user agent (first 512 bytes, ASCII
// case-insensitive): the bot category and entry come from the catalogue
// (contract/bots Match), browser, OS and device only for likely browsers.
func classifyWith(e *bots.Engine, ua string) uaInfo {
	if ua == "" {
		return uaInfo{uaNone, brNone, osNone, devUnknown, botLikelyAutomated, 0}
	}
	var buf [uaScan]byte
	n := copy(buf[:], ua)
	b := buf[:n]
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	id, cat := e.MatchLower(b)
	if id != 0 {
		return botInfoOf(id, cat)
	}
	info := uaInfo{bot: cat, browser: brNone, os: osNone, device: devUnknown}
	switch {
	case cat == botLikelyBrowser:
		info.class = uaBrowser
		info.browser, info.os, info.device = browserOf(b), osOf(b), deviceOf(b)
	case has(b, "bot") || has(b, "crawler") || has(b, "spider"):
		info.class = uaBotUnverified // claims to be a bot the catalogue does not know
	default:
		info.class = uaOther
	}
	return info
}

// botInfoOf is the classification of a user agent that names catalogue
// entry id of category cat: tools and scanners are tool, every other entry
// a bot (bot_verified is decided per request from the address).
func botInfoOf(id uint16, cat int) uaInfo {
	info := uaInfo{bot: cat, id: id, browser: brNone, os: osNone, device: devUnknown, class: uaBotUnverified}
	if cat == botTool || cat == botScanner {
		info.class = uaTool
	}
	return info
}

// uaCache remembers the classification of recent user agents in a small
// direct-mapped table keyed by a keyed hash of the first 512 bytes (32 KiB,
// fixed). Lock-free: one atomic word per slot holds a 40-bit tag of the hash
// and the packed classification; a race only costs a re-classification.
type uaCache struct {
	seed  maphash.Seed
	bots  *bots.Engine
	slots [uaCacheSlots]atomic.Uint64
}

const (
	uaCacheSlots = 4096
	uaValid      = 1 << 23
)

func newUACache(e *bots.Engine) *uaCache { return &uaCache{seed: maphash.MakeSeed(), bots: e} }

// packUA packs a classification into the 23 bits below uaValid. Bit 0 says
// which form: a catalogue bot keeps only its id (bits 1..16; category and
// class follow from the id), any other user agent class, browser, OS,
// device and category.
func packUA(i uaInfo) uint64 {
	if i.id != 0 {
		return 1 | uint64(i.id)<<1
	}
	return uint64(i.class)<<1 | uint64(i.browser)<<4 | uint64(i.os)<<8 | uint64(i.device)<<11 | uint64(i.bot)<<14
}

func (c *uaCache) unpackUA(v uint64) uaInfo {
	if v&1 != 0 {
		id := uint16(v >> 1)
		return botInfoOf(id, c.bots.Category(id))
	}
	return uaInfo{class: int(v >> 1 & 7), browser: int(v >> 4 & 15), os: int(v >> 8 & 7), device: int(v >> 11 & 7), bot: int(v >> 14 & 15)}
}

func (c *uaCache) classify(ua string) uaInfo {
	if ua == "" {
		return classifyWith(c.bots, ua)
	}
	if len(ua) > uaScan {
		ua = ua[:uaScan]
	}
	h := maphash.String(c.seed, ua)
	slot := &c.slots[h%uaCacheSlots]
	tag := h >> 24 << 24
	if v := slot.Load(); v&uaValid != 0 && v>>24<<24 == tag {
		return c.unpackUA(v)
	}
	info := classifyWith(c.bots, ua)
	slot.Store(tag | uaValid | packUA(info))
	return info
}

func has(b []byte, s string) bool { return bytes.Contains(b, []byte(s)) }

func browserOf(b []byte) int {
	switch {
	case has(b, "samsungbrowser"):
		return brSamsung
	case has(b, "edg/") || has(b, "edge/") || has(b, "edga/") || has(b, "edgios/"):
		return brEdge
	case has(b, "opr/") || has(b, "opera"):
		return brOpera
	case has(b, "firefox/") || has(b, "fxios/"):
		return brFirefox
	case has(b, "crios/") || has(b, "chrome/") || has(b, "chromium/"):
		return brChrome
	case has(b, "msie ") || has(b, "trident/"):
		return brIE
	case has(b, "safari/"):
		return brSafari
	}
	return brOther
}

func osOf(b []byte) int {
	switch {
	case has(b, "windows"):
		return osWindows
	case has(b, "iphone") || has(b, "ipad") || has(b, "ipod"):
		return osIOS
	case has(b, "android"):
		return osAndroid
	case has(b, "cros "):
		return osChromeOS
	case has(b, "mac os x") || has(b, "macintosh"):
		return osMacOS
	case has(b, "linux") || has(b, "x11"):
		return osLinux
	}
	return osOther
}

func deviceOf(b []byte) int {
	switch {
	case has(b, "ipad") || has(b, "tablet") || (has(b, "android") && !has(b, "mobile")):
		return devTablet
	case has(b, "mobi") || has(b, "iphone") || has(b, "ipod"):
		return devMobile
	case has(b, "windows") || has(b, "macintosh") || has(b, "x11") || has(b, "linux") || has(b, "cros "):
		return devDesktop
	}
	return devOther
}

// Methods in the order of the method list ("OTHER" last).
var methods = []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE", "OTHER"}

func methodIndex(m string) int {
	for i, x := range methods[:len(methods)-1] {
		if m == x {
			return i
		}
	}
	return len(methods) - 1
}

// Net classes in the order of common.schema.json netClass.
var netClasses = []string{"residential", "mobile", "cgnat", "hosting", "business", "education", "government", "tor", "vpn", "proxy", "unknown"}

func netClassIndex(s string) int {
	for i, x := range netClasses {
		if s == x {
			return i
		}
	}
	return len(netClasses) - 1
}

// Countries: index of an upper-case ISO code, nCountries-1 for ZZ/unknown.
const nCountries = 26*26 + 1

func countryIndex(c string) int {
	if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' || c == "ZZ" {
		return nCountries - 1
	}
	return int(c[0]-'A')*26 + int(c[1]-'A')
}

func countryCode(i int) string {
	if i >= nCountries-1 {
		return "ZZ"
	}
	return string([]byte{byte('A' + i/26), byte('A' + i%26)})
}

func statusIndex(code int) int {
	switch {
	case code < 200:
		return 0
	case code < 300:
		return 1
	case code < 400:
		return 2
	case code < 500:
		return 3
	}
	return 4
}

// referrerKey derives the ReferrerKey of a Referer header for a request to
// host; registrable returns the registrable domain of a host ("" none). The result is a substring of ref or a
// constant whenever ref is lower case (no allocation).
//
// own holds the websites of this gateway (nil: none): a Referer from a host
// of any of them is _intern too (D36 amendment 2026-10-29,
// websites.Set.OwnHost), also an IP literal website.
func referrerKey(ref, host string, registrable func(string) string, own *sites.Registry) (key, label string) {
	if ref == "" {
		return cm.ReferrerDirect, ""
	}
	i := strings.Index(ref, "://")
	if i <= 0 {
		return cm.ReferrerOther, ""
	}
	h := ref[i+3:]
	if j := strings.IndexAny(h, "/?#"); j >= 0 {
		h = h[:j]
	}
	if j := strings.LastIndexByte(h, '@'); j >= 0 {
		h = h[j+1:]
	}
	if h != "" && own.OwnHost(h) {
		return cm.ReferrerIntern, ""
	}
	if strings.HasPrefix(h, "[") {
		return cm.ReferrerOther, "" // IPv6 literal
	}
	if j := strings.LastIndexByte(h, ':'); j >= 0 {
		h = h[:j]
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return cm.ReferrerOther, ""
	}
	if hasUpper(h) {
		h = strings.ToLower(h) // rare: browsers send lower-case hosts
	}
	if !hostChars(h) {
		return cm.ReferrerOther, ""
	}
	if k, name, ok := cm.AIAssistantOf(h); ok {
		return k, name
	}
	if sameSite(h, host) {
		return cm.ReferrerIntern, ""
	}
	last := h[strings.LastIndexByte(h, '.')+1:]
	if last == "" || last[0] < 'a' || last[0] > 'z' {
		return cm.ReferrerOther, "" // an IPv4 address or a bad label
	}
	d := registrable(h)
	if d == "" {
		return cm.ReferrerOther, ""
	}
	return d, ""
}

func hasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// hostChars: lower-case letters, digits, hyphen and dots, labels not empty,
// not starting or ending with a hyphen.
func hostChars(h string) bool {
	start := 0
	for i := 0; i <= len(h); i++ {
		if i == len(h) || h[i] == '.' {
			l := h[start:i]
			if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
				return false
			}
			start = i + 1
			continue
		}
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// sameSite: the referrer host is the request host or shares its last two
// labels (www.example.org and example.org, shop.example.org).
func sameSite(ref, host string) bool {
	if host == "" {
		return false
	}
	if j := strings.LastIndexByte(host, ':'); j >= 0 && !strings.Contains(host[j:], "]") {
		host = host[:j]
	}
	if strings.EqualFold(ref, host) {
		return true
	}
	return strings.EqualFold(lastLabels(ref, 2), lastLabels(host, 2)) && strings.Count(lastLabels(ref, 2), ".") == 1
}

func lastLabels(h string, n int) string {
	h = strings.TrimSuffix(h, ".")
	for i := len(h) - 1; i >= 0; i-- {
		if h[i] == '.' {
			n--
			if n == 0 {
				return h[i+1:]
			}
		}
	}
	return h
}
