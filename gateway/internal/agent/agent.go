// Package agent reduces a user agent to coarse fields: family (lower case,
// no dots), major version and a bot flag (behaviour fingerprints, MVP-18).
package agent

import (
	"regexp"
	"strconv"
	"strings"
)

// Info is the coarse agent.
type Info struct {
	Family string
	Major  int
	Bot    bool
}

type rule struct {
	family string
	re     *regexp.Regexp // first submatch is the version (optional)
	bot    bool
}

// Order matters: specific tools and bots before browsers, Edge/Opera before Chrome, Chrome before Safari.
var rules = []rule{
	{"sqlmap", regexp.MustCompile(`(?i)sqlmap/?(\d+)?`), false},
	{"nikto", regexp.MustCompile(`(?i)nikto/?(\d+)?`), false},
	{"nuclei", regexp.MustCompile(`(?i)nuclei/?v?(\d+)?`), false},
	{"wpscan", regexp.MustCompile(`(?i)wpscan\s*v?(\d+)?`), false},
	{"nmap", regexp.MustCompile(`(?i)nmap`), false},
	{"masscan", regexp.MustCompile(`(?i)masscan/?(\d+)?`), false},
	{"zgrab", regexp.MustCompile(`(?i)zgrab/?(\d+)?`), false},
	{"gobuster", regexp.MustCompile(`(?i)gobuster/?(\d+)?`), false},
	{"ffuf", regexp.MustCompile(`(?i)fuzz faster u fool v?(\d+)?|ffuf/?(\d+)?`), false},
	{"dirbuster", regexp.MustCompile(`(?i)dirbuster`), false},
	{"gotestwaf", regexp.MustCompile(`(?i)gotestwaf`), false},
	{"googlebot", regexp.MustCompile(`(?i)googlebot/?(\d+)?`), true},
	{"bingbot", regexp.MustCompile(`(?i)bingbot/?(\d+)?`), true},
	{"applebot", regexp.MustCompile(`(?i)applebot/?(\d+)?`), true},
	{"duckduckbot", regexp.MustCompile(`(?i)duckduckbot/?(\d+)?`), true},
	{"yandexbot", regexp.MustCompile(`(?i)yandexbot/?(\d+)?`), true},
	{"ahrefsbot", regexp.MustCompile(`(?i)ahrefsbot/?(\d+)?`), true},
	{"semrushbot", regexp.MustCompile(`(?i)semrushbot/?(\d+)?`), true},
	{"gptbot", regexp.MustCompile(`(?i)gptbot/?(\d+)?`), true},
	{"claudebot", regexp.MustCompile(`(?i)claudebot/?(\d+)?`), true},
	{"python-requests", regexp.MustCompile(`(?i)python-requests/(\d+)`), false},
	{"python-urllib", regexp.MustCompile(`(?i)python-urllib/(\d+)`), false},
	{"python-httpx", regexp.MustCompile(`(?i)python-httpx/(\d+)`), false},
	{"aiohttp", regexp.MustCompile(`(?i)aiohttp/(\d+)`), false},
	{"go-http-client", regexp.MustCompile(`(?i)go-http-client/(\d+)`), false},
	{"curl", regexp.MustCompile(`(?i)\bcurl/(\d+)`), false},
	{"wget", regexp.MustCompile(`(?i)\bwget/(\d+)`), false},
	{"okhttp", regexp.MustCompile(`(?i)okhttp/(\d+)`), false},
	{"java", regexp.MustCompile(`(?i)\bjava/(\d+)`), false},
	{"axios", regexp.MustCompile(`(?i)axios/(\d+)`), false},
	{"node-fetch", regexp.MustCompile(`(?i)node-fetch/?(\d+)?`), false},
	{"postman", regexp.MustCompile(`(?i)postmanruntime/(\d+)`), false},
	{"k6", regexp.MustCompile(`(?i)\bk6/(\d+)`), false},
	{"headless-chrome", regexp.MustCompile(`HeadlessChrome/(\d+)`), true},
	{"edge", regexp.MustCompile(`Edg(?:e|A|iOS)?/(\d+)`), false},
	{"opera", regexp.MustCompile(`(?:OPR|Opera)/(\d+)`), false},
	{"samsung", regexp.MustCompile(`SamsungBrowser/(\d+)`), false},
	{"firefox", regexp.MustCompile(`(?:Firefox|FxiOS)/(\d+)`), false},
	{"chrome", regexp.MustCompile(`(?:Chrome|CriOS)/(\d+)`), false},
	{"safari", regexp.MustCompile(`Version/(\d+)[0-9.]* (?:Mobile/\S+ )?Safari/`), false},
}

var botWords = regexp.MustCompile(`(?i)bot\b|crawler|spider|slurp|scraper`)

// Parse maps a user agent to its coarse form.
func Parse(ua string) Info {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return Info{Family: "none"}
	}
	if len(ua) > 1024 {
		ua = ua[:1024]
	}
	for _, r := range rules {
		m := r.re.FindStringSubmatch(ua)
		if m == nil {
			continue
		}
		major := 0
		for _, g := range m[1:] {
			if g != "" {
				if n, err := strconv.Atoi(g); err == nil && n <= 9999 {
					major = n
				}
				break
			}
		}
		return Info{Family: r.family, Major: major, Bot: r.bot}
	}
	if botWords.MatchString(ua) {
		return Info{Family: "other-bot", Bot: true}
	}
	return Info{Family: "other"}
}
