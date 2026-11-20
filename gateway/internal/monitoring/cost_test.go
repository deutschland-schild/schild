package monitoring

import (
	"bytes"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	cm "github.com/deutschland-schild/schild/contract/monitoring"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
)

// referenceClassifyUA classifies with the contract's reference matcher
// (contract/bots Catalogue.Match over the shipped catalogue, every token
// searched with strings.Contains) and the generic checks one by one; the
// single-pass matcher and the cache must give the same answer (MVP-21
// measurement finding 5, MVP-22 catalogue).
func referenceClassifyUA(ua string) uaInfo {
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
	e := bots.Default()
	entry, catName := e.Catalogue().Match(ua)
	cat := -1
	for i, c := range cm.BotCategories {
		if c == catName {
			cat = i
		}
	}
	info := uaInfo{bot: cat, browser: brNone, os: osNone, device: devUnknown}
	if entry != nil {
		info.id = e.ID(entry.ID)
	}
	generic := func(ts ...string) bool {
		for _, t := range ts {
			if has(b, t) {
				return true
			}
		}
		return false
	}
	switch {
	case cat == botTool || cat == botScanner:
		info.class = uaTool
	case cat == botLikelyBrowser:
		info.class = uaBrowser
		info.browser, info.os, info.device = browserOf(b), osOf(b), deviceOf(b)
	case cat == botLikelyAutomated:
		if generic("bot", "crawler", "spider") {
			info.class = uaBotUnverified
		} else {
			info.class = uaOther
		}
	default:
		info.class = uaBotUnverified
	}
	return info
}

// standInTokens is the stand-in token list classify.go used before the
// MVP-22 catalogue (lower case, by category). Every token still names a
// catalogue entry or an automation token; the categories that changed
// are listed in categoryChanges.
var standInTokens = map[int][]string{
	botSearch:      {"googlebot", "bingbot", "yandexbot", "duckduckbot", "baiduspider", "applebot", "seznambot", "qwantbot", "petalbot", "sogou", "exabot", "mojeekbot", "yahoo! slurp", "google-inspectiontool", "storebot-google", "adsbot-google"},
	botAITraining:  {"gptbot", "ccbot", "claudebot", "anthropic-ai", "bytespider", "applebot-extended", "meta-externalagent", "amazonbot", "diffbot", "cohere-ai", "cohere-training-data-crawler", "omgilibot", "imagesiftbot", "ai2bot", "timpibot", "pangubot", "facebookbot", "google-extended"},
	botAISearch:    {"oai-searchbot", "perplexitybot", "claude-searchbot", "youbot", "duckassistbot", "phindbot"},
	botAIAssistant: {"chatgpt-user", "claude-user", "perplexity-user", "mistralai-user", "meta-externalfetcher", "claude-web"},
	botPreview:     {"facebookexternalhit", "twitterbot", "linkedinbot", "slackbot", "discordbot", "telegrambot", "whatsapp", "skypeuripreview", "pinterestbot", "redditbot", "mastodon", "embedly", "vkshare", "iframely"},
	botFeed:        {"feedly", "feedbin", "inoreader", "newsblur", "feedfetcher", "theoldreader", "tiny tiny rss", "freshrss", "miniflux", "netnewswire"},
	botMonitoring:  {"uptimerobot", "pingdom", "statuscake", "betteruptime", "site24x7", "updown.io", "hetrixtools", "uptime-kuma", "checkly", "freshping", "monitis", "nodeping"},
	botSEO:         {"ahrefsbot", "semrushbot", "mj12bot", "dotbot", "rogerbot", "screaming frog", "seokicks", "blexbot", "dataforseobot", "serpstatbot", "barkrowler", "sistrix", "seznam"},
	botArchive:     {"ia_archiver", "archive.org_bot", "heritrix", "researchscan", "netcraftsurveyagent"},
	botScanner:     {"nuclei", "sqlmap", "nikto", "nmap", "masscan", "zgrab", "wpscan", "acunetix", "nessus", "openvas", "censysinspect", "expanse", "internet-measurement", "dirbuster", "gobuster", "ffuf", "wfuzz", "qualys", "l9explore", "leakix"},
	botTool:        {"curl/", "wget/", "python-requests", "python-urllib", "python-httpx", "go-http-client", "libwww-perl", "okhttp", "java/", "apache-httpclient", "axios/", "node-fetch", "aiohttp", "guzzlehttp", "postmanruntime", "insomnia", "httpie", "powershell", "scrapy"},
}

// categoryChanges: stand-in tokens whose category the catalogue changed,
// and why.
var categoryChanges = map[string]int{
	"exabot":    botAITraining,  // "ExaBot" is Exa's AI crawler in ai.robots.txt; Exalead's Exabot is gone
	"cohere-ai": botAIAssistant, // ai.robots.txt: retrieves data for user-initiated prompts
	"seznam":    botSearch,      // part of the SeznamBot entry (Seznam.cz search engine)
}
var uaCorpus = []string{
	chromeUA,
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130 Safari/537.36 Edg/130.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
	"Mozilla/5.0 (compatible; Applebot-Extended/0.1)",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot/0.1)",
	"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
	"Mozilla/5.0 (compatible; Seznam screenshot-generator 2.1; +http://fulltext.sblog.cz/screenshot/) SeznamBot",
	"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
	"ChatGPT-User/1.0; +https://openai.com/bot",
	"Mozilla/5.0 (compatible; Claude-SearchBot/1.0; +claude.ai)",
	"curl/8.5.0", "Wget/1.21", "python-requests/2.32.3", "Go-http-client/1.1", "okhttp/4.12.0", "Java/17.0.2",
	"sqlmap/1.8#stable (https://sqlmap.org)", "Mozilla/5.0 zgrab/0.x", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0 Safari/537.36",
	"SomeCrawler/1.0", "my-spider", "data scraper", "weird-client", "UptimeRobot/2.0", "Feedly/1.0 (+http://www.feedly.com/fetcher.html)",
	"Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko", "Opera/9.80 (Windows NT 6.1) Presto/2.12 Version/12.16 OPR/1",
	"MOZILLA/5.0 GOOGLEBOT", "bot", "b", "Mozilla/", "Mozilla/5.0 " + string(bytes.Repeat([]byte("x"), 600)) + " Googlebot",
}

func TestClassifyUAMatchesReference(t *testing.T) {
	c := newUACache(bots.Default())
	for _, ua := range uaCorpus {
		want := referenceClassifyUA(ua)
		if got := classifyUA(ua); got != want {
			t.Errorf("%q: single pass %+v, reference %+v", ua, got, want)
		}
		for i := 0; i < 2; i++ { // miss, then hit
			if got := c.classify(ua); got != want {
				t.Errorf("%q: cache %+v, reference %+v", ua, got, want)
			}
		}
	}
	// Every catalogue and automation token alone and embedded.
	cat := bots.Default().Catalogue()
	toks := append([]string(nil), cat.AutomationTokens...)
	for _, b := range cat.Bots {
		toks = append(toks, b.UAMatch...)
	}
	for _, tk := range toks {
		for _, ua := range []string{tk, "Mozilla/5.0 (" + tk + ")", "x" + strings.ToUpper(tk) + "/1"} {
			want := referenceClassifyUA(ua)
			if got := classifyUA(ua); got != want {
				t.Errorf("%q: single pass %+v, reference %+v", ua, got, want)
			}
			for i := 0; i < 2; i++ {
				if got := c.classify(ua); got != want {
					t.Errorf("%q: cache %+v, reference %+v", ua, got, want)
				}
			}
		}
	}
}

// Every token of the former stand-in list still lands in a catalogue
// category (none falls back to likely_*), the same one as before except
// for the documented changes.
func TestStandInTokensKeepTheirCategory(t *testing.T) {
	for cat, toks := range standInTokens {
		for _, tk := range toks {
			want := cat
			if c, ok := categoryChanges[tk]; ok {
				want = c
			}
			for _, ua := range []string{"Mozilla/5.0 (compatible; " + tk + "/1.0)", tk + "/1.0"} {
				got := classifyUA(ua)
				if got.bot != want || got.id == 0 {
					t.Errorf("%q: category %s (entry %d), want %s", ua, cm.BotCategories[got.bot], got.id, cm.BotCategories[want])
				}
			}
		}
	}
}

// The cache is fixed in size: a flood of distinct user agents only replaces
// slots and never returns a wrong class.
func TestUACacheBoundedAndCorrect(t *testing.T) {
	c := newUACache(bots.Default())
	for i := 0; i < 50000; i++ {
		ua := uaCorpus[i%len(uaCorpus)] + " v" + strconv.Itoa(i)
		if got, want := c.classify(ua), referenceClassifyUA(ua[:min(len(ua), uaScan)]); got != want {
			t.Fatalf("%q: %+v, want %+v", ua, got, want)
		}
	}
	vs := []uaInfo{{5, 8, 7, 4, 12, 0}, {0, 0, 0, 0, 0, 0}, {2, 3, 4, 1, 11, 0}, {0, 8, 7, 4, 12, 0}}
	for id := 1; id <= bots.Default().NumBots(); id++ {
		vs = append(vs, botInfoOf(uint16(id), bots.Default().Category(uint16(id))))
	}
	for _, v := range vs {
		p := packUA(v)
		if p >= uaValid || c.unpackUA(p) != v {
			t.Fatalf("pack %+v: %x -> %+v", v, p, c.unpackUA(p))
		}
	}
}

// Record on the common request (same path, UA, referrer, client): the spec
// budget is at most 2 µs at p50. Run: go test -run - -bench Record ./internal/monitoring
func BenchmarkRecordCommon(b *testing.B) {
	rc := newRecorder(time.Now())
	q := Req{R: newReq("/products/123", chromeUA, "https://www.google.com/search?q=x"), Class: Forwarded, Status: 200, Timed: true,
		Total: 3 * time.Millisecond, UpstreamDur: 2 * time.Millisecond, BytesOut: 12000,
		Client: netip.MustParseAddr("198.51.100.10"), Country: "DE", ASN: 3320, ASOrg: "Deutsche Telekom AG", NetClass: "residential"}
	for i := 0; i < 64; i++ {
		rc.record(&q)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc.record(&q)
	}
}

// Record with a rotating set of 64 user agents (cache hits, several classes).
func BenchmarkRecordMixedUA(b *testing.B) {
	rc := newRecorder(time.Now())
	reqs := make([]*http.Request, 64)
	for i := range reqs {
		reqs[i] = newReq("/products/123", uaCorpus[i%len(uaCorpus)]+fmt.Sprint(i), "")
	}
	q := Req{Class: Forwarded, Status: 200, Timed: true, Client: netip.MustParseAddr("198.51.100.10"), Country: "DE", NetClass: "residential"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.R = reqs[i%len(reqs)]
		rc.record(&q)
	}
}

// classifyUA without the cache (every request a new user agent).
func BenchmarkClassifyUAMiss(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = classifyUA(uaCorpus[i%len(uaCorpus)])
	}
}

func BenchmarkClassifyUAReference(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = referenceClassifyUA(uaCorpus[i%len(uaCorpus)])
	}
}
