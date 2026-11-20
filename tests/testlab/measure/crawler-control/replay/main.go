// Command replay is the TEST ONLY ground-truth replay of the MVP-29 measurement (crawler control, D57). It builds one
// deterministic request list from the shipped bot catalogue plus browser, tool and edge-case user agents, sends it to
// one ingress (Host header picks the website, X-Forwarded-For the client address, trusted from 127.0.0.1) and writes
// one JSON line per request with the class, what a correct gateway must do, and what came back.
//
// Addresses: documentation ranges for everything that must look foreign, and the first usable address of a published
// range of the catalogue for "inside the operator's ranges" (such packets never leave this machine).
//
//	replay -catalogue client/internal/bots/catalogue.json -target http://127.0.0.1:29190 -host shop.test -out run.jsonl
//	replay -list   # print the request list only
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type catalogue struct {
	Bots []struct {
		ID       string   `json:"id"`
		Category string   `json:"category"`
		UAMatch  []string `json:"ua_match"`
		Verify   struct {
			Ranges string `json:"ranges"`
		} `json:"verify"`
	} `json:"bots"`
	Ranges []struct {
		ID       string   `json:"id"`
		Prefixes []string `json:"prefixes"`
	} `json:"ranges"`
}

// Req is one request of the replay with its ground truth.
type Req struct {
	N        int    `json:"n"`
	Class    string `json:"class"`    // ai_training, search_engine, other_crawler, spoofed_googlebot, browser, automated, edge
	Bot      string `json:"bot"`      // catalogue id the UA names ("" none)
	Category string `json:"category"` // catalogue category of Bot
	Inside   bool   `json:"inside"`   // address inside the bot's published ranges
	Ranges   bool   `json:"ranges"`   // the operator of Bot publishes ranges (an outside address is an impersonator)
	UA       string `json:"ua"`
	IP       string `json:"ip"`
	Note     string `json:"note,omitempty"`
}

// Res is Req plus the answer.
type Res struct {
	Req
	Status     int     `json:"status"`
	CrawlerBlk bool    `json:"crawler_blocked"` // 403 with the crawler body
	BodySHA    string  `json:"body_sha"`
	Headers    string  `json:"headers"` // sorted response headers without Date
	Err        string  `json:"err,omitempty"`
	Ms         float64 `json:"ms"`
}

const crawlerBody = "This website does not allow this crawler.\n"

// realUAs are user agents as the operators document them (ai_training and search engines).
var realUAs = map[string][]string{
	"gptbot":                       {"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)"},
	"claudebot":                    {"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"},
	"anthropic-ai":                 {"anthropic-ai"},
	"ccbot":                        {"CCBot/2.0 (https://commoncrawl.org/faq/)", "Mozilla/5.0 (compatible; CCBot/2.0; +http://commoncrawl.org/faq/)"},
	"bytespider":                   {"Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)"},
	"amazonbot":                    {"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36"},
	"meta-externalagent":           {"meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)"},
	"facebookbot":                  {"Mozilla/5.0 (compatible; FacebookBot/1.0; +https://developers.facebook.com/docs/sharing/webmasters/facebookbot/)"},
	"diffbot":                      {"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 (compatible; Diffbot/0.1; +http://www.diffbot.com)"},
	"ai2bot-dolma":                 {"Mozilla/5.0 (compatible) Ai2Bot-Dolma (+https://www.allenai.org/crawler)"},
	"img2dataset":                  {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0 (compatible; img2dataset; +https://github.com/rom1504/img2dataset)"},
	"omgili":                       {"omgili/0.5 +http://omgili.com"},
	"timpibot":                     {"Timpibot/0.8 (+http://www.timpi.io)"},
	"googleother":                  {"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.69 Mobile Safari/537.36 (compatible; GoogleOther)", "GoogleOther"},
	"yandexadditionalbot":          {"Mozilla/5.0 (compatible; YandexAdditionalBot/3.0; +http://yandex.com/bots)"},
	"imagesiftbot":                 {"Mozilla/5.0 (compatible; ImagesiftBot; +imagesift.com)"},
	"cohere-training-data-crawler": {"cohere-training-data-crawler"},
	"googlebot": {"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.69 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/131.0.6778.69 Safari/537.36",
		"Googlebot/2.1 (+http://www.google.com/bot.html)"},
	"googlebot-image": {"Googlebot-Image/1.0"},
	"bingbot":         {"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/131.0.0.0 Safari/537.36", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
	"applebot":        {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)"},
	"duckduckbot":     {"DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)"},
	"yandexbot":       {"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"},
	"baiduspider":     {"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"},
	"seznambot":       {"Mozilla/5.0 (compatible; SeznamBot/4.0; +https://o-seznam.cz/napoveda/vyhledavani/en/seznambot-crawler/)"},
	"mojeekbot":       {"Mozilla/5.0 (compatible; MojeekBot/0.11; +https://www.mojeek.com/bot.html)"},
	"qwantbot":        {"Mozilla/5.0 (compatible; Qwantbot/1.0; +https://help.qwant.com/bot/)"},
	"petalbot":        {"Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)"},
}

// browsers: real browser user agents, including in-app browsers and devices.
var browsers = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 YaBrowser/24.10.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; U; Android 12; en-US; V2111 Build/SP1A.210812.003) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/100.0.4896.58 UCBrowser/13.6.0.1315 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 11; KFTRWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/130.4.1 like Chrome/130.0.6723.102 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; HUAWEI P60) AppleWebKit/537.36 (KHTML, like Gecko) HuaweiBrowser/15.0.4.312 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/476.0.0.40.103;FBBV/650000000;FBDV/iPhone15,2;FBMD/iPhone;FBSN/iOS;FBSV/17.5;FBSS/3;FBCR/;FBID/phone;FBLC/de_DE;FBOP/80]",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 350.0.0.31.94 (iPhone15,2; iOS 17_5; de_DE; de; scale=3.00; 1179x2556; 640000000)",
	"Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A.230805.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.6778.39 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/480.0.0.40.109;]",
	"Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A.230805.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.6778.39 Mobile Safari/537.36 musical_ly_2023709030 JsSdk/1.0 NetType/WIFI Channel/googleplay AppName/musical_ly app_version/37.9.3 ByteLocale/de ByteFullLocale/de Region/DE BytedanceWebview/d8a21c6",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Line/14.10.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.50(0x1800322a) NetType/WIFI Language/zh_CN",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [Pinterest/iOS]",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Snapchat/13.10.0.40 (like Safari/8618.2.12.10.4, panda)",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 Telegram-Android/11.4.2 (Google Pixel 8; Android 14; SDK 34; HIGH)",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Twitter for iPhone/10.60",
	"Mozilla/5.0 (Linux; Android 14; SM-A546B; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.6778.39 Mobile Safari/537.36 GSA/15.44.29.29.arm64",
	"Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.128 Safari/537.36 WebAppManager",
	"Mozilla/5.0 (PlayStation; PlayStation 5/6.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Vivaldi/7.0.3495.18",
	"Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Linux; Android 14; 23078PND5G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 XiaoMi/MiuiBrowser/14.20.0-gn",
	"Mozilla/5.0 (Linux; Android 13; Quest 3) AppleWebKit/537.36 (KHTML, like Gecko) OculusBrowser/35.0.0.6.66 SamsungBrowser/4.0 Chrome/130.0.0.0 VR Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15 Ecosia ios@11.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1 DuckDuckGo/7",
	"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 Brave/1",
}

// automated: user agents that name no catalogue crawler (likely_automated in the bot overview) or name a tool.
var automated = []struct{ ua, note string }{
	{"python-requests/2.32.3", "no catalogue entry"},
	{"Go-http-client/1.1", "no catalogue entry"},
	{"Go-http-client/2.0", "no catalogue entry"},
	{"node-fetch/1.0 (+https://github.com/bitinn/node-fetch)", "no catalogue entry"},
	{"PostmanRuntime/7.42.0", "no catalogue entry"},
	{"Apache-HttpClient/4.5.14 (Java/17.0.12)", "names tool java"},
	{"libwww-perl/6.77", "no catalogue entry"},
	{"Python-urllib/3.12", "no catalogue entry"},
	{"aiohttp/3.10.10", "no catalogue entry"},
	{"Ruby", "no catalogue entry"},
	{"curl/8.5.0", "names tool curl"},
	{"Wget/1.21.4", "names tool wget"},
	{"okhttp/4.12.0", "names tool okhttp"},
	{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36", "headless"},
	{"Mozilla/5.0 (compatible; UnknownCrawler/1.0; +https://example.org/bot)", "unknown crawler"},
	{"Mozilla/5.0 (compatible; MyAITrainer/1.0)", "unknown AI crawler, does not name a catalogue entry"},
	{"bot", "only bot"},
	{"-", "dash"},
	{"", "empty user agent"},
}

func addrInside(cat *catalogue, set string) string {
	for _, r := range cat.Ranges {
		if r.ID != set {
			continue
		}
		for _, p := range r.Prefixes {
			pf, err := netip.ParsePrefix(p)
			if err != nil || !pf.Addr().Is4() {
				continue
			}
			a := pf.Masked().Addr()
			if pf.Bits() < 32 {
				a = a.Next()
			}
			return a.String()
		}
	}
	return ""
}

func build(cat *catalogue) []Req {
	var out []Req
	n := 0
	foreign := func() string { // documentation addresses, one per request so no behaviour limit joins them
		n++
		nets := []string{"192.0.2.", "198.51.100.", "203.0.113."}
		return fmt.Sprintf("%s%d", nets[n%3], 1+(n/3)%250)
	}
	add := func(r Req) { out = append(out, r) }
	for _, b := range cat.Bots {
		class := "other_crawler"
		switch b.Category {
		case "ai_training":
			class = "ai_training"
		case "search_engine":
			class = "search_engine"
		}
		uas := append([]string(nil), realUAs[b.ID]...)
		for _, t := range b.UAMatch {
			uas = append(uas, "Mozilla/5.0 (compatible; "+t+"/1.0; +https://crawler.example/"+b.ID+")")
		}
		in := ""
		if b.Verify.Ranges != "" {
			in = addrInside(cat, b.Verify.Ranges)
		}
		for _, ua := range uas {
			if in != "" {
				add(Req{Class: class, Bot: b.ID, Category: b.Category, Inside: true, Ranges: true, UA: ua, IP: in})
			}
			add(Req{Class: class, Bot: b.ID, Category: b.Category, Ranges: in != "", UA: ua, IP: foreign()})
		}
	}
	// Spoofed Googlebot: the real user agents from addresses outside Google's ranges.
	gin := addrInside(cat, "googlebot")
	for i, ua := range realUAs["googlebot"] {
		for _, ip := range []string{foreign(), foreign(), "8.8.8." + fmt.Sprint(10+i), "1.1.1." + fmt.Sprint(10+i)} {
			add(Req{Class: "spoofed_googlebot", Bot: "googlebot", Category: "search_engine", Ranges: true, UA: ua, IP: ip})
		}
		add(Req{Class: "search_engine", Bot: "googlebot", Category: "search_engine", Inside: true, Ranges: true, UA: ua, IP: gin, Note: "real googlebot inside ranges"})
	}
	for _, ua := range browsers {
		for i := 0; i < 2; i++ {
			add(Req{Class: "browser", UA: ua, IP: foreign()})
		}
	}
	for _, a := range automated {
		bot := ""
		switch a.note {
		case "names tool curl":
			bot = "curl"
		case "names tool wget":
			bot = "wget"
		case "names tool okhttp":
			bot = "okhttp"
		case "names tool java":
			bot = "java"
		}
		cl := "automated"
		if bot != "" {
			cl = "tool"
		}
		add(Req{Class: cl, Bot: bot, Category: map[bool]string{true: "tool_library"}[bot != ""], UA: a.ua, IP: foreign(), Note: a.note})
	}
	// Edge cases. Bot names the entry the catalogue's longest-token rule picks.
	long := strings.Repeat("x", 600)
	pad := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 "
	edges := []Req{
		{Bot: "gptbot", Category: "ai_training", UA: "gptbot/1.0", Note: "lower case"},
		{Bot: "gptbot", Category: "ai_training", UA: "GPTBOT/1.0", Note: "upper case"},
		{Bot: "gptbot", Category: "ai_training", UA: "Mozilla/5.0 (compatible; gPtBoT/1.2)", Note: "mixed case"},
		{Bot: "claudebot", Category: "ai_training", UA: "Mozilla/5.0 (compatible; CLAUDEBOT/1.0)", Note: "upper case"},
		{Bot: "gptbot", Category: "ai_training", UA: "Mozilla/5.0 (compatible; SuperGPTBotChecker/1.0)", Note: "token as substring of another word"},
		{Bot: "ccbot", Category: "ai_training", UA: "Mozilla/5.0 (compatible; MyCCBotMonitor/1.0)", Note: "token as substring of another word"},
		{Bot: "gptbot", Category: "ai_training", UA: pad + "GPTBot/1.2 " + long, Note: "very long UA, token before byte 512"},
		{Bot: "", Category: "", UA: pad + long + " GPTBot/1.2", Note: "very long UA, token after byte 512 (not scanned)"},
		{Bot: "", Category: "", UA: pad + long, Note: "very long browser UA"},
		{Bot: "googlebot", Category: "search_engine", Ranges: true, UA: "Mozilla/5.0 (compatible; GPTBot/1.2; Googlebot/2.1)", Note: "two tokens, longest wins (Googlebot)"},
		{Bot: "bingbot", Category: "search_engine", Ranges: true, UA: "Mozilla/5.0 (compatible; GPTBot/1.2; Bingbot/2.0)", Note: "two tokens, longest wins (bingbot)"},
		{Bot: "", Category: "", UA: "Mozilla/5.0 (compatible; GPТBot/1.2)", Note: "Cyrillic Т homoglyph"},
		{Bot: "", Category: "", UA: "Mozilla/5.0 (compatible; GPT Bot/1.2)", Note: "token split by a space"},
		{Bot: "", Category: "", UA: "Mozilla/5.0 (compatible; GPT%42ot/1.2)", Note: "percent-encoded"},
		{Bot: "gptbot", Category: "ai_training", UA: "\tGPTBot/1.2 ", Note: "surrounding whitespace"},
		{Bot: "googlebot", Category: "search_engine", Ranges: true, UA: "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 GoogleBotDetector", Note: "browser UA with a word containing googlebot"},
	}
	for _, e := range edges {
		e.Class, e.IP = "edge", foreign()
		add(e)
	}
	for i := range out {
		out[i].N = i
	}
	return out
}

func headerString(h http.Header) string {
	var ks []string
	for k := range h {
		if k == "Date" {
			continue
		}
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	for _, k := range ks {
		b.WriteString(k + ": " + strings.Join(h[k], ",") + "\n")
	}
	return b.String()
}

func main() {
	catPath := flag.String("catalogue", "client/internal/bots/catalogue.json", "")
	target := flag.String("target", "http://127.0.0.1:29190", "")
	host := flag.String("host", "shop.test", "")
	out := flag.String("out", "run.jsonl", "")
	rps := flag.Int("rps", 40, "")
	list := flag.Bool("list", false, "print the request list only")
	path := flag.String("path", "/blog/hallo-welt", "")
	flag.Parse()
	raw, err := os.ReadFile(*catPath)
	if err != nil {
		panic(err)
	}
	var cat catalogue
	if err := json.Unmarshal(raw, &cat); err != nil {
		panic(err)
	}
	reqs := build(&cat)
	if *list {
		enc := json.NewEncoder(os.Stdout)
		for _, r := range reqs {
			_ = enc.Encode(r)
		}
		return
	}
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, MaxIdleConnsPerHost: 16, DisableCompression: true}
	hc := &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	tick := time.NewTicker(time.Second / time.Duration(*rps))
	defer tick.Stop()
	for _, q := range reqs {
		<-tick.C
		sem <- struct{}{}
		wg.Add(1)
		go func(q Req) {
			defer wg.Done()
			defer func() { <-sem }()
			rq, _ := http.NewRequest("GET", *target+*path, nil)
			rq.Host = *host
			rq.Header["User-Agent"] = []string{q.UA} // empty stays empty
			rq.Header.Set("X-Forwarded-For", q.IP)
			rq.Header.Set("Accept", "text/html")
			rs := Res{Req: q}
			t0 := time.Now()
			resp, err := hc.Do(rq)
			rs.Ms = float64(time.Since(t0).Microseconds()) / 1000
			if err != nil {
				rs.Err = err.Error()
			} else {
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				rs.Status = resp.StatusCode
				rs.CrawlerBlk = resp.StatusCode == 403 && string(b) == crawlerBody
				s := sha256.Sum256(b)
				rs.BodySHA = hex.EncodeToString(s[:8])
				rs.Headers = headerString(resp.Header)
			}
			line, _ := json.Marshal(rs)
			mu.Lock()
			w.Write(line)
			w.WriteByte('\n')
			mu.Unlock()
		}(q)
	}
	wg.Wait()
}
